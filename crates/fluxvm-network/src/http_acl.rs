// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! HTTP method + host + path ACL for the live L7 egress proxy.
//!
//! Rules are `<allow|deny> <METHOD|*> <host-glob>[/<path-glob>]`, e.g.
//! `allow GET docs.python.org/*`, `allow POST api.openai.com/v1/chat/completions`,
//! `deny * */admin/*`. See `docs/http-acl.md`.
//!
//! Semantics: no rules = ACL off. Otherwise a matching `deny` always wins, and
//! if any `allow` rule exists a request must match one (default deny). `*` in
//! a host or path glob matches any run of characters, including `/`. Hosts and
//! methods compare case-insensitively; paths are case-sensitive and are matched
//! without the query string, after [`normalize_path`].

/// Result of an ACL check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny(String),
}

impl Verdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
struct Rule {
    action: Action,
    /// Upper-case method, or `None` for `*`.
    method: Option<String>,
    /// Lower-case host glob.
    host: String,
    /// Path glob starting with `/`; `None` = any path.
    path: Option<String>,
    source: String,
}

impl Rule {
    fn method_matches(&self, method: &str) -> bool {
        self.method
            .as_deref()
            .is_none_or(|m| m.eq_ignore_ascii_case(method))
    }

    fn host_matches(&self, host: &str) -> bool {
        glob_match(&self.host, host)
    }

    fn path_matches(&self, path: &str) -> bool {
        self.path.as_deref().is_none_or(|p| glob_match(p, path))
    }

    /// True when the rule constrains neither method nor path.
    fn covers_whole_host(&self) -> bool {
        let any_method = self
            .method
            .as_deref()
            .is_none_or(|m| m.eq_ignore_ascii_case("CONNECT"));
        let any_path = self.path.as_deref().is_none_or(|p| p == "/*");
        any_method && any_path
    }
}

/// A parsed rule set.
#[derive(Debug, Clone, Default)]
pub struct HttpAcl {
    rules: Vec<Rule>,
}

impl HttpAcl {
    /// Parse rules. Any malformed rule is an error: a silently dropped `deny`
    /// rule would fail open.
    pub fn parse(rules: &[String]) -> Result<Self, String> {
        let mut out = Vec::with_capacity(rules.len());
        for raw in rules {
            out.push(parse_rule(raw).map_err(|e| format!("http rule {raw:?}: {e}"))?);
        }
        Ok(Self { rules: out })
    }

    pub fn is_active(&self) -> bool {
        !self.rules.is_empty()
    }

    fn has_allow(&self) -> bool {
        self.rules.iter().any(|r| r.action == Action::Allow)
    }

    /// Check a plain-HTTP request. `host` must already be canonical (see
    /// [`effective_host`]); `raw_path` is the request path without the query.
    pub fn check(&self, method: &str, host: &str, raw_path: &str) -> Verdict {
        if !self.is_active() {
            return Verdict::Allow;
        }
        let path = match normalize_path(raw_path) {
            Ok(p) => p,
            Err(e) => return Verdict::Deny(format!("rejected path: {e}")),
        };
        let host = host.to_ascii_lowercase();
        for r in &self.rules {
            if r.action == Action::Deny
                && r.method_matches(method)
                && r.host_matches(&host)
                && r.path_matches(&path)
            {
                return Verdict::Deny(format!("denied by rule {:?}", r.source));
            }
        }
        if !self.has_allow() {
            return Verdict::Allow;
        }
        for r in &self.rules {
            if r.action == Action::Allow
                && r.method_matches(method)
                && r.host_matches(&host)
                && r.path_matches(&path)
            {
                return Verdict::Allow;
            }
        }
        Verdict::Deny(format!("no allow rule matches {method} {host}{path}"))
    }

    /// Check a `CONNECT` tunnel. Inside a tunnel the method and path are
    /// invisible, so the tunnel is allowed only when that is provably safe:
    /// no deny rule can apply to the host, and an allow rule covers every
    /// method and path on it.
    pub fn check_connect(&self, host: &str) -> Verdict {
        if !self.is_active() {
            return Verdict::Allow;
        }
        let host = host.to_ascii_lowercase();
        for r in &self.rules {
            if r.action == Action::Deny && r.host_matches(&host) {
                return Verdict::Deny(format!(
                    "tunnel to {host} refused: deny rule {:?} cannot be enforced inside a tunnel",
                    r.source
                ));
            }
        }
        if !self.has_allow() {
            return Verdict::Allow;
        }
        if self
            .rules
            .iter()
            .any(|r| r.action == Action::Allow && r.host_matches(&host) && r.covers_whole_host())
        {
            return Verdict::Allow;
        }
        Verdict::Deny(format!(
            "tunnel to {host} refused: no allow rule covers every method and path on it"
        ))
    }
}

fn parse_rule(raw: &str) -> Result<Rule, String> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() != 3 {
        return Err("expected `<allow|deny> <METHOD|*> <host>[/<path>]`".into());
    }
    let action = match parts[0].to_ascii_lowercase().as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        other => return Err(format!("unknown action {other:?}, expected allow or deny")),
    };
    let method = if parts[1] == "*" {
        None
    } else if !parts[1].is_empty() && parts[1].bytes().all(|b| b.is_ascii_alphabetic()) {
        Some(parts[1].to_ascii_uppercase())
    } else {
        return Err(format!("invalid method {:?}", parts[1]));
    };
    let target = parts[2];
    let (host, path) = match target.find('/') {
        Some(i) => (&target[..i], Some(&target[i..])),
        None => (target, None),
    };
    if host.is_empty() {
        return Err("empty host glob".into());
    }
    if host
        .bytes()
        .any(|b| b == b'@' || b == b'\\' || b == b'?' || b == b'#' || b.is_ascii_control())
    {
        return Err("invalid character in host glob".into());
    }
    if let Some(p) = path {
        validate_path_glob(p)?;
    }
    Ok(Rule {
        action,
        method,
        host: host.to_ascii_lowercase(),
        path: path.map(str::to_string),
        source: raw.trim().to_string(),
    })
}

/// A path glob is compared with the *normalized* request path, so a glob that
/// could never equal one (encoded bytes, dot segments, doubled slashes) would
/// silently never match. For a `deny` rule that fails open, so reject it.
fn validate_path_glob(p: &str) -> Result<(), String> {
    if p.bytes()
        .any(|b| matches!(b, b'%' | b'?' | b'#' | b'\\') || b.is_ascii_control())
    {
        return Err("path glob must be a literal decoded path (no %, ?, #, or backslash)".into());
    }
    if p.contains("//") {
        return Err("path glob must not contain `//`".into());
    }
    if p.split('/').any(|s| s == "." || s == "..") {
        return Err("path glob must not contain `.` or `..` segments".into());
    }
    Ok(())
}

/// Glob match where `*` matches any run of characters (including `/` and
/// nothing) and everything else is literal. Iterative, so hostile patterns
/// cannot blow the stack.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Canonicalize a request path (no query) so rules see what the upstream
/// will: percent-escapes of unreserved characters are decoded (so `%2e%2e`
/// is `..` and `%61` is `a`), other escapes are kept with upper-case hex,
/// duplicate slashes collapse, and `.` / `..` segments are resolved (clamped
/// at the root). A trailing `/`, `/.` or `/..` yields a trailing slash.
///
/// Paths that cannot be interpreted unambiguously are rejected: malformed
/// `%` escapes, `%00`, encoded slash (`%2F`) or backslash (`%5C`), a raw
/// backslash, control or non-ASCII bytes, and anything not starting with `/`.
pub fn normalize_path(raw: &str) -> Result<String, String> {
    let raw = raw.split(['?', '#']).next().unwrap_or("");
    if raw.is_empty() {
        return Ok("/".into());
    }
    if !raw.starts_with('/') {
        return Err(format!("path {raw:?} does not start with `/`"));
    }
    let bytes = raw.as_bytes();
    let mut decoded = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or_else(|| "malformed percent-escape".to_string())?;
                i += 3;
                match hex {
                    0 => return Err("encoded NUL".into()),
                    b'/' | b'\\' => return Err("encoded slash or backslash".into()),
                    h if is_unreserved(h) => decoded.push(h as char),
                    h => decoded.push_str(&format!("%{h:02X}")),
                }
            }
            b'\\' => return Err("backslash in path".into()),
            b if b < 0x20 || b == 0x7f || b >= 0x80 => {
                return Err("control or non-ASCII byte in path".into());
            }
            b => {
                decoded.push(b as char);
                i += 1;
            }
        }
    }
    let mut stack: Vec<&str> = Vec::new();
    let mut trailing = false;
    let segs: Vec<&str> = decoded.split('/').collect();
    for (idx, seg) in segs.iter().enumerate() {
        let last = idx == segs.len() - 1;
        match *seg {
            "" | "." => trailing = last,
            ".." => {
                stack.pop();
                trailing = last;
            }
            s => {
                stack.push(s);
                trailing = false;
            }
        }
    }
    let mut out = String::from("/");
    out.push_str(&stack.join("/"));
    if trailing && !stack.is_empty() {
        out.push('/');
    }
    Ok(out)
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Canonical host: userinfo-free, port stripped, trailing dot removed,
/// lower-case. Rejects empty hosts and hosts with characters that make the
/// authority ambiguous.
pub fn canon_host(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty host".into());
    }
    if s.bytes().any(|b| {
        b == b'@' || b == b'/' || b == b'\\' || b.is_ascii_whitespace() || b.is_ascii_control()
    }) {
        return Err(format!("ambiguous host {s:?}"));
    }
    if !s.starts_with('[') && s.matches(':').count() > 1 {
        return Err(format!("unbracketed IPv6 literal {s:?}"));
    }
    let host = if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']').ok_or("unterminated IPv6 literal")?;
        &s[..end + 2]
    } else {
        match s.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
            Some((_, port)) if port.is_empty() => &s[..s.len() - 1],
            _ => s,
        }
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("empty host".into());
    }
    Ok(host)
}

/// The host a request is really addressed to. `uri_host` is the authority of
/// an absolute-form request line, `host_header` the `Host` header. If both are
/// present and differ the request is ambiguous (the filter would judge one
/// host while the upstream connection goes to the other) and is rejected.
pub fn effective_host(uri_host: Option<&str>, host_header: Option<&str>) -> Result<String, String> {
    let from_uri = uri_host.map(canon_host).transpose()?;
    let from_header = host_header.map(canon_host).transpose()?;
    match (from_uri, from_header) {
        (Some(u), Some(h)) if u != h => Err(format!(
            "request URI host {u:?} differs from Host header {h:?}"
        )),
        (Some(u), _) => Ok(u),
        (None, Some(h)) => Ok(h),
        (None, None) => Err("request has no host".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(rules: &[&str]) -> HttpAcl {
        HttpAcl::parse(&rules.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn denied(v: Verdict) -> bool {
        matches!(v, Verdict::Deny(_))
    }

    #[test]
    fn empty_rules_are_a_no_op() {
        let a = acl(&[]);
        assert!(!a.is_active());
        assert!(a.check("DELETE", "anything.example", "/admin").is_allow());
        assert!(a.check_connect("anything.example").is_allow());
    }

    #[test]
    fn allow_rules_default_deny() {
        let a = acl(&[
            "allow GET docs.python.org/*",
            "allow POST api.openai.com/v1/chat/completions",
        ]);
        assert!(
            a.check("GET", "docs.python.org", "/3/library/os.html")
                .is_allow()
        );
        assert!(a.check("GET", "docs.python.org", "/").is_allow());
        assert!(
            a.check("POST", "api.openai.com", "/v1/chat/completions")
                .is_allow()
        );
        assert!(denied(a.check("POST", "docs.python.org", "/3/")));
        assert!(denied(a.check(
            "GET",
            "api.openai.com",
            "/v1/chat/completions"
        )));
        assert!(denied(a.check("POST", "api.openai.com", "/v1/models")));
        assert!(denied(a.check("GET", "evil.example", "/")));
    }

    #[test]
    fn deny_wins_over_allow() {
        let a = acl(&["allow * example.com/*", "deny * */admin/*"]);
        assert!(a.check("GET", "example.com", "/public/x").is_allow());
        assert!(denied(a.check("GET", "example.com", "/admin/users")));
        assert!(denied(a.check("POST", "example.com", "/admin/users")));
    }

    #[test]
    fn deny_only_rules_allow_everything_else() {
        let a = acl(&["deny DELETE */*"]);
        assert!(a.check("GET", "example.com", "/x").is_allow());
        assert!(denied(a.check("DELETE", "example.com", "/x")));
    }

    #[test]
    fn method_and_host_are_case_insensitive_path_is_not() {
        let a = acl(&["allow get Docs.Python.ORG/Docs/*"]);
        assert!(a.check("GET", "docs.python.org", "/Docs/a").is_allow());
        assert!(a.check("get", "DOCS.PYTHON.ORG", "/Docs/a").is_allow());
        assert!(denied(a.check("GET", "docs.python.org", "/docs/a")));
    }

    #[test]
    fn omitted_path_matches_any_path() {
        let a = acl(&["allow GET example.com"]);
        assert!(a.check("GET", "example.com", "/anything/at/all").is_allow());
        assert!(a.check("GET", "example.com", "/").is_allow());
    }

    #[test]
    fn star_matches_across_slashes_and_empty() {
        assert!(glob_match("/v1/*", "/v1/a/b/c"));
        assert!(glob_match("/v1/*", "/v1/"));
        assert!(!glob_match("/v1/*", "/v1"));
        assert!(glob_match("*.example.com", "a.b.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
    }

    #[test]
    fn deny_trailing_star_does_not_cover_bare_directory() {
        // Documented: `/admin/*` needs a companion `/admin` rule for the bare path.
        let a = acl(&["deny * */admin/*"]);
        assert!(a.check("GET", "h.example", "/admin").is_allow());
        let both = acl(&["deny * */admin/*", "deny * */admin"]);
        assert!(denied(both.check("GET", "h.example", "/admin")));
    }

    #[test]
    fn query_string_is_ignored_for_matching() {
        let a = acl(&["deny * */admin/*"]);
        assert!(denied(a.check("GET", "h.example", "/admin/x?y=1")));
        let b = acl(&["allow GET h.example/ok"]);
        assert!(b.check("GET", "h.example", "/ok?x=/admin/").is_allow());
    }

    #[test]
    fn dot_dot_segments_cannot_bypass_deny() {
        let a = acl(&["allow * h.example/*", "deny * */admin/*"]);
        for p in [
            "/a/../admin/x",
            "/a/b/../../admin/x",
            "/./admin/x",
            "/admin/./x",
            "/%61dmin/x",
            "//admin/x",
            "/admin//x",
            "/x/%2e%2e/admin/x",
            "/x/%2E%2E/admin/x",
            "/x/.%2e/admin/x",
            "/admin/x/",
            "/../admin/x",
            "/../../admin/x",
        ] {
            assert!(denied(a.check("GET", "h.example", p)), "bypassed via {p}");
        }
    }

    #[test]
    fn trailing_dot_segment_hits_directory_rule() {
        let a = acl(&["allow * h.example/*", "deny * */admin/*"]);
        assert!(denied(a.check("GET", "h.example", "/admin/.")));
        assert!(denied(a.check("GET", "h.example", "/admin/x/..")));
    }

    #[test]
    fn deny_on_percent_encoded_literal_segment() {
        let a = acl(&["allow * h.example/*", "deny * */secret/*"]);
        assert!(denied(a.check("GET", "h.example", "/%73%65%63%72%65%74/k")));
    }

    #[test]
    fn allow_rule_cannot_be_satisfied_by_traversal() {
        let a = acl(&["allow GET h.example/public/*"]);
        assert!(a.check("GET", "h.example", "/public/x").is_allow());
        assert!(denied(a.check("GET", "h.example", "/public/../private/x")));
        assert!(denied(a.check(
            "GET",
            "h.example",
            "/public/%2e%2e/private/x"
        )));
    }

    #[test]
    fn ambiguous_encodings_are_rejected_not_guessed() {
        let a = acl(&["allow * h.example/*"]);
        for p in [
            "/a%2fb",
            "/a%2Fb",
            "/a%5cb",
            "/a\\b",
            "/a%00b",
            "/a%zz",
            "/a%2",
            "/a%",
            "/a\tb",
            "/caf\u{e9}",
            "no-slash",
        ] {
            assert!(denied(a.check("GET", "h.example", p)), "accepted {p:?}");
        }
    }

    #[test]
    fn normalize_examples() {
        let n = |s: &str| normalize_path(s).unwrap();
        assert_eq!(n("/"), "/");
        assert_eq!(n(""), "/");
        assert_eq!(n("/a/../admin"), "/admin");
        assert_eq!(n("/%61dmin"), "/admin");
        assert_eq!(n("//admin"), "/admin");
        assert_eq!(n("/admin/."), "/admin/");
        assert_eq!(n("/admin/"), "/admin/");
        assert_eq!(n("/a/b/.."), "/a/");
        assert_eq!(n("/a/.."), "/");
        assert_eq!(n("/../.."), "/");
        assert_eq!(n("/x/%2e%2E/y"), "/y");
        assert_eq!(n("/a%20b"), "/a%20b");
        assert_eq!(n("/a%3bb"), "/a%3Bb");
        assert_eq!(n("/a?b=/../c"), "/a");
        assert_eq!(n("/a#frag"), "/a");
    }

    #[test]
    fn effective_host_prefers_agreement_and_rejects_mismatch() {
        assert_eq!(
            effective_host(Some("Example.COM"), Some("example.com:8080")).unwrap(),
            "example.com"
        );
        assert_eq!(
            effective_host(None, Some("a.example.")).unwrap(),
            "a.example"
        );
        assert_eq!(
            effective_host(Some("a.example"), None).unwrap(),
            "a.example"
        );
        assert!(effective_host(Some("evil.example"), Some("good.example")).is_err());
        assert!(effective_host(None, None).is_err());
        assert!(effective_host(None, Some("")).is_err());
        assert!(effective_host(None, Some("user@good.example")).is_err());
        assert!(effective_host(None, Some("good.example/x")).is_err());
    }

    #[test]
    fn canon_host_handles_ports_and_ipv6() {
        assert_eq!(canon_host("example.com:443").unwrap(), "example.com");
        assert_eq!(canon_host("example.com.:443").unwrap(), "example.com");
        assert_eq!(canon_host("[::1]:8080").unwrap(), "[::1]");
        assert_eq!(canon_host("[::1]").unwrap(), "[::1]");
        assert_eq!(canon_host("EXAMPLE.com").unwrap(), "example.com");
        assert!(canon_host("[::1").is_err());
        assert!(canon_host("a b").is_err());
        assert!(canon_host("::1").is_err());
    }

    #[test]
    fn host_glob_cannot_be_dodged_with_port_or_dot() {
        let a = acl(&["deny * evil.example/*", "allow * */*"]);
        let h = effective_host(None, Some("EVIL.example.:80")).unwrap();
        assert!(denied(a.check("GET", &h, "/x")));
    }

    #[test]
    fn parse_rejects_malformed_rules() {
        for bad in [
            "",
            "allow",
            "allow GET",
            "permit GET example.com/*",
            "allow GE7 example.com",
            "allow GET /path-only",
            "allow GET a@example.com/x",
            "deny * */admin/../x",
            "deny * */a%2fb",
            "deny * */a//b",
            "deny * */x?y=1",
            "allow GET example.com/a b",
        ] {
            assert!(
                HttpAcl::parse(&[bad.to_string()]).is_err(),
                "accepted bad rule {bad:?}"
            );
        }
    }

    #[test]
    fn connect_needs_full_host_cover_and_no_applicable_deny() {
        let a = acl(&["allow GET docs.python.org/*", "allow * api.example.com"]);
        assert!(denied(a.check_connect("docs.python.org")));
        assert!(a.check_connect("api.example.com").is_allow());
        assert!(denied(a.check_connect("other.example")));

        let b = acl(&["allow * */*", "deny * */admin/*"]);
        assert!(denied(b.check_connect("anything.example")));

        let c = acl(&["allow CONNECT api.example.com/*"]);
        assert!(c.check_connect("api.example.com").is_allow());

        let d = acl(&["deny * evil.example/*"]);
        assert!(denied(d.check_connect("evil.example")));
        assert!(d.check_connect("fine.example").is_allow());
    }

    #[test]
    fn hostile_glob_terminates_quickly() {
        let p = "*a".repeat(200);
        let t = "a".repeat(2000);
        // Must terminate promptly; the answer itself is not the point.
        let _ = glob_match(&p, &t);
    }
}
