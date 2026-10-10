// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! OCI `User` resolution against the image's own `/etc/passwd` and `/etc/group`.

use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

/// `uid`, `uid:gid`, `name`, `name:group` or `uid:group`. A numeric uid with no passwd entry gets gid 0, as in Docker.
pub fn resolve_user(spec: &str, passwd: &str, group: &str) -> Result<Identity> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("empty user");
    }
    let (u, g) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let entry = passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 || l.starts_with('#') {
            return None;
        }
        let uid: u32 = f[2].parse().ok()?;
        let gid: u32 = f[3].parse().ok()?;
        let hit = match u.parse::<u32>() {
            Ok(n) => uid == n,
            Err(_) => f[0] == u,
        };
        hit.then(|| (uid, gid, f[5].to_string()))
    });
    let (uid, pw_gid, home) = match (entry, u.parse::<u32>()) {
        (Some(e), _) => e,
        (None, Ok(n)) => (n, 0, "/".to_string()),
        (None, Err(_)) => bail!("user {u:?} is not in the image's /etc/passwd"),
    };
    let gid = match g {
        None => pw_gid,
        Some(g) => match g.parse::<u32>() {
            Ok(n) => n,
            Err(_) => group
                .lines()
                .find_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() >= 3 && f[0] == g)
                        .then(|| f[2].parse().ok())
                        .flatten()
                })
                .ok_or_else(|| anyhow::anyhow!("group {g:?} is not in the image's /etc/group"))?,
        },
    };
    Ok(Identity {
        uid,
        gid,
        home: if home.is_empty() { "/".into() } else { home },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nnginx:x:101:101:nginx:/var/cache/nginx:/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
    const GROUP: &str = "root:x:0:\nnginx:x:101:\nwww-data:x:33:nginx\n";

    #[test]
    fn names_and_numbers_resolve() {
        let id = |s| resolve_user(s, PASSWD, GROUP).unwrap();
        assert_eq!(
            id("nginx"),
            Identity {
                uid: 101,
                gid: 101,
                home: "/var/cache/nginx".into()
            }
        );
        assert_eq!(id("0").home, "/root");
        assert_eq!(
            (id("nginx:www-data").uid, id("nginx:www-data").gid),
            (101, 33)
        );
        assert_eq!(
            (id("65534:65534").uid, id("65534:65534").gid),
            (65534, 65534)
        );
        assert_eq!(
            id("1000"),
            Identity {
                uid: 1000,
                gid: 0,
                home: "/".into()
            }
        );
        assert_eq!((id("1000:1000").uid, id("1000:1000").gid), (1000, 1000));
        // distroless: no passwd file at all.
        assert_eq!(resolve_user("65532:65532", "", "").unwrap().uid, 65532);
    }

    #[test]
    fn unknown_names_fail() {
        assert!(resolve_user("ghost", PASSWD, GROUP).is_err());
        assert!(resolve_user("nginx:ghosts", PASSWD, GROUP).is_err());
        assert!(resolve_user("", PASSWD, GROUP).is_err());
    }
}
