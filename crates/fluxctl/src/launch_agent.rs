// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxctl service install | uninstall | status`: run `fluxctl serve` as a launchd LaunchAgent of the logged-in user.
//! Not a system LaunchDaemon: Virtualization.framework restores saved VM state only in an unlocked login session
//! (see deploy/launchd-notes.md).

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LABEL: &str = "dev.zyvor.fluxvm";

pub fn plist_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

fn log_path(home: &Path) -> PathBuf {
    home.join("Library/Logs/fluxvm.log")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The LaunchAgent: `fluxctl [--config FILE] serve`, started at login and restarted if it exits. No token or secret
/// is written into it; the daemon reads its config file.
pub fn render_plist(fluxctl: &Path, config: Option<&Path>, log: &Path) -> String {
    let mut args = vec![fluxctl.display().to_string()];
    if let Some(c) = config {
        args.push("--config".into());
        args.push(c.display().to_string());
    }
    args.push("serve".into());
    let args: String = args
        .iter()
        .map(|a| format!("    <string>{}</string>\n", xml_escape(a)))
        .collect();
    let log = xml_escape(&log.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#
    )
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn domain() -> String {
    // SAFETY: getuid has no preconditions and cannot fail.
    format!("gui/{}", unsafe { libc::getuid() })
}

fn launchctl(args: &[&str]) -> Result<std::process::Output> {
    Command::new("/bin/launchctl")
        .args(args)
        .output()
        .context("running /bin/launchctl (launchd is macOS only)")
}

/// Writes the plist (replacing an older one) and (re)loads it.
pub fn install(config: Option<&Path>) -> Result<PathBuf> {
    if !cfg!(target_os = "macos") {
        bail!("`fluxctl service` installs a macOS LaunchAgent; on Linux use a systemd unit");
    }
    let home = home()?;
    let exe = std::env::current_exe()
        .context("locating fluxctl")?
        .canonicalize()?;
    let config = match config {
        Some(c) => Some(
            c.canonicalize()
                .with_context(|| format!("config file {}", c.display()))?,
        ),
        None => None,
    };
    let plist = plist_path(&home);
    let log = log_path(&home);
    for dir in [plist.parent(), log.parent()].into_iter().flatten() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(&plist, render_plist(&exe, config.as_deref(), &log))
        .with_context(|| format!("writing {}", plist.display()))?;
    let target = format!("{}/{LABEL}", domain());
    // Replacing a loaded agent: unload the old definition first; it is fine if none was loaded.
    let _ = launchctl(&["bootout", &target]);
    let out = launchctl(&["bootstrap", &domain(), &plist.display().to_string()])?;
    if !out.status.success() {
        bail!(
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(plist)
}

/// Unloads and deletes the agent. VMs keep running only until the daemon's children exit with it.
pub fn uninstall() -> Result<bool> {
    let plist = plist_path(&home()?);
    let _ = launchctl(&["bootout", &format!("{}/{LABEL}", domain())]);
    match std::fs::remove_file(&plist) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", plist.display())),
    }
}

/// `{installed, loaded, pid, plist, log}` from the plist file and `launchctl print`.
pub fn status() -> Result<serde_json::Value> {
    let home = home()?;
    let plist = plist_path(&home);
    let out = launchctl(&["print", &format!("{}/{LABEL}", domain())])?;
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |key: &str| {
        text.lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix(key)?
                    .trim()
                    .strip_prefix('=')?
                    .trim()
                    .into()
            })
            .map(str::to_owned)
    };
    Ok(serde_json::json!({
        "installed": plist.is_file(),
        "loaded": out.status.success(),
        "state": field("state"),
        "pid": field("pid").and_then(|p| p.parse::<u32>().ok()),
        "last_exit_code": field("last exit code"),
        "plist": plist,
        "log": log_path(&home),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_runs_serve_with_the_config_and_escapes_paths() {
        let p = render_plist(
            Path::new("/opt/homebrew/bin/fluxctl"),
            Some(Path::new("/Users/a&b/fluxvm.toml")),
            Path::new("/Users/a&b/Library/Logs/fluxvm.log"),
        );
        assert!(p.contains("<string>/opt/homebrew/bin/fluxctl</string>\n    <string>--config</string>\n    <string>/Users/a&amp;b/fluxvm.toml</string>\n    <string>serve</string>"));
        assert!(p.contains("<key>KeepAlive</key><true/>"));
        assert!(p.contains(&format!("<string>{LABEL}</string>")));
        assert!(!p.contains("a&b"));
        let bare = render_plist(Path::new("/f"), None, Path::new("/l"));
        assert!(!bare.contains("--config"));
        assert_eq!(
            plist_path(Path::new("/Users/me")),
            Path::new("/Users/me/Library/LaunchAgents/dev.zyvor.fluxvm.plist")
        );
    }
}
