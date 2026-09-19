// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! A per-thread "run netns-sensitive tools over there" scope.
//!
//! The eBPF loader shells out to `tc` and the TCX helper with an interface
//! *name*, and a name only means something inside one network namespace. A
//! bridge-less direct VM's tap and outer device live in the pod's namespace,
//! not the daemon's, so those tools must run there. Threading a namespace
//! argument through every loader function (attach, reconcile, reconfigure,
//! status, remove ...) would touch dozens of call sites; instead the caller
//! enters a scope and the few places that spawn a netns-sensitive tool consult
//! it.
//!
//! Only the *network* namespace is entered (`nsenter --net`): bpffs pins,
//! `/run` sidecars and the daemon's filesystem view stay visible, which
//! `ip netns exec` would break by re-mounting `/sys`. `bpftool` is
//! deliberately NOT wrapped: programs and maps are not namespaced.
//!
//! The scope is thread-local and the loader is synchronous, so it cannot leak
//! across tasks; the RAII guard restores the previous value on drop.

use std::{cell::RefCell, process::Command};

thread_local! {
    static SCOPE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Restores the previous scope when dropped.
#[must_use = "the scope ends when the guard is dropped"]
pub struct NetnsScope {
    prev: Option<String>,
}

/// Enters `netns_path` (or the daemon's own namespace when `None`) for the
/// current thread until the returned guard is dropped.
pub fn enter(netns_path: Option<&str>) -> NetnsScope {
    let prev = SCOPE.with(|s| s.replace(netns_path.map(str::to_string)));
    NetnsScope { prev }
}

impl Drop for NetnsScope {
    fn drop(&mut self) {
        let prev = self.prev.take();
        SCOPE.with(|s| *s.borrow_mut() = prev);
    }
}

/// The namespace path the current thread is scoped to, if any.
pub fn current() -> Option<String> {
    SCOPE.with(|s| s.borrow().clone())
}

/// A `Command` for `program` that runs inside the current scope's namespace,
/// or directly when no scope is active. Use for tools whose behaviour depends
/// on the network namespace (`tc`, the TCX helper, `ip`).
pub fn command(program: &str) -> Command {
    match current() {
        Some(ns) => {
            let mut c = Command::new("nsenter");
            c.arg(format!("--net={ns}")).arg("--").arg(program);
            c
        }
        None => Command::new(program),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(c: &Command) -> Vec<String> {
        std::iter::once(c.get_program())
            .chain(c.get_args())
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn no_scope_runs_the_program_directly() {
        assert_eq!(current(), None);
        assert_eq!(argv(&command("tc")), ["tc"]);
    }

    #[test]
    fn scope_wraps_in_nsenter_net_only() {
        let _g = enter(Some("/run/netns/fvcni-abc"));
        let a = argv(&command("tc"));
        assert_eq!(a, ["nsenter", "--net=/run/netns/fvcni-abc", "--", "tc"]);
        assert!(
            !a.iter().any(|x| x.contains("mount") || x == "-a"),
            "must not enter the mount namespace or bpffs pins vanish"
        );
    }

    #[test]
    fn scopes_nest_and_restore() {
        assert_eq!(current(), None);
        {
            let _outer = enter(Some("/run/netns/a"));
            assert_eq!(current().as_deref(), Some("/run/netns/a"));
            {
                let _inner = enter(Some("/run/netns/b"));
                assert_eq!(current().as_deref(), Some("/run/netns/b"));
                {
                    let _host = enter(None);
                    assert_eq!(current(), None, "None re-enters the daemon's namespace");
                }
                assert_eq!(current().as_deref(), Some("/run/netns/b"));
            }
            assert_eq!(current().as_deref(), Some("/run/netns/a"));
        }
        assert_eq!(current(), None);
    }

    #[test]
    fn scope_is_per_thread() {
        let _g = enter(Some("/run/netns/main"));
        let other = std::thread::spawn(current).join().unwrap();
        assert_eq!(other, None, "another thread must not inherit the scope");
        assert_eq!(current().as_deref(), Some("/run/netns/main"));
    }
}
