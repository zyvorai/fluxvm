// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! What this host can enforce.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Probe {
    pub landlock_abi: u32,
    pub filesystem: bool,
    pub filesystem_truncate: bool,
    pub filesystem_ioctl_dev: bool,
    pub tcp_rules: bool,
    pub scope_ipc: bool,
    pub seccomp: bool,
    /// Whether the default policy (strict) would run here.
    pub default_policy_ok: bool,
}

pub fn probe() -> Probe {
    let abi = crate::landlock::kernel_abi();
    #[cfg(target_os = "linux")]
    let seccomp = crate::seccomp::available();
    #[cfg(not(target_os = "linux"))]
    let seccomp = false;
    Probe {
        landlock_abi: abi,
        filesystem: abi >= 1,
        filesystem_truncate: abi >= 3,
        filesystem_ioctl_dev: abi >= 5,
        tcp_rules: abi >= 4,
        scope_ipc: abi >= 6,
        seccomp,
        default_policy_ok: crate::landlock::plan(&crate::policy::Policy::default(), abi).is_ok()
            && seccomp,
    }
}

impl Probe {
    pub fn render(&self) -> String {
        let yn = |b: bool| if b { "yes" } else { "no" };
        format!(
            "landlock ABI            : {}\n\
             filesystem rules        : {}\n\
             fs truncate/refer (>=3) : {}\n\
             fs device ioctl   (>=5) : {}\n\
             TCP port rules    (>=4) : {}\n\
             IPC scoping       (>=6) : {}\n\
             seccomp-bpf             : {}\n\
             default policy (strict) : {}\n",
            self.landlock_abi,
            yn(self.filesystem),
            yn(self.filesystem_truncate),
            yn(self.filesystem_ioctl_dev),
            yn(self.tcp_rules),
            yn(self.scope_ipc),
            yn(self.seccomp),
            if self.default_policy_ok {
                "runs"
            } else {
                "refused (use --best-effort)"
            },
        )
    }
}
