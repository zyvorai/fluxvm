// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

use crate::error::{FluxError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestKind {
    Linux,
    Windows,
}

#[derive(Debug, Clone)]
pub struct VmConfig {
    pub memory_mib: u32,
    pub cpus: u8,
    pub guest: GuestKind,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub disk: Option<PathBuf>,
    pub tap: Option<String>,
    pub mac: String,
    pub vhost_net: bool,
    pub net_queues: u8,
    pub cmdline: String,
    pub firmware: Option<PathBuf>,
    pub net_mbit_limit: u32,
    pub dry_run: bool,
    pub print_host_net: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            memory_mib: 256,
            cpus: 1,
            guest: GuestKind::Linux,
            kernel: None,
            initrd: None,
            disk: None,
            tap: None,
            mac: "02:00:00:00:00:01".into(),
            vhost_net: true,
            net_queues: 1,
            cmdline: "console=ttyS0 reboot=k panic=1 pci=off".into(),
            firmware: None,
            net_mbit_limit: 0,
            dry_run: false,
            print_host_net: false,
        }
    }
}

impl VmConfig {
    pub fn from_args() -> Result<Self> {
        let mut c = Self::default();
        let mut args = env::args().skip(1);
        while let Some(a) = args.next() {
            match a.as_str() {
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "--memory-mib" => c.memory_mib = parse_next(&mut args, "--memory-mib")?,
                "--cpus" => c.cpus = parse_next(&mut args, "--cpus")?,
                "--guest" => {
                    let v: String = parse_next(&mut args, "--guest")?;
                    c.guest = match v.as_str() {
                        "linux" => GuestKind::Linux,
                        "windows" => GuestKind::Windows,
                        _ => {
                            return Err(FluxError::Unsupported(
                                "guest must be linux|windows".into(),
                            ))
                        }
                    };
                }
                "--kernel" => c.kernel = Some(PathBuf::from(req(&mut args, "--kernel")?)),
                "--initrd" => c.initrd = Some(PathBuf::from(req(&mut args, "--initrd")?)),
                "--disk" => c.disk = Some(PathBuf::from(req(&mut args, "--disk")?)),
                "--tap" => c.tap = Some(req(&mut args, "--tap")?),
                "--mac" => c.mac = req(&mut args, "--mac")?,
                "--vhost-net" => c.vhost_net = true,
                "--no-vhost-net" => c.vhost_net = false,
                "--net-queues" => c.net_queues = parse_next(&mut args, "--net-queues")?,
                "--cmdline" => c.cmdline = req(&mut args, "--cmdline")?,
                "--firmware" => c.firmware = Some(PathBuf::from(req(&mut args, "--firmware")?)),
                "--net-mbit-limit" => c.net_mbit_limit = parse_next(&mut args, "--net-mbit-limit")?,
                "--dry-run" => c.dry_run = true,
                "--print-host-net" => c.print_host_net = true,
                other => {
                    return Err(FluxError::Unsupported(format!("unknown arg {other}")));
                }
            }
        }
        c.validate()?;
        Ok(c)
    }

    pub fn memory_bytes(&self) -> usize {
        (self.memory_mib as usize) * 1024 * 1024
    }

    pub fn validate(&self) -> Result<()> {
        if self.cpus == 0 || self.cpus > 32 {
            return Err(FluxError::Unsupported("cpus must be 1..=32".into()));
        }
        if self.memory_mib < 64 {
            return Err(FluxError::Unsupported("memory-mib must be >= 64".into()));
        }
        Ok(())
    }
}

fn req(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| FluxError::Unsupported(format!("{flag} needs a value")))
}

fn parse_next<T: std::str::FromStr>(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    let v = req(args, flag)?;
    v.parse()
        .map_err(|e| FluxError::Unsupported(format!("{flag}: {e}")))
}

pub fn print_help() {
    eprintln!(
        "\
fluxvm — lightweight KVM VMM skeleton

USAGE:
  fluxvm [OPTIONS]

OPTIONS:
  --guest linux|windows
  --memory-mib <N>          default 256
  --cpus <N>                default 1
  --kernel <PATH>           Linux bzImage/vmlinux
  --initrd <PATH>
  --disk <PATH>             virtio-blk image
  --tap <NAME>              existing host TAP
  --mac <AA:BB:...>
  --vhost-net / --no-vhost-net
  --net-queues <N>
  --net-mbit-limit <N>
  --cmdline <STR>
  --firmware <OVMF.fd>      Windows / UEFI
  --dry-run                 print topology, do not KVM_RUN
  --print-host-net          print TAP setup script
  -h, --help
"
    );
}
