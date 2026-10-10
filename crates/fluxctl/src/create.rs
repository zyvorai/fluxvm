// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxctl create` without a hand-written spec: `--name` and `--image` start a `vz` VM request, and the `--apple-*`
//! style flags fill in `apple.*` fields. With `--spec` the flags are applied on top of the file.

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum GuestOs {
    Linux,
    Macos,
}

#[derive(Args, Debug, Default)]
pub struct CreateArgs {
    /// JSON spec file (the REST create body). Flags below override its fields.
    #[arg(long, required_unless_present_any = ["name", "image"])]
    pub spec: Option<PathBuf>,
    /// VM name; with `--image` this builds a `vz` request without a spec file.
    #[arg(long)]
    pub name: Option<String>,
    /// Disk image or, for a macOS guest, the IPSW.
    #[arg(long)]
    pub image: Option<PathBuf>,
    #[arg(long)]
    pub vcpus: Option<u8>,
    #[arg(long)]
    pub memory_mib: Option<u64>,
    #[arg(long)]
    pub disk_size_gib: Option<u64>,
    /// Guest OS on the `vz` backend (`apple.guest_os`).
    #[arg(long, value_enum)]
    pub guest: Option<GuestOs>,
    /// Open the guest's console window.
    #[arg(long)]
    pub window: bool,
    /// Initial display, `WIDTHxHEIGHT` or `WIDTHxHEIGHT@PPI` (`apple.display_*`).
    #[arg(long, value_name = "WxH[@PPI]")]
    pub display: Option<String>,
    /// Number of displays for a macOS guest (1-8).
    #[arg(long)]
    pub displays: Option<u8>,
    /// Expose the host Rosetta runtime to a Linux guest.
    #[arg(long)]
    pub rosetta: bool,
    /// Linux guest SPICE clipboard sharing.
    #[arg(long)]
    pub clipboard: bool,
    /// Expose the host microphone to the guest.
    #[arg(long)]
    pub microphone: bool,
    /// Do not play guest audio on the host.
    #[arg(long)]
    pub mute: bool,
    /// Nested virtualization for a Linux guest (macOS 15+ host).
    #[arg(long)]
    pub nested_virtualization: bool,
    /// Add an XHCI controller so USB devices can be hot-attached.
    #[arg(long)]
    pub usb_controller: bool,
    /// Sparse ASIF overlay for guest writes (macOS 27+).
    #[arg(long)]
    pub asif_overlay: bool,
    /// Install a macOS guest from the IPSW before first boot.
    #[arg(long)]
    pub install: bool,
    /// Boot a macOS guest into Recovery.
    #[arg(long)]
    pub recovery: bool,
    /// Bridge the guest onto this host interface (for example `en0`).
    #[arg(long, value_name = "IFACE")]
    pub bridge: Option<String>,
    /// macOS 27 first-boot account: full name, user name and a file holding the password.
    #[arg(long)]
    pub provision_full_name: Option<String>,
    #[arg(long, requires = "provision_password_file")]
    pub provision_username: Option<String>,
    #[arg(long, requires = "provision_username")]
    pub provision_password_file: Option<PathBuf>,
    #[arg(long)]
    pub provision_auto_login: bool,
    #[arg(long)]
    pub provision_remote_login: bool,
}

/// `WIDTHxHEIGHT` or `WIDTHxHEIGHT@PPI`.
fn parse_display(s: &str) -> Result<(u32, u32, Option<u32>)> {
    let (dims, ppi) = match s.split_once('@') {
        Some((d, p)) => (d, Some(p.parse::<u32>().context("display ppi")?)),
        None => (s, None),
    };
    let (w, h) = dims
        .split_once(['x', 'X'])
        .context("display must be WIDTHxHEIGHT or WIDTHxHEIGHT@PPI")?;
    Ok((
        w.parse().context("display width")?,
        h.parse().context("display height")?,
        ppi,
    ))
}

/// The REST create body: the spec file (or a fresh `vz` request) with every flag that was given applied on top.
pub fn create_body(a: &CreateArgs) -> Result<Value> {
    let mut body = match &a.spec {
        Some(p) => serde_json::from_slice::<Value>(
            &std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        )?,
        None => json!({"backend": "vz"}),
    };
    let obj = body
        .as_object_mut()
        .context("the spec must be a JSON object")?;
    if let Some(n) = &a.name {
        obj.insert("name".into(), json!(n));
    }
    if let Some(i) = &a.image {
        obj.insert("image".into(), json!(i));
    }
    if a.spec.is_none() && (!obj.contains_key("name") || !obj.contains_key("image")) {
        bail!("without --spec both --name and --image are required");
    }
    if let Some(v) = a.vcpus {
        obj.insert("vcpus".into(), json!(v));
    }
    if let Some(v) = a.memory_mib {
        obj.insert("memory_mib".into(), json!(v));
    }
    if let Some(v) = a.disk_size_gib {
        obj.insert("disk_size_gib".into(), json!(v));
    }

    let mut apple = serde_json::Map::new();
    if let Some(g) = a.guest {
        apple.insert(
            "guest_os".into(),
            json!(match g {
                GuestOs::Linux => "linux",
                GuestOs::Macos => "macos",
            }),
        );
    }
    if let Some(d) = &a.display {
        let (w, h, ppi) = parse_display(d)?;
        apple.insert("display_width".into(), json!(w));
        apple.insert("display_height".into(), json!(h));
        if let Some(p) = ppi {
            apple.insert("display_ppi".into(), json!(p));
        }
    }
    if let Some(n) = a.displays {
        apple.insert("display_count".into(), json!(n));
    }
    for (on, key) in [
        (a.window, "window"),
        (a.rosetta, "rosetta"),
        (a.clipboard, "clipboard"),
        (a.microphone, "microphone"),
        (a.nested_virtualization, "nested_virtualization"),
        (a.usb_controller, "usb_controller"),
        (a.asif_overlay, "asif_overlay"),
        (a.install, "install"),
        (a.recovery, "recovery"),
        (a.provision_auto_login, "provision_auto_login"),
        (a.provision_remote_login, "provision_remote_login"),
    ] {
        if on {
            apple.insert(key.into(), json!(true));
        }
    }
    if a.mute {
        apple.insert("audio_output".into(), json!(false));
    }
    if let Some(b) = &a.bridge {
        apple.insert("bridge_interface".into(), json!(b));
    }
    if let Some(v) = &a.provision_full_name {
        apple.insert("provision_full_name".into(), json!(v));
    }
    if let Some(v) = &a.provision_username {
        apple.insert("provision_username".into(), json!(v));
    }
    if let Some(p) = &a.provision_password_file {
        apple.insert("provision_password_file".into(), json!(p));
    }
    if !apple.is_empty() {
        let slot = obj.entry("apple").or_insert_with(|| json!({}));
        let existing = slot.as_object_mut().context("apple must be an object")?;
        existing.extend(apple);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> CreateArgs {
        CreateArgs {
            name: Some("mac".into()),
            image: Some("/img/macos.ipsw".into()),
            ..Default::default()
        }
    }

    #[test]
    fn builds_a_vz_request_from_flags() {
        let mut a = args();
        a.guest = Some(GuestOs::Macos);
        a.display = Some("2560x1440@144".into());
        a.install = true;
        a.mute = true;
        a.vcpus = Some(6);
        let b = create_body(&a).unwrap();
        assert_eq!(b["backend"], "vz");
        assert_eq!(b["name"], "mac");
        assert_eq!(b["vcpus"], 6);
        assert_eq!(b["apple"]["guest_os"], "macos");
        assert_eq!(b["apple"]["display_width"], 2560);
        assert_eq!(b["apple"]["display_ppi"], 144);
        assert_eq!(b["apple"]["install"], true);
        assert_eq!(b["apple"]["audio_output"], false);
        assert!(b["apple"].get("rosetta").is_none());
    }

    #[test]
    fn name_without_image_is_refused() {
        let a = CreateArgs {
            name: Some("x".into()),
            ..Default::default()
        };
        assert!(create_body(&a).is_err());
    }

    #[test]
    fn display_forms() {
        assert_eq!(parse_display("1920x1080").unwrap(), (1920, 1080, None));
        assert_eq!(
            parse_display("5120X2880@218").unwrap(),
            (5120, 2880, Some(218))
        );
        assert!(parse_display("1920").is_err());
    }
}
