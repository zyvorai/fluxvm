// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Compiles the Swift runner (runner/Runner.swift) into `fluxvm-vz-runner` and signs it with the
// com.apple.security.virtualization entitlement. macOS only; elsewhere this crate builds without a runner.

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=runner/Runner.swift");
    println!("cargo:rerun-if-changed=runner/Entitlements.plist");
    println!("cargo:rerun-if-env-changed=FLUXVM_SKIP_VZ_RUNNER");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || env::var_os("FLUXVM_SKIP_VZ_RUNNER").is_some()
    {
        return;
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("fluxvm-vz-runner");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let swiftc = Command::new("xcrun")
        .args([
            "swiftc",
            "-swift-version",
            "5",
            "-O",
            "-target",
            "arm64-apple-macosx14.0",
            "-framework",
            "AppKit",
            "-framework",
            "Virtualization",
        ])
        .arg(manifest.join("runner/Runner.swift"))
        .arg("-o")
        .arg(&out)
        .status();
    match swiftc {
        Ok(s) if s.success() => {}
        _ => {
            println!(
                "cargo:warning=could not compile the Swift runner (install the Xcode command line tools); the vz backend will not launch VMs"
            );
            return;
        }
    }
    let sign = Command::new("codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(manifest.join("runner/Entitlements.plist"))
        .arg(&out)
        .status();
    if !matches!(sign, Ok(s) if s.success()) {
        println!(
            "cargo:warning=could not sign the Swift runner; Virtualization.framework will refuse to start VMs"
        );
        return;
    }
    println!("cargo:rustc-env=FLUXVM_VZ_RUNNER_BUILT={}", out.display());
}
