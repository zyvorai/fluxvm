// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Compiles the Swift runner (runner/Runner.swift) into `fluxvm-vz-runner` and signs it with the
// com.apple.security.virtualization entitlement. macOS only; elsewhere this crate builds without a runner.

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=runner/Runner.swift");
    println!("cargo:rerun-if-changed=runner");
    println!("cargo:rerun-if-changed=runner/Entitlements.plist");
    println!("cargo:rerun-if-changed=runner/Entitlements.networking.plist");
    println!("cargo:rerun-if-env-changed=FLUXVM_VZ_BRIDGE");
    println!("cargo:rerun-if-env-changed=FLUXVM_SKIP_VZ_RUNNER");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || env::var_os("FLUXVM_SKIP_VZ_RUNNER").is_some()
    {
        return;
    }
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out = out_dir.join("fluxvm-vz-runner");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // With more than one source file swiftc only accepts top-level code in a file named main.swift.
    let main_swift = out_dir.join("main.swift");
    let _ = fs::remove_file(&main_swift);
    if std::os::unix::fs::symlink(manifest.join("runner/Runner.swift"), &main_swift).is_err() {
        println!("cargo:warning=could not stage runner/Runner.swift as main.swift");
        return;
    }
    let mut extra: Vec<PathBuf> = fs::read_dir(manifest.join("runner"))
        .map(|d| {
            d.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.extension().is_some_and(|x| x == "swift")
                        && p.file_name().is_some_and(|n| n != "Runner.swift")
                })
                .collect()
        })
        .unwrap_or_default();
    extra.sort();
    for p in &extra {
        println!("cargo:rerun-if-changed={}", p.display());
    }
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
        .arg(&main_swift)
        .args(&extra)
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
    let entitlement = if env::var_os("FLUXVM_VZ_BRIDGE").is_some() {
        manifest.join("runner/Entitlements.networking.plist")
    } else {
        manifest.join("runner/Entitlements.plist")
    };
    let sign = Command::new("codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(entitlement)
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
