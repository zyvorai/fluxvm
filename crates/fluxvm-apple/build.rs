// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
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

    // A runner left over from an earlier build must not stand in for one that no longer compiles.
    let _ = fs::remove_file(&out);
    let has_swiftc = Command::new("xcrun")
        .args(["--find", "swiftc"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !has_swiftc {
        println!(
            "cargo:warning=no Swift toolchain (install Xcode or the Command Line Tools); the vz backend will not launch VMs"
        );
        return;
    }
    // AccessoryAccess is new in the macOS 27 SDK. Weak-link it so a runner built with Xcode 27 still
    // starts on the macOS 14-26 baseline when physical USB passthrough is not requested. Older SDKs
    // (CI's Xcode 26.6) do not have it, so linking it would fail.
    let sdk = Command::new("xcrun")
        .args(["--show-sdk-path"])
        .output()
        .ok()
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim().to_string()));
    let has_accessory_access = sdk.is_some_and(|p| {
        p.join("System/Library/Frameworks/AccessoryAccess.framework")
            .exists()
    });
    let mut swiftc_args: Vec<&str> = vec![
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
        "-framework",
        "vmnet",
    ];
    if has_accessory_access {
        swiftc_args.extend(["-Xlinker", "-weak_framework", "-Xlinker", "AccessoryAccess"]);
    }
    let swiftc = Command::new("xcrun")
        .args(&swiftc_args)
        .arg(&main_swift)
        .args(&extra)
        .arg("-o")
        .arg(&out)
        .output();
    match swiftc {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            for line in stderr.lines().filter(|l| l.contains("error:")).take(20) {
                println!("cargo:warning={line}");
            }
            panic!(
                "the Swift runner does not compile (the runner needs the macOS 27 SDK, Xcode 27); \
                 set FLUXVM_SKIP_VZ_RUNNER=1 to build without it\n{stderr}"
            );
        }
        Err(e) => panic!("could not run swiftc: {e}"),
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
        let _ = fs::remove_file(&out);
        panic!(
            "could not sign the Swift runner; Virtualization.framework would refuse to start VMs"
        );
    }
    println!("cargo:rustc-env=FLUXVM_VZ_RUNNER_BUILT={}", out.display());
}
