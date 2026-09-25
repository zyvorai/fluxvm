// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Security profiles, host capability discovery, measured-boot evidence,
//! and confidential-VM operation gates.
//!
//! Phase 6 keeps three claims distinct on purpose:
//!
//! - `standard` — today's QEMU/CH/Firecracker launch, no extra evidence.
//! - `measured` — Secure Boot + swtpm + approved signed image + policy
//!   evaluation on *software-test* evidence. Achievable on current QEMU
//!   hosts. A host-controlled swtpm cannot prove the host cannot inspect
//!   the guest; this profile never calls that hardware attestation.
//! - `confidential-snp` / `confidential-tdx` — control-plane launch args
//!   and evidence verification. Real launch and host-memory protection
//!   stay unverified until a hardware integration run flips the matching
//!   `HostCapabilities` flag.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityProfile {
    #[default]
    Standard,
    Measured,
    ConfidentialSnp,
    ConfidentialTdx,
}

impl SecurityProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Measured => "measured",
            Self::ConfidentialSnp => "confidential-snp",
            Self::ConfidentialTdx => "confidential-tdx",
        }
    }

    pub fn is_confidential(self) -> bool {
        matches!(self, Self::ConfidentialSnp | Self::ConfidentialTdx)
    }

    pub fn requires_measurement_chain(self) -> bool {
        !matches!(self, Self::Standard)
    }

    pub fn parse_fleet(raw: &str) -> Result<Self, String> {
        match raw {
            "" | "standard" => Ok(Self::Standard),
            "measured" => Ok(Self::Measured),
            "confidential-snp" => Ok(Self::ConfidentialSnp),
            "confidential-tdx" => Ok(Self::ConfidentialTdx),
            other => Err(format!(
                "unknown security_profile '{other}' (expected standard, measured, confidential-snp, confidential-tdx)"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostCapabilities {
    pub qemu: bool,
    pub secure_boot_ready: bool,
    pub swtpm: bool,
    pub signed_catalog_configured: bool,
    pub snp_present: bool,
    pub tdx_present: bool,
    pub snp_launch_verified: bool,
    pub tdx_launch_verified: bool,
}

/// Heartbeat payload from `fluxvm-agent node` (`NodeInfo.security`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct NodeSecurityCapabilities {
    pub measured: bool,
    pub snp: bool,
    pub tdx: bool,
    pub snp_launch_verified: bool,
    pub tdx_launch_verified: bool,
}

impl NodeSecurityCapabilities {
    /// Fail-closed when `GET /v1/security/capabilities` cannot be reached.
    pub fn standard_only() -> Self {
        Self::default()
    }

    pub fn supports(&self, profile: SecurityProfile) -> Result<(), String> {
        match profile {
            SecurityProfile::Standard => Ok(()),
            SecurityProfile::Measured => require(
                self.measured,
                "node cannot satisfy measured security profile",
            ),
            SecurityProfile::ConfidentialSnp => require(
                self.snp,
                "node cannot satisfy confidential-snp security profile",
            ),
            SecurityProfile::ConfidentialTdx => require(
                self.tdx,
                "node cannot satisfy confidential-tdx security profile",
            ),
        }
    }
}

impl From<HostCapabilities> for NodeSecurityCapabilities {
    fn from(c: HostCapabilities) -> Self {
        Self {
            measured: c.supports(SecurityProfile::Measured).is_ok(),
            snp: c.supports(SecurityProfile::ConfidentialSnp).is_ok(),
            tdx: c.supports(SecurityProfile::ConfidentialTdx).is_ok(),
            snp_launch_verified: c.snp_launch_verified,
            tdx_launch_verified: c.tdx_launch_verified,
        }
    }
}

/// Profile recorded after launch — confidential-* only when hardware verified.
pub fn achieved_security_profile(
    requested: SecurityProfile,
    caps: &HostCapabilities,
) -> SecurityProfile {
    match requested {
        SecurityProfile::Standard => SecurityProfile::Standard,
        SecurityProfile::Measured => SecurityProfile::Measured,
        SecurityProfile::ConfidentialSnp if caps.snp_launch_verified => {
            SecurityProfile::ConfidentialSnp
        }
        SecurityProfile::ConfidentialTdx if caps.tdx_launch_verified => {
            SecurityProfile::ConfidentialTdx
        }
        _ => SecurityProfile::Measured,
    }
}

impl HostCapabilities {
    pub fn discover(cfg: &crate::config::Config) -> Self {
        Self::discover_at(Path::new("/"), cfg)
    }

    /// Probe a filesystem root (`/` on a real host; a temporary tree in tests).
    /// Prefers KVM sysfs switches (same idea as sandbox confidential detect)
    /// and falls back to cpuinfo / device nodes.
    pub fn discover_at(root: &Path, cfg: &crate::config::Config) -> Self {
        let cpu = fs::read_to_string(root.join("proc/cpuinfo")).unwrap_or_default();
        let qemu = which(&cfg.qemu_binary);
        let sev_snp_sysfs = switch_on(&root.join("sys/module/kvm_amd/parameters/sev_snp"))
            && root.join("dev/sev").exists();
        let tdx_sysfs = switch_on(&root.join("sys/module/kvm_intel/parameters/tdx"));
        Self {
            qemu,
            secure_boot_ready: qemu
                && cfg.qemu_ovmf_code.is_some()
                && cfg.qemu_ovmf_vars_template.is_some(),
            swtpm: which(&cfg.swtpm_binary),
            signed_catalog_configured: cfg.catalog.path.is_some()
                && !cfg.catalog.trusted_signers.is_empty(),
            snp_present: sev_snp_sysfs
                || cpu_has(&cpu, "sev_snp")
                || cpu_has(&cpu, "sev-snp")
                || root.join("dev/sev").exists(),
            tdx_present: tdx_sysfs || cpu_has(&cpu, "tdx") || root.join("dev/tdx-guest").exists(),
            snp_launch_verified: cfg.security.snp_launch_verified,
            tdx_launch_verified: cfg.security.tdx_launch_verified,
        }
    }

    pub fn supports(&self, profile: SecurityProfile) -> Result<(), String> {
        match profile {
            SecurityProfile::Standard => Ok(()),
            SecurityProfile::Measured => {
                require(self.qemu, "measured requires a QEMU backend host")?;
                require(
                    self.secure_boot_ready,
                    "measured requires qemu_ovmf_code and qemu_ovmf_vars_template",
                )?;
                require(self.swtpm, "measured requires a usable swtpm binary")?;
                require(
                    self.signed_catalog_configured,
                    "measured requires catalog.path and catalog.trusted_signers",
                )?;
                Ok(())
            }
            SecurityProfile::ConfidentialSnp => {
                require(self.qemu, "confidential-snp requires a QEMU backend host")?;
                require(
                    self.snp_present,
                    "confidential-snp requires SEV-SNP CPU/firmware on this node",
                )?;
                Ok(())
            }
            SecurityProfile::ConfidentialTdx => {
                require(self.qemu, "confidential-tdx requires a QEMU backend host")?;
                require(
                    self.tdx_present,
                    "confidential-tdx requires TDX CPU/firmware on this node",
                )?;
                Ok(())
            }
        }
    }
}

fn require(ok: bool, msg: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(msg.into()) }
}

fn which(bin: &str) -> bool {
    if bin.contains('/') {
        return Path::new(bin).is_file();
    }
    std::env::var("PATH")
        .ok()
        .map(|p| p.split(':').any(|dir| Path::new(dir).join(bin).is_file()))
        .unwrap_or(false)
}

fn cpu_has(cpuinfo: &str, flag: &str) -> bool {
    cpuinfo
        .lines()
        .filter(|l| l.starts_with("flags") || l.starts_with("Features"))
        .any(|l| l.split_whitespace().any(|tok| tok == flag))
}

fn switch_on(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|v| matches!(v.trim(), "Y" | "y" | "1"))
        .unwrap_or(false)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MeasurementPolicy {
    #[serde(default)]
    pub image_sha256: Option<String>,
    #[serde(default)]
    pub firmware_sha256: Option<String>,
    #[serde(default)]
    pub kernel_sha256: Option<String>,
    #[serde(default)]
    pub pcrs: BTreeMap<String, String>,
    #[serde(default)]
    pub test_secret: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceClass {
    SoftwareTest,
    SevSnp,
    Tdx,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityEvidence {
    pub class: EvidenceClass,
    pub profile: SecurityProfile,
    pub hardware_attestation: bool,
    pub image_sha256: Option<String>,
    pub firmware_sha256: Option<String>,
    pub kernel_sha256: Option<String>,
    pub catalog_signed: bool,
    pub secure_boot: bool,
    pub vtpm_attached: bool,
    pub pcrs: BTreeMap<String, String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl SecurityEvidence {
    pub fn evaluate(&self, policy: &MeasurementPolicy) -> Result<()> {
        check_opt(
            "image_sha256",
            policy.image_sha256.as_deref(),
            self.image_sha256.as_deref(),
        )?;
        check_opt(
            "firmware_sha256",
            policy.firmware_sha256.as_deref(),
            self.firmware_sha256.as_deref(),
        )?;
        check_opt(
            "kernel_sha256",
            policy.kernel_sha256.as_deref(),
            self.kernel_sha256.as_deref(),
        )?;
        for (idx, expected) in &policy.pcrs {
            match self.pcrs.get(idx) {
                Some(got) if got.eq_ignore_ascii_case(expected) => {}
                Some(got) => bail!("PCR{idx} mismatch: expected {expected}, got {got}"),
                None => bail!("PCR{idx} missing from evidence"),
            }
        }
        Ok(())
    }
}

fn check_opt(name: &str, expected: Option<&str>, got: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    match got {
        Some(got) if got.eq_ignore_ascii_case(expected) => Ok(()),
        Some(got) => bail!("{name} mismatch: expected {expected}, got {got}"),
        None => bail!("{name} missing from evidence"),
    }
}

#[derive(Debug, Clone)]
pub struct MeasuredLaunchInputs<'a> {
    pub image: &'a Path,
    pub firmware: Option<&'a Path>,
    pub kernel: Option<&'a Path>,
    pub catalog_signed: bool,
    pub secure_boot: bool,
    pub vtpm_attached: bool,
}

pub fn sha256_file(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(hex_sha256(&fs::read(path)?)))
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn software_pcrs(
    firmware_sha: Option<&str>,
    kernel_sha: Option<&str>,
    image_sha: Option<&str>,
) -> BTreeMap<String, String> {
    let z = "00".repeat(32);
    let mut pcrs = BTreeMap::new();
    pcrs.insert("0".into(), extend_pcr(&z, firmware_sha.unwrap_or(&z)));
    pcrs.insert("4".into(), extend_pcr(&z, kernel_sha.unwrap_or(&z)));
    pcrs.insert("7".into(), extend_pcr(&z, image_sha.unwrap_or(&z)));
    pcrs
}

fn extend_pcr(current_hex: &str, measurement_hex: &str) -> String {
    let mut raw = decode_hex(current_hex);
    raw.extend(decode_hex(measurement_hex));
    hex_sha256(&raw)
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("00"), 16).ok())
        .collect()
}

pub fn collect_measured_evidence(inputs: MeasuredLaunchInputs<'_>) -> Result<SecurityEvidence> {
    if !inputs.secure_boot {
        bail!("measured profile requires Secure Boot");
    }
    if !inputs.vtpm_attached {
        bail!("measured profile requires a vTPM (swtpm)");
    }
    if !inputs.catalog_signed {
        bail!("measured profile requires an approved signed catalog image");
    }
    let image_sha256 = sha256_file(inputs.image)?;
    let firmware_sha256 = inputs.firmware.map(sha256_file).transpose()?.flatten();
    let kernel_sha256 = inputs.kernel.map(sha256_file).transpose()?.flatten();
    let pcrs = software_pcrs(
        firmware_sha256.as_deref(),
        kernel_sha256.as_deref(),
        image_sha256.as_deref(),
    );
    Ok(SecurityEvidence {
        class: EvidenceClass::SoftwareTest,
        profile: SecurityProfile::Measured,
        hardware_attestation: false,
        image_sha256,
        firmware_sha256,
        kernel_sha256,
        catalog_signed: true,
        secure_boot: true,
        vtpm_attached: true,
        pcrs,
        notes: vec![
            "evidence class is software-test".into(),
            "swtpm is host-controlled and cannot prove the host cannot inspect the guest".into(),
        ],
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRelease {
    pub released: bool,
    pub secret: Option<String>,
    pub reason: String,
}

pub fn release_test_secret(
    evidence: &SecurityEvidence,
    policy: &MeasurementPolicy,
) -> SecretRelease {
    match evidence.evaluate(policy) {
        Ok(()) => SecretRelease {
            released: true,
            secret: policy.test_secret.clone(),
            reason: "policy matched software-test evidence".into(),
        },
        Err(e) => SecretRelease {
            released: false,
            secret: None,
            reason: format!("policy denied: {e}"),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmOperation {
    HotplugCpu,
    HotplugMemory,
    HotplugNic,
    HotplugShare,
    SnapshotSave,
    SnapshotRestore,
    ExtraArgs,
    SharedMemory,
    Hugepages,
    Loadvm,
}

impl VmOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotplugCpu => "hotplug/cpu",
            Self::HotplugMemory => "hotplug/memory",
            Self::HotplugNic => "hotplug/nic",
            Self::HotplugShare => "hotplug/share",
            Self::SnapshotSave => "snapshot",
            Self::SnapshotRestore => "snapshot-restore",
            Self::ExtraArgs => "extra_args",
            Self::SharedMemory => "shared_memory",
            Self::Hugepages => "hugepages",
            Self::Loadvm => "loadvm",
        }
    }
}

pub fn check_operation(profile: SecurityProfile, op: VmOperation) -> Result<()> {
    if profile.is_confidential() {
        bail!(
            "operation {} is incompatible with security profile {} — confidential VMs do not inherit ordinary QEMU memory/hotplug/snapshot behavior",
            op.as_str(),
            profile.as_str()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn validate_create_request(
    profile: SecurityProfile,
    backend_is_qemu: bool,
    extra_args: &[String],
    shared_memory: bool,
    hugepages: bool,
    loadvm: bool,
    caps: &HostCapabilities,
    allow_unverified_confidential: bool,
) -> Result<()> {
    caps.supports(profile).map_err(|e| anyhow::anyhow!(e))?;
    if profile != SecurityProfile::Standard && !backend_is_qemu {
        bail!(
            "security_profile {} requires backend qemu; other backends cannot provide the measured/confidential launch path",
            profile.as_str()
        );
    }
    if profile.is_confidential() {
        if !extra_args.is_empty() {
            check_operation(profile, VmOperation::ExtraArgs)?;
        }
        if shared_memory {
            check_operation(profile, VmOperation::SharedMemory)?;
        }
        if hugepages {
            check_operation(profile, VmOperation::Hugepages)?;
        }
        if loadvm {
            check_operation(profile, VmOperation::Loadvm)?;
        }
        let unverified = match profile {
            SecurityProfile::ConfidentialSnp => !caps.snp_launch_verified,
            SecurityProfile::ConfidentialTdx => !caps.tdx_launch_verified,
            _ => false,
        };
        if unverified && !allow_unverified_confidential {
            bail!(
                "{} control plane is testable, but the hardware security claim is gated on an integration run (set security.allow_unverified_confidential to exercise launch-arg generation only)",
                profile.as_str()
            );
        }
    }
    Ok(())
}

pub fn write_evidence(workspace: &Path, evidence: &SecurityEvidence) -> Result<PathBuf> {
    let path = workspace.join("security-evidence.json");
    fs::write(&path, serde_json::to_vec_pretty(evidence)?)?;
    Ok(path)
}

pub fn read_evidence(workspace: &Path) -> Result<SecurityEvidence> {
    let raw = fs::read_to_string(workspace.join("security-evidence.json"))?;
    Ok(serde_json::from_str(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(snp: bool, tdx: bool, verified: bool) -> HostCapabilities {
        HostCapabilities {
            qemu: true,
            secure_boot_ready: true,
            swtpm: true,
            signed_catalog_configured: true,
            snp_present: snp,
            tdx_present: tdx,
            snp_launch_verified: verified,
            tdx_launch_verified: verified,
        }
    }

    #[test]
    fn profiles_round_trip_kebab_case() {
        let json = serde_json::to_string(&SecurityProfile::ConfidentialSnp).unwrap();
        assert_eq!(json, "\"confidential-snp\"");
    }

    #[test]
    fn measured_requires_sb_tpm_signed_image() {
        let err = collect_measured_evidence(MeasuredLaunchInputs {
            image: Path::new("/nope"),
            firmware: None,
            kernel: None,
            catalog_signed: false,
            secure_boot: true,
            vtpm_attached: true,
        })
        .unwrap_err();
        assert!(err.to_string().contains("signed catalog"));
    }

    #[test]
    fn software_test_evidence_never_claims_hardware() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.qcow2");
        fs::write(&image, b"image-bytes").unwrap();
        let ev = collect_measured_evidence(MeasuredLaunchInputs {
            image: &image,
            firmware: None,
            kernel: None,
            catalog_signed: true,
            secure_boot: true,
            vtpm_attached: true,
        })
        .unwrap();
        assert_eq!(ev.class, EvidenceClass::SoftwareTest);
        assert!(!ev.hardware_attestation);
        assert!(ev.pcrs.contains_key("7"));
    }

    #[test]
    fn secret_release_is_fail_closed() {
        let ev = SecurityEvidence {
            class: EvidenceClass::SoftwareTest,
            profile: SecurityProfile::Measured,
            hardware_attestation: false,
            image_sha256: Some("aa".into()),
            firmware_sha256: None,
            kernel_sha256: None,
            catalog_signed: true,
            secure_boot: true,
            vtpm_attached: true,
            pcrs: BTreeMap::new(),
            notes: vec![],
        };
        let deny = release_test_secret(
            &ev,
            &MeasurementPolicy {
                image_sha256: Some("bb".into()),
                test_secret: Some("s3cret".into()),
                ..Default::default()
            },
        );
        assert!(!deny.released);
        assert!(deny.secret.is_none());
        let allow = release_test_secret(
            &ev,
            &MeasurementPolicy {
                image_sha256: Some("aa".into()),
                test_secret: Some("s3cret".into()),
                ..Default::default()
            },
        );
        assert!(allow.released);
        assert_eq!(allow.secret.as_deref(), Some("s3cret"));
    }

    #[test]
    fn confidential_rejects_hotplug_and_snapshots() {
        assert!(
            check_operation(SecurityProfile::ConfidentialSnp, VmOperation::HotplugCpu).is_err()
        );
        assert!(check_operation(SecurityProfile::Measured, VmOperation::HotplugCpu).is_ok());
    }

    #[test]
    fn extra_args_are_not_proof_of_confidential_launch() {
        let err = validate_create_request(
            SecurityProfile::ConfidentialSnp,
            true,
            &["-object".into(), "sev-snp-guest,id=sev0".into()],
            false,
            false,
            false,
            &caps(true, false, false),
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("extra_args"));
    }

    #[test]
    fn unverified_confidential_is_fail_closed_without_dev_flag() {
        assert!(
            validate_create_request(
                SecurityProfile::ConfidentialSnp,
                true,
                &[],
                false,
                false,
                false,
                &caps(true, false, false),
                false,
            )
            .is_err()
        );
        assert!(
            validate_create_request(
                SecurityProfile::ConfidentialSnp,
                true,
                &[],
                false,
                false,
                false,
                &caps(true, false, false),
                true,
            )
            .is_ok()
        );
    }
}
