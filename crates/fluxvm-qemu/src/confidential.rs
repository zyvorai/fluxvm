// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Confidential-VM QEMU providers.
//!
//! SNP and TDX stay behind separate traits so argument generation,
//! malformed-evidence rejection, policy denial, and fail-closed behavior
//! can be tested without claiming a hardware-protected launch. Real
//! launch + host-memory protection remain unverified until
//! `HostCapabilities::{snp,tdx}_launch_verified` is flipped after a
//! hardware integration run.

use anyhow::{Result, bail};
use fluxvm_core::security::{
    EvidenceClass, MeasurementPolicy, SecurityEvidence, SecurityProfile,
};
use std::collections::BTreeMap;

/// Launch arguments a confidential provider wants added to the QEMU
/// command line. Never derived from `CreateVmRequest.extra_args`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialLaunchArgs {
    pub machine: String,
    pub objects: Vec<String>,
    pub extras: Vec<String>,
}

pub trait SnpLaunchProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn build_args(&self, cbitpos: u8, reduced_phys_bits: u8) -> Result<ConfidentialLaunchArgs>;
    fn verify_evidence(
        &self,
        evidence: &SecurityEvidence,
        policy: &MeasurementPolicy,
    ) -> Result<()>;
}

pub trait TdxLaunchProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn build_args(&self) -> Result<ConfidentialLaunchArgs>;
    fn verify_evidence(
        &self,
        evidence: &SecurityEvidence,
        policy: &MeasurementPolicy,
    ) -> Result<()>;
}

#[derive(Debug, Default, Clone)]
pub struct ControlPlaneSnpProvider;

impl SnpLaunchProvider for ControlPlaneSnpProvider {
    fn name(&self) -> &'static str {
        "control-plane-snp"
    }

    fn build_args(&self, cbitpos: u8, reduced_phys_bits: u8) -> Result<ConfidentialLaunchArgs> {
        if cbitpos == 0 {
            bail!("SEV-SNP cbitpos must be non-zero");
        }
        if reduced_phys_bits == 0 {
            bail!("SEV-SNP reduced-phys-bits must be non-zero");
        }
        Ok(ConfidentialLaunchArgs {
            machine: "q35,accel=kvm,confidential-guest-support=sev0".into(),
            objects: vec![format!(
                "sev-snp-guest,id=sev0,cbitpos={cbitpos},reduced-phys-bits={reduced_phys_bits},kernel-hashes=on"
            )],
            extras: vec![],
        })
    }

    fn verify_evidence(
        &self,
        evidence: &SecurityEvidence,
        policy: &MeasurementPolicy,
    ) -> Result<()> {
        if evidence.class != EvidenceClass::SevSnp {
            bail!(
                "SNP verifier rejected evidence class (expected sev-snp, got {:?})",
                evidence.class
            );
        }
        if evidence.profile != SecurityProfile::ConfidentialSnp {
            bail!("SNP verifier rejected profile {:?}", evidence.profile);
        }
        if !evidence.hardware_attestation {
            bail!("SNP verifier fail-closed: hardware_attestation is false");
        }
        evidence.evaluate(policy)
    }
}

#[derive(Debug, Default, Clone)]
pub struct ControlPlaneTdxProvider;

impl TdxLaunchProvider for ControlPlaneTdxProvider {
    fn name(&self) -> &'static str {
        "control-plane-tdx"
    }

    fn build_args(&self) -> Result<ConfidentialLaunchArgs> {
        Ok(ConfidentialLaunchArgs {
            machine: "q35,accel=kvm,confidential-guest-support=tdx0".into(),
            objects: vec!["tdx-guest,id=tdx0".into()],
            extras: vec![],
        })
    }

    fn verify_evidence(
        &self,
        evidence: &SecurityEvidence,
        policy: &MeasurementPolicy,
    ) -> Result<()> {
        if evidence.class != EvidenceClass::Tdx {
            bail!(
                "TDX verifier rejected evidence class (expected tdx, got {:?})",
                evidence.class
            );
        }
        if evidence.profile != SecurityProfile::ConfidentialTdx {
            bail!("TDX verifier rejected profile {:?}", evidence.profile);
        }
        if !evidence.hardware_attestation {
            bail!("TDX verifier fail-closed: hardware_attestation is false");
        }
        evidence.evaluate(policy)
    }
}

pub fn apply_confidential_args(args: &mut Vec<String>, launch: &ConfidentialLaunchArgs) -> Result<()> {
    if let Some(idx) = args.iter().position(|a| a == "-machine") {
        let val_idx = idx + 1;
        if val_idx < args.len() {
            args[val_idx] = launch.machine.clone();
        }
    } else {
        args.push("-machine".into());
        args.push(launch.machine.clone());
    }
    for obj in &launch.objects {
        args.push("-object".into());
        args.push(obj.clone());
    }
    args.extend(launch.extras.iter().cloned());
    Ok(())
}

pub fn confidential_args_for(profile: SecurityProfile) -> Result<Option<ConfidentialLaunchArgs>> {
    match profile {
        SecurityProfile::ConfidentialSnp => ControlPlaneSnpProvider.build_args(51, 1).map(Some),
        SecurityProfile::ConfidentialTdx => ControlPlaneTdxProvider.build_args().map(Some),
        _ => Ok(None),
    }
}

#[allow(dead_code)]
pub fn parse_snp_report(bytes: &[u8]) -> Result<SecurityEvidence> {
    if bytes.len() < 16 || &bytes[..4] != b"SNP\x01" {
        bail!("malformed SNP report: missing SNP\\x01 header");
    }
    Ok(SecurityEvidence {
        class: EvidenceClass::SevSnp,
        profile: SecurityProfile::ConfidentialSnp,
        hardware_attestation: true,
        image_sha256: Some(bytes[4..12].iter().map(|b| format!("{b:02x}")).collect()),
        firmware_sha256: None,
        kernel_sha256: None,
        catalog_signed: true,
        secure_boot: true,
        vtpm_attached: true,
        pcrs: BTreeMap::new(),
        notes: vec![
            "parsed by control-plane SNP provider; host-memory protection unverified".into(),
        ],
    })
}

#[allow(dead_code)]
pub fn parse_tdx_quote(bytes: &[u8]) -> Result<SecurityEvidence> {
    if bytes.len() < 16 || &bytes[..4] != b"TDX\x01" {
        bail!("malformed TDX quote: missing TDX\\x01 header");
    }
    Ok(SecurityEvidence {
        class: EvidenceClass::Tdx,
        profile: SecurityProfile::ConfidentialTdx,
        hardware_attestation: true,
        image_sha256: Some(bytes[4..12].iter().map(|b| format!("{b:02x}")).collect()),
        firmware_sha256: None,
        kernel_sha256: None,
        catalog_signed: true,
        secure_boot: true,
        vtpm_attached: true,
        pcrs: BTreeMap::new(),
        notes: vec![
            "parsed by control-plane TDX provider; host-memory protection unverified".into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::security::MeasurementPolicy;

    #[test]
    fn snp_args_include_machine_and_object() {
        let args = ControlPlaneSnpProvider.build_args(51, 1).unwrap();
        assert!(args.machine.contains("confidential-guest-support=sev0"));
        assert!(args.objects[0].contains("sev-snp-guest"));
        assert!(args.objects[0].contains("cbitpos=51"));
    }

    #[test]
    fn snp_args_reject_zero_cbit() {
        assert!(ControlPlaneSnpProvider.build_args(0, 1).is_err());
    }

    #[test]
    fn tdx_args_include_tdx_guest_object() {
        let args = ControlPlaneTdxProvider.build_args().unwrap();
        assert!(args.machine.contains("tdx0"));
        assert_eq!(args.objects[0], "tdx-guest,id=tdx0");
    }

    #[test]
    fn apply_replaces_machine_instead_of_duplicating() {
        let mut args = vec![
            "-machine".into(),
            "q35,accel=kvm".into(),
            "-cpu".into(),
            "host".into(),
        ];
        let launch = ControlPlaneTdxProvider.build_args().unwrap();
        apply_confidential_args(&mut args, &launch).unwrap();
        assert_eq!(args.iter().filter(|a| *a == "-machine").count(), 1);
        assert!(args[1].contains("tdx0"));
        assert!(args.contains(&"-object".to_string()));
    }

    #[test]
    fn malformed_snp_report_is_rejected() {
        assert!(parse_snp_report(b"nope").is_err());
        assert!(parse_snp_report(b"").is_err());
    }

    #[test]
    fn well_formed_snp_report_still_fail_closed_without_policy_match() {
        let mut bytes = b"SNP\x01".to_vec();
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let ev = parse_snp_report(&bytes).unwrap();
        let policy = MeasurementPolicy {
            image_sha256: Some("deadbeef".into()),
            ..Default::default()
        };
        assert!(ControlPlaneSnpProvider.verify_evidence(&ev, &policy).is_err());
    }

    #[test]
    fn software_test_evidence_is_not_snp_attestation() {
        let ev = SecurityEvidence {
            class: EvidenceClass::SoftwareTest,
            profile: SecurityProfile::Measured,
            hardware_attestation: false,
            image_sha256: None,
            firmware_sha256: None,
            kernel_sha256: None,
            catalog_signed: true,
            secure_boot: true,
            vtpm_attached: true,
            pcrs: BTreeMap::new(),
            notes: vec![],
        };
        let err = ControlPlaneSnpProvider
            .verify_evidence(&ev, &MeasurementPolicy::default())
            .unwrap_err();
        assert!(err.to_string().contains("rejected evidence class"));
    }

    #[test]
    fn snp_evidence_without_hardware_flag_is_rejected() {
        let ev = SecurityEvidence {
            class: EvidenceClass::SevSnp,
            profile: SecurityProfile::ConfidentialSnp,
            hardware_attestation: false,
            image_sha256: None,
            firmware_sha256: None,
            kernel_sha256: None,
            catalog_signed: true,
            secure_boot: true,
            vtpm_attached: true,
            pcrs: BTreeMap::new(),
            notes: vec![],
        };
        let err = ControlPlaneSnpProvider
            .verify_evidence(&ev, &MeasurementPolicy::default())
            .unwrap_err();
        assert!(err.to_string().contains("hardware_attestation"));
    }

    #[test]
    fn extra_args_are_not_consulted_by_providers() {
        let args = ControlPlaneSnpProvider.build_args(51, 1).unwrap();
        assert!(args.extras.is_empty());
    }
}
