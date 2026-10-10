// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
//! Pure placement scorer for Apple (`vz`) hosts: filters out hosts that lack a requested capability and
//! prefers the tightest fit (bin-packing) among the rest. No I/O; callers supply the host snapshot.

/// What an Apple host can offer right now.
#[derive(Debug, Clone)]
pub struct AppleHostCaps {
    pub free_cpu: u32,
    pub free_memory_mib: u64,
    pub nested_virtualization: bool,
    /// macOS 26+ custom vmnet networks.
    pub vmnet: bool,
    /// macOS 27+ custom Virtio devices.
    pub custom_virtio: bool,
    pub bridged_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ApplePlacementRequest {
    pub vcpus: u32,
    pub memory_mib: u64,
    pub needs_nested: bool,
    pub needs_vmnet: bool,
    pub needs_custom_virtio: bool,
    pub bridge_interface: Option<String>,
}

/// `None` when the host cannot run the request; otherwise a score where higher is better. The score
/// favours the host that is left with the least spare CPU and memory (tightest fit).
pub fn score(c: &AppleHostCaps, r: &ApplePlacementRequest) -> Option<i64> {
    if c.free_cpu < r.vcpus || c.free_memory_mib < r.memory_mib {
        return None;
    }
    if r.needs_nested && !c.nested_virtualization {
        return None;
    }
    if r.needs_vmnet && !c.vmnet {
        return None;
    }
    if r.needs_custom_virtio && !c.custom_virtio {
        return None;
    }
    if let Some(i) = &r.bridge_interface
        && !c.bridged_interfaces.iter().any(|x| x == i)
    {
        return None;
    }
    let cpu_after = i64::from(c.free_cpu - r.vcpus);
    let mem_after = i64::try_from((c.free_memory_mib - r.memory_mib) / 64).unwrap_or(i64::MAX / 2);
    Some(-(cpu_after.saturating_mul(1024).saturating_add(mem_after)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> AppleHostCaps {
        AppleHostCaps {
            free_cpu: 24,
            free_memory_mib: 196_608,
            nested_virtualization: false,
            vmnet: true,
            custom_virtio: false,
            bridged_interfaces: vec!["en0".into()],
        }
    }

    #[test]
    fn feature_mismatch_is_rejected() {
        let r = ApplePlacementRequest {
            vcpus: 8,
            memory_mib: 32_768,
            needs_nested: true,
            ..Default::default()
        };
        assert_eq!(score(&host(), &r), None);
        for r in [
            ApplePlacementRequest {
                needs_custom_virtio: true,
                ..Default::default()
            },
            ApplePlacementRequest {
                bridge_interface: Some("en5".into()),
                ..Default::default()
            },
        ] {
            assert_eq!(score(&host(), &r), None);
        }
        let ok = ApplePlacementRequest {
            needs_vmnet: true,
            bridge_interface: Some("en0".into()),
            ..Default::default()
        };
        assert!(score(&host(), &ok).is_some());
    }

    #[test]
    fn insufficient_capacity_is_rejected() {
        let r = ApplePlacementRequest {
            vcpus: 25,
            ..Default::default()
        };
        assert_eq!(score(&host(), &r), None);
        let r = ApplePlacementRequest {
            memory_mib: 196_609,
            ..Default::default()
        };
        assert_eq!(score(&host(), &r), None);
    }

    #[test]
    fn tighter_fit_scores_higher() {
        let r = ApplePlacementRequest {
            vcpus: 8,
            memory_mib: 32_768,
            ..Default::default()
        };
        let big = host();
        let small = AppleHostCaps {
            free_cpu: 10,
            free_memory_mib: 40_000,
            ..host()
        };
        assert!(score(&small, &r).unwrap() > score(&big, &r).unwrap());
    }
}
