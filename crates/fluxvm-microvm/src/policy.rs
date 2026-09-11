// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Pure policy used by convert + node-agent + shadow Pod.
//! No kube types so it is unit-testable without a cluster.

pub const ANN_DRIVEN_BY: &str = "microvm.fluxvm.zyvor.io/driven-by";
pub const ANN_CONVERTED_FROM: &str = "microvm.fluxvm.zyvor.io/converted-from";
pub const DRIVEN_BY_FLUXVM_KUBE: &str = "fluxvm-kube";
pub const DRIVEN_BY_MICROVM: &str = "microvm";

pub const SHADOW_CPU: &str = "10m";
pub const SHADOW_MEMORY: &str = "32Mi";

/// Converted MicroVMs are a status projection. fluxvm-kube owns the VMM.
/// The MicroVM node agent must not POST /v1/vms for them.
pub fn node_agent_should_drive(
    annotations: Option<&std::collections::BTreeMap<String, String>>,
) -> bool {
    match annotations
        .and_then(|a| a.get(ANN_DRIVEN_BY))
        .map(String::as_str)
    {
        Some(DRIVEN_BY_FLUXVM_KUBE) => false,
        _ => true,
    }
}

pub fn converted_annotations() -> std::collections::BTreeMap<String, String> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(ANN_CONVERTED_FROM.to_string(), "disposablevm".into());
    m.insert(ANN_DRIVEN_BY.to_string(), DRIVEN_BY_FLUXVM_KUBE.into());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_microvm_is_driven() {
        assert!(node_agent_should_drive(None));
        let mut a = std::collections::BTreeMap::new();
        a.insert(ANN_DRIVEN_BY.into(), DRIVEN_BY_MICROVM.into());
        assert!(node_agent_should_drive(Some(&a)));
    }

    #[test]
    fn converted_microvm_is_not_driven() {
        let a = converted_annotations();
        assert!(!node_agent_should_drive(Some(&a)));
        assert_eq!(a.get(ANN_DRIVEN_BY).unwrap(), DRIVEN_BY_FLUXVM_KUBE);
    }

    #[test]
    fn shadow_budget_is_tiny() {
        assert_eq!(SHADOW_CPU, "10m");
        assert_eq!(SHADOW_MEMORY, "32Mi");
    }
}
