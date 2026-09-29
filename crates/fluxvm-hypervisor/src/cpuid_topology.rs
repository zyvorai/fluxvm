// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Guest CPU topology as seen through CPUID.
//!
//! Pure functions over a list of CPUID entries so the logic is unit-testable
//! without KVM. The host's values describe the *physical* package; the guest
//! must instead see its own vCPU count, or Linux's sibling/core maths (and
//! AP bring-up against the MADT/MPTABLE) go wrong. Matches the normalization
//! Firecracker (`cpuid.normalize()`) and Cloud Hypervisor
//! (`update_cpuid_topology`) apply: one package, `vcpus / threads_per_core`
//! cores, `threads_per_core` threads per core.
//!
//! Intel: leaf 1 (logical processor count, HTT), leaf 4 (cores per package and
//! cache sharing), leaf 0xB and 0x1F (extended topology, x2APIC id in EDX).
//! AMD: leaf 0xB plus 0x80000008 (core count) and 0x8000001E (extended APIC /
//! core id), with 0x80000001 ECX[22] (TopologyExtensions) forced on so a guest
//! kernel actually reads 0x8000001E — Firecracker never needs this because it
//! only supports AMD-on-AMD and passes 0x80000001 through from real hardware,
//! where the bit is already set; we synthesize AMD identity independently of
//! the host, so nothing else guarantees it. Bit-for-bit cross-checked against
//! the AMD64 Architecture Programmer's Manual Volume 3 and against
//! `arch/x86/kernel/cpu/amd.c` (`amd_get_topology`, `bsp_init_amd`) and
//! Firecracker's own `src/vmm/src/cpu_config/x86_64/cpuid/amd/normalize.rs`.
//! Never run on real AMD silicon (this lab host is Intel-only), which would
//! exercise AMD-specific MSRs, errata and power management this CPUID-only
//! approach cannot represent.

/// One `kvm_cpuid_entry2` (same layout, `#[repr(C)]`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuidEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

/// `KVM_CPUID_FLAG_SIGNIFCANT_INDEX`: the entry is selected by ECX as well.
pub const FLAG_SIGNIFICANT_INDEX: u32 = 1;

/// Level types in leaf 0xB / 0x1F ECX[15:8].
const LEVEL_INVALID: u32 = 0;
const LEVEL_SMT: u32 = 1;
const LEVEL_CORE: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vendor {
    Intel,
    Amd,
    Other,
}

/// The guest topology to present to one vCPU.
#[derive(Clone, Copy, Debug)]
pub struct Topology {
    /// Total vCPUs in the guest (one package).
    pub vcpus: u32,
    /// Hardware threads per core (1 = no SMT, as Firecracker's `smt=false`).
    pub threads_per_core: u32,
    /// This vCPU's id, used as its (x2)APIC id.
    pub apic_id: u32,
}

pub fn vendor(entries: &[CpuidEntry]) -> Vendor {
    match entries.iter().find(|e| e.function == 0 && e.index == 0) {
        Some(e) if (e.ebx, e.edx, e.ecx) == (0x756e_6547, 0x4965_6e69, 0x6c65_746e) => {
            Vendor::Intel
        }
        Some(e) if (e.ebx, e.edx, e.ecx) == (0x6874_7541, 0x6974_6e65, 0x444d_4163) => Vendor::Amd,
        _ => Vendor::Other,
    }
}

/// Bits needed to number `x` distinct ids (`ceil(log2(x))`, 0 for x <= 1).
pub fn ceil_log2(x: u32) -> u32 {
    if x <= 1 {
        0
    } else {
        32 - (x - 1).leading_zeros()
    }
}

/// Extended-topology levels for leaf 0xB / 0x1F as
/// `(shift, logical processors at this level, level type)`.
fn levels(t: &Topology) -> [(u32, u32, u32); 2] {
    let smt_shift = ceil_log2(t.threads_per_core);
    let cores = t.vcpus.div_ceil(t.threads_per_core);
    let pkg_shift = smt_shift + ceil_log2(cores);
    [
        (smt_shift, t.threads_per_core, LEVEL_SMT),
        (pkg_shift, t.vcpus, LEVEL_CORE),
    ]
}

/// The sub-leaves of an extended-topology leaf: SMT, core, then an invalid
/// terminator (so the guest's loop stops).
fn extended_leaf(function: u32, t: &Topology) -> Vec<CpuidEntry> {
    let lv = levels(t);
    let mut out = Vec::with_capacity(3);
    for (i, (shift, count, ty)) in lv.iter().enumerate() {
        out.push(CpuidEntry {
            function,
            index: i as u32,
            flags: FLAG_SIGNIFICANT_INDEX,
            eax: *shift,
            ebx: *count & 0xffff,
            ecx: (i as u32) | (ty << 8),
            edx: t.apic_id,
            padding: [0; 3],
        });
    }
    out.push(CpuidEntry {
        function,
        index: lv.len() as u32,
        flags: FLAG_SIGNIFICANT_INDEX,
        eax: 0,
        ebx: 0,
        ecx: (lv.len() as u32) | (LEVEL_INVALID << 8),
        edx: t.apic_id,
        padding: [0; 3],
    });
    out
}

/// Rewrite the topology-related leaves of `entries` for the guest.
///
/// Returns an error if the result would not fit in `max_entries`.
pub fn apply(
    entries: &mut Vec<CpuidEntry>,
    t: Topology,
    max_entries: usize,
) -> Result<(), &'static str> {
    let t = Topology {
        vcpus: t.vcpus.max(1),
        threads_per_core: t.threads_per_core.max(1),
        apic_id: t.apic_id,
    };
    let n = t.vcpus;
    let cores = n.div_ceil(t.threads_per_core);
    let vendor = vendor(entries);
    let had_0xb = entries.iter().any(|e| e.function == 0xb);
    let had_0x1f = entries.iter().any(|e| e.function == 0x1f);

    for e in entries.iter_mut() {
        match e.function {
            1 => {
                // EBX[31:24] initial APIC id, EBX[23:16] logical processors per
                // package. The host's count (often > the guest's) makes
                // Linux's AP bring-up disagree with the MADT.
                e.ebx = (e.ebx & 0x0000_ffff) | ((n & 0xff) << 16) | ((t.apic_id & 0xff) << 24);
                // HTT (EDX[28]) must be set for a multi-vCPU guest, or
                // detect_ht() leaves phys_proc_id == raw APIC id and CPU1 lands
                // in "package 1" (BUG_ON in identify_secondary_cpu).
                if n > 1 {
                    e.edx |= 1 << 28;
                }
            }
            4 if e.eax & 0x1f != 0 => {
                // Deterministic cache parameters. EAX[31:26] = cores per
                // package - 1; EAX[25:14] = logical processors sharing this
                // cache - 1: private to a core (its threads) at L1/L2, shared
                // by the whole package from L3 up.
                let level = (e.eax >> 5) & 0x7;
                let sharing = if level >= 3 {
                    n - 1
                } else {
                    t.threads_per_core - 1
                };
                e.eax = (e.eax & 0x0000_3fff)
                    | (sharing.min(0xfff) << 14)
                    | ((cores - 1).min(0x3f) << 26);
            }
            0x8000_0001 if vendor == Vendor::Amd => {
                // ECX[22] = TopologyExtensions. Firecracker never has to set this:
                // it only supports AMD guests on real AMD hosts and passes leaf
                // 0x8000_0001 through untouched, where hardware already reports it.
                // We synthesize AMD identity ourselves (no real AMD host CPUID to
                // inherit it from), so without this bit Linux's amd_get_topology()
                // never even reads leaf 0x8000001e below — the whole leaf would be
                // silently dead weight. Force it whenever the guest is AMD.
                e.ecx |= 1 << 22;
            }
            0x8000_0008 if vendor == Vendor::Amd => {
                // ECX[7:0] = number of cores - 1, ECX[15:12] = APIC id size.
                e.ecx = (e.ecx & !0xf0ff) | ((n - 1) & 0xff) | (ceil_log2(n).min(0xf) << 12);
            }
            0x8000_001e if vendor == Vendor::Amd => {
                // EAX = extended APIC id; EBX[7:0] core id, EBX[15:8] threads
                // per core - 1; ECX[7:0] node id, ECX[10:8] nodes per package - 1
                // (one node, matches Firecracker's NODES_PER_PROCESSOR = 0).
                e.eax = t.apic_id;
                e.ebx = ((t.apic_id / t.threads_per_core) & 0xff) | ((t.threads_per_core - 1) << 8);
                e.ecx = 0;
                e.edx = 0;
            }
            _ => {}
        }
    }

    // Leaf 4 with a single vCPU must not advertise the host's core count either,
    // which the loop above already handled (cores - 1 == 0).

    // Extended topology leaves: replace the host's (physical package) with ours.
    entries.retain(|e| e.function != 0xb && e.function != 0x1f);
    if had_0xb || vendor == Vendor::Intel {
        entries.extend(extended_leaf(0xb, &t));
    }
    if had_0x1f {
        entries.extend(extended_leaf(0x1f, &t));
    }
    entries.sort_by_key(|e| (e.function, e.index));
    if entries.len() > max_entries {
        return Err("CPUID entries exceed the KVM buffer");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENUINE_INTEL: (u32, u32, u32) = (0x756e_6547, 0x4965_6e69, 0x6c65_746e);
    const AUTHENTIC_AMD: (u32, u32, u32) = (0x6874_7541, 0x6974_6e65, 0x444d_4163);

    fn host(vendor: (u32, u32, u32)) -> Vec<CpuidEntry> {
        let e = |function, index, eax, ebx, ecx, edx| CpuidEntry {
            function,
            index,
            flags: if matches!(function, 4 | 0xb | 0x1f) {
                FLAG_SIGNIFICANT_INDEX
            } else {
                0
            },
            eax,
            ebx,
            ecx,
            edx,
            padding: [0; 3],
        };
        vec![
            e(0, 0, 0x16, vendor.0, vendor.2, vendor.1),
            // host: 12 logical CPUs, HTT already set
            e(1, 0, 0x000a_0671, 0x0c00_0800, 0, 1 << 28),
            // L1d (level 1), L2 (level 2), L3 (level 3), terminator; host says
            // 12 sharing L2 and 11 cores per package.
            e(4, 0, 0x2c00_4121, 0, 0, 0),
            e(4, 1, 0x2c00_4143 | (11 << 14), 0, 0, 0),
            e(4, 2, 0x2c00_c163 | (15 << 14), 0, 0, 0),
            e(4, 3, 0, 0, 0, 0),
            // host extended topology: SMT=2, core=12, plus a stale 3rd level
            e(0xb, 0, 1, 2, 1 << 8, 7),
            e(0xb, 1, 4, 12, 1 | (2 << 8), 7),
            e(0xb, 2, 0, 0, 2, 7),
            e(0x1f, 0, 1, 2, 1 << 8, 7),
            e(0x1f, 1, 4, 12, 1 | (2 << 8), 7),
            e(0x1f, 2, 0, 0, 2, 7),
            // TopologyExtensions (ECX[22]) starts unset, as it would on a
            // non-AMD host with no real leaf to inherit it from.
            e(0x8000_0001, 0, 0, 0, 0x2193_fbff, 0),
            e(0x8000_0008, 0, 0x3027, 0, 0x000b, 0),
            e(0x8000_001e, 0, 9, 9, 9, 9),
        ]
    }

    fn get(v: &[CpuidEntry], f: u32, i: u32) -> CpuidEntry {
        *v.iter().find(|e| e.function == f && e.index == i).unwrap()
    }

    fn topo(vcpus: u32, tpc: u32, apic_id: u32) -> Topology {
        Topology {
            vcpus,
            threads_per_core: tpc,
            apic_id,
        }
    }

    #[test]
    fn ceil_log2_values() {
        let got: Vec<u32> = [0, 1, 2, 3, 4, 5, 8, 9, 255, 256]
            .iter()
            .map(|x| ceil_log2(*x))
            .collect();
        assert_eq!(got, vec![0, 0, 1, 2, 2, 3, 3, 4, 8, 8]);
    }

    #[test]
    fn detects_vendors() {
        assert_eq!(vendor(&host(GENUINE_INTEL)), Vendor::Intel);
        assert_eq!(vendor(&host(AUTHENTIC_AMD)), Vendor::Amd);
        assert_eq!(vendor(&[]), Vendor::Other);
    }

    #[test]
    fn intel_extended_topology_for_1_2_4_8_vcpus() {
        for (n, pkg_shift) in [(1u32, 0u32), (2, 1), (4, 2), (8, 3)] {
            for id in 0..n {
                let mut v = host(GENUINE_INTEL);
                apply(&mut v, topo(n, 1, id), 256).unwrap();
                for leaf in [0xbu32, 0x1f] {
                    let smt = get(&v, leaf, 0);
                    assert_eq!(smt.eax, 0, "n={n} SMT shift");
                    assert_eq!(smt.ebx, 1, "one thread per core");
                    assert_eq!(smt.ecx, 1 << 8, "level 0, type SMT");
                    assert_eq!(smt.edx, id, "x2APIC id == vCPU id");
                    let core = get(&v, leaf, 1);
                    assert_eq!(core.eax, pkg_shift, "n={n} package shift");
                    assert_eq!(core.ebx, n, "logical CPUs in package");
                    assert_eq!(core.ecx, 1 | (2 << 8), "level 1, type core");
                    assert_eq!(core.edx, id);
                    let end = get(&v, leaf, 2);
                    assert_eq!((end.ebx, end.ecx >> 8 & 0xff), (0, 0), "terminated");
                    // no stale extra sub-leaves survive
                    assert_eq!(v.iter().filter(|e| e.function == leaf).count(), 3);
                }
            }
        }
    }

    #[test]
    fn smt_guest_reports_two_threads_per_core() {
        let mut v = host(GENUINE_INTEL);
        apply(&mut v, topo(8, 2, 5), 256).unwrap();
        let smt = get(&v, 0xb, 0);
        assert_eq!((smt.eax, smt.ebx, smt.ecx >> 8), (1, 2, 1));
        let core = get(&v, 0xb, 1);
        assert_eq!((core.eax, core.ebx), (1 + 2, 8), "4 cores => 2 more bits");
        // leaf 4: 4 cores per package, L1/L2 shared by the 2 threads
        assert_eq!(get(&v, 4, 0).eax >> 26, 3);
        assert_eq!(get(&v, 4, 1).eax >> 14 & 0xfff, 1);
        assert_eq!(get(&v, 4, 2).eax >> 14 & 0xfff, 7);
    }

    #[test]
    fn non_power_of_two_counts_round_up() {
        let mut v = host(GENUINE_INTEL);
        apply(&mut v, topo(3, 1, 2), 256).unwrap();
        assert_eq!(get(&v, 0xb, 1).eax, 2, "3 cores need 2 bits");
        assert_eq!(get(&v, 1, 0).ebx >> 16 & 0xff, 3);
    }

    #[test]
    fn leaf_1_and_4_follow_the_guest_not_the_host() {
        let mut v = host(GENUINE_INTEL);
        apply(&mut v, topo(4, 1, 3), 256).unwrap();
        let l1 = get(&v, 1, 0);
        assert_eq!(l1.ebx >> 24, 3, "initial APIC id");
        assert_eq!(l1.ebx >> 16 & 0xff, 4, "logical processors per package");
        assert_ne!(l1.edx & (1 << 28), 0, "HTT for a multi-vCPU guest");
        assert_eq!(l1.ebx & 0xffff, 0x0800, "CLFLUSH size and brand id kept");
        for i in 0..3 {
            assert_eq!(get(&v, 4, i).eax >> 26, 3, "cores per package - 1");
        }
        // L1/L2 private to the (single-thread) core, L3 shared by all 4
        assert_eq!(get(&v, 4, 0).eax >> 14 & 0xfff, 0);
        assert_eq!(get(&v, 4, 1).eax >> 14 & 0xfff, 0);
        assert_eq!(get(&v, 4, 2).eax >> 14 & 0xfff, 3);
        // the terminator sub-leaf (type 0) is left alone
        assert_eq!(get(&v, 4, 3).eax, 0);
    }

    #[test]
    fn single_vcpu_drops_the_host_core_count() {
        let mut v = host(GENUINE_INTEL);
        apply(&mut v, topo(1, 1, 0), 256).unwrap();
        assert_eq!(get(&v, 4, 0).eax >> 26, 0);
        assert_eq!(get(&v, 1, 0).ebx >> 16 & 0xff, 1);
    }

    #[test]
    fn intel_without_1f_does_not_grow_one_and_without_b_gets_it() {
        let mut v: Vec<CpuidEntry> = host(GENUINE_INTEL)
            .into_iter()
            .filter(|e| e.function != 0x1f && e.function != 0xb)
            .collect();
        apply(&mut v, topo(2, 1, 1), 256).unwrap();
        assert!(v.iter().all(|e| e.function != 0x1f));
        assert_eq!(v.iter().filter(|e| e.function == 0xb).count(), 3);
    }

    #[test]
    fn amd_gets_core_count_and_extended_ids_and_intel_does_not() {
        let mut a = host(AUTHENTIC_AMD);
        apply(&mut a, topo(4, 1, 3), 256).unwrap();
        let l8 = get(&a, 0x8000_0008, 0);
        assert_eq!(l8.ecx & 0xff, 3, "NC = cores - 1");
        assert_eq!(l8.ecx >> 12 & 0xf, 2, "APIC id size");
        assert_eq!(l8.eax, 0x3027, "address sizes untouched");
        let l1e = get(&a, 0x8000_001e, 0);
        assert_eq!((l1e.eax, l1e.ebx & 0xff, l1e.ebx >> 8 & 0xff), (3, 3, 0));
        assert_eq!((l1e.ecx, l1e.edx), (0, 0));

        let mut i = host(GENUINE_INTEL);
        apply(&mut i, topo(4, 1, 3), 256).unwrap();
        assert_eq!(get(&i, 0x8000_0008, 0).ecx, 0x000b, "Intel leaf untouched");
        assert_eq!(get(&i, 0x8000_001e, 0).eax, 9);
    }

    #[test]
    fn amd_topology_extensions_bit_is_forced_on_so_leaf_1e_is_not_dead_weight() {
        let mut a = host(AUTHENTIC_AMD);
        assert_eq!(
            get(&a, 0x8000_0001, 0).ecx & (1 << 22),
            0,
            "fixture starts with TopologyExtensions unset, like a non-AMD host"
        );
        apply(&mut a, topo(4, 1, 0), 256).unwrap();
        let ecx = get(&a, 0x8000_0001, 0).ecx;
        assert_eq!(ecx & (1 << 22), 1 << 22, "TopologyExtensions forced on");
        // every other feature bit the fixture set is left alone
        assert_eq!(ecx & !(1 << 22), 0x2193_fbff & !(1 << 22));

        // Intel's leaf 0x8000_0001 (`host()` gives every vendor one, the way a
        // real CPU does) is never touched: bit 22 has no defined meaning
        // there, and the match arm above is gated on vendor == Amd.
        let mut i = host(GENUINE_INTEL);
        let intel_ecx_before = get(&i, 0x8000_0001, 0).ecx;
        apply(&mut i, topo(4, 1, 0), 256).unwrap();
        assert_eq!(get(&i, 0x8000_0001, 0).ecx, intel_ecx_before);
    }

    /// Independent "oracle": decodes leaf 0x8000_0008 / 0x8000_001E exactly as
    /// `arch/x86/kernel/cpu/amd.c` does (`bsp_init_amd`'s `x86_coreid_bits`
    /// selection, `amd_get_topology`'s `smp_num_siblings`/`cpu_core_id`), so
    /// this test does not just check the implementation against itself.
    fn kernel_amd_coreid_bits(ecx_8000_0008: u32) -> u32 {
        let apic_id_size = (ecx_8000_0008 >> 12) & 0xf;
        if apic_id_size != 0 {
            apic_id_size
        } else {
            // get_count_order(NC + 1)
            let nc = ecx_8000_0008 & 0xff;
            ceil_log2(nc + 1)
        }
    }

    #[test]
    fn amd_every_core_count_from_1_to_128_decodes_the_way_the_kernel_would() {
        for n in 1u32..=128 {
            let mut v = host(AUTHENTIC_AMD);
            apply(&mut v, topo(n, 1, 0), 256).unwrap();
            let l8 = get(&v, 0x8000_0008, 0);
            assert_eq!(l8.ecx & 0xff, n - 1, "n={n} NC");
            let bits = kernel_amd_coreid_bits(l8.ecx);
            // amd_detect_cmp(): cpu_core_id = initial_apicid & ((1<<bits)-1);
            // phys_proc_id = initial_apicid >> bits. A single package must
            // decode every apic id 0..n as core ids 0..n with phys_proc_id 0.
            for apic_id in 0..n {
                let core_id = apic_id & ((1u32 << bits) - 1);
                let phys_proc_id = apic_id >> bits;
                assert_eq!(core_id, apic_id, "n={n} apic_id={apic_id} core_id");
                assert_eq!(phys_proc_id, 0, "n={n} apic_id={apic_id} single package");
            }
        }
    }

    #[test]
    fn amd_apic_id_size_bit_width_boundaries() {
        // ceil_log2 crosses a power-of-two boundary at 7/8/9 cores (3 bits
        // covers up to 8, 4 bits needed for 9).
        for (n, want_bits) in [(6u32, 3u32), (7, 3), (8, 3), (9, 4), (16, 4), (17, 5)] {
            let mut v = host(AUTHENTIC_AMD);
            apply(&mut v, topo(n, 1, 0), 256).unwrap();
            let bits = get(&v, 0x8000_0008, 0).ecx >> 12 & 0xf;
            assert_eq!(bits, want_bits, "n={n}");
        }
    }

    #[test]
    fn amd_smt_threads_per_core_in_extended_apic_id_leaf() {
        // Matches Firecracker's update_extended_apic_id_entry(): EBX[7:0] is
        // apic_id / threads_per_core (the core id), EBX[15:8] is
        // threads_per_core - 1.
        let mut v = host(AUTHENTIC_AMD);
        apply(&mut v, topo(8, 2, 5), 256).unwrap();
        let l1e = get(&v, 0x8000_001e, 0);
        assert_eq!(l1e.ebx & 0xff, 5 / 2, "core id");
        assert_eq!(l1e.ebx >> 8 & 0xff, 1, "threads per core - 1");
    }

    #[test]
    fn output_is_sorted_and_bounded() {
        let mut v = host(GENUINE_INTEL);
        apply(&mut v, topo(2, 1, 0), 256).unwrap();
        assert!(v
            .windows(2)
            .all(|w| (w[0].function, w[0].index) <= (w[1].function, w[1].index)));
        let mut small = host(GENUINE_INTEL);
        assert!(apply(&mut small, topo(2, 1, 0), 4).is_err());
    }
}
