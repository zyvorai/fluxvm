// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/fluxvm"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
)

type Snapshot struct {
	Pods            []kube.Pod
	Namespaces      []kube.Namespace
	Services        []kube.Service
	NetworkPolicies []kube.NetworkPolicy
}

type Options struct {
	MaxAddresses             int
	IncludeServiceClusterIPs bool
	GlobalAudit              bool
}

type Result struct {
	Managed          bool
	Policy           fluxvm.PodNetworkPolicy
	SelectedPolicies []string
	Unsupported      []string
}

func Compile(target kube.Pod, snapshot Snapshot, opts Options) (Result, error) {
	if opts.MaxAddresses <= 0 {
		opts.MaxAddresses = 12000
	}
	selected := selectedEgressPolicies(target, snapshot.NetworkPolicies)
	if len(selected) == 0 {
		return Result{Managed: false}, nil
	}

	result := Result{
		Managed: true,
		Policy: fluxvm.PodNetworkPolicy{
			DefaultDeny: true,
			AuditMode:   opts.GlobalAudit,
		},
	}
	allowed := map[string]struct{}{}
	portRules := map[fluxvm.PodPeerPortRule]struct{}{}
	knownAddresses := knownClusterAddresses(snapshot)
	allowAll := false

	for _, np := range selected {
		result.SelectedPolicies = append(result.SelectedPolicies, np.Metadata.Namespace+"/"+np.Metadata.Name)
		for ruleIndex, rule := range np.Spec.Egress {
			prefix := fmt.Sprintf("%s/%s egress[%d]", np.Metadata.Namespace, np.Metadata.Name, ruleIndex)
			if len(rule.Ports) > 0 {
				// Set 13: numeric TCP/UDP ports compile to an exact
				// protocol+port allow per resolved peer (dataplane schema
				// v7's fluxvm_pid4_port/fluxvm_pid6_port). Named ports and
				// endPort ranges are still not representable and are
				// reported unsupported rather than widened.
				tuples, unsupported := compilePortTuples(prefix, rule.Ports)
				result.Unsupported = append(result.Unsupported, unsupported...)
				if len(tuples) == 0 {
					continue
				}
				if len(rule.To) == 0 {
					result.Unsupported = append(result.Unsupported, prefix+": port-restricted rule has no `to` peers; an all-address port allow is not representable, rule denied")
					continue
				}
				for peerIndex, peer := range rule.To {
					peerPrefix := fmt.Sprintf("%s to[%d]", prefix, peerIndex)
					addrs, all, peerUnsupported, err := resolvePeerAddresses(np, peer, snapshot, knownAddresses, opts.IncludeServiceClusterIPs)
					if err != nil {
						return safeDeny(result), fmt.Errorf("%s: %w", peerPrefix, err)
					}
					if peerUnsupported != "" {
						result.Unsupported = append(result.Unsupported, peerPrefix+": "+peerUnsupported)
					}
					if all {
						result.Unsupported = append(result.Unsupported, peerPrefix+": empty peer combined with a port restriction is not representable (would require an all-address port allow); denied for this peer")
						continue
					}
					for addr := range addrs {
						for _, t := range tuples {
							portRules[fluxvm.PodPeerPortRule{Address: addr, Protocol: t.protocol, Port: t.port}] = struct{}{}
						}
					}
				}
				continue
			}
			if len(rule.To) == 0 {
				// No `to` and no `ports` means all destinations for this rule.
				allowAll = true
				continue
			}
			for peerIndex, peer := range rule.To {
				peerPrefix := fmt.Sprintf("%s to[%d]", prefix, peerIndex)
				all, unsupported, err := resolvePeer(np, peer, snapshot, knownAddresses, opts.IncludeServiceClusterIPs, allowed)
				if err != nil {
					return safeDeny(result), fmt.Errorf("%s: %w", peerPrefix, err)
				}
				if unsupported != "" {
					result.Unsupported = append(result.Unsupported, peerPrefix+": "+unsupported)
				}
				if all {
					allowAll = true
				}
			}
		}
	}

	if allowAll {
		// NetworkPolicy allow rules are additive. One unrestricted egress rule
		// means the union permits every destination; exact-address and
		// port-scoped entries are no longer relevant.
		result.Policy.DefaultDeny = false
		result.Policy.AllowAddresses = nil
		result.Policy.AllowPortRules = nil
		return result, nil
	}

	result.Policy.AllowAddresses = sortedKeys(allowed)
	if len(result.Policy.AllowAddresses) > opts.MaxAddresses {
		return safeDeny(result), fmt.Errorf("compiled allow-address set has %d entries, exceeds configured maximum %d", len(result.Policy.AllowAddresses), opts.MaxAddresses)
	}

	// A peer already allowed on every port makes any port-scoped entry for
	// the same address redundant -- drop it rather than spend port-map
	// budget on a rule the address-wide allow already covers (it would also
	// be ignored at enforcement time, since fluxvm_pid4/6 is checked first).
	for rule := range portRules {
		if _, ok := allowed[rule.Address]; ok {
			delete(portRules, rule)
		}
	}
	result.Policy.AllowPortRules = sortedPortRules(portRules)
	if len(result.Policy.AllowPortRules) > opts.MaxAddresses {
		return safeDeny(result), fmt.Errorf("compiled allow-port-rule set has %d entries, exceeds configured maximum %d", len(result.Policy.AllowPortRules), opts.MaxAddresses)
	}
	return result, nil
}

func safeDeny(result Result) Result {
	result.Managed = true
	result.Policy.DefaultDeny = true
	result.Policy.AllowAddresses = nil
	result.Policy.DenyAddresses = nil
	result.Policy.AllowPortRules = nil
	return result
}

type portTuple struct {
	protocol fluxvm.PodPolicyProtocol
	port     uint16
}

// compilePortTuples lowers a NetworkPolicyPort list to exact protocol+port
// tuples, reporting (via the returned messages, prefixed with `prefix`)
// every entry it cannot represent instead of silently dropping or widening
// it: named ports (Kubernetes resolves those per-container, which this
// controller does not fetch) and `endPort` ranges (Set 6S's map has no
// range dimension) are both unsupported today.
func compilePortTuples(prefix string, ports []kube.NetworkPolicyPort) (tuples []portTuple, unsupported []string) {
	for _, p := range ports {
		if p.EndPort != nil {
			unsupported = append(unsupported, prefix+": port ranges (endPort) are not representable; that port entry is denied")
			continue
		}
		proto, ok := normalizePortProtocol(p.Protocol)
		if !ok {
			unsupported = append(unsupported, fmt.Sprintf("%s: protocol %q is not representable; that port entry is denied", prefix, p.Protocol))
			continue
		}
		port, ok := numericPort(p.Port)
		if !ok {
			unsupported = append(unsupported, prefix+": named ports are not representable; that port entry is denied")
			continue
		}
		tuples = append(tuples, portTuple{protocol: proto, port: port})
	}
	return tuples, unsupported
}

func normalizePortProtocol(raw string) (fluxvm.PodPolicyProtocol, bool) {
	// Kubernetes defaults an omitted `protocol` to TCP.
	switch strings.ToUpper(raw) {
	case "", "TCP":
		return fluxvm.ProtocolTCP, true
	case "UDP":
		return fluxvm.ProtocolUDP, true
	default:
		return "", false
	}
}

// numericPort accepts only a plain numeric port, matching how
// encoding/json decodes an `IntOrString`-shaped field into `interface{}`:
// a JSON number becomes float64, a named port becomes string.
func numericPort(raw interface{}) (uint16, bool) {
	n, ok := raw.(float64)
	if !ok || n != float64(int64(n)) || n < 0 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

func selectedEgressPolicies(target kube.Pod, policies []kube.NetworkPolicy) []kube.NetworkPolicy {
	var selected []kube.NetworkPolicy
	for _, np := range policies {
		if np.Metadata.Namespace != target.Metadata.Namespace {
			continue
		}
		if !kube.MatchesSelector(target.Metadata.Labels, np.Spec.PodSelector) {
			continue
		}
		if !isolatesEgress(np.Spec) {
			continue
		}
		selected = append(selected, np)
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Metadata.Namespace == selected[j].Metadata.Namespace {
			return selected[i].Metadata.Name < selected[j].Metadata.Name
		}
		return selected[i].Metadata.Namespace < selected[j].Metadata.Namespace
	})
	return selected
}

func isolatesEgress(spec kube.NetworkPolicySpec) bool {
	if len(spec.PolicyTypes) == 0 {
		// Kubernetes defaults policyTypes to Ingress, adding Egress only when
		// at least one egress rule is present.
		return len(spec.Egress) > 0
	}
	for _, policyType := range spec.PolicyTypes {
		if policyType == "Egress" {
			return true
		}
	}
	return false
}

// resolvePeer resolves a peer directly into the caller's unrestricted
// allow set. It is a thin wrapper over resolvePeerAddresses kept for the
// no-`ports` call sites, which have no separate use for the resolved
// address set once it's merged in.
func resolvePeer(
	np kube.NetworkPolicy,
	peer kube.NetworkPolicyPeer,
	snapshot Snapshot,
	knownAddresses []netip.Addr,
	includeServiceVIPs bool,
	allowed map[string]struct{},
) (allowAll bool, unsupported string, err error) {
	addrs, allowAll, unsupported, err := resolvePeerAddresses(np, peer, snapshot, knownAddresses, includeServiceVIPs)
	if err != nil {
		return false, "", err
	}
	for addr := range addrs {
		allowed[addr] = struct{}{}
	}
	return allowAll, unsupported, nil
}

// resolvePeerAddresses is the address-resolution core shared by unrestricted
// (`resolvePeer`) and port-restricted (`Compile`'s `ports` branch) rules --
// it returns the resolved addresses instead of writing into a shared allow
// set, since the port-restricted path needs to pair each address with its
// rule's ports rather than allow it outright.
func resolvePeerAddresses(
	np kube.NetworkPolicy,
	peer kube.NetworkPolicyPeer,
	snapshot Snapshot,
	knownAddresses []netip.Addr,
	includeServiceVIPs bool,
) (addrs map[string]struct{}, allowAll bool, unsupported string, err error) {
	addrs = map[string]struct{}{}
	selectorCount := 0
	if peer.PodSelector != nil {
		selectorCount++
	}
	if peer.NamespaceSelector != nil {
		selectorCount++
	}
	if peer.IPBlock != nil {
		if selectorCount != 0 {
			return nil, false, "", fmt.Errorf("invalid NetworkPolicyPeer mixes ipBlock with selectors")
		}
		allowAll, unsupported, err = resolveIPBlock(*peer.IPBlock, knownAddresses, addrs)
		return addrs, allowAll, unsupported, err
	}
	if selectorCount == 0 {
		// Empty peer `{}` means all destinations.
		return addrs, true, "", nil
	}

	namespaces := selectedNamespaces(np.Metadata.Namespace, peer.NamespaceSelector, snapshot.Namespaces)
	selectedPods := map[string]struct{}{}
	for _, pod := range snapshot.Pods {
		if _, ok := namespaces[pod.Metadata.Namespace]; !ok {
			continue
		}
		if peer.PodSelector != nil && !kube.MatchesSelector(pod.Metadata.Labels, *peer.PodSelector) {
			continue
		}
		if terminalPod(pod) {
			continue
		}
		selectedPods[pod.Metadata.UID] = struct{}{}
		for _, raw := range kube.PodAddresses(pod) {
			addr, parseErr := netip.ParseAddr(raw)
			if parseErr != nil {
				continue
			}
			addrs[addr.String()] = struct{}{}
		}
	}

	if includeServiceVIPs {
		includeConservativeServiceVIPs(snapshot, namespaces, selectedPods, addrs)
	}
	return addrs, false, "", nil
}

func resolveIPBlock(block kube.IPBlock, known []netip.Addr, allowed map[string]struct{}) (bool, string, error) {
	prefix, err := netip.ParsePrefix(block.CIDR)
	if err != nil {
		return false, "", fmt.Errorf("invalid ipBlock CIDR %q: %w", block.CIDR, err)
	}
	prefix = prefix.Masked()
	var excepts []netip.Prefix
	for _, raw := range block.Except {
		ex, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil {
			return false, "", fmt.Errorf("invalid ipBlock except CIDR %q: %w", raw, parseErr)
		}
		if ex.Addr().BitLen() != prefix.Addr().BitLen() || ex.Bits() < prefix.Bits() || !prefix.Contains(ex.Addr()) {
			return false, "", fmt.Errorf("ipBlock except %q is outside %q", raw, block.CIDR)
		}
		excepts = append(excepts, ex.Masked())
	}
	isHostPrefix := (prefix.Addr().Is4() && prefix.Bits() == 32) || (prefix.Addr().Is6() && prefix.Bits() == 128)
	if isHostPrefix {
		if !excluded(prefix.Addr(), excepts) {
			allowed[prefix.Addr().String()] = struct{}{}
		}
		return false, "", nil
	}

	// FluxVM's Set 6S map accepts exact addresses, not CIDRs. Resolve only
	// currently-known Pod/Service addresses inside the block. This may deny
	// external addresses Kubernetes would allow, but never widens access.
	for _, addr := range known {
		if prefix.Contains(addr) && !excluded(addr, excepts) {
			allowed[addr.String()] = struct{}{}
		}
	}
	return false, "broad ipBlock is exact-address approximated to currently-known cluster IPs; unknown external addresses remain denied", nil
}

func selectedNamespaces(policyNamespace string, selector *kube.LabelSelector, namespaces []kube.Namespace) map[string]struct{} {
	out := map[string]struct{}{}
	if selector == nil {
		out[policyNamespace] = struct{}{}
		return out
	}
	for _, ns := range namespaces {
		if kube.MatchesSelector(ns.Metadata.Labels, *selector) {
			out[ns.Metadata.Name] = struct{}{}
		}
	}
	return out
}

func knownClusterAddresses(snapshot Snapshot) []netip.Addr {
	seen := map[netip.Addr]struct{}{}
	for _, pod := range snapshot.Pods {
		for _, raw := range kube.PodAddresses(pod) {
			if addr, err := netip.ParseAddr(raw); err == nil {
				seen[addr] = struct{}{}
			}
		}
	}
	for _, svc := range snapshot.Services {
		for _, raw := range serviceIPs(svc) {
			if addr, err := netip.ParseAddr(raw); err == nil {
				seen[addr] = struct{}{}
			}
		}
	}
	out := make([]netip.Addr, 0, len(seen))
	for addr := range seen {
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func includeConservativeServiceVIPs(snapshot Snapshot, namespaces, peerPods map[string]struct{}, allowed map[string]struct{}) {
	for _, svc := range snapshot.Services {
		if _, ok := namespaces[svc.Metadata.Namespace]; !ok || len(svc.Spec.Selector) == 0 {
			continue
		}
		matched := 0
		safe := true
		for _, pod := range snapshot.Pods {
			if pod.Metadata.Namespace != svc.Metadata.Namespace || terminalPod(pod) {
				continue
			}
			if !matchesExactSelector(pod.Metadata.Labels, svc.Spec.Selector) {
				continue
			}
			matched++
			if _, ok := peerPods[pod.Metadata.UID]; !ok {
				safe = false
				break
			}
		}
		if !safe || matched == 0 {
			continue
		}
		for _, raw := range serviceIPs(svc) {
			if addr, err := netip.ParseAddr(raw); err == nil {
				allowed[addr.String()] = struct{}{}
			}
		}
	}
}

func serviceIPs(svc kube.Service) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range svc.Spec.ClusterIPs {
		if raw == "" || strings.EqualFold(raw, "None") {
			continue
		}
		if _, ok := seen[raw]; !ok {
			seen[raw] = struct{}{}
			out = append(out, raw)
		}
	}
	if svc.Spec.ClusterIP != "" && !strings.EqualFold(svc.Spec.ClusterIP, "None") {
		if _, ok := seen[svc.Spec.ClusterIP]; !ok {
			out = append(out, svc.Spec.ClusterIP)
		}
	}
	return out
}

func matchesExactSelector(labels, selector map[string]string) bool {
	for key, want := range selector {
		if labels[key] != want {
			return false
		}
	}
	return true
}

func excluded(addr netip.Addr, excepts []netip.Prefix) bool {
	for _, prefix := range excepts {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func terminalPod(pod kube.Pod) bool {
	return pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed"
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		a, aerr := netip.ParseAddr(out[i])
		b, berr := netip.ParseAddr(out[j])
		if aerr == nil && berr == nil {
			return a.Less(b)
		}
		return out[i] < out[j]
	})
	return out
}

func sortedPortRules(values map[fluxvm.PodPeerPortRule]struct{}) []fluxvm.PodPeerPortRule {
	out := make([]fluxvm.PodPeerPortRule, 0, len(values))
	for rule := range values {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			a, aerr := netip.ParseAddr(out[i].Address)
			b, berr := netip.ParseAddr(out[j].Address)
			if aerr == nil && berr == nil {
				return a.Less(b)
			}
			return out[i].Address < out[j].Address
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Port < out[j].Port
	})
	return out
}
