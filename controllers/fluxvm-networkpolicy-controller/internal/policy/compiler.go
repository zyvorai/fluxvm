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
	selectedEgress := selectedEgressPolicies(target, snapshot.NetworkPolicies)
	selectedIngress := selectedIngressPolicies(target, snapshot.NetworkPolicies)
	if len(selectedEgress) == 0 && len(selectedIngress) == 0 {
		return Result{Managed: false}, nil
	}

	result := Result{Managed: true}
	knownAddresses := knownClusterAddresses(snapshot)

	if len(selectedEgress) > 0 {
		egressPolicy, egressNames, egressUnsupported, err := compileEgress(target, selectedEgress, snapshot, knownAddresses, opts)
		if err != nil {
			return safeDeny(result), err
		}
		result.Policy = egressPolicy
		result.SelectedPolicies = append(result.SelectedPolicies, egressNames...)
		result.Unsupported = append(result.Unsupported, egressUnsupported...)
	} else {
		// No egress-isolating policy selects this Pod at all -- distinct
		// from "selected but grants nothing beyond default", which
		// compileEgress itself represents via DefaultDeny/empty allow sets.
		// Matches this Set's pre-ingress-support behavior exactly: a Pod
		// with only an ingress-isolating NetworkPolicy keeps unrestricted
		// egress, same as Kubernetes' own semantics.
		result.Policy = fluxvm.PodNetworkPolicy{DefaultDeny: false}
	}

	if len(selectedIngress) > 0 {
		ingressPolicy, ingressNames, ingressUnsupported, err := compileIngress(target, selectedIngress, snapshot, knownAddresses, opts)
		if err != nil {
			return safeDeny(result), err
		}
		result.Policy.Ingress = &ingressPolicy
		result.SelectedPolicies = append(result.SelectedPolicies, ingressNames...)
		result.Unsupported = append(result.Unsupported, ingressUnsupported...)
	}

	return result, nil
}

func safeDeny(result Result) Result {
	result.Managed = true
	result.Policy.DefaultDeny = true
	result.Policy.AllowAddresses = nil
	result.Policy.DenyAddresses = nil
	result.Policy.AllowPortRules = nil
	result.Policy.AllowCidrs = nil
	result.Policy.PortRanges = nil
	result.Policy.Ingress = &fluxvm.PodIngressPolicy{DefaultDeny: true}
	return result
}

// compileEgress mirrors the pre-Set-13-ingress-support Compile() body
// almost exactly, generalized to take the already-selected policy list
// (Compile selects egress and ingress independently, since a Pod can be
// selected by an ingress-only, egress-only, or both-directions policy set).
func compileEgress(
	target kube.Pod,
	selected []kube.NetworkPolicy,
	snapshot Snapshot,
	knownAddresses []netip.Addr,
	opts Options,
) (fluxvm.PodNetworkPolicy, []string, []string, error) {
	policy := fluxvm.PodNetworkPolicy{DefaultDeny: true, AuditMode: opts.GlobalAudit}
	var names, unsupportedOut []string
	allowed := map[string]struct{}{}
	portRules := map[fluxvm.PodPeerPortRule]struct{}{}
	ranges := map[rangeGroupKey][]portRangeTuple{}
	allowAll := false

	for _, np := range selected {
		names = append(names, np.Metadata.Namespace+"/"+np.Metadata.Name)
		for ruleIndex, rule := range np.Spec.Egress {
			prefix := fmt.Sprintf("%s/%s egress[%d]", np.Metadata.Namespace, np.Metadata.Name, ruleIndex)
			if len(rule.Ports) > 0 {
				// Set 13: numeric TCP/UDP ports and endPort ranges compile
				// to exact protocol+port / protocol+range allows per
				// resolved peer (dataplane schema v8's
				// fluxvm_pid4_port(_range)/fluxvm_pid6_port(_range)). A
				// named port resolves independently per selected peer Pod
				// (Kubernetes semantics: an egress rule's named port refers
				// to that name on each individual *destination* container),
				// so it cannot be resolved once up front the way a numeric
				// port or range can.
				tuples, rangeTuples, namedPorts, entryUnsupported := compilePortEntries(prefix, rule.Ports)
				unsupportedOut = append(unsupportedOut, entryUnsupported...)
				if len(tuples) == 0 && len(rangeTuples) == 0 && len(namedPorts) == 0 {
					continue
				}
				if len(rule.To) == 0 {
					unsupportedOut = append(unsupportedOut, prefix+": port-restricted rule has no `to` peers; an all-address port allow is not representable, rule denied")
					continue
				}
				for peerIndex, peer := range rule.To {
					peerPrefix := fmt.Sprintf("%s to[%d]", prefix, peerIndex)
					addrPods, all, peerUnsupported, err := resolvePeerAddressesWithPods(np, peer, snapshot, knownAddresses, opts.IncludeServiceClusterIPs)
					if err != nil {
						return policy, names, unsupportedOut, fmt.Errorf("%s: %w", peerPrefix, err)
					}
					if peerUnsupported != "" {
						unsupportedOut = append(unsupportedOut, peerPrefix+": "+peerUnsupported)
					}
					if all {
						unsupportedOut = append(unsupportedOut, peerPrefix+": empty peer combined with a port restriction is not representable (would require an all-address port allow); denied for this peer")
						continue
					}
					for addr, pod := range addrPods {
						for _, t := range tuples {
							portRules[fluxvm.PodPeerPortRule{Address: addr, Protocol: t.protocol, Port: t.port}] = struct{}{}
						}
						for _, r := range rangeTuples {
							key := rangeGroupKey{address: addr, protocol: r.protocol}
							ranges[key] = append(ranges[key], r)
						}
						for _, req := range namedPorts {
							if pod == nil {
								unsupportedOut = append(unsupportedOut, fmt.Sprintf("%s: named port %q cannot resolve against a non-Pod peer (ipBlock); denied for this peer", peerPrefix, req.name))
								continue
							}
							port, ok := resolveNamedPort(*pod, req.name, req.protocol)
							if !ok {
								unsupportedOut = append(unsupportedOut, fmt.Sprintf("%s: named port %q does not resolve on peer Pod %s/%s; denied for this peer", peerPrefix, req.name, pod.Metadata.Namespace, pod.Metadata.Name))
								continue
							}
							portRules[fluxvm.PodPeerPortRule{Address: addr, Protocol: req.protocol, Port: port}] = struct{}{}
						}
					}
				}
				continue
			}
			if len(rule.To) == 0 {
				allowAll = true
				continue
			}
			for peerIndex, peer := range rule.To {
				peerPrefix := fmt.Sprintf("%s to[%d]", prefix, peerIndex)
				all, cidr, unsupported, err := resolvePeer(np, peer, snapshot, knownAddresses, opts.IncludeServiceClusterIPs, allowed)
				if err != nil {
					return policy, names, unsupportedOut, fmt.Errorf("%s: %w", peerPrefix, err)
				}
				if unsupported != "" {
					unsupportedOut = append(unsupportedOut, peerPrefix+": "+unsupported)
				}
				if cidr != nil {
					policy.AllowCidrs = append(policy.AllowCidrs, *cidr)
				}
				if all {
					allowAll = true
				}
			}
		}
	}

	if allowAll {
		policy.DefaultDeny = false
		policy.AllowAddresses = nil
		policy.AllowPortRules = nil
		policy.AllowCidrs = nil
		policy.PortRanges = nil
		return policy, names, unsupportedOut, nil
	}

	policy.AllowAddresses = sortedKeys(allowed)
	if len(policy.AllowAddresses) > opts.MaxAddresses {
		return policy, names, unsupportedOut, fmt.Errorf("compiled allow-address set has %d entries, exceeds configured maximum %d", len(policy.AllowAddresses), opts.MaxAddresses)
	}
	for rule := range portRules {
		if _, ok := allowed[rule.Address]; ok {
			delete(portRules, rule)
		}
	}
	policy.AllowPortRules = sortedPortRules(portRules)
	if len(policy.AllowPortRules) > opts.MaxAddresses {
		return policy, names, unsupportedOut, fmt.Errorf("compiled allow-port-rule set has %d entries, exceeds configured maximum %d", len(policy.AllowPortRules), opts.MaxAddresses)
	}
	rangesOut, rangeUnsupported := finalizePortRanges(ranges, allowed)
	unsupportedOut = append(unsupportedOut, rangeUnsupported...)
	policy.PortRanges = rangesOut
	return policy, names, unsupportedOut, nil
}

// compileIngress mirrors compileEgress, using `from` peers instead of `to`
// and target's own container spec (not the peer's) for named-port
// resolution -- see this file's package doc / docs/secure-containers-set13.md
// for why the two directions resolve named ports differently.
func compileIngress(
	target kube.Pod,
	selected []kube.NetworkPolicy,
	snapshot Snapshot,
	knownAddresses []netip.Addr,
	opts Options,
) (fluxvm.PodIngressPolicy, []string, []string, error) {
	policy := fluxvm.PodIngressPolicy{DefaultDeny: true, AuditMode: opts.GlobalAudit}
	var names, unsupportedOut []string
	allowed := map[string]struct{}{}
	portRules := map[fluxvm.PodPeerPortRule]struct{}{}
	ranges := map[rangeGroupKey][]portRangeTuple{}
	allowAll := false

	for _, np := range selected {
		names = append(names, np.Metadata.Namespace+"/"+np.Metadata.Name)
		for ruleIndex, rule := range np.Spec.Ingress {
			prefix := fmt.Sprintf("%s/%s ingress[%d]", np.Metadata.Namespace, np.Metadata.Name, ruleIndex)
			if len(rule.Ports) > 0 {
				tuples, rangeTuples, namedPorts, entryUnsupported := compilePortEntries(prefix, rule.Ports)
				unsupportedOut = append(unsupportedOut, entryUnsupported...)
				// Unlike egress, a named port here resolves once against
				// `target` itself (the Pod the policy protects), not per
				// peer -- fold any that resolve into `tuples` up front.
				for _, req := range namedPorts {
					port, ok := resolveNamedPort(target, req.name, req.protocol)
					if !ok {
						unsupportedOut = append(unsupportedOut, fmt.Sprintf("%s: named port %q does not resolve on Pod %s/%s; that port entry is denied", prefix, req.name, target.Metadata.Namespace, target.Metadata.Name))
						continue
					}
					tuples = append(tuples, portTuple{protocol: req.protocol, port: port})
				}
				if len(tuples) == 0 && len(rangeTuples) == 0 {
					continue
				}
				if len(rule.From) == 0 {
					unsupportedOut = append(unsupportedOut, prefix+": port-restricted rule has no `from` peers; an all-address port allow is not representable, rule denied")
					continue
				}
				for peerIndex, peer := range rule.From {
					peerPrefix := fmt.Sprintf("%s from[%d]", prefix, peerIndex)
					addrs, all, peerUnsupported, err := resolvePeerAddresses(np, peer, snapshot, knownAddresses, opts.IncludeServiceClusterIPs)
					if err != nil {
						return policy, names, unsupportedOut, fmt.Errorf("%s: %w", peerPrefix, err)
					}
					if peerUnsupported != "" {
						unsupportedOut = append(unsupportedOut, peerPrefix+": "+peerUnsupported)
					}
					if all {
						unsupportedOut = append(unsupportedOut, peerPrefix+": empty peer combined with a port restriction is not representable (would require an all-address port allow); denied for this peer")
						continue
					}
					for addr := range addrs {
						for _, t := range tuples {
							portRules[fluxvm.PodPeerPortRule{Address: addr, Protocol: t.protocol, Port: t.port}] = struct{}{}
						}
						for _, r := range rangeTuples {
							key := rangeGroupKey{address: addr, protocol: r.protocol}
							ranges[key] = append(ranges[key], r)
						}
					}
				}
				continue
			}
			if len(rule.From) == 0 {
				allowAll = true
				continue
			}
			for peerIndex, peer := range rule.From {
				peerPrefix := fmt.Sprintf("%s from[%d]", prefix, peerIndex)
				all, cidr, unsupported, err := resolvePeer(np, peer, snapshot, knownAddresses, opts.IncludeServiceClusterIPs, allowed)
				if err != nil {
					return policy, names, unsupportedOut, fmt.Errorf("%s: %w", peerPrefix, err)
				}
				if unsupported != "" {
					unsupportedOut = append(unsupportedOut, peerPrefix+": "+unsupported)
				}
				if cidr != nil {
					policy.AllowCidrs = append(policy.AllowCidrs, *cidr)
				}
				if all {
					allowAll = true
				}
			}
		}
	}

	if allowAll {
		policy.DefaultDeny = false
		policy.AllowAddresses = nil
		policy.AllowPortRules = nil
		policy.AllowCidrs = nil
		policy.PortRanges = nil
		return policy, names, unsupportedOut, nil
	}

	policy.AllowAddresses = sortedKeys(allowed)
	if len(policy.AllowAddresses) > opts.MaxAddresses {
		return policy, names, unsupportedOut, fmt.Errorf("compiled ingress allow-address set has %d entries, exceeds configured maximum %d", len(policy.AllowAddresses), opts.MaxAddresses)
	}
	for rule := range portRules {
		if _, ok := allowed[rule.Address]; ok {
			delete(portRules, rule)
		}
	}
	policy.AllowPortRules = sortedPortRules(portRules)
	if len(policy.AllowPortRules) > opts.MaxAddresses {
		return policy, names, unsupportedOut, fmt.Errorf("compiled ingress allow-port-rule set has %d entries, exceeds configured maximum %d", len(policy.AllowPortRules), opts.MaxAddresses)
	}
	rangesOut, rangeUnsupported := finalizePortRanges(ranges, allowed)
	unsupportedOut = append(unsupportedOut, rangeUnsupported...)
	policy.PortRanges = rangesOut
	return policy, names, unsupportedOut, nil
}

type portTuple struct {
	protocol fluxvm.PodPolicyProtocol
	port     uint16
}

type portRangeTuple struct {
	protocol   fluxvm.PodPolicyProtocol
	start, end uint16
}

type rangeGroupKey struct {
	address  string
	protocol fluxvm.PodPolicyProtocol
}

type namedPortRequest struct {
	name     string
	protocol fluxvm.PodPolicyProtocol
}

// maxPortRangesPerPeer mirrors bpf/fluxvm_pod_policy.bpf.h's
// FLUXVM_MAX_PORT_RANGES -- the fixed-size kernel array a peer+protocol's
// ranges are written into. Enforced here, not just defensively in
// crates/fluxvm-network/src/ebpf.rs, because *this* is the layer that
// decides policy (deny the excess) rather than just bounding a write.
const maxPortRangesPerPeer = 8

// compilePortEntries splits a NetworkPolicyPort list into what Set 13 can
// represent today: exact numeric protocol+port tuples, protocol+range
// tuples (schema v8, endPort), and named-port requests that the caller must
// resolve itself (egress resolves per selected peer Pod; ingress resolves
// once against the policy's own target Pod -- see compileEgress/
// compileIngress). Every entry it cannot represent at all (an
// unrecognized protocol) is reported via `unsupported`, prefixed with
// `prefix`, instead of silently dropped or widened.
func compilePortEntries(prefix string, ports []kube.NetworkPolicyPort) (tuples []portTuple, ranges []portRangeTuple, named []namedPortRequest, unsupported []string) {
	for _, p := range ports {
		proto, ok := normalizePortProtocol(p.Protocol)
		if !ok {
			unsupported = append(unsupported, fmt.Sprintf("%s: protocol %q is not representable; that port entry is denied", prefix, p.Protocol))
			continue
		}
		if p.EndPort != nil {
			start, ok := numericPort(p.Port)
			end := *p.EndPort
			if !ok || end < int32(start) || end > 65535 {
				unsupported = append(unsupported, prefix+": endPort range is malformed (port must be numeric and <= endPort); that port entry is denied")
				continue
			}
			ranges = append(ranges, portRangeTuple{protocol: proto, start: start, end: uint16(end)})
			continue
		}
		if name, ok := p.Port.(string); ok {
			named = append(named, namedPortRequest{name: name, protocol: proto})
			continue
		}
		port, ok := numericPort(p.Port)
		if !ok {
			unsupported = append(unsupported, fmt.Sprintf("%s: port value %v is neither a numeric port nor a name; that port entry is denied", prefix, p.Port))
			continue
		}
		tuples = append(tuples, portTuple{protocol: proto, port: port})
	}
	return tuples, ranges, named, unsupported
}

// finalizePortRanges caps each (address, protocol) group at
// maxPortRangesPerPeer, matching bpf/fluxvm_pod_policy.bpf.h's fixed-size
// fluxvm_port_range_set array, and drops any group whose address already
// has an unrestricted allow (redundant, same reasoning as the AllowAddresses
// vs. AllowPortRules dedup already applied to portRules by the caller).
// Excess ranges beyond the cap are reported unsupported (denied), never
// silently dropped without a trace.
func finalizePortRanges(groups map[rangeGroupKey][]portRangeTuple, allowedAddresses map[string]struct{}) ([]fluxvm.PodPeerPortRange, []string) {
	var out []fluxvm.PodPeerPortRange
	var unsupported []string
	keys := make([]rangeGroupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].address != keys[j].address {
			return keys[i].address < keys[j].address
		}
		return keys[i].protocol < keys[j].protocol
	})
	for _, key := range keys {
		if _, ok := allowedAddresses[key.address]; ok {
			continue
		}
		tuples := dedupeRangeTuples(groups[key])
		if len(tuples) > maxPortRangesPerPeer {
			unsupported = append(unsupported, fmt.Sprintf(
				"peer %s protocol %s: %d port ranges exceed the maximum of %d representable per peer+protocol; the excess is denied",
				key.address, key.protocol, len(tuples), maxPortRangesPerPeer,
			))
			tuples = tuples[:maxPortRangesPerPeer]
		}
		for _, t := range tuples {
			out = append(out, fluxvm.PodPeerPortRange{Address: key.address, Protocol: t.protocol, Start: t.start, End: t.end})
		}
	}
	return out, unsupported
}

func dedupeRangeTuples(tuples []portRangeTuple) []portRangeTuple {
	seen := map[portRangeTuple]struct{}{}
	var out []portRangeTuple
	for _, t := range tuples {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].start != out[j].start {
			return out[i].start < out[j].start
		}
		return out[i].end < out[j].end
	})
	return out
}

// resolveNamedPort resolves `name` against `pod`'s own declared container
// ports, matching `protocol` the same way Kubernetes does (a ContainerPort
// with no explicit Protocol defaults to TCP, same as NetworkPolicyPort
// itself -- see normalizePortProtocol).
func resolveNamedPort(pod kube.Pod, name string, protocol fluxvm.PodPolicyProtocol) (uint16, bool) {
	for _, c := range pod.Spec.Containers {
		for _, p := range c.Ports {
			if p.Name != name {
				continue
			}
			cproto, ok := normalizePortProtocol(p.Protocol)
			if !ok || cproto != protocol {
				continue
			}
			if p.ContainerPort < 0 || p.ContainerPort > 65535 {
				continue
			}
			return uint16(p.ContainerPort), true
		}
	}
	return 0, false
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

func selectedIngressPolicies(target kube.Pod, policies []kube.NetworkPolicy) []kube.NetworkPolicy {
	var selected []kube.NetworkPolicy
	for _, np := range policies {
		if np.Metadata.Namespace != target.Metadata.Namespace {
			continue
		}
		if !kube.MatchesSelector(target.Metadata.Labels, np.Spec.PodSelector) {
			continue
		}
		if !isolatesIngress(np.Spec) {
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

func isolatesIngress(spec kube.NetworkPolicySpec) bool {
	if len(spec.PolicyTypes) == 0 {
		// Unlike Egress, Kubernetes defaults policyTypes to *include*
		// Ingress unconditionally -- a NetworkPolicy with only egress rules
		// and no explicit policyTypes still isolates ingress (with zero
		// ingress rules, meaning deny-all-ingress).
		return true
	}
	for _, policyType := range spec.PolicyTypes {
		if policyType == "Ingress" {
			return true
		}
	}
	return false
}

// resolvePeer resolves a peer directly into the caller's unrestricted allow
// set, for the plain (non-port-restricted) rule branches in compileEgress/
// compileIngress. Unlike resolvePeerAddresses (used by the port-restricted
// branches, which cannot represent a CIDR peer at all -- see
// bpf/fluxvm_pod_policy.bpf.h's port maps, keyed by exact address only),
// this path can emit a real CIDR entry for a broad ipBlock, so it handles
// ipBlock directly rather than delegating to resolvePeerAddresses.
func resolvePeer(
	np kube.NetworkPolicy,
	peer kube.NetworkPolicyPeer,
	snapshot Snapshot,
	knownAddresses []netip.Addr,
	includeServiceVIPs bool,
	allowed map[string]struct{},
) (allowAll bool, cidr *fluxvm.PodPeerCidr, unsupported string, err error) {
	selectorCount := 0
	if peer.PodSelector != nil {
		selectorCount++
	}
	if peer.NamespaceSelector != nil {
		selectorCount++
	}
	if peer.IPBlock != nil {
		if selectorCount != 0 {
			return false, nil, "", fmt.Errorf("invalid NetworkPolicyPeer mixes ipBlock with selectors")
		}
		return resolveIPBlock(*peer.IPBlock, knownAddresses, allowed, true)
	}
	addrs, allowAll, unsupported, err := resolvePeerAddresses(np, peer, snapshot, knownAddresses, includeServiceVIPs)
	if err != nil {
		return false, nil, "", err
	}
	for addr := range addrs {
		allowed[addr] = struct{}{}
	}
	return allowAll, nil, unsupported, nil
}

// resolvePeerAddresses is the address-resolution core for the
// port-restricted branches (via resolvePeerAddressesWithPods for egress,
// directly for ingress) -- it returns the resolved addresses instead of
// writing into a shared allow set, since those branches need to pair each
// address with its rule's ports rather than allow it outright. A broad
// ipBlock here is always exact-address approximated (never a real CIDR
// entry, `preferCidr: false`): the port-scoped maps
// (fluxvm_pid4_port/6_port, fluxvm_pid4_port_range/6_port_range) have no
// CIDR dimension to pair a range or exact port against.
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
		allowAll, _, unsupported, err = resolveIPBlock(*peer.IPBlock, knownAddresses, addrs, false)
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

// resolvePeerAddressesWithPods mirrors resolvePeerAddresses but additionally
// tracks which live Pod (if any) contributed each resolved address --
// compileEgress's port-restricted branch needs this to resolve a named port
// against that specific peer Pod's own container spec (Kubernetes
// semantics: an egress rule's named port refers to that name on each
// individual destination container). An address with no single owning Pod
// (ipBlock-derived, or a Service VIP potentially fronting several Pods)
// maps to a nil pod -- a named port can never resolve against those.
func resolvePeerAddressesWithPods(
	np kube.NetworkPolicy,
	peer kube.NetworkPolicyPeer,
	snapshot Snapshot,
	knownAddresses []netip.Addr,
	includeServiceVIPs bool,
) (addrs map[string]*kube.Pod, allowAll bool, unsupported string, err error) {
	addrs = map[string]*kube.Pod{}
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
		plain := map[string]struct{}{}
		allowAll, _, unsupported, err = resolveIPBlock(*peer.IPBlock, knownAddresses, plain, false)
		for a := range plain {
			addrs[a] = nil
		}
		return addrs, allowAll, unsupported, err
	}
	if selectorCount == 0 {
		return addrs, true, "", nil
	}

	namespaces := selectedNamespaces(np.Metadata.Namespace, peer.NamespaceSelector, snapshot.Namespaces)
	selectedPods := map[string]struct{}{}
	for i := range snapshot.Pods {
		pod := snapshot.Pods[i]
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
			addrs[addr.String()] = &snapshot.Pods[i]
		}
	}

	if includeServiceVIPs {
		plain := map[string]struct{}{}
		includeConservativeServiceVIPs(snapshot, namespaces, selectedPods, plain)
		for a := range plain {
			if _, exists := addrs[a]; !exists {
				addrs[a] = nil
			}
		}
	}
	return addrs, false, "", nil
}

// resolveIPBlock resolves one ipBlock peer. `preferCidr` distinguishes the
// two call shapes above: `resolvePeer` (true) can emit a real schema-v8
// CIDR entry for a non-host, `except`-free prefix; the port-restricted
// paths (false) always fall back to exact-address approximation, since
// their target maps have no CIDR dimension. A host prefix (`/32`/`/128`)
// always resolves to a plain exact address either way -- it needs no CIDR
// map entry at all.
func resolveIPBlock(block kube.IPBlock, known []netip.Addr, allowed map[string]struct{}, preferCidr bool) (allowAll bool, cidr *fluxvm.PodPeerCidr, unsupported string, err error) {
	prefix, err := netip.ParsePrefix(block.CIDR)
	if err != nil {
		return false, nil, "", fmt.Errorf("invalid ipBlock CIDR %q: %w", block.CIDR, err)
	}
	prefix = prefix.Masked()
	var excepts []netip.Prefix
	for _, raw := range block.Except {
		ex, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil {
			return false, nil, "", fmt.Errorf("invalid ipBlock except CIDR %q: %w", raw, parseErr)
		}
		if ex.Addr().BitLen() != prefix.Addr().BitLen() || ex.Bits() < prefix.Bits() || !prefix.Contains(ex.Addr()) {
			return false, nil, "", fmt.Errorf("ipBlock except %q is outside %q", raw, block.CIDR)
		}
		excepts = append(excepts, ex.Masked())
	}
	isHostPrefix := (prefix.Addr().Is4() && prefix.Bits() == 32) || (prefix.Addr().Is6() && prefix.Bits() == 128)
	if isHostPrefix {
		if !excluded(prefix.Addr(), excepts) {
			allowed[prefix.Addr().String()] = struct{}{}
		}
		return false, nil, "", nil
	}

	if preferCidr && len(excepts) == 0 {
		// Schema v8: a real CIDR entry (fluxvm_pid4_cidr/6_cidr), not an
		// approximation to currently-known addresses.
		return false, &fluxvm.PodPeerCidr{Addr: prefix.Addr().String(), PrefixLen: uint8(prefix.Bits())}, "", nil
	}

	// Either a port-restricted context (no CIDR dimension available at
	// all) or a CIDR with `except` (Kubernetes `except` subtracts from a
	// CIDR, which an LPM trie entry can't natively express). Resolve only
	// currently-known Pod/Service addresses inside the block. This may deny
	// external addresses Kubernetes would allow, but never widens access.
	for _, addr := range known {
		if prefix.Contains(addr) && !excluded(addr, excepts) {
			allowed[addr.String()] = struct{}{}
		}
	}
	msg := "broad ipBlock is exact-address approximated to currently-known cluster IPs; unknown external addresses remain denied"
	if preferCidr && len(excepts) > 0 {
		msg = "broad ipBlock with `except` is exact-address approximated to currently-known cluster IPs (a CIDR entry cannot represent `except`); unknown external addresses remain denied"
	}
	return false, nil, msg, nil
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
