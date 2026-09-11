// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/fluxvm"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
)

// 64, not the kit's original 512: bpf/fluxvm_pod_policy.bpf.h's
// FLUXVM_MAX_POD_RULE is capped at 64 because a 512-iteration non-unrolled
// scan in fluxvm_pod_policy_rich_verdict blows the kernel verifier's
// BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192 jumps) when present in both the v4 and
// v6 paths of one program.
const defaultMaxRules = 64

type Snapshot struct {
	Pods            []kube.Pod
	Namespaces      []kube.Namespace
	Services        []kube.Service
	EndpointSlices  []kube.EndpointSlice // FLUXVM_SECURE_CONTAINERS_SET18
	NetworkPolicies []kube.NetworkPolicy
}

type Options struct {
	// MaxAddresses is retained for Set 13 flag/API compatibility. Set 14 emits
	// CIDR tuple rules and uses MaxRules as the actual kernel-bound limit.
	MaxAddresses             int
	MaxRules                 int
	IncludeServiceClusterIPs bool
	GlobalAudit              bool
}

type Result struct {
	Managed          bool
	Policy           fluxvm.PodNetworkPolicy
	SelectedPolicies []string
	Unsupported      []string
}

type peerResolution struct {
	CIDRs        []string
	Pods         []kube.Pod
	SelectorPeer bool
}

type portSpec struct {
	Protocol string
	Start    uint16
	End      uint16
	Name     string
}

func Compile(target kube.Pod, snapshot Snapshot, opts Options) (Result, error) {
	if opts.MaxRules <= 0 {
		opts.MaxRules = defaultMaxRules
	}

	selected := selectedPolicies(target, snapshot.NetworkPolicies)
	if len(selected) == 0 {
		return Result{Managed: false}, nil
	}

	result := Result{
		Managed: true,
		Policy:  fluxvm.PodNetworkPolicy{SchemaVersion: 2, AuditMode: opts.GlobalAudit},
	}
	for _, np := range selected {
		result.SelectedPolicies = append(result.SelectedPolicies, np.Metadata.Namespace+"/"+np.Metadata.Name)
		ingress, egress := policyDirections(np.Spec)
		result.Policy.IngressIsolated = result.Policy.IngressIsolated || ingress
		result.Policy.EgressIsolated = result.Policy.EgressIsolated || egress
	}
	// Rollout safety: an older Set 6S API ignores Set 14 fields. Setting the
	// legacy bit whenever either direction is isolated makes that downgrade
	// over-deny rather than silently bypass an ingress-only policy.
	result.Policy.DefaultDeny = result.Policy.IngressIsolated || result.Policy.EgressIsolated

	var rules []fluxvm.PodPolicyRule
	for _, np := range selected {
		ingress, egress := policyDirections(np.Spec)
		if ingress {
			for i, rule := range np.Spec.Ingress {
				prefix := fmt.Sprintf("%s/%s ingress[%d]", np.Metadata.Namespace, np.Metadata.Name, i)
				compiled, unsupported, err := compileRule(target, snapshot, np, "ingress", rule.From, rule.Ports, opts.IncludeServiceClusterIPs)
				if err != nil {
					return safeDeny(result), fmt.Errorf("%s: %w", prefix, err)
				}
				for _, msg := range unsupported {
					result.Unsupported = append(result.Unsupported, prefix+": "+msg)
				}
				rules = append(rules, compiled...)
			}
		}
		if egress {
			for i, rule := range np.Spec.Egress {
				prefix := fmt.Sprintf("%s/%s egress[%d]", np.Metadata.Namespace, np.Metadata.Name, i)
				compiled, unsupported, err := compileRule(target, snapshot, np, "egress", rule.To, rule.Ports, opts.IncludeServiceClusterIPs)
				if err != nil {
					return safeDeny(result), fmt.Errorf("%s: %w", prefix, err)
				}
				for _, msg := range unsupported {
					result.Unsupported = append(result.Unsupported, prefix+": "+msg)
				}
				rules = append(rules, compiled...)
			}
		}
	}

	result.Policy.Rules = canonicalRules(rules)
	if len(result.Policy.Rules) > opts.MaxRules {
		return safeDeny(result), fmt.Errorf("compiled Pod policy has %d tuple rules, exceeds configured maximum %d", len(result.Policy.Rules), opts.MaxRules)
	}
	return result, nil
}

func safeDeny(result Result) Result {
	result.Managed = true
	result.Policy = fluxvm.PodNetworkPolicy{
		SchemaVersion:   2,
		DefaultDeny:     true,
		AuditMode:       result.Policy.AuditMode,
		IngressIsolated: true,
		EgressIsolated:  true,
	}
	return result
}

func selectedPolicies(target kube.Pod, policies []kube.NetworkPolicy) []kube.NetworkPolicy {
	var selected []kube.NetworkPolicy
	for _, np := range policies {
		if np.Metadata.Namespace != target.Metadata.Namespace {
			continue
		}
		if !kube.MatchesSelector(target.Metadata.Labels, np.Spec.PodSelector) {
			continue
		}
		ingress, egress := policyDirections(np.Spec)
		if !ingress && !egress {
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

func policyDirections(spec kube.NetworkPolicySpec) (ingress, egress bool) {
	if len(spec.PolicyTypes) == 0 {
		// networking.k8s.io/v1 defaulting: Ingress is always implied; Egress is
		// also implied when at least one egress rule is present.
		return true, len(spec.Egress) > 0
	}
	for _, typ := range spec.PolicyTypes {
		switch strings.ToLower(typ) {
		case "ingress":
			ingress = true
		case "egress":
			egress = true
		}
	}
	return ingress, egress
}

func compileRule(target kube.Pod, snapshot Snapshot, np kube.NetworkPolicy, direction string, peers []kube.NetworkPolicyPeer, rawPorts []kube.NetworkPolicyPort, includeServiceVIPs bool) ([]fluxvm.PodPolicyRule, []string, error) {
	ports, unsupported, err := parsePorts(rawPorts)
	if err != nil {
		return nil, nil, err
	}

	// No `ports` entries means all protocols and ports.
	if len(rawPorts) == 0 {
		ports = []portSpec{{}}
	}

	// A named egress port is destination-pod-relative. With no peer selector
	// there is no finite destination Pod set from which to resolve the name.
	if direction == "egress" && len(peers) == 0 && containsNamed(ports) {
		return nil, append(unsupported, "named egress port with unrestricted destinations cannot be resolved safely; rule denied"), nil
	}

	var peerSets []peerResolution
	if len(peers) == 0 {
		peerSets = []peerResolution{{CIDRs: []string{"0.0.0.0/0", "::/0"}}}
	} else {
		for i, peer := range peers {
			// FLUXVM_SECURE_CONTAINERS_SET18: ClusterIPs are destination VIPs.
			// They are meaningful only for egress peers, never as ingress source identities.
			resolved, msg, resolveErr := resolvePeer(np, peer, snapshot, includeServiceVIPs && direction == "egress")
			if resolveErr != nil {
				return nil, nil, fmt.Errorf("peer[%d]: %w", i, resolveErr)
			}
			if msg != "" {
				unsupported = append(unsupported, fmt.Sprintf("peer[%d]: %s", i, msg))
			}
			peerSets = append(peerSets, resolved)
		}
	}

	var rules []fluxvm.PodPolicyRule
	for _, peerset := range peerSets {
		for _, ps := range ports {
			if ps.Name == "" {
				for _, cidr := range peerset.CIDRs {
					rules = append(rules, makeRule(direction, cidr, ps))
				}
				continue
			}

			if direction == "ingress" {
				resolvedPorts := kube.NamedContainerPorts(target, ps.Name, ps.Protocol)
				if len(resolvedPorts) == 0 {
					unsupported = append(unsupported, fmt.Sprintf("named ingress port %q/%s is not declared by target Pod; rule denied", ps.Name, ps.Protocol))
					continue
				}
				for _, port := range resolvedPorts {
					numeric := portSpec{Protocol: ps.Protocol, Start: port, End: port}
					for _, cidr := range peerset.CIDRs {
						rules = append(rules, makeRule(direction, cidr, numeric))
					}
				}
				continue
			}

			// Named egress ports must bind the resolved destination Pod's own
			// address to that Pod's declared named port. Do not combine a port
			// learned from one Pod with a different selected Pod's address.
			if !peerset.SelectorPeer {
				unsupported = append(unsupported, fmt.Sprintf("named egress port %q/%s requires podSelector-based peers; rule denied for non-selector peer", ps.Name, ps.Protocol))
				continue
			}
			for _, dst := range peerset.Pods {
				resolvedPorts := kube.NamedContainerPorts(dst, ps.Name, ps.Protocol)
				if len(resolvedPorts) == 0 {
					continue
				}
				for _, rawIP := range kube.PodAddresses(dst) {
					cidr, ok := hostCIDR(rawIP)
					if !ok {
						continue
					}
					for _, port := range resolvedPorts {
						rules = append(rules, makeRule(direction, cidr, portSpec{Protocol: ps.Protocol, Start: port, End: port}))
					}
				}
			}
		}
	}
	return rules, unsupported, nil
}

func makeRule(direction, cidr string, ps portSpec) fluxvm.PodPolicyRule {
	return fluxvm.PodPolicyRule{Direction: direction, CIDR: cidr, Protocol: ps.Protocol, PortStart: ps.Start, PortEnd: ps.End}
}

func parsePorts(raw []kube.NetworkPolicyPort) ([]portSpec, []string, error) {
	var out []portSpec
	var unsupported []string
	for i, p := range raw {
		proto := strings.ToUpper(strings.TrimSpace(p.Protocol))
		if proto == "" {
			proto = "TCP"
		}
		if proto != "TCP" && proto != "UDP" && proto != "SCTP" {
			unsupported = append(unsupported, fmt.Sprintf("ports[%d]: unsupported protocol %q; entry denied", i, p.Protocol))
			continue
		}
		if p.Port == nil {
			if p.EndPort != nil {
				return nil, nil, fmt.Errorf("ports[%d]: endPort requires a numeric port", i)
			}
			out = append(out, portSpec{Protocol: proto})
			continue
		}
		switch v := p.Port.(type) {
		case string:
			name := strings.TrimSpace(v)
			if name == "" {
				return nil, nil, fmt.Errorf("ports[%d]: empty named port", i)
			}
			if p.EndPort != nil {
				return nil, nil, fmt.Errorf("ports[%d]: endPort is invalid with named port %q", i, name)
			}
			out = append(out, portSpec{Protocol: proto, Name: name})
		default:
			port, err := numericPort(v)
			if err != nil {
				return nil, nil, fmt.Errorf("ports[%d]: %w", i, err)
			}
			end := port
			if p.EndPort != nil {
				if *p.EndPort < int32(port) || *p.EndPort > 65535 {
					return nil, nil, fmt.Errorf("ports[%d]: invalid endPort %d for start %d", i, *p.EndPort, port)
				}
				end = uint16(*p.EndPort)
			}
			out = append(out, portSpec{Protocol: proto, Start: port, End: end})
		}
	}
	return out, unsupported, nil
}

func numericPort(v any) (uint16, error) {
	var n int64
	switch x := v.(type) {
	case float64:
		if x != float64(int64(x)) {
			return 0, fmt.Errorf("port %v is not an integer", x)
		}
		n = int64(x)
	case float32:
		if x != float32(int64(x)) {
			return 0, fmt.Errorf("port %v is not an integer", x)
		}
		n = int64(x)
	case int:
		n = int64(x)
	case int32:
		n = int64(x)
	case int64:
		n = x
	case json.Number:
		parsed, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid port %q", x)
		}
		n = parsed
	default:
		return 0, fmt.Errorf("unsupported numeric port representation %T", v)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d is outside 1..65535", n)
	}
	return uint16(n), nil
}

func containsNamed(ports []portSpec) bool {
	for _, p := range ports {
		if p.Name != "" {
			return true
		}
	}
	return false
}

func resolvePeer(np kube.NetworkPolicy, peer kube.NetworkPolicyPeer, snapshot Snapshot, includeServiceVIPs bool) (peerResolution, string, error) {
	selectors := 0
	if peer.PodSelector != nil {
		selectors++
	}
	if peer.NamespaceSelector != nil {
		selectors++
	}
	if peer.IPBlock != nil {
		if selectors != 0 {
			return peerResolution{}, "", fmt.Errorf("invalid NetworkPolicyPeer mixes ipBlock with selectors")
		}
		cidrs, err := resolveIPBlock(*peer.IPBlock)
		return peerResolution{CIDRs: cidrs}, "", err
	}
	if selectors == 0 {
		return peerResolution{CIDRs: []string{"0.0.0.0/0", "::/0"}}, "", nil
	}

	namespaces := selectedNamespaces(np.Metadata.Namespace, peer.NamespaceSelector, snapshot.Namespaces)
	selectedUIDs := map[string]struct{}{}
	var pods []kube.Pod
	cidrSet := map[string]struct{}{}
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
		selectedUIDs[pod.Metadata.UID] = struct{}{}
		pods = append(pods, pod)
		for _, raw := range kube.PodAddresses(pod) {
			if cidr, ok := hostCIDR(raw); ok {
				cidrSet[cidr] = struct{}{}
			}
		}
	}
	if includeServiceVIPs {
		includeEndpointSliceServiceVIPs(snapshot, namespaces, selectedUIDs, cidrSet)
	}
	return peerResolution{CIDRs: sortedStrings(cidrSet), Pods: pods, SelectorPeer: true}, "", nil
}

func resolveIPBlock(block kube.IPBlock) ([]string, error) {
	base, err := netip.ParsePrefix(block.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid ipBlock CIDR %q: %w", block.CIDR, err)
	}
	base = base.Masked()
	prefixes := []netip.Prefix{base}
	for _, raw := range block.Except {
		ex, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid ipBlock except CIDR %q: %w", raw, parseErr)
		}
		ex = ex.Masked()
		if ex.Addr().BitLen() != base.Addr().BitLen() || ex.Bits() < base.Bits() || !base.Contains(ex.Addr()) {
			return nil, fmt.Errorf("ipBlock except %q is outside %q", raw, block.CIDR)
		}
		var next []netip.Prefix
		for _, current := range prefixes {
			next = append(next, subtractPrefix(current, ex)...)
		}
		prefixes = next
	}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	sort.Strings(out)
	return out, nil
}

func subtractPrefix(base, remove netip.Prefix) []netip.Prefix {
	base = base.Masked()
	remove = remove.Masked()
	if base.Addr().BitLen() != remove.Addr().BitLen() || !base.Contains(remove.Addr()) {
		return []netip.Prefix{base}
	}
	if remove.Bits() <= base.Bits() {
		return nil
	}
	left, right := splitPrefix(base)
	var out []netip.Prefix
	out = append(out, subtractPrefix(left, remove)...)
	out = append(out, subtractPrefix(right, remove)...)
	return out
}

func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	p = p.Masked()
	bit := p.Bits()
	nextBits := bit + 1
	left := netip.PrefixFrom(p.Addr(), nextBits).Masked()
	if p.Addr().Is4() {
		a := p.Addr().As4()
		byteIndex := bit / 8
		bitInByte := 7 - (bit % 8)
		a[byteIndex] |= 1 << bitInByte
		return left, netip.PrefixFrom(netip.AddrFrom4(a), nextBits).Masked()
	}
	a := p.Addr().As16()
	byteIndex := bit / 8
	bitInByte := 7 - (bit % 8)
	a[byteIndex] |= 1 << bitInByte
	return left, netip.PrefixFrom(netip.AddrFrom16(a), nextBits).Masked()
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

// FLUXVM_SECURE_CONTAINERS_SET18: Include a Service VIP only when the
// EndpointSlice routing truth proves that every endpoint that may receive
// new Service traffic for that address family is already selected by the
// NetworkPolicy peer. This replaces Set 14's selector-only approximation.
//
// The proof is intentionally fail closed:
//   - selectorless Services are not inferred from a podSelector peer;
//   - a Service with no usable EndpointSlice backend gets no VIP rule;
//   - an endpoint without a Pod targetRef, an unknown Pod UID, selector
//     drift, or an address that does not belong to that Pod invalidates only
//     that address family of the Service;
//   - Ready==nil is routable per discovery/v1 semantics;
//   - serving+terminating is also treated as potentially routable because
//     Service proxies may use draining endpoints when no normal endpoint is
//     available.
func includeEndpointSliceServiceVIPs(snapshot Snapshot, namespaces, peerPods map[string]struct{}, cidrs map[string]struct{}) {
	podsByUID := make(map[string]kube.Pod, len(snapshot.Pods))
	podAddrByUID := make(map[string]map[string]struct{}, len(snapshot.Pods))
	for _, pod := range snapshot.Pods {
		if pod.Metadata.UID == "" {
			continue
		}
		podsByUID[pod.Metadata.UID] = pod
		addrs := map[string]struct{}{}
		for _, raw := range kube.PodAddresses(pod) {
			if addr, err := netip.ParseAddr(raw); err == nil {
				addrs[addr.String()] = struct{}{}
			}
		}
		podAddrByUID[pod.Metadata.UID] = addrs
	}

	for _, svc := range snapshot.Services {
		if _, ok := namespaces[svc.Metadata.Namespace]; !ok || len(svc.Spec.Selector) == 0 {
			continue
		}

		slices := endpointSlicesForService(snapshot.EndpointSlices, svc)
		if len(slices) == 0 {
			continue
		}
		for _, rawVIP := range serviceIPs(svc) {
			vip, err := netip.ParseAddr(rawVIP)
			if err != nil {
				continue
			}
			family := "IPv6"
			if vip.Is4() {
				family = "IPv4"
			}
			if serviceFamilyEndpointSafe(svc, slices, family, peerPods, podsByUID, podAddrByUID) {
				if cidr, ok := hostCIDR(vip.String()); ok {
					cidrs[cidr] = struct{}{}
				}
			}
		}
	}
}

func endpointSlicesForService(all []kube.EndpointSlice, svc kube.Service) []kube.EndpointSlice {
	const serviceNameLabel = "kubernetes.io/service-name"
	var out []kube.EndpointSlice
	for _, slice := range all {
		if slice.Metadata.Namespace != svc.Metadata.Namespace || slice.Metadata.Labels[serviceNameLabel] != svc.Metadata.Name {
			continue
		}
		out = append(out, slice)
	}
	return out
}

func serviceFamilyEndpointSafe(
	svc kube.Service,
	slices []kube.EndpointSlice,
	family string,
	peerPods map[string]struct{},
	podsByUID map[string]kube.Pod,
	podAddrByUID map[string]map[string]struct{},
) bool {
	usable := 0
	for _, slice := range slices {
		if !strings.EqualFold(slice.AddressType, family) {
			continue
		}
		for _, ep := range slice.Endpoints {
			if !endpointMayReceiveServiceTraffic(ep) {
				continue
			}
			usable++
			if !endpointBackedBySelectedPod(svc, ep, peerPods, podsByUID, podAddrByUID) {
				return false
			}
		}
	}
	return usable > 0
}

func endpointMayReceiveServiceTraffic(ep kube.Endpoint) bool {
	// discovery.k8s.io/v1: nil Ready and Serving mean true; nil Terminating
	// means false. Ready captures the normal Service path. serving+terminating
	// captures the draining fallback some Service proxies may use.
	ready := ep.Conditions.Ready == nil || *ep.Conditions.Ready
	serving := ep.Conditions.Serving == nil || *ep.Conditions.Serving
	terminating := ep.Conditions.Terminating != nil && *ep.Conditions.Terminating
	return ready || (serving && terminating)
}

func endpointBackedBySelectedPod(
	svc kube.Service,
	ep kube.Endpoint,
	peerPods map[string]struct{},
	podsByUID map[string]kube.Pod,
	podAddrByUID map[string]map[string]struct{},
) bool {
	ref := ep.TargetRef
	if ref == nil || !strings.EqualFold(ref.Kind, "Pod") || ref.UID == "" {
		return false
	}
	if ref.Namespace != "" && ref.Namespace != svc.Metadata.Namespace {
		return false
	}
	if _, ok := peerPods[ref.UID]; !ok {
		return false
	}
	pod, ok := podsByUID[ref.UID]
	if !ok || pod.Metadata.Namespace != svc.Metadata.Namespace || terminalPod(pod) || !matchesExactSelector(pod.Metadata.Labels, svc.Spec.Selector) {
		return false
	}
	known := podAddrByUID[ref.UID]
	if len(ep.Addresses) == 0 || len(known) == 0 {
		return false
	}
	for _, raw := range ep.Addresses {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return false
		}
		if _, ok := known[addr.String()]; !ok {
			return false
		}
	}
	return true
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

func hostCIDR(raw string) (string, bool) {
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	if a.Is4() {
		return a.String() + "/32", true
	}
	return a.String() + "/128", true
}

func matchesExactSelector(labels, selector map[string]string) bool {
	for key, want := range selector {
		if labels[key] != want {
			return false
		}
	}
	return true
}
func terminalPod(pod kube.Pod) bool {
	return pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed"
}

func canonicalRules(in []fluxvm.PodPolicyRule) []fluxvm.PodPolicyRule {
	seen := map[fluxvm.PodPolicyRule]struct{}{}
	out := make([]fluxvm.PodPolicyRule, 0, len(in))
	for _, r := range in {
		if r.CIDR == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.CIDR != b.CIDR {
			return a.CIDR < b.CIDR
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.PortStart != b.PortStart {
			return a.PortStart < b.PortStart
		}
		return a.PortEnd < b.PortEnd
	})
	return out
}
func sortedStrings(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
