// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/fluxvm"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
)

func pod(ns, name, uid, node, ip string, labels map[string]string) kube.Pod {
	return kube.Pod{
		Metadata: kube.ObjectMeta{Name: name, Namespace: ns, UID: uid, Labels: labels, Annotations: map[string]string{}},
		Spec:     kube.PodSpec{NodeName: node},
		Status:   kube.PodStatus{Phase: "Running", PodIP: ip, PodIPs: []kube.PodIP{{IP: ip}}},
	}
}

func ns(name string, labels map[string]string) kube.Namespace {
	return kube.Namespace{Metadata: kube.ObjectMeta{Name: name, Labels: labels}}
}

func podWithPort(ns, name, uid, node, ip string, labels map[string]string, portName string, portNumber int32, protocol string) kube.Pod {
	p := pod(ns, name, uid, node, ip, labels)
	p.Spec.Containers = []kube.Container{{Ports: []kube.ContainerPort{{Name: portName, ContainerPort: portNumber, Protocol: protocol}}}}
	return p
}

func TestNoEgressPolicyIsUnmanaged(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}}, Options{})
	if err != nil || r.Managed {
		t.Fatalf("got managed=%v err=%v", r.Managed, err)
	}
}

func TestExplicitEmptyEgressDeniesAll(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{
		Metadata: kube.ObjectMeta{Name: "deny", Namespace: "app"},
		Spec:     kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}},
	}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Managed || !r.Policy.DefaultDeny || len(r.Policy.AllowAddresses) != 0 {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestSelectorUnionAcrossPolicies(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "node2", "10.0.0.20", map[string]string{"role": "db"})
	cache := pod("infra", "cache", "u3", "node2", "fd00::30", map[string]string{"role": "cache"})
	snap := Snapshot{
		Pods:       []kube.Pod{target, db, cache},
		Namespaces: []kube.Namespace{ns("app", map[string]string{"team": "app"}), ns("infra", map[string]string{"team": "infra"})},
		NetworkPolicies: []kube.NetworkPolicy{
			{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}},
			{Metadata: kube.ObjectMeta{Name: "cache", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{NamespaceSelector: &kube.LabelSelector{MatchLabels: map[string]string{"team": "infra"}}, PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "cache"}}}}}}}},
		},
	}
	r, err := Compile(target, snap, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.20", "fd00::30"}
	if !reflect.DeepEqual(r.Policy.AllowAddresses, want) {
		t.Fatalf("allow=%v want=%v", r.Policy.AllowAddresses, want)
	}
}

func TestNumericPortRuleCompiles(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "node2", "10.0.0.20", map[string]string{"role": "db"})
	port := kube.NetworkPolicyPort{Protocol: "TCP", Port: float64(5432)}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{port}, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []fluxvm.PodPeerPortRule{{Address: "10.0.0.20", Protocol: fluxvm.ProtocolTCP, Port: 5432}}
	if len(r.Policy.AllowAddresses) != 0 || len(r.Unsupported) != 0 || !reflect.DeepEqual(r.Policy.AllowPortRules, want) {
		t.Fatalf("unexpected numeric-port result: %+v", r)
	}
}

func TestPortRuleDefaultsToTCP(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "node2", "10.0.0.20", map[string]string{"role": "db"})
	port := kube.NetworkPolicyPort{Port: float64(53)} // Protocol omitted -> Kubernetes default TCP.
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "dns", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{port}, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []fluxvm.PodPeerPortRule{{Address: "10.0.0.20", Protocol: fluxvm.ProtocolTCP, Port: 53}}
	if !reflect.DeepEqual(r.Policy.AllowPortRules, want) {
		t.Fatalf("unexpected default-protocol result: %+v", r)
	}
}

func TestAddressWideAllowMakesPortRuleRedundant(t *testing.T) {
	// Union semantics: a peer already allowed on every port by one selected
	// policy must not also carry a redundant port-scoped entry from a
	// second, more restrictive policy that selects the same peer.
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "node2", "10.0.0.20", map[string]string{"role": "db"})
	unrestricted := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "all-db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	restricted := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db-5432", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{{Protocol: "TCP", Port: float64(5432)}}, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{unrestricted, restricted}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Policy.AllowAddresses, []string{"10.0.0.20"}) || len(r.Policy.AllowPortRules) != 0 {
		t.Fatalf("expected address-wide allow to absorb the port rule: %+v", r)
	}
}

func TestNamedPortDeniedWhenPeerLacksIt(t *testing.T) {
	// Set 13 completion: a named port now resolves per selected peer Pod's
	// own container spec (see TestNamedPortResolvesAgainstPeerContainerSpec
	// below) instead of being unconditionally denied -- but a peer that
	// simply doesn't declare that name must still deny it, not widen.
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "node2", "10.0.0.20", map[string]string{"role": "db"})
	port := kube.NetworkPolicyPort{Protocol: "TCP", Port: "postgres"}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{port}, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.AllowAddresses) != 0 || len(r.Policy.AllowPortRules) != 0 || len(r.Unsupported) != 1 || !strings.Contains(r.Unsupported[0], "does not resolve") {
		t.Fatalf("unexpected named-port result: %+v", r)
	}
}

func TestNamedPortResolvesAgainstPeerContainerSpec(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	db := podWithPort("app", "db", "u2", "node2", "10.0.0.20", map[string]string{"role": "db"}, "postgres", 5432, "TCP")
	port := kube.NetworkPolicyPort{Protocol: "TCP", Port: "postgres"}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{port}, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []fluxvm.PodPeerPortRule{{Address: "10.0.0.20", Protocol: fluxvm.ProtocolTCP, Port: 5432}}
	if !reflect.DeepEqual(r.Policy.AllowPortRules, want) || len(r.Unsupported) != 0 {
		t.Fatalf("unexpected named-port resolution result: %+v", r)
	}
}

func TestPortRangeCompiles(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "node2", "10.0.0.20", map[string]string{"role": "db"})
	endPort := int32(6000)
	port := kube.NetworkPolicyPort{Protocol: "TCP", Port: float64(5000), EndPort: &endPort}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{port}, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []fluxvm.PodPeerPortRange{{Address: "10.0.0.20", Protocol: fluxvm.ProtocolTCP, Start: 5000, End: 6000}}
	if len(r.Policy.AllowAddresses) != 0 || len(r.Policy.AllowPortRules) != 0 || !reflect.DeepEqual(r.Policy.PortRanges, want) || len(r.Unsupported) != 0 {
		t.Fatalf("unexpected port-range result: %+v", r)
	}
}

func TestPortRangeExceedingCapIsPartiallyDenied(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "node2", "10.0.0.20", map[string]string{"role": "db"})
	var ports []kube.NetworkPolicyPort
	for i := 0; i < maxPortRangesPerPeer+2; i++ {
		start := float64(1000 + i*10)
		end := int32(1005 + i*10)
		ports = append(ports, kube.NetworkPolicyPort{Protocol: "TCP", Port: start, EndPort: &end})
	}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: ports, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.PortRanges) != maxPortRangesPerPeer {
		t.Fatalf("expected exactly %d ranges after capping, got %d: %+v", maxPortRangesPerPeer, len(r.Policy.PortRanges), r)
	}
	if len(r.Unsupported) != 1 || !strings.Contains(r.Unsupported[0], "exceed the maximum") {
		t.Fatalf("expected one exceeded-maximum unsupported entry: %+v", r)
	}
}

func TestEmptyToWithPortsFailsStricter(t *testing.T) {
	// A port-restricted rule with no `to` has no peer to attach the port
	// rule to, and Set 6S has no all-address port-scoped allow -- must deny,
	// not silently drop the port restriction and allow everyone.
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "any-5432", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{{Protocol: "TCP", Port: float64(5432)}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Policy.DefaultDeny || len(r.Policy.AllowAddresses) != 0 || len(r.Policy.AllowPortRules) != 0 || len(r.Unsupported) != 1 {
		t.Fatalf("unexpected empty-to-with-ports result: %+v", r)
	}
}

func TestEmptyToWithoutPortsAllowsAll(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "all", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Policy.DefaultDeny {
		t.Fatalf("expected default allow: %+v", r)
	}
}

func TestHostIPBlockExact(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "ip", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "1.1.1.1/32"}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Policy.AllowAddresses, []string{"1.1.1.1"}) || len(r.Unsupported) != 0 {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestBroadIPBlockOnlyKnownAddresses(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	peer := pod("app", "b", "u2", "node2", "10.2.3.4", nil)
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "ip", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, peer}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.1", "10.2.3.4"}
	if !reflect.DeepEqual(r.Policy.AllowAddresses, want) || len(r.Unsupported) != 1 {
		t.Fatalf("got %+v want %v", r, want)
	}
}

func TestBroadIPBlockWithoutExceptCompilesToRealCidr(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "ip", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "203.0.113.0/24"}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []fluxvm.PodPeerCidr{{Addr: "203.0.113.0", PrefixLen: 24}}
	if !reflect.DeepEqual(r.Policy.AllowCidrs, want) || len(r.Policy.AllowAddresses) != 0 || len(r.Unsupported) != 0 {
		t.Fatalf("unexpected CIDR result: %+v", r)
	}
}

func TestPortRestrictedIPBlockNeverEmitsCidr(t *testing.T) {
	// The port-scoped maps have no CIDR dimension -- a broad ipBlock paired
	// with `ports` must stay exact-address approximated, unlike the plain
	// (unrestricted) ipBlock case above.
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	peer := pod("app", "b", "u2", "node2", "203.0.113.5", nil)
	port := kube.NetworkPolicyPort{Protocol: "TCP", Port: float64(443)}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "ip", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{port}, To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "203.0.113.0/24"}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, peer}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []fluxvm.PodPeerPortRule{{Address: "203.0.113.5", Protocol: fluxvm.ProtocolTCP, Port: 443}}
	if len(r.Policy.AllowCidrs) != 0 || !reflect.DeepEqual(r.Policy.AllowPortRules, want) {
		t.Fatalf("unexpected port-restricted ipBlock result: %+v", r)
	}
}

func TestEgressOnlyPolicyLeavesIngressNil(t *testing.T) {
	// The mirror of TestIngressCompilesFromPeers's own egress-untouched
	// assertion: when only an egress-isolating policy selects the Pod (and
	// Kubernetes' Ingress-included-by-default doesn't apply because
	// policyTypes is explicit), `Policy.Ingress` must stay nil/null on the
	// wire -- not an explicit `{DefaultDeny: false}` struct -- matching
	// PodNetworkPolicy.ingress's documented "unconfigured means allow"
	// semantics (dataplane.rs) exactly the way an entirely-unmanaged Pod's
	// policy would. Caught live by scripts/test-networkpolicy-live.sh
	// before this regression test existed.
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	peer := pod("app", "b", "u2", "node2", "10.0.0.20", map[string]string{"role": "peer"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "egress-only", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "peer"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, peer}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Policy.Ingress != nil {
		t.Fatalf("expected nil Ingress when no ingress-isolating policy selects the Pod: %+v", r.Policy)
	}
}

func TestIngressCompilesFromPeers(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	client := pod("app", "c", "u2", "node2", "10.0.0.30", map[string]string{"role": "client"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "allow-client", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Ingress"}, Ingress: []kube.NetworkPolicyIngressRule{{From: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "client"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, client}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Policy.Ingress == nil || !reflect.DeepEqual(r.Policy.Ingress.AllowAddresses, []string{"10.0.0.30"}) || !r.Policy.Ingress.DefaultDeny {
		t.Fatalf("unexpected ingress result: %+v", r)
	}
	// Egress is untouched by an ingress-only policy -- unrestricted, same as
	// Kubernetes' own semantics for a Pod selected only by an
	// ingress-isolating NetworkPolicy.
	if r.Policy.DefaultDeny {
		t.Fatalf("expected egress to remain unrestricted: %+v", r.Policy)
	}
}

func TestIngressNamedPortResolvesAgainstTargetItself(t *testing.T) {
	// Unlike egress, an ingress rule's named port resolves against the
	// policy's own protected Pod (target), not the peer -- it restricts
	// which of *this* Pod's ports the peer may reach.
	target := podWithPort("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"}, "http", 8080, "TCP")
	client := pod("app", "c", "u2", "node2", "10.0.0.30", map[string]string{"role": "client"})
	port := kube.NetworkPolicyPort{Protocol: "TCP", Port: "http"}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "allow-client", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Ingress"}, Ingress: []kube.NetworkPolicyIngressRule{{Ports: []kube.NetworkPolicyPort{port}, From: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "client"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, client}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []fluxvm.PodPeerPortRule{{Address: "10.0.0.30", Protocol: fluxvm.ProtocolTCP, Port: 8080}}
	if r.Policy.Ingress == nil || !reflect.DeepEqual(r.Policy.Ingress.AllowPortRules, want) {
		t.Fatalf("unexpected ingress named-port result: %+v", r)
	}
}

func TestIngressDefaultsToIsolatingWhenPolicyTypesUnset(t *testing.T) {
	// Unlike Egress (which defaults OUT unless an egress rule is present),
	// Kubernetes always treats an unset policyTypes as isolating Ingress --
	// even a policy with only egress rules and no ingress rules at all
	// still denies all ingress by default.
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "egress-only", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, Egress: []kube.NetworkPolicyEgressRule{{}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Policy.Ingress == nil || !r.Policy.Ingress.DefaultDeny || len(r.Policy.Ingress.AllowAddresses) != 0 {
		t.Fatalf("expected default deny-all ingress: %+v", r)
	}
}

func TestConservativeServiceVIP(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	dns := pod("infra", "dns", "u2", "node2", "10.10.0.2", map[string]string{"k8s-app": "dns"})
	svc := kube.Service{Metadata: kube.ObjectMeta{Name: "dns", Namespace: "infra"}, Spec: kube.ServiceSpec{ClusterIP: "10.96.0.10", ClusterIPs: []string{"10.96.0.10"}, Selector: map[string]string{"k8s-app": "dns"}}}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "dns", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{NamespaceSelector: &kube.LabelSelector{MatchLabels: map[string]string{"name": "infra"}}, PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"k8s-app": "dns"}}}}}}}}
	snap := Snapshot{Pods: []kube.Pod{target, dns}, Namespaces: []kube.Namespace{ns("app", map[string]string{"name": "app"}), ns("infra", map[string]string{"name": "infra"})}, Services: []kube.Service{svc}, NetworkPolicies: []kube.NetworkPolicy{np}}
	r, err := Compile(target, snap, Options{IncludeServiceClusterIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.10.0.2", "10.96.0.10"}
	if !reflect.DeepEqual(r.Policy.AllowAddresses, want) {
		t.Fatalf("allow=%v want=%v", r.Policy.AllowAddresses, want)
	}
}

func TestAddressLimitReturnsSafeDeny(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	p1 := pod("app", "b", "u2", "node2", "10.0.0.2", map[string]string{"role": "peer"})
	p2 := pod("app", "c", "u3", "node2", "10.0.0.3", map[string]string{"role": "peer"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "peer", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "peer"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, p1, p2}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{MaxAddresses: 1})
	if err == nil {
		t.Fatal("expected limit error")
	}
	if !r.Policy.DefaultDeny || len(r.Policy.AllowAddresses) != 0 {
		t.Fatalf("expected safe deny, got %+v", r)
	}
}

func TestNotInMatchesMissingLabel(t *testing.T) {
	sel := kube.LabelSelector{MatchExpressions: []kube.LabelSelectorRequirement{{Key: "env", Operator: "NotIn", Values: []string{"prod"}}}}
	if !kube.MatchesSelector(map[string]string{"app": "x"}, sel) {
		t.Fatal("NotIn should match missing key")
	}
	if kube.MatchesSelector(map[string]string{"env": "prod"}, sel) {
		t.Fatal("NotIn matched excluded value")
	}
}
