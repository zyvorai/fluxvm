// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/fluxvm"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
)

func pod(ns, name, uid, node, ip string, labels map[string]string) kube.Pod {
	return kube.Pod{Metadata: kube.ObjectMeta{Name: name, Namespace: ns, UID: uid, Labels: labels, Annotations: map[string]string{}}, Spec: kube.PodSpec{NodeName: node}, Status: kube.PodStatus{Phase: "Running", PodIP: ip, PodIPs: []kube.PodIP{{IP: ip}}}}
}
func ns(name string, labels map[string]string) kube.Namespace {
	return kube.Namespace{Metadata: kube.ObjectMeta{Name: name, Labels: labels}}
}
func strp(s string) *string { return &s }
func i32(v int32) *int32    { return &v }

func TestNoPolicyIsUnmanaged(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "10.0.0.1", map[string]string{"app": "web"})
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}}, Options{})
	if err != nil || r.Managed {
		t.Fatalf("managed=%v err=%v", r.Managed, err)
	}
}

func TestExplicitEgressDenyAll(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "deny", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Policy.EgressIsolated || r.Policy.IngressIsolated || len(r.Policy.Rules) != 0 || !r.Policy.DefaultDeny {
		t.Fatalf("%+v", r.Policy)
	}
}

func TestDefaultPolicyTypesWithEgressAlsoIsolatesIngress(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "both", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, Egress: []kube.NetworkPolicyEgressRule{{}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Policy.IngressIsolated || !r.Policy.EgressIsolated {
		t.Fatalf("%+v", r.Policy)
	}
}

func TestSelectorUnionAcrossPolicies(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "n2", "10.0.0.20", map[string]string{"role": "db"})
	cache := pod("infra", "cache", "u3", "n2", "fd00::30", map[string]string{"role": "cache"})
	snap := Snapshot{Pods: []kube.Pod{target, db, cache}, Namespaces: []kube.Namespace{ns("app", map[string]string{"team": "app"}), ns("infra", map[string]string{"team": "infra"})}, NetworkPolicies: []kube.NetworkPolicy{
		{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}},
		{Metadata: kube.ObjectMeta{Name: "cache", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{NamespaceSelector: &kube.LabelSelector{MatchLabels: map[string]string{"team": "infra"}}, PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "cache"}}}}}}}},
	}}
	r, err := Compile(target, snap, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []fluxvm.PodPolicyRule{{Direction: "egress", CIDR: "10.0.0.20/32"}, {Direction: "egress", CIDR: "fd00::30/128"}}
	if !reflect.DeepEqual(r.Policy.Rules, want) {
		t.Fatalf("rules=%+v", r.Policy.Rules)
	}
}

func TestNumericTCPPortIsExactTuple(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "n2", "10.0.0.20", map[string]string{"role": "db"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{{Protocol: "TCP", Port: float64(5432)}}, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := fluxvm.PodPolicyRule{Direction: "egress", CIDR: "10.0.0.20/32", Protocol: "TCP", PortStart: 5432, PortEnd: 5432}
	if len(r.Policy.Rules) != 1 || r.Policy.Rules[0] != want {
		t.Fatalf("%+v", r.Policy.Rules)
	}
}

func TestEndPortRangePreserved(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "10.0.0.1", map[string]string{"app": "web"})
	end := int32(8100)
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "range", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{{Protocol: "UDP", Port: float64(8000), EndPort: &end}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.Rules) != 2 {
		t.Fatalf("%+v", r.Policy.Rules)
	}
	for _, rr := range r.Policy.Rules {
		if rr.Protocol != "UDP" || rr.PortStart != 8000 || rr.PortEnd != 8100 {
			t.Fatalf("%+v", rr)
		}
	}
}

func TestSCTPSupported(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "sctp", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{{Protocol: "SCTP", Port: float64(5000)}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.Rules) != 2 || r.Policy.Rules[0].Protocol != "SCTP" {
		t.Fatalf("%+v", r.Policy.Rules)
	}
}

func TestIPBlockExactCIDRAndExceptDecomposition(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "ip", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.Rules) != 8 {
		t.Fatalf("rules=%d %+v", len(r.Policy.Rules), r.Policy.Rules)
	}
	for _, rr := range r.Policy.Rules {
		p, _ := netipParse(rr.CIDR)
		if p.Contains(mustAddr("10.1.2.3")) {
			t.Fatalf("except leaked via %s", rr.CIDR)
		}
	}
}

func TestIPv6HostBlock(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "fd00::1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "ip6", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "2001:db8::1/128"}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.Rules) != 1 || r.Policy.Rules[0].CIDR != "2001:db8::1/128" {
		t.Fatalf("%+v", r.Policy.Rules)
	}
}

func TestUnrestrictedDestinationRuleUsesBothFamilies(t *testing.T) {
	target := pod("app", "a", "u1", "n1", "10.0.0.1", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "all", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.Rules) != 2 {
		t.Fatalf("%+v", r.Policy.Rules)
	}
}

func TestIngressSelectorRule(t *testing.T) {
	target := pod("app", "web", "u1", "n1", "10.0.0.10", map[string]string{"app": "web"})
	src := pod("app", "client", "u2", "n2", "10.0.0.30", map[string]string{"role": "client"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "in", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Ingress"}, Ingress: []kube.NetworkPolicyIngressRule{{From: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "client"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, src}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := fluxvm.PodPolicyRule{Direction: "ingress", CIDR: "10.0.0.30/32"}
	if len(r.Policy.Rules) != 1 || r.Policy.Rules[0] != want {
		t.Fatalf("%+v", r.Policy.Rules)
	}
}

func TestIngressNamedPortResolvesTarget(t *testing.T) {
	target := pod("app", "web", "u1", "n1", "10.0.0.10", map[string]string{"app": "web"})
	target.Spec.Containers = []kube.Container{{Name: "web", Ports: []kube.ContainerPort{{Name: "https", ContainerPort: 8443, Protocol: "TCP"}}}}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "in", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Ingress"}, Ingress: []kube.NetworkPolicyIngressRule{{Ports: []kube.NetworkPolicyPort{{Protocol: "TCP", Port: "https"}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.Rules) != 2 {
		t.Fatalf("%+v", r.Policy.Rules)
	}
	for _, rr := range r.Policy.Rules {
		if rr.PortStart != 8443 || rr.PortEnd != 8443 {
			t.Fatalf("%+v", rr)
		}
	}
}

func TestEgressNamedPortBindsDestinationPod(t *testing.T) {
	target := pod("app", "web", "u1", "n1", "10.0.0.10", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "n2", "10.0.0.20", map[string]string{"role": "db"})
	db.Spec.Containers = []kube.Container{{Name: "db", Ports: []kube.ContainerPort{{Name: "sql", ContainerPort: 5432, Protocol: "TCP"}}}}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "out", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{{Port: "sql"}}, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := fluxvm.PodPolicyRule{Direction: "egress", CIDR: "10.0.0.20/32", Protocol: "TCP", PortStart: 5432, PortEnd: 5432}
	if len(r.Policy.Rules) != 1 || r.Policy.Rules[0] != want {
		t.Fatalf("%+v", r.Policy.Rules)
	}
}

func TestUnrestrictedNamedEgressFailsClosedPerRule(t *testing.T) {
	target := pod("app", "web", "u1", "n1", "10.0.0.10", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "out", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{{Port: "sql"}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.Rules) != 0 || len(r.Unsupported) == 0 || !strings.Contains(r.Unsupported[0], "cannot be resolved") {
		t.Fatalf("%+v", r)
	}
}

// FLUXVM_SECURE_CONTAINERS_SET18
func TestEndpointSliceServiceVIP(t *testing.T) {
	target := pod("app", "web", "u1", "n1", "10.0.0.10", map[string]string{"app": "web"})
	dns := pod("infra", "dns", "u2", "n2", "10.10.0.2", map[string]string{"k8s-app": "dns"})
	svc := kube.Service{Metadata: kube.ObjectMeta{Name: "dns", Namespace: "infra"}, Spec: kube.ServiceSpec{ClusterIP: "10.96.0.10", ClusterIPs: []string{"10.96.0.10"}, Selector: map[string]string{"k8s-app": "dns"}}}
	ready := true
	slice := kube.EndpointSlice{Metadata: kube.ObjectMeta{Name: "dns-a", Namespace: "infra", Labels: map[string]string{"kubernetes.io/service-name": "dns"}}, AddressType: "IPv4", Endpoints: []kube.Endpoint{{Addresses: []string{"10.10.0.2"}, Conditions: kube.EndpointConditions{Ready: &ready}, TargetRef: &kube.ObjectReference{Kind: "Pod", Namespace: "infra", Name: "dns", UID: "u2"}}}}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "dns", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{NamespaceSelector: &kube.LabelSelector{MatchLabels: map[string]string{"name": "infra"}}, PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"k8s-app": "dns"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, dns}, Namespaces: []kube.Namespace{ns("app", map[string]string{"name": "app"}), ns("infra", map[string]string{"name": "infra"})}, Services: []kube.Service{svc}, EndpointSlices: []kube.EndpointSlice{slice}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{IncludeServiceClusterIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []fluxvm.PodPolicyRule{{Direction: "egress", CIDR: "10.10.0.2/32"}, {Direction: "egress", CIDR: "10.96.0.10/32"}}
	if !reflect.DeepEqual(r.Policy.Rules, want) {
		t.Fatalf("%+v", r.Policy.Rules)
	}
}

func TestRuleLimitReturnsSafeDeny(t *testing.T) {
	target := pod("app", "web", "u1", "n1", "10.0.0.10", map[string]string{"app": "web"})
	p1 := pod("app", "p1", "u2", "n2", "10.0.0.21", map[string]string{"role": "peer"})
	p2 := pod("app", "p2", "u3", "n2", "10.0.0.22", map[string]string{"role": "peer"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "many", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "peer"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, p1, p2}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{MaxRules: 1})
	if err == nil {
		t.Fatal("expected limit error")
	}
	if !r.Policy.DefaultDeny || !r.Policy.IngressIsolated || !r.Policy.EgressIsolated || len(r.Policy.Rules) != 0 {
		t.Fatalf("%+v", r.Policy)
	}
}

func TestMalformedIPBlockReturnsSafeDeny(t *testing.T) {
	target := pod("app", "web", "u1", "n1", "10.0.0.10", map[string]string{"app": "web"})
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "bad", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"192.168.0.0/16"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err == nil || !r.Policy.DefaultDeny || len(r.Policy.Rules) != 0 {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestInvalidEndPortRejected(t *testing.T) {
	target := pod("app", "web", "u1", "n1", "10.0.0.10", map[string]string{"app": "web"})
	end := int32(79)
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "bad", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{{Port: float64(80), EndPort: &end}}}}}}
	_, err := Compile(target, Snapshot{Pods: []kube.Pod{target}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNotInMatchesMissingLabel(t *testing.T) {
	sel := kube.LabelSelector{MatchExpressions: []kube.LabelSelectorRequirement{{Key: "env", Operator: "NotIn", Values: []string{"prod"}}}}
	if !kube.MatchesSelector(map[string]string{"app": "x"}, sel) {
		t.Fatal("NotIn should match missing")
	}
	if kube.MatchesSelector(map[string]string{"env": "prod"}, sel) {
		t.Fatal("matched excluded")
	}
}

// small wrappers keep the test body readable without exporting compiler internals.
func netipParse(s string) (netip.Prefix, error) { return netip.ParsePrefix(s) }
func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}
