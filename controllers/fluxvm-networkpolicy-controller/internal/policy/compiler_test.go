// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"reflect"
	"strings"
	"testing"

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

func TestPortRuleFailsStricter(t *testing.T) {
	target := pod("app", "a", "u1", "node1", "10.0.0.1", map[string]string{"app": "web"})
	db := pod("app", "db", "u2", "node2", "10.0.0.20", map[string]string{"role": "db"})
	port := kube.NetworkPolicyPort{Protocol: "TCP", Port: float64(5432)}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{Ports: []kube.NetworkPolicyPort{port}, To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	r, err := Compile(target, Snapshot{Pods: []kube.Pod{target, db}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policy.AllowAddresses) != 0 || len(r.Unsupported) != 1 || !strings.Contains(r.Unsupported[0], "ports") {
		t.Fatalf("unexpected stricter result: %+v", r)
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
