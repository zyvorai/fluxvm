// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"net/netip"
	"testing"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
)

func set18Bool(v bool) *bool { return &v }

func set18Pod(name, uid, ip string, labels map[string]string) kube.Pod {
	return kube.Pod{
		Metadata: kube.ObjectMeta{Name: name, Namespace: "set18", UID: uid, Labels: labels},
		Status:   kube.PodStatus{Phase: "Running", PodIP: ip, PodIPs: []kube.PodIP{{IP: ip}}},
	}
}

func set18Slice(name, service, family string, endpoints ...kube.Endpoint) kube.EndpointSlice {
	return kube.EndpointSlice{
		Metadata:    kube.ObjectMeta{Name: name, Namespace: "set18", Labels: map[string]string{"kubernetes.io/service-name": service}},
		AddressType: family,
		Endpoints:   endpoints,
	}
}

func set18Endpoint(uid, name, ip string, ready, serving, terminating *bool) kube.Endpoint {
	return kube.Endpoint{
		Addresses:  []string{ip},
		Conditions: kube.EndpointConditions{Ready: ready, Serving: serving, Terminating: terminating},
		TargetRef:  &kube.ObjectReference{Kind: "Pod", Namespace: "set18", Name: name, UID: uid},
	}
}

func set18BaseSnapshot() (Snapshot, map[string]struct{}) {
	selected := set18Pod("db-selected", "uid-selected", "10.0.0.20", map[string]string{"app": "db", "policy-peer": "yes"})
	unselected := set18Pod("db-unselected", "uid-unselected", "10.0.0.21", map[string]string{"app": "db", "policy-peer": "no"})
	svc := kube.Service{Metadata: kube.ObjectMeta{Name: "db", Namespace: "set18"}, Spec: kube.ServiceSpec{ClusterIP: "10.96.0.10", ClusterIPs: []string{"10.96.0.10"}, Selector: map[string]string{"app": "db"}}}
	return Snapshot{Pods: []kube.Pod{selected, unselected}, Services: []kube.Service{svc}}, map[string]struct{}{"uid-selected": {}}
}

func TestSet18EndpointSliceAllowsVIPWhenOnlyRoutableBackendIsSelected(t *testing.T) {
	s, peers := set18BaseSnapshot()
	f := false
	tt := true
	s.EndpointSlices = []kube.EndpointSlice{set18Slice("db-v4", "db", "IPv4",
		set18Endpoint("uid-selected", "db-selected", "10.0.0.20", &tt, &tt, &f),
		set18Endpoint("uid-unselected", "db-unselected", "10.0.0.21", &f, &f, &f),
	)}
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, peers, cidrs)
	if _, ok := cidrs["10.96.0.10/32"]; !ok {
		t.Fatalf("expected Service VIP when every routable EndpointSlice backend is selected: %#v", cidrs)
	}
}

func TestSet18EndpointSliceRejectsVIPWhenRoutableBackendIsOutsidePeer(t *testing.T) {
	s, peers := set18BaseSnapshot()
	tt := true
	f := false
	s.EndpointSlices = []kube.EndpointSlice{set18Slice("db-v4", "db", "IPv4",
		set18Endpoint("uid-selected", "db-selected", "10.0.0.20", &tt, &tt, &f),
		set18Endpoint("uid-unselected", "db-unselected", "10.0.0.21", &tt, &tt, &f),
	)}
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, peers, cidrs)
	if _, ok := cidrs["10.96.0.10/32"]; ok {
		t.Fatalf("unsafe Service VIP widened policy: %#v", cidrs)
	}
}

func TestSet18ServingTerminatingBackendStillBlocksVIP(t *testing.T) {
	s, peers := set18BaseSnapshot()
	tt := true
	f := false
	s.EndpointSlices = []kube.EndpointSlice{set18Slice("db-v4", "db", "IPv4",
		set18Endpoint("uid-selected", "db-selected", "10.0.0.20", &tt, &tt, &f),
		set18Endpoint("uid-unselected", "db-unselected", "10.0.0.21", &f, &tt, &tt),
	)}
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, peers, cidrs)
	if _, ok := cidrs["10.96.0.10/32"]; ok {
		t.Fatal("serving+terminating endpoint may receive drain traffic and must block unsafe VIP")
	}
}

func TestSet18ReadyNilIsRoutable(t *testing.T) {
	s, peers := set18BaseSnapshot()
	f := false
	s.EndpointSlices = []kube.EndpointSlice{set18Slice("db-v4", "db", "IPv4",
		set18Endpoint("uid-selected", "db-selected", "10.0.0.20", nil, nil, &f),
	)}
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, peers, cidrs)
	if _, ok := cidrs["10.96.0.10/32"]; !ok {
		t.Fatal("discovery/v1 ready=nil must be interpreted as routable")
	}
}

func TestSet18DualStackSafetyIsPerFamily(t *testing.T) {
	selected := set18Pod("db-selected", "uid-selected", "10.0.0.20", map[string]string{"app": "db"})
	selected.Status.PodIPs = append(selected.Status.PodIPs, kube.PodIP{IP: "fd00::20"})
	rogue := set18Pod("db-rogue", "uid-rogue", "fd00::21", map[string]string{"app": "db"})
	svc := kube.Service{Metadata: kube.ObjectMeta{Name: "db", Namespace: "set18"}, Spec: kube.ServiceSpec{ClusterIPs: []string{"10.96.0.10", "fd00:96::10"}, Selector: map[string]string{"app": "db"}}}
	tt, f := true, false
	s := Snapshot{Pods: []kube.Pod{selected, rogue}, Services: []kube.Service{svc}, EndpointSlices: []kube.EndpointSlice{
		set18Slice("db-v4", "db", "IPv4", set18Endpoint("uid-selected", "db-selected", "10.0.0.20", &tt, &tt, &f)),
		set18Slice("db-v6", "db", "IPv6", set18Endpoint("uid-rogue", "db-rogue", "fd00::21", &tt, &tt, &f)),
	}}
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, map[string]struct{}{"uid-selected": {}}, cidrs)
	v4 := netip.MustParseAddr("10.96.0.10").String() + "/32"
	v6 := netip.MustParseAddr("fd00:96::10").String() + "/128"
	if _, ok := cidrs[v4]; !ok {
		t.Fatalf("expected safe IPv4 VIP: %#v", cidrs)
	}
	if _, ok := cidrs[v6]; ok {
		t.Fatalf("unsafe IPv6 family must stay excluded: %#v", cidrs)
	}
}

func TestSet18ServiceVIPIsNeverAnIngressSourceIdentity(t *testing.T) {
	target := set18Pod("web", "uid-web", "10.0.0.10", map[string]string{"app": "web"})
	backend := set18Pod("db", "uid-db", "10.0.0.20", map[string]string{"app": "db"})
	svc := kube.Service{Metadata: kube.ObjectMeta{Name: "db", Namespace: "set18"}, Spec: kube.ServiceSpec{ClusterIP: "10.96.0.10", ClusterIPs: []string{"10.96.0.10"}, Selector: map[string]string{"app": "db"}}}
	ready := true
	endpointSlice := set18Slice("db-v4", "db", "IPv4", set18Endpoint("uid-db", "db", "10.0.0.20", &ready, nil, nil))
	np := kube.NetworkPolicy{
		Metadata: kube.ObjectMeta{Name: "db-to-web", Namespace: "set18"},
		Spec: kube.NetworkPolicySpec{
			PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []string{"Ingress"},
			Ingress:     []kube.NetworkPolicyIngressRule{{From: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"app": "db"}}}}}},
		},
	}
	got, err := Compile(target, Snapshot{Pods: []kube.Pod{target, backend}, Services: []kube.Service{svc}, EndpointSlices: []kube.EndpointSlice{endpointSlice}, NetworkPolicies: []kube.NetworkPolicy{np}}, Options{IncludeServiceClusterIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Policy.Rules) != 1 || got.Policy.Rules[0].Direction != "ingress" || got.Policy.Rules[0].CIDR != "10.0.0.20/32" {
		t.Fatalf("Service VIP must never be compiled as an ingress source: %+v", got.Policy.Rules)
	}
}

func TestSet18StaleEndpointAddressBlocksVIP(t *testing.T) {
	s, peers := set18BaseSnapshot()
	tt := true
	s.EndpointSlices = []kube.EndpointSlice{set18Slice("db-v4", "db", "IPv4",
		set18Endpoint("uid-selected", "db-selected", "10.0.0.99", &tt, nil, nil),
	)}
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, peers, cidrs)
	if _, ok := cidrs["10.96.0.10/32"]; ok {
		t.Fatalf("stale EndpointSlice address widened Service VIP policy: %#v", cidrs)
	}
}
