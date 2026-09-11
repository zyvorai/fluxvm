// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"testing"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
)

func TestCoverageVIPModeOffNeverEmitsServiceVIP(t *testing.T) {
	target := set18Pod("client", "uid-client", "10.0.0.10", map[string]string{"role": "client"})
	selected := set18Pod("db-selected", "uid-selected", "10.0.0.20", map[string]string{"app": "db", "policy-peer": "yes"})
	svc := kube.Service{Metadata: kube.ObjectMeta{Name: "db", Namespace: "set18"}, Spec: kube.ServiceSpec{ClusterIP: "10.96.0.10", ClusterIPs: []string{"10.96.0.10"}, Selector: map[string]string{"app": "db"}}}
	tt := true
	f := false
	slice := set18Slice("db-v4", "db", "IPv4", set18Endpoint("uid-selected", "db-selected", "10.0.0.20", &tt, &tt, &f))
	np := kube.NetworkPolicy{
		Metadata: kube.ObjectMeta{Name: "client-egress", Namespace: "set18"},
		Spec: kube.NetworkPolicySpec{
			PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"role": "client"}},
			PolicyTypes: []string{"Egress"},
			Egress: []kube.NetworkPolicyEgressRule{{
				To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"policy-peer": "yes"}}}},
			}},
		},
	}
	got, err := Compile(target, Snapshot{
		Pods:            []kube.Pod{target, selected},
		Services:        []kube.Service{svc},
		EndpointSlices:  []kube.EndpointSlice{slice},
		NetworkPolicies: []kube.NetworkPolicy{np},
	}, Options{IncludeServiceClusterIPs: false})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got.Policy.Rules {
		if r.CIDR == "10.96.0.10/32" {
			t.Fatalf("VIP mode off still emitted Service VIP: %+v", got.Policy.Rules)
		}
	}
}

func TestCoverageEmptyEndpointSliceBlocksVIP(t *testing.T) {
	s, peers := set18BaseSnapshot()
	s.EndpointSlices = nil
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, peers, cidrs)
	if len(cidrs) != 0 {
		t.Fatalf("empty EndpointSlice must not emit VIP: %#v", cidrs)
	}
}

func TestCoverageSelectorlessServiceNeverVIP(t *testing.T) {
	s, peers := set18BaseSnapshot()
	s.Services[0].Spec.Selector = nil
	tt := true
	f := false
	s.EndpointSlices = []kube.EndpointSlice{set18Slice("db-v4", "db", "IPv4",
		set18Endpoint("uid-selected", "db-selected", "10.0.0.20", &tt, &tt, &f),
	)}
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, peers, cidrs)
	if len(cidrs) != 0 {
		t.Fatalf("selectorless Service must not emit VIP: %#v", cidrs)
	}
}

func TestCoverageSelectedServingTerminatingAloneAdmitsVIP(t *testing.T) {
	s, peers := set18BaseSnapshot()
	tt := true
	f := false
	// Only selected backend, draining but serving — proxies may still route.
	s.EndpointSlices = []kube.EndpointSlice{set18Slice("db-v4", "db", "IPv4",
		set18Endpoint("uid-selected", "db-selected", "10.0.0.20", &f, &tt, &tt),
	)}
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, peers, cidrs)
	if _, ok := cidrs["10.96.0.10/32"]; !ok {
		t.Fatalf("selected serving+terminating alone should admit VIP: %#v", cidrs)
	}
}

func TestCoverageDualStackPartialFailure(t *testing.T) {
	selected := set18Pod("db-selected", "uid-selected", "10.0.0.20", map[string]string{"app": "db", "policy-peer": "yes"})
	selected.Status.PodIPs = []kube.PodIP{{IP: "10.0.0.20"}, {IP: "2001:db8::20"}}
	unselected := set18Pod("db-unselected", "uid-unselected", "10.0.0.21", map[string]string{"app": "db", "policy-peer": "no"})
	unselected.Status.PodIPs = []kube.PodIP{{IP: "10.0.0.21"}, {IP: "2001:db8::21"}}
	svc := kube.Service{
		Metadata: kube.ObjectMeta{Name: "db", Namespace: "set18"},
		Spec: kube.ServiceSpec{
			ClusterIP:  "10.96.0.10",
			ClusterIPs: []string{"10.96.0.10", "2001:db8:96::10"},
			Selector:   map[string]string{"app": "db"},
		},
	}
	tt := true
	f := false
	s := Snapshot{
		Pods:     []kube.Pod{selected, unselected},
		Services: []kube.Service{svc},
		EndpointSlices: []kube.EndpointSlice{
			set18Slice("db-v4", "db", "IPv4",
				set18Endpoint("uid-selected", "db-selected", "10.0.0.20", &tt, &tt, &f),
			),
			set18Slice("db-v6", "db", "IPv6",
				set18Endpoint("uid-selected", "db-selected", "2001:db8::20", &tt, &tt, &f),
				set18Endpoint("uid-unselected", "db-unselected", "2001:db8::21", &tt, &tt, &f),
			),
		},
	}
	peers := map[string]struct{}{"uid-selected": {}}
	cidrs := map[string]struct{}{}
	includeEndpointSliceServiceVIPs(s, map[string]struct{}{"set18": {}}, peers, cidrs)
	if _, ok := cidrs["10.96.0.10/32"]; !ok {
		t.Fatalf("IPv4 VIP should remain: %#v", cidrs)
	}
	if _, ok := cidrs["2001:db8:96::10/128"]; ok {
		t.Fatalf("IPv6 VIP must be denied when unselected Ready backend exists: %#v", cidrs)
	}
}
