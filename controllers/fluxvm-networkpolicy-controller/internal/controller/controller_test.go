// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/fluxvm"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/metrics"
)

type fakeKube struct {
	pods []kube.Pod
	ns   []kube.Namespace
	svc  []kube.Service
	np   []kube.NetworkPolicy
}

func (f *fakeKube) Pods(context.Context) ([]kube.Pod, error)                      { return f.pods, nil }
func (f *fakeKube) Namespaces(context.Context) ([]kube.Namespace, error)          { return f.ns, nil }
func (f *fakeKube) Services(context.Context) ([]kube.Service, error)              { return f.svc, nil }
func (f *fakeKube) NetworkPolicies(context.Context) ([]kube.NetworkPolicy, error) { return f.np, nil }

type fakeFlux struct {
	vms      []fluxvm.VMRecord
	policies map[string]*fluxvm.PodNetworkPolicy
	set      map[string]fluxvm.PodNetworkPolicy
	cleared  []string
}

func (f *fakeFlux) ListVMs(context.Context) ([]fluxvm.VMRecord, error) { return f.vms, nil }
func (f *fakeFlux) GetPodPolicy(_ context.Context, id string) (*fluxvm.PodNetworkPolicy, error) {
	if p, ok := f.policies[id]; ok && p != nil {
		cp := *p
		return &cp, nil
	}
	return nil, nil
}
func (f *fakeFlux) SetPodPolicy(_ context.Context, id string, p fluxvm.PodNetworkPolicy) error {
	if f.set == nil {
		f.set = map[string]fluxvm.PodNetworkPolicy{}
	}
	cp := p
	f.set[id] = cp
	f.policies[id] = &cp
	return nil
}
func (f *fakeFlux) ClearPodPolicy(_ context.Context, id string) error {
	f.cleared = append(f.cleared, id)
	f.policies[id] = nil
	return nil
}

func TestReconcileAppliesSamePolicyToDuplicatePodVMs(t *testing.T) {
	target := kube.Pod{Metadata: kube.ObjectMeta{Name: "web", Namespace: "app", UID: "uid-web", Labels: map[string]string{"app": "web"}}, Spec: kube.PodSpec{NodeName: "node-a"}, Status: kube.PodStatus{Phase: "Running", PodIP: "10.0.0.10"}}
	peer := kube.Pod{Metadata: kube.ObjectMeta{Name: "db", Namespace: "app", UID: "uid-db", Labels: map[string]string{"role": "db"}}, Spec: kube.PodSpec{NodeName: "node-b"}, Status: kube.PodStatus{Phase: "Running", PodIP: "10.0.0.20"}}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db-egress", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "db"}}}}}}}}
	uid := "uid-web"
	ff := &fakeFlux{vms: []fluxvm.VMRecord{{ID: "vm-a", Request: fluxvm.VMRequest{PodUID: &uid}}, {ID: "vm-b", Request: fluxvm.VMRequest{PodUID: &uid}}}, policies: map[string]*fluxvm.PodNetworkPolicy{}}
	c := &Controller{Kube: &fakeKube{pods: []kube.Pod{target, peer}, np: []kube.NetworkPolicy{np}}, FluxVM: ff, Metrics: metrics.New(), NodeName: "node-a", MaxAddresses: 100}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ff.set) != 2 {
		t.Fatalf("set=%+v", ff.set)
	}
	want := []string{"10.0.0.20"}
	for _, id := range []string{"vm-a", "vm-b"} {
		if !reflect.DeepEqual(ff.set[id].AllowAddresses, want) {
			t.Fatalf("%s=%+v", id, ff.set[id])
		}
	}
}

func TestReconcileClearsStalePolicyWhenPodBecomesUnmanaged(t *testing.T) {
	target := kube.Pod{Metadata: kube.ObjectMeta{Name: "web", Namespace: "app", UID: "uid-web", Labels: map[string]string{"app": "web"}}, Spec: kube.PodSpec{NodeName: "node-a"}, Status: kube.PodStatus{Phase: "Running", PodIP: "10.0.0.10"}}
	uid := "uid-web"
	existing := &fluxvm.PodNetworkPolicy{DefaultDeny: true}
	ff := &fakeFlux{vms: []fluxvm.VMRecord{{ID: "vm-a", Request: fluxvm.VMRequest{PodUID: &uid}}}, policies: map[string]*fluxvm.PodNetworkPolicy{"vm-a": existing}}
	c := &Controller{Kube: &fakeKube{pods: []kube.Pod{target}}, FluxVM: ff, Metrics: metrics.New(), NodeName: "node-a"}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ff.cleared, []string{"vm-a"}) {
		t.Fatalf("cleared=%v", ff.cleared)
	}
}

func TestCompileErrorStillAppliesDenyAll(t *testing.T) {
	target := kube.Pod{Metadata: kube.ObjectMeta{Name: "web", Namespace: "app", UID: "uid-web", Labels: map[string]string{"app": "web"}}, Spec: kube.PodSpec{NodeName: "node-a"}, Status: kube.PodStatus{Phase: "Running", PodIP: "10.0.0.10"}}
	peer1 := kube.Pod{Metadata: kube.ObjectMeta{Name: "p1", Namespace: "app", UID: "p1", Labels: map[string]string{"role": "peer"}}, Status: kube.PodStatus{Phase: "Running", PodIP: "10.0.0.21"}}
	peer2 := kube.Pod{Metadata: kube.ObjectMeta{Name: "p2", Namespace: "app", UID: "p2", Labels: map[string]string{"role": "peer"}}, Status: kube.PodStatus{Phase: "Running", PodIP: "10.0.0.22"}}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "many", Namespace: "app"}, Spec: kube.NetworkPolicySpec{PodSelector: kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, PolicyTypes: []string{"Egress"}, Egress: []kube.NetworkPolicyEgressRule{{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"role": "peer"}}}}}}}}
	uid := "uid-web"
	ff := &fakeFlux{vms: []fluxvm.VMRecord{{ID: "vm-a", Request: fluxvm.VMRequest{PodUID: &uid}}}, policies: map[string]*fluxvm.PodNetworkPolicy{}}
	c := &Controller{Kube: &fakeKube{pods: []kube.Pod{target, peer1, peer2}, np: []kube.NetworkPolicy{np}}, FluxVM: ff, Metrics: metrics.New(), NodeName: "node-a", MaxAddresses: 1}
	err := c.Reconcile(context.Background())
	if err == nil {
		t.Fatal("expected reconciliation error")
	}
	p, ok := ff.set["vm-a"]
	if !ok || !p.DefaultDeny || len(p.AllowAddresses) != 0 {
		t.Fatalf("safe deny not applied: %+v", ff.set)
	}
}

func TestKubernetesListFailureStopsBeforeFluxVMWrites(t *testing.T) {
	bad := &errorKube{}
	ff := &fakeFlux{policies: map[string]*fluxvm.PodNetworkPolicy{}}
	c := &Controller{Kube: bad, FluxVM: ff, Metrics: metrics.New(), NodeName: "node-a"}
	if err := c.Reconcile(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if len(ff.set) != 0 || len(ff.cleared) != 0 {
		t.Fatal("unexpected FluxVM writes")
	}
}

type errorKube struct{}

func (*errorKube) Pods(context.Context) ([]kube.Pod, error)                      { return nil, errors.New("boom") }
func (*errorKube) Namespaces(context.Context) ([]kube.Namespace, error)          { return nil, nil }
func (*errorKube) Services(context.Context) ([]kube.Service, error)              { return nil, nil }
func (*errorKube) NetworkPolicies(context.Context) ([]kube.NetworkPolicy, error) { return nil, nil }
