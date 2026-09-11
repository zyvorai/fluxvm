// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package kube

// This package deliberately models only the Kubernetes fields required by the
// FluxVM NetworkPolicy compiler. Keeping the controller on the standard
// library avoids pulling the full client-go graph into the node runtime.

type ObjectMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	UID             string            `json:"uid"`
	ResourceVersion string            `json:"resourceVersion"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
}

type ListMeta struct {
	Continue        string `json:"continue"`
	ResourceVersion string `json:"resourceVersion"`
}

type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
	Status   PodStatus  `json:"status"`
}

type PodSpec struct {
	NodeName       string      `json:"nodeName"`
	Containers     []Container `json:"containers"`
	InitContainers []Container `json:"initContainers"`
}

type Container struct {
	Name  string          `json:"name"`
	Ports []ContainerPort `json:"ports"`
}

type ContainerPort struct {
	Name          string `json:"name"`
	ContainerPort int32  `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

type PodStatus struct {
	Phase  string  `json:"phase"`
	PodIP  string  `json:"podIP"`
	PodIPs []PodIP `json:"podIPs"`
}

type PodIP struct {
	IP string `json:"ip"`
}

type Namespace struct {
	Metadata ObjectMeta `json:"metadata"`
}

type Service struct {
	Metadata ObjectMeta  `json:"metadata"`
	Spec     ServiceSpec `json:"spec"`
}

type ServiceSpec struct {
	ClusterIP  string            `json:"clusterIP"`
	ClusterIPs []string          `json:"clusterIPs"`
	Selector   map[string]string `json:"selector"`
	Type       string            `json:"type"`
}

// FLUXVM_SECURE_CONTAINERS_SET18: EndpointSlice is the Service-routing
// source of truth used to decide whether an opt-in Service ClusterIP can be
// safely represented by a selector-based NetworkPolicy peer.
type EndpointSlice struct {
	Metadata    ObjectMeta `json:"metadata"`
	AddressType string     `json:"addressType"`
	Endpoints   []Endpoint `json:"endpoints"`
}

type Endpoint struct {
	Addresses  []string           `json:"addresses"`
	Conditions EndpointConditions `json:"conditions"`
	TargetRef  *ObjectReference   `json:"targetRef"`
}

type EndpointConditions struct {
	Ready       *bool `json:"ready"`
	Serving     *bool `json:"serving"`
	Terminating *bool `json:"terminating"`
}

type ObjectReference struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type NetworkPolicy struct {
	Metadata ObjectMeta        `json:"metadata"`
	Spec     NetworkPolicySpec `json:"spec"`
}

type NetworkPolicySpec struct {
	PodSelector LabelSelector              `json:"podSelector"`
	PolicyTypes []string                   `json:"policyTypes"`
	Ingress     []NetworkPolicyIngressRule `json:"ingress"`
	Egress      []NetworkPolicyEgressRule  `json:"egress"`
}

type NetworkPolicyIngressRule struct {
	Ports []NetworkPolicyPort `json:"ports"`
	From  []NetworkPolicyPeer `json:"from"`
}

type NetworkPolicyEgressRule struct {
	Ports []NetworkPolicyPort `json:"ports"`
	To    []NetworkPolicyPeer `json:"to"`
}

type NetworkPolicyPort struct {
	Protocol string      `json:"protocol"`
	Port     interface{} `json:"port"`
	EndPort  *int32      `json:"endPort"`
}

type NetworkPolicyPeer struct {
	PodSelector       *LabelSelector `json:"podSelector"`
	NamespaceSelector *LabelSelector `json:"namespaceSelector"`
	IPBlock           *IPBlock       `json:"ipBlock"`
}

type IPBlock struct {
	CIDR   string   `json:"cidr"`
	Except []string `json:"except"`
}

type LabelSelector struct {
	MatchLabels      map[string]string          `json:"matchLabels"`
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions"`
}

type LabelSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

func PodAddresses(p Pod) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, item := range p.Status.PodIPs {
		if item.IP == "" {
			continue
		}
		if _, ok := seen[item.IP]; ok {
			continue
		}
		seen[item.IP] = struct{}{}
		out = append(out, item.IP)
	}
	if p.Status.PodIP != "" {
		if _, ok := seen[p.Status.PodIP]; !ok {
			out = append(out, p.Status.PodIP)
		}
	}
	return out
}

func NamedContainerPorts(p Pod, name, protocol string) []uint16 {
	seen := map[uint16]struct{}{}
	var out []uint16
	for _, c := range append(append([]Container(nil), p.Spec.Containers...), p.Spec.InitContainers...) {
		for _, cp := range c.Ports {
			cpProto := cp.Protocol
			if cpProto == "" {
				cpProto = "TCP"
			}
			if cp.Name != name || !equalFoldASCII(cpProto, protocol) || cp.ContainerPort <= 0 || cp.ContainerPort > 65535 {
				continue
			}
			port := uint16(cp.ContainerPort)
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			out = append(out, port)
		}
	}
	return out
}

func MatchesSelector(labels map[string]string, selector LabelSelector) bool {
	for key, want := range selector.MatchLabels {
		got, ok := labels[key]
		if !ok || got != want {
			return false
		}
	}
	for _, req := range selector.MatchExpressions {
		got, exists := labels[req.Key]
		switch req.Operator {
		case "In":
			if !exists || !contains(req.Values, got) {
				return false
			}
		case "NotIn":
			if exists && contains(req.Values, got) {
				return false
			}
		case "Exists":
			if !exists {
				return false
			}
		case "DoesNotExist":
			if exists {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'a' && ca <= 'z' {
			ca -= 'a' - 'A'
		}
		if cb >= 'a' && cb <= 'z' {
			cb -= 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
