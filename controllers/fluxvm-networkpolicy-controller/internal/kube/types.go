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
	NodeName string `json:"nodeName"`
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

type NetworkPolicy struct {
	Metadata ObjectMeta        `json:"metadata"`
	Spec     NetworkPolicySpec `json:"spec"`
}

type NetworkPolicySpec struct {
	PodSelector LabelSelector             `json:"podSelector"`
	PolicyTypes []string                  `json:"policyTypes"`
	Egress      []NetworkPolicyEgressRule `json:"egress"`
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
			// Kubernetes set-based NotIn, like !=, also matches objects where
			// the key is absent.
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
