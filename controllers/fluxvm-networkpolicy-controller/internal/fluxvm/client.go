// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type VMRecord struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Status  string    `json:"status"`
	Request VMRequest `json:"request"`
}

type VMRequest struct {
	PodUID *string `json:"pod_uid"`
}

// PodPolicyProtocol matches the lowercase JSON the FluxVM API's
// PodPolicyProtocol enum expects (crates/fluxvm-network/src/dataplane.rs).
type PodPolicyProtocol string

const (
	ProtocolTCP PodPolicyProtocol = "tcp"
	ProtocolUDP PodPolicyProtocol = "udp"
)

// PodPeerPortRule is one exact protocol+port allow for a peer that has no
// address-wide allow entry -- Set 13's representation of a Kubernetes
// NetworkPolicy egress rule that carries a `ports` list. See
// docs/secure-containers-set13.md and dataplane schema v7
// (docs/drop-reason-migration-state.md) for the enforcement side.
type PodPeerPortRule struct {
	Address  string            `json:"address"`
	Protocol PodPolicyProtocol `json:"protocol"`
	Port     uint16            `json:"port"`
}

// PodPeerCidr is a CIDR-based peer allow (schema v8), for a Kubernetes
// NetworkPolicy `ipBlock` peer whose CIDR is not a host route. Field names
// match crates/fluxvm-network/src/dataplane.rs's `PodPeerCidr` exactly.
type PodPeerCidr struct {
	Addr      string `json:"addr"`
	PrefixLen uint8  `json:"prefix_len"`
}

// PodPeerPortRange is a protocol-scoped inclusive port range for one peer
// address (schema v8), for a Kubernetes NetworkPolicyPort carrying
// `endPort`. Field names match `PodPeerPortRange` in dataplane.rs exactly.
type PodPeerPortRange struct {
	Address  string            `json:"address"`
	Protocol PodPolicyProtocol `json:"protocol"`
	Start    uint16            `json:"start"`
	End      uint16            `json:"end"`
}

// PodIngressPolicy is the Pod-ingress-direction counterpart to
// PodNetworkPolicy's own egress-direction fields (schema v8), for
// Kubernetes NetworkPolicy `ingress` rules. No DenyAddresses field --
// Kubernetes NetworkPolicyIngressRule has no deny concept, matching
// dataplane.rs's `PodIngressPolicy`.
type PodIngressPolicy struct {
	DefaultDeny    bool               `json:"default_deny"`
	AuditMode      bool               `json:"audit_mode"`
	AllowAddresses []string           `json:"allow_addresses"`
	AllowCidrs     []PodPeerCidr      `json:"allow_cidrs"`
	AllowPortRules []PodPeerPortRule  `json:"allow_port_rules"`
	PortRanges     []PodPeerPortRange `json:"port_ranges"`
}

func (p *PodIngressPolicy) canonicalize() {
	p.AllowAddresses = canonicalStrings(p.AllowAddresses)
	p.AllowCidrs = canonicalCidrs(p.AllowCidrs)
	p.AllowPortRules = canonicalPortRules(p.AllowPortRules)
	p.PortRanges = canonicalPortRanges(p.PortRanges)
}

func equalIngressPolicy(a, b *PodIngressPolicy) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ac := *a
	bc := *b
	ac.canonicalize()
	bc.canonicalize()
	if ac.DefaultDeny != bc.DefaultDeny || ac.AuditMode != bc.AuditMode {
		return false
	}
	if len(ac.AllowAddresses) != len(bc.AllowAddresses) || len(ac.AllowCidrs) != len(bc.AllowCidrs) ||
		len(ac.AllowPortRules) != len(bc.AllowPortRules) || len(ac.PortRanges) != len(bc.PortRanges) {
		return false
	}
	for i := range ac.AllowAddresses {
		if ac.AllowAddresses[i] != bc.AllowAddresses[i] {
			return false
		}
	}
	for i := range ac.AllowCidrs {
		if ac.AllowCidrs[i] != bc.AllowCidrs[i] {
			return false
		}
	}
	for i := range ac.AllowPortRules {
		if ac.AllowPortRules[i] != bc.AllowPortRules[i] {
			return false
		}
	}
	for i := range ac.PortRanges {
		if ac.PortRanges[i] != bc.PortRanges[i] {
			return false
		}
	}
	return true
}

type PodNetworkPolicy struct {
	DefaultDeny    bool              `json:"default_deny"`
	AuditMode      bool              `json:"audit_mode"`
	AllowAddresses []string          `json:"allow_addresses"`
	DenyAddresses  []string          `json:"deny_addresses"`
	AllowPortRules []PodPeerPortRule `json:"allow_port_rules"`
	// Schema v8 additions -- see PodPeerCidr/PodPeerPortRange/PodIngressPolicy
	// doc comments above for the semantics of each.
	AllowCidrs []PodPeerCidr      `json:"allow_cidrs"`
	PortRanges []PodPeerPortRange `json:"port_ranges"`
	Ingress    *PodIngressPolicy  `json:"ingress"`
}

func (p *PodNetworkPolicy) Canonicalize() {
	p.AllowAddresses = canonicalStrings(p.AllowAddresses)
	p.DenyAddresses = canonicalStrings(p.DenyAddresses)
	p.AllowPortRules = canonicalPortRules(p.AllowPortRules)
	p.AllowCidrs = canonicalCidrs(p.AllowCidrs)
	p.PortRanges = canonicalPortRanges(p.PortRanges)
	if p.Ingress != nil {
		p.Ingress.canonicalize()
	}
}

func EqualPolicy(a, b *PodNetworkPolicy) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ac := *a
	bc := *b
	ac.Canonicalize()
	bc.Canonicalize()
	if ac.DefaultDeny != bc.DefaultDeny || ac.AuditMode != bc.AuditMode {
		return false
	}
	if len(ac.AllowAddresses) != len(bc.AllowAddresses) || len(ac.DenyAddresses) != len(bc.DenyAddresses) ||
		len(ac.AllowPortRules) != len(bc.AllowPortRules) || len(ac.AllowCidrs) != len(bc.AllowCidrs) ||
		len(ac.PortRanges) != len(bc.PortRanges) {
		return false
	}
	for i := range ac.AllowAddresses {
		if ac.AllowAddresses[i] != bc.AllowAddresses[i] {
			return false
		}
	}
	for i := range ac.DenyAddresses {
		if ac.DenyAddresses[i] != bc.DenyAddresses[i] {
			return false
		}
	}
	for i := range ac.AllowPortRules {
		if ac.AllowPortRules[i] != bc.AllowPortRules[i] {
			return false
		}
	}
	for i := range ac.AllowCidrs {
		if ac.AllowCidrs[i] != bc.AllowCidrs[i] {
			return false
		}
	}
	for i := range ac.PortRanges {
		if ac.PortRanges[i] != bc.PortRanges[i] {
			return false
		}
	}
	if !equalIngressPolicy(ac.Ingress, bc.Ingress) {
		return false
	}
	return true
}

type Client struct {
	baseURL   string
	tokenFile string
	http      *http.Client
}

type Options struct {
	BaseURL            string
	TokenFile          string
	CAFile             string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

func NewClient(opts Options) (*Client, error) {
	if opts.BaseURL == "" {
		opts.BaseURL = "http://127.0.0.1:7788"
	}
	parsed, err := url.Parse(opts.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid FluxVM API URL %q", opts.BaseURL)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	transport := &http.Transport{}
	if parsed.Scheme == "https" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.InsecureSkipVerify} //nolint:gosec -- explicit opt-in
		if !opts.InsecureSkipVerify && opts.CAFile != "" {
			pem, readErr := os.ReadFile(filepath.Clean(opts.CAFile))
			if readErr != nil {
				return nil, fmt.Errorf("read FluxVM CA file: %w", readErr)
			}
			pool, poolErr := x509.SystemCertPool()
			if poolErr != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("FluxVM CA file %q contains no usable certificates", opts.CAFile)
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}
	return &Client{
		baseURL:   strings.TrimRight(opts.BaseURL, "/"),
		tokenFile: opts.TokenFile,
		http:      &http.Client{Transport: transport, Timeout: opts.Timeout},
	}, nil
}

func (c *Client) ListVMs(ctx context.Context) ([]VMRecord, error) {
	var response struct {
		Items []VMRecord `json:"items"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/vms", nil, &response); err != nil {
		return nil, err
	}
	return response.Items, nil
}

func (c *Client) GetPodPolicy(ctx context.Context, vmID string) (*PodNetworkPolicy, error) {
	var raw json.RawMessage
	if err := c.doJSON(ctx, http.MethodGet, "/v1/vms/"+url.PathEscape(vmID)+"/network/pod-policy", nil, &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var policy PodNetworkPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, fmt.Errorf("decode FluxVM Pod policy for VM %s: %w", vmID, err)
	}
	policy.Canonicalize()
	return &policy, nil
}

func (c *Client) SetPodPolicy(ctx context.Context, vmID string, policy PodNetworkPolicy) error {
	policy.Canonicalize()
	return c.doJSON(ctx, http.MethodPost, "/v1/vms/"+url.PathEscape(vmID)+"/network/pod-policy", policy, nil)
}

func (c *Client) ClearPodPolicy(ctx context.Context, vmID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/vms/"+url.PathEscape(vmID)+"/network/pod-policy", nil, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, target any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if token, err := readOptionalToken(c.tokenFile); err != nil {
		return err
	} else if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fluxvm-networkpolicy-controller/0.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("FluxVM %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return fmt.Errorf("FluxVM %s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
	}
	if target == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 16<<20))
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("decode FluxVM %s %s: %w", method, path, err)
	}
	return nil
}

func readOptionalToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read FluxVM token file %q: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func canonicalStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func canonicalPortRules(rules []PodPeerPortRule) []PodPeerPortRule {
	set := make(map[PodPeerPortRule]struct{}, len(rules))
	for _, rule := range rules {
		if rule.Address != "" {
			set[rule] = struct{}{}
		}
	}
	out := make([]PodPeerPortRule, 0, len(set))
	for rule := range set {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func canonicalCidrs(cidrs []PodPeerCidr) []PodPeerCidr {
	set := make(map[PodPeerCidr]struct{}, len(cidrs))
	for _, c := range cidrs {
		if c.Addr != "" {
			set[c] = struct{}{}
		}
	}
	out := make([]PodPeerCidr, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].PrefixLen < out[j].PrefixLen
	})
	return out
}

func canonicalPortRanges(ranges []PodPeerPortRange) []PodPeerPortRange {
	set := make(map[PodPeerPortRange]struct{}, len(ranges))
	for _, r := range ranges {
		if r.Address != "" {
			set[r] = struct{}{}
		}
	}
	out := make([]PodPeerPortRange, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].End < out[j].End
	})
	return out
}
