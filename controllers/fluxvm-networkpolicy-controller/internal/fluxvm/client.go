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

// PodPolicyRule is the Set 14 wire rule. One rule is one peer CIDR combined
// with one protocol/port interval. Rules are ORed; fields inside a rule are
// ANDed. Empty protocol with zero ports means all L4 protocols/ports.
type PodPolicyRule struct {
	Direction string `json:"direction"`
	CIDR      string `json:"cidr"`
	Protocol  string `json:"protocol,omitempty"`
	PortStart uint16 `json:"port_start,omitempty"`
	PortEnd   uint16 `json:"port_end,omitempty"`
}

type PodNetworkPolicy struct {
	// SchemaVersion 2 enables directional CIDR/L4 rules. Version 0/1 retains
	// the Set 6S exact-address egress ABI and remains readable during rollout.
	SchemaVersion   int             `json:"schema_version,omitempty"`
	DefaultDeny     bool            `json:"default_deny"`
	AuditMode       bool            `json:"audit_mode"`
	AllowAddresses  []string        `json:"allow_addresses"`
	DenyAddresses   []string        `json:"deny_addresses"`
	EgressIsolated  bool            `json:"egress_isolated,omitempty"`
	IngressIsolated bool            `json:"ingress_isolated,omitempty"`
	Rules           []PodPolicyRule `json:"rules,omitempty"`
}

func (p *PodNetworkPolicy) Canonicalize() {
	p.AllowAddresses = canonicalStrings(p.AllowAddresses)
	p.DenyAddresses = canonicalStrings(p.DenyAddresses)
	for i := range p.Rules {
		p.Rules[i].Direction = strings.ToLower(strings.TrimSpace(p.Rules[i].Direction))
		p.Rules[i].Protocol = strings.ToUpper(strings.TrimSpace(p.Rules[i].Protocol))
	}
	sort.Slice(p.Rules, func(i, j int) bool {
		a, b := p.Rules[i], p.Rules[j]
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
	if len(p.Rules) > 1 {
		out := p.Rules[:0]
		for _, r := range p.Rules {
			if len(out) == 0 || out[len(out)-1] != r {
				out = append(out, r)
			}
		}
		p.Rules = out
	}
}

func EqualPolicy(a, b *PodNetworkPolicy) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ac, bc := *a, *b
	ac.Rules = append([]PodPolicyRule(nil), a.Rules...)
	bc.Rules = append([]PodPolicyRule(nil), b.Rules...)
	ac.AllowAddresses = append([]string(nil), a.AllowAddresses...)
	bc.AllowAddresses = append([]string(nil), b.AllowAddresses...)
	ac.DenyAddresses = append([]string(nil), a.DenyAddresses...)
	bc.DenyAddresses = append([]string(nil), b.DenyAddresses...)
	ac.Canonicalize()
	bc.Canonicalize()
	ab, _ := json.Marshal(ac)
	bb, _ := json.Marshal(bc)
	return bytes.Equal(ab, bb)
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
	return &Client{baseURL: strings.TrimRight(opts.BaseURL, "/"), tokenFile: opts.TokenFile, http: &http.Client{Transport: transport, Timeout: opts.Timeout}}, nil
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
	req.Header.Set("User-Agent", "fluxvm-networkpolicy-controller/0.2")
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
