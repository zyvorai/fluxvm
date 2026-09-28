// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout is the per-request timeout when WithTimeout is not given.
const DefaultTimeout = 30 * time.Second

// Client talks to one FluxVM API endpoint. It is safe for concurrent use.
type Client struct {
	baseURL    string
	token      string
	timeout    time.Duration
	headers    http.Header
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithToken sets the bearer token (a static token or an OIDC JWT). Omit it
// only when the server runs unauthenticated on loopback.
func WithToken(token string) Option { return func(c *Client) { c.token = token } }

// WithTimeout sets the default per-request timeout. A context deadline that
// is sooner still wins.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// WithHeader adds a header sent on every request (for example the
// X-Client-Cert-* identity headers set by a trusted mTLS frontend).
func WithHeader(key, value string) Option {
	return func(c *Client) { c.headers.Add(key, value) }
}

// WithHTTPClient supplies the underlying http.Client (custom TLS, proxy,
// transport). It is copied, not modified; the copy never follows redirects
// so proxied guest 3xx responses pass through untouched.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			cp := *h
			c.httpClient = &cp
		}
	}
}

// NewClient returns a Client for baseURL, e.g. "http://127.0.0.1:8080".
func NewClient(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		timeout:    DefaultTimeout,
		headers:    http.Header{},
		httpClient: &http.Client{},
	}
	for _, opt := range opts {
		opt(c)
	}
	c.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

// do performs one request and returns the status, headers and body for every
// HTTP status. timeout <= 0 uses the client default.
func (c *Client) do(ctx context.Context, method, path string, body []byte, hdr http.Header, timeout time.Duration) (int, http.Header, []byte, error) {
	if c.baseURL == "" {
		return 0, nil, nil, errors.New("fluxvm: base URL is required")
	}
	if timeout <= 0 {
		timeout = c.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("fluxvm: building request: %w", err)
	}
	for k, vs := range c.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for k, vs := range hdr {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, classify(ctx, method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, classify(ctx, method, path, err)
	}
	return resp.StatusCode, resp.Header, data, nil
}

// classify maps a transport error onto the package's sentinels. A caller's
// own cancellation is returned as context.Canceled, untouched.
func classify(ctx context.Context, method, path string, err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded ||
		(errors.As(err, &ne) && ne.Timeout()) {
		return fmt.Errorf("%w: %s %s: %w", ErrTimeout, method, path, context.DeadlineExceeded)
	}
	return fmt.Errorf("%w: %s %s: %v", ErrConnection, method, path, err)
}

// call sends an optional JSON payload and decodes a JSON answer into out
// (nil to ignore). Statuses other than expect (default 200/201) become
// *APIError.
func (c *Client) call(ctx context.Context, method, path string, payload, out interface{}, timeout time.Duration, expect ...int) error {
	var body []byte
	hdr := http.Header{"Accept": {"application/json"}}
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("fluxvm: encoding request: %w", err)
		}
		body = b
		hdr.Set("Content-Type", "application/json")
	}
	status, rh, data, err := c.do(ctx, method, path, body, hdr, timeout)
	if err != nil {
		return err
	}
	if len(expect) == 0 {
		expect = []int{http.StatusOK, http.StatusCreated}
	}
	ok := false
	for _, s := range expect {
		if s == status {
			ok = true
		}
	}
	if !ok {
		return newAPIError(status, rh, data)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if raw, isRaw := out.(*json.RawMessage); isRaw {
		*raw = append((*raw)[:0], data...)
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &APIError{Status: status, Message: "response was not the expected JSON: " + err.Error(), Body: data}
	}
	return nil
}

// Health calls GET /healthz (no auth needed) and reports whether the server says ok.
func (c *Client) Health(ctx context.Context) (bool, error) {
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.call(ctx, http.MethodGet, "/healthz", nil, &out, 0); err != nil {
		return false, err
	}
	return out.OK, nil
}

// OpenAPI calls GET /v1/openapi.json (no auth needed) and returns the raw spec.
func (c *Client) OpenAPI(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.call(ctx, http.MethodGet, "/v1/openapi.json", nil, &out, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// HostConfidential calls GET /v1/host/confidential: what the host offers for
// confidential guests.
func (c *Client) HostConfidential(ctx context.Context) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.call(ctx, http.MethodGet, "/v1/host/confidential", nil, &out, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateSandbox calls POST /v1/sandboxes (needs an admin token).
func (c *Client) CreateSandbox(ctx context.Context, req CreateSandboxRequest) (*Sandbox, error) {
	if req.Confidential != "" && req.Confidential != "auto" && req.Confidential != "required" {
		return nil, errors.New(`fluxvm: Confidential must be "auto" or "required"`)
	}
	var raw json.RawMessage
	if err := c.call(ctx, http.MethodPost, "/v1/sandboxes", req, &raw, 0, http.StatusCreated); err != nil {
		return nil, err
	}
	info, err := parseSandboxInfo(raw)
	if err != nil {
		return nil, err
	}
	return &Sandbox{client: c, Info: info}, nil
}

// ListSandboxes calls GET /v1/sandboxes: the caller's tenant's sandboxes.
func (c *Client) ListSandboxes(ctx context.Context) ([]SandboxInfo, error) {
	var out struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := c.call(ctx, http.MethodGet, "/v1/sandboxes", nil, &out, 0); err != nil {
		return nil, err
	}
	infos := make([]SandboxInfo, 0, len(out.Items))
	for _, item := range out.Items {
		info, err := parseSandboxInfo(item)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

// GetSandbox attaches to an existing sandbox via GET /v1/vms/{id} (a sandbox
// is a VM record; there is no dedicated GET /v1/sandboxes/{id}).
func (c *Client) GetSandbox(ctx context.Context, id string) (*Sandbox, error) {
	var raw json.RawMessage
	if err := c.call(ctx, http.MethodGet, "/v1/vms/"+url.PathEscape(id), nil, &raw, 0); err != nil {
		return nil, err
	}
	info, err := parseSandboxInfo(raw)
	if err != nil {
		return nil, err
	}
	return &Sandbox{client: c, Info: info}, nil
}
