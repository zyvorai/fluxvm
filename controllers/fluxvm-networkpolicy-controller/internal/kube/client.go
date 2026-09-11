// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package kube

import (
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
	"strconv"
	"strings"
	"time"
)

const (
	defaultSAToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultSACA    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type Client struct {
	baseURL   string
	tokenFile string
	http      *http.Client
	pageSize  int
}

type Options struct {
	BaseURL            string
	TokenFile          string
	CAFile             string
	InsecureSkipVerify bool
	Timeout            time.Duration
	PageSize           int
}

func InClusterBaseURL() string {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = os.Getenv("KUBERNETES_SERVICE_PORT")
	}
	if host == "" {
		return ""
	}
	if port == "" {
		port = "443"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "https://" + host + ":" + port
}

func NewClient(opts Options) (*Client, error) {
	if opts.BaseURL == "" {
		opts.BaseURL = InClusterBaseURL()
	}
	if opts.BaseURL == "" {
		return nil, errors.New("Kubernetes API URL is empty and in-cluster environment variables are unavailable")
	}
	parsed, err := url.Parse(opts.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Kubernetes API URL %q", opts.BaseURL)
	}
	if opts.TokenFile == "" {
		opts.TokenFile = defaultSAToken
	}
	if opts.CAFile == "" {
		opts.CAFile = defaultSACA
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.PageSize <= 0 {
		opts.PageSize = 500
	}

	transport := &http.Transport{}
	if parsed.Scheme == "https" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.InsecureSkipVerify} //nolint:gosec -- explicit opt-in flag
		if !opts.InsecureSkipVerify && opts.CAFile != "" {
			pem, readErr := os.ReadFile(filepath.Clean(opts.CAFile))
			if readErr != nil {
				return nil, fmt.Errorf("read Kubernetes CA file: %w", readErr)
			}
			pool, poolErr := x509.SystemCertPool()
			if poolErr != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("Kubernetes CA file %q contains no usable certificates", opts.CAFile)
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &Client{
		baseURL:   strings.TrimRight(opts.BaseURL, "/"),
		tokenFile: opts.TokenFile,
		http:      &http.Client{Transport: transport, Timeout: opts.Timeout},
		pageSize:  opts.PageSize,
	}, nil
}

type listResponse[T any] struct {
	Metadata ListMeta `json:"metadata"`
	Items    []T      `json:"items"`
}

func listAll[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var out []T
	continuation := ""
	for {
		u, err := url.Parse(c.baseURL + path)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("limit", strconv.Itoa(c.pageSize))
		if continuation != "" {
			q.Set("continue", continuation)
		}
		u.RawQuery = q.Encode()

		var page listResponse[T]
		if err := c.getJSON(ctx, u.String(), &page); err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if page.Metadata.Continue == "" {
			return out, nil
		}
		continuation = page.Metadata.Continue
	}
}

func (c *Client) Pods(ctx context.Context) ([]Pod, error) {
	return listAll[Pod](ctx, c, "/api/v1/pods")
}

func (c *Client) Namespaces(ctx context.Context) ([]Namespace, error) {
	return listAll[Namespace](ctx, c, "/api/v1/namespaces")
}

func (c *Client) Services(ctx context.Context) ([]Service, error) {
	return listAll[Service](ctx, c, "/api/v1/services")
}

// FLUXVM_SECURE_CONTAINERS_SET18: EndpointSlices are consulted only when
// Service ClusterIP inclusion is enabled by the controller. The discovery
// v1 API is stable and is kube-proxy's Service-backend source of truth.
func (c *Client) EndpointSlices(ctx context.Context) ([]EndpointSlice, error) {
	return listAll[EndpointSlice](ctx, c, "/apis/discovery.k8s.io/v1/endpointslices")
}

func (c *Client) NetworkPolicies(ctx context.Context) ([]NetworkPolicy, error) {
	return listAll[NetworkPolicy](ctx, c, "/apis/networking.k8s.io/v1/networkpolicies")
}

func (c *Client) getJSON(ctx context.Context, endpoint string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if token, err := readOptionalToken(c.tokenFile); err != nil {
		return err
	} else if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fluxvm-networkpolicy-controller/0.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Kubernetes GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return fmt.Errorf("Kubernetes GET %s returned %s: %s", endpoint, resp.Status, strings.TrimSpace(string(body)))
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<20))
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("decode Kubernetes GET %s: %w", endpoint, err)
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
		return "", fmt.Errorf("read token file %q: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}
