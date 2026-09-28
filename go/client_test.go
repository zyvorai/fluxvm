// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T, opts ...Option) (*Client, *mockState) {
	t.Helper()
	srv, st := newMock()
	t.Cleanup(srv.Close)
	opts = append([]Option{WithToken(adminToken), WithTimeout(5 * time.Second)}, opts...)
	return NewClient(srv.URL, opts...), st
}

func newSandbox(t *testing.T, c *Client) *Sandbox {
	t.Helper()
	sb, err := c.CreateSandbox(context.Background(), CreateSandboxRequest{Template: "python"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	return sb
}

func bodyMap(t *testing.T, r recorded) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("request body is not JSON: %q", r.Body)
	}
	return m
}

// ---- create / list / auth

func TestCreateSendsOnlySetFieldsAndBearerToken(t *testing.T) {
	c, st := setup(t)
	sb, err := c.CreateSandbox(context.Background(), CreateSandboxRequest{
		Name: "demo", TTLSeconds: 60, MemoryMiB: 256, HTTPProxyPorts: []uint16{8080, 9090},
		Volumes:      []Volume{{Name: "data", GuestPath: "/data"}},
		Confidential: "auto",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := st.requests[0]
	if r.Method != "POST" || r.Path != "/v1/sandboxes" {
		t.Fatalf("got %s %s", r.Method, r.Path)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+adminToken {
		t.Fatalf("Authorization = %q", got)
	}
	sent := bodyMap(t, r)
	if sent["name"] != "demo" || sent["ttl_seconds"] != float64(60) || sent["memory_mib"] != float64(256) || sent["confidential"] != "auto" {
		t.Fatalf("unexpected body %v", sent)
	}
	vols := sent["volumes"].([]interface{})[0].(map[string]interface{})
	if vols["name"] != "data" || vols["guest_path"] != "/data" || vols["read_only"] != false {
		t.Fatalf("volume = %v", vols)
	}
	for _, absent := range []string{"template", "spec", "vcpus", "http_proxy_port"} {
		if _, ok := sent[absent]; ok {
			t.Errorf("%s should be omitted", absent)
		}
	}
	if sb.Info.Name != "demo" || sb.Info.Status != "running" || sb.ID() == "" {
		t.Fatalf("info = %+v", sb.Info)
	}
	if sb.Info.Confidential["requested"] != "auto" {
		t.Fatalf("confidential = %v", sb.Info.Confidential)
	}
	if sb.Info.GuestIP == nil || *sb.Info.GuestIP != "10.0.0.2" || sb.Info.PID == nil || *sb.Info.PID != 4242 {
		t.Fatalf("info = %+v", sb.Info)
	}
	if sb.Info.ExpiresAt != nil {
		t.Fatalf("expires_at should be nil, got %v", *sb.Info.ExpiresAt)
	}
	if !strings.Contains(string(sb.Info.Raw), `"request"`) {
		t.Fatalf("Raw should keep the whole record: %s", sb.Info.Raw)
	}
}

func TestCreateRejectsBadConfidentialWithoutContactingServer(t *testing.T) {
	c, st := setup(t)
	if _, err := c.CreateSandbox(context.Background(), CreateSandboxRequest{Template: "x", Confidential: "sometimes"}); err == nil {
		t.Fatal("expected error")
	}
	if st.reqCount() != 0 {
		t.Fatal("no request should have been sent")
	}
}

func TestCreateValidationErrorIsAPIError400(t *testing.T) {
	c, _ := setup(t)
	_, err := c.CreateSandbox(context.Background(), CreateSandboxRequest{Template: "missing"})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 400 || ae.Message != "template missing not found" {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, ErrAuth) || errors.Is(err, ErrNotFound) {
		t.Fatal("400 must not match auth or not-found sentinels")
	}
}

func TestListAndGetSandbox(t *testing.T) {
	c, st := setup(t)
	a := newSandbox(t, c)
	b := newSandbox(t, c)
	infos, err := c.ListSandboxes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 2 || infos[0].ID != a.ID() || infos[1].ID != b.ID() {
		t.Fatalf("infos = %+v", infos)
	}
	got, err := c.GetSandbox(context.Background(), a.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() != a.ID() {
		t.Fatalf("got %s", got.ID())
	}
	if r := st.last(); r.Method != "GET" || r.Path != "/v1/vms/"+a.ID() {
		t.Fatalf("GetSandbox used %s %s", r.Method, r.Path)
	}
	if _, err := c.GetSandbox(context.Background(), "00000000-0000-4000-8000-ffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestMissingAndBadTokenAre401(t *testing.T) {
	srv, _ := newMock()
	defer srv.Close()
	for _, tok := range []string{"", "nope"} {
		c := NewClient(srv.URL, WithToken(tok))
		_, err := c.ListSandboxes(context.Background())
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != 401 || ae.Message != "missing or invalid bearer token" {
			t.Fatalf("token %q: err = %v", tok, err)
		}
		if !errors.Is(err, ErrAuth) || errors.Is(err, ErrForbidden) {
			t.Fatalf("token %q: wrong sentinel match for %v", tok, err)
		}
	}
}

func TestReadOnlyTokenIsForbiddenAndForbiddenIsAlsoAuth(t *testing.T) {
	srv, _ := newMock()
	defer srv.Close()
	c := NewClient(srv.URL, WithToken(readonlyToken))
	_, err := c.CreateSandbox(context.Background(), CreateSandboxRequest{Template: "python"})
	if !errors.Is(err, ErrForbidden) || !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v", err)
	}
	// Reads are allowed for a read-only token.
	if _, err := c.ListSandboxes(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimitedCarriesRetryAfter(t *testing.T) {
	c, st := setup(t)
	st.rateLimitNext = true
	_, err := c.ListSandboxes(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	if ae.Status != 429 || ae.RetryAfter != 7*time.Second {
		t.Fatalf("ae = %+v", ae)
	}
}

func TestNonJSONErrorBodyBecomesMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream exploded", 502)
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL).ListSandboxes(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 502 || !strings.Contains(ae.Message, "upstream exploded") || len(ae.Body) == 0 {
		t.Fatalf("err = %v", err)
	}
}

func TestHealthOpenAPIHostConfidentialNeedNoSandbox(t *testing.T) {
	srv, _ := newMock()
	defer srv.Close()
	c := NewClient(srv.URL) // no token: healthz and openapi are public
	if ok, err := c.Health(context.Background()); err != nil || !ok {
		t.Fatalf("Health = %v, %v", ok, err)
	}
	spec, err := c.OpenAPI(context.Background())
	if err != nil || !strings.Contains(string(spec), "3.0.0") {
		t.Fatalf("OpenAPI = %s, %v", spec, err)
	}
	c2 := NewClient(srv.URL, WithToken(adminToken))
	hc, err := c2.HostConfidential(context.Background())
	if err != nil || hc["launch_supported"] != false {
		t.Fatalf("HostConfidential = %v, %v", hc, err)
	}
}

func TestCustomHeadersAreSentAndOverridable(t *testing.T) {
	c, st := setup(t, WithHeader("X-Client-Cert-Subject", "CN=tester"))
	if _, err := c.ListSandboxes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := st.last().Header.Get("X-Client-Cert-Subject"); got != "CN=tester" {
		t.Fatalf("header = %q", got)
	}
}

// ---- delete

func TestDeleteThenGoneAndDeleteAgainIsNotFound(t *testing.T) {
	c, _ := setup(t)
	sb := newSandbox(t, c)
	if err := sb.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sb.Delete(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete err = %v", err)
	}
	if err := sb.Refresh(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("refresh err = %v", err)
	}
}

func TestRefreshUpdatesInfo(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	st.sandboxes[sb.ID()]["status"] = "paused"
	if err := sb.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sb.Info.Status != "paused" {
		t.Fatalf("status = %q", sb.Info.Status)
	}
}

// ---- process

func TestRunSendsShellStringAndParsesResult(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	res, err := sb.Run(context.Background(), "echo hello")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Stdout != "hello\n" || res.ExitCode != 0 {
		t.Fatalf("res = %+v", res)
	}
	sent := bodyMap(t, st.last())
	if sent["command"] != "echo hello" {
		t.Fatalf("sent = %v", sent)
	}
	if _, ok := sent["timeout_seconds"]; ok {
		t.Fatal("timeout_seconds should be omitted by default")
	}
	res, err = sb.Run(context.Background(), "false")
	if err != nil || res.OK() || res.ExitCode != 1 || res.Stderr != "failed" {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

func TestRunArgsQuotesLikeShlex(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	if _, err := sb.RunArgs(context.Background(), []string{"echo", "a b", "it's", "", "plain-1_2.3/x"}); err != nil {
		t.Fatal(err)
	}
	want := `echo 'a b' 'it'"'"'s' '' plain-1_2.3/x`
	if got := bodyMap(t, st.last())["command"]; got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestRunTimeoutIsSentAndGuestTimeoutIsNotAnError(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	res, err := sb.Run(context.Background(), "sleep 5", WithExecTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 124 || res.OK() {
		t.Fatalf("res = %+v", res)
	}
	if got := bodyMap(t, st.last())["timeout_seconds"]; got != float64(2) {
		t.Fatalf("timeout_seconds = %v", got)
	}
}

func TestRunGuestAgentErrorIsAPIError400(t *testing.T) {
	c, _ := setup(t)
	sb := newSandbox(t, c)
	_, err := sb.Run(context.Background(), "agent-error now")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 400 || ae.Message != "guest agent error: boom" {
		t.Fatalf("err = %v", err)
	}
}

func TestSandboxRoutesOnlyForAdmin(t *testing.T) {
	srv, _ := newMock()
	defer srv.Close()
	admin := NewClient(srv.URL, WithToken(adminToken))
	sb, err := admin.CreateSandbox(context.Background(), CreateSandboxRequest{Template: "python"})
	if err != nil {
		t.Fatal(err)
	}
	ro, err := NewClient(srv.URL, WithToken(readonlyToken)).GetSandbox(context.Background(), sb.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ro.Run(context.Background(), "echo hi"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Run err = %v", err)
	}
	if _, err := ro.Baseline(context.Background(), []string{"/w"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Baseline err = %v", err)
	}
}

// ---- files

func TestWriteThenReadRoundTripsBinaryAndMode(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	data := []byte{0, 1, 2, 0xff, 'h', 'i', '\n'}
	if err := sb.WriteFile(context.Background(), "/tmp/x.bin", data, WithMode(0o755)); err != nil {
		t.Fatal(err)
	}
	sent := bodyMap(t, st.last())
	if sent["path"] != "/tmp/x.bin" || sent["mode"] != float64(0o755) || sent["content_base64"] != "AAEC/2hpCg==" {
		t.Fatalf("sent = %v", sent)
	}
	got, err := sb.ReadFileInfo(context.Background(), "/tmp/x.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != string(data) || got.Mode != 0o755 {
		t.Fatalf("got = %+v", got)
	}
	plain, err := sb.ReadFile(context.Background(), "/tmp/x.bin")
	if err != nil || string(plain) != string(data) {
		t.Fatalf("ReadFile = %v, %v", plain, err)
	}
}

func TestWriteWithoutModeOmitsIt(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	if err := sb.WriteFile(context.Background(), "/a", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, ok := bodyMap(t, st.last())["mode"]; ok {
		t.Fatal("mode should be omitted")
	}
}

func TestReadMissingFileIsAPIError400(t *testing.T) {
	c, _ := setup(t)
	sb := newSandbox(t, c)
	_, err := sb.ReadFile(context.Background(), "/nope")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 400 || !strings.Contains(ae.Message, "no such file") {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteOverTheGuestLimitFailsLocally(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	before := st.reqCount()
	err := sb.WriteFile(context.Background(), "/big", make([]byte, MaxFileTransferBytes+1))
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if st.reqCount() != before {
		t.Fatal("no request should have been sent")
	}
}

// ---- snapshot

func TestSnapshotReturnsServerPath(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	got, err := sb.Snapshot(context.Background(), "/var/lib/fluxvm/snap1")
	if err != nil || got != "/var/lib/fluxvm/snap1" {
		t.Fatalf("got %q, %v", got, err)
	}
	if bodyMap(t, st.last())["path"] != "/var/lib/fluxvm/snap1" {
		t.Fatalf("body = %s", st.last().Body)
	}
}

// ---- change-set

func TestBaselineThenChangesReportsAddedModifiedDeleted(t *testing.T) {
	c, st := setup(t)
	ctx := context.Background()
	sb := newSandbox(t, c)
	for path, content := range map[string]string{"/workspace/keep.txt": "same", "/workspace/edit.txt": "v1", "/workspace/gone.txt": "bye"} {
		if err := sb.WriteFile(ctx, path, []byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	base, err := sb.Baseline(ctx, []string{"/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	if base.Files != 3 || base.Mode != "sha256" || len(base.Paths) != 1 || base.Paths[0] != "/workspace" {
		t.Fatalf("base = %+v", base)
	}
	if got := bodyMap(t, st.last())["paths"].([]interface{}); len(got) != 1 || got[0] != "/workspace" {
		t.Fatalf("baseline body = %s", st.last().Body)
	}
	_ = sb.WriteFile(ctx, "/workspace/edit.txt", []byte("v2"))
	_ = sb.WriteFile(ctx, "/workspace/new.txt", []byte("hi"))
	delete(st.files[sb.ID()], "/workspace/gone.txt")

	ch, err := sb.Changes(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Added) != 1 || ch.Added[0] != "/workspace/new.txt" ||
		len(ch.Modified) != 1 || ch.Modified[0] != "/workspace/edit.txt" ||
		len(ch.Deleted) != 1 || ch.Deleted[0] != "/workspace/gone.txt" {
		t.Fatalf("ch = %+v", ch)
	}
	if ch.Unchanged != 1 || ch.Clean() || ch.BaselineTakenAtUnix != 1790585116 || ch.Mode != "sha256" {
		t.Fatalf("ch = %+v", ch)
	}
	if string(st.last().Body) != "{}" {
		t.Fatalf("nil paths should send an empty object, got %s", st.last().Body)
	}
}

func TestChangesCanNarrowToASubsetOfPaths(t *testing.T) {
	c, st := setup(t)
	ctx := context.Background()
	sb := newSandbox(t, c)
	_ = sb.WriteFile(ctx, "/a/x", []byte("1"))
	_ = sb.WriteFile(ctx, "/b/y", []byte("1"))
	if _, err := sb.Baseline(ctx, []string{"/a", "/b"}); err != nil {
		t.Fatal(err)
	}
	_ = sb.WriteFile(ctx, "/a/x", []byte("2"))
	_ = sb.WriteFile(ctx, "/b/y", []byte("2"))
	ch, err := sb.Changes(ctx, []string{"/a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Modified) != 1 || ch.Modified[0] != "/a/x" {
		t.Fatalf("ch = %+v", ch)
	}
	if got := bodyMap(t, st.last())["paths"].([]interface{}); len(got) != 1 || got[0] != "/a" {
		t.Fatalf("body = %s", st.last().Body)
	}
}

func TestCleanChangesetAndMissingBaseline(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	sb := newSandbox(t, c)
	if _, err := sb.Changes(ctx, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no baseline err = %v", err)
	}
	_ = sb.WriteFile(ctx, "/w/f", []byte("1"))
	if _, err := sb.Baseline(ctx, []string{"/w"}); err != nil {
		t.Fatal(err)
	}
	ch, err := sb.Changes(ctx, nil)
	if err != nil || !ch.Clean() {
		t.Fatalf("ch = %+v err = %v", ch, err)
	}
}

func TestBaselineRejectsUnsafePathsWithAPIError400(t *testing.T) {
	c, _ := setup(t)
	sb := newSandbox(t, c)
	for _, paths := range [][]string{{"relative/../x"}, {"/a/../b"}, {}, nil} {
		_, err := sb.Baseline(context.Background(), paths)
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != 400 {
			t.Fatalf("paths %v: err = %v", paths, err)
		}
	}
}

// ---- http proxy

func TestHTTPExplicitPortWithQueryBodyAndHeaders(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	resp, err := sb.HTTP(context.Background(), HTTPRequest{
		Port: 8080, Method: "post", Path: "/api/items",
		Body:   map[string]int{"a": 1},
		Header: http.Header{"X-Test": {"1"}},
		Query:  url.Values{"q": {"x y"}, "n": {"1", "2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := st.last()
	if r.Method != "POST" || !strings.HasPrefix(r.Path, "/v1/sandboxes/"+sb.ID()+"/http/8080/api/items?") {
		t.Fatalf("request = %s %s", r.Method, r.Path)
	}
	q, _ := url.ParseQuery(strings.SplitN(r.Path, "?", 2)[1])
	if q.Get("q") != "x y" || strings.Join(q["n"], ",") != "1,2" {
		t.Fatalf("query = %v", q)
	}
	if r.Header.Get("Authorization") != "Bearer "+adminToken || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", r.Header)
	}
	if !resp.OK() || resp.Header.Get("X-Guest") != "hello" {
		t.Fatalf("resp = %+v", resp)
	}
	var echoed map[string]interface{}
	if err := resp.JSON(&echoed); err != nil {
		t.Fatal(err)
	}
	if echoed["method"] != "POST" || echoed["port"] != "8080" || echoed["x_test"] != "1" || echoed["body"] != `{"a":1}` {
		t.Fatalf("echoed = %v", echoed)
	}
}

func TestHTTPDefaultPortRouteAndBodyKinds(t *testing.T) {
	c, st := setup(t)
	sb := newSandbox(t, c)
	if _, err := sb.HTTP(context.Background(), HTTPRequest{Method: "GET", Path: "health"}); err != nil {
		t.Fatal(err)
	}
	if got := st.last().Path; got != "/sandbox/"+sb.ID()+"/health" {
		t.Fatalf("path = %s", got)
	}
	for _, tc := range []struct {
		body interface{}
		ctyp string
	}{
		{[]byte{1, 2}, "application/octet-stream"},
		{"hello", "text/plain; charset=utf-8"},
		{[]int{1}, "application/json"},
	} {
		if _, err := sb.HTTP(context.Background(), HTTPRequest{Method: "PUT", Path: "/x", Body: tc.body}); err != nil {
			t.Fatal(err)
		}
		if got := st.last().Header.Get("Content-Type"); got != tc.ctyp {
			t.Fatalf("body %T: Content-Type = %q, want %q", tc.body, got, tc.ctyp)
		}
	}
	// An explicit Content-Type wins.
	if _, err := sb.HTTP(context.Background(), HTTPRequest{Method: "PUT", Path: "/x", Body: "a=b", Header: http.Header{"content-type": {"application/x-www-form-urlencoded"}}}); err != nil {
		t.Fatal(err)
	}
	if got := st.last().Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q", got)
	}
}

func TestHTTPGuestStatusIsReturnedNotRaisedAndRedirectsAreNotFollowed(t *testing.T) {
	c, _ := setup(t)
	sb := newSandbox(t, c)
	resp, err := sb.HTTP(context.Background(), HTTPRequest{Port: 8080, Method: "GET", Path: "teapot"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 418 || resp.OK() || resp.Text() != "short and stout" || resp.Header.Get("X-Guest") != "yes" {
		t.Fatalf("resp = %+v", resp)
	}
	var ae *APIError
	if err := resp.RaiseForStatus(); !errors.As(err, &ae) || ae.Status != 418 {
		t.Fatalf("RaiseForStatus = %v", err)
	}
	redir, err := sb.HTTP(context.Background(), HTTPRequest{Port: 8080, Method: "GET", Path: "redirect"})
	if err != nil || redir.Status != 302 || redir.Header.Get("Location") != "/elsewhere" {
		t.Fatalf("redirect resp = %+v err = %v", redir, err)
	}
}

func TestHTTPPathEscapingKeepsSafeCharacters(t *testing.T) {
	if got := escapeProxyPath("a b/c:d@e/f%g"); got != "a%20b/c:d@e/f%25g" {
		t.Fatalf("escape = %q", got)
	}
}

func TestHTTPProxyNeedsAdmin(t *testing.T) {
	srv, _ := newMock()
	defer srv.Close()
	sb, _ := NewClient(srv.URL, WithToken(adminToken)).CreateSandbox(context.Background(), CreateSandboxRequest{Template: "p"})
	ro := NewClient(srv.URL, WithToken(readonlyToken))
	roSb, err := ro.GetSandbox(context.Background(), sb.ID())
	if err != nil {
		t.Fatal(err)
	}
	// The proxy answers 403 itself; that is indistinguishable from a guest 403
	// so it is returned as a response, not raised.
	resp, err := roSb.HTTP(context.Background(), HTTPRequest{Port: 8080, Method: "GET", Path: "x"})
	if err != nil || resp.Status != 403 {
		t.Fatalf("resp = %+v err = %v", resp, err)
	}
}

// ---- timeouts, cancellation, connection failures

func TestClientTimeoutMapsToErrTimeout(t *testing.T) {
	c, _ := setup(t, WithTimeout(200*time.Millisecond))
	sb := newSandbox(t, c)
	_, err := sb.HTTP(context.Background(), HTTPRequest{Port: 8080, Method: "GET", Path: "slow"})
	if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestPerRequestTimeoutOverridesClientDefault(t *testing.T) {
	c, _ := setup(t, WithTimeout(100*time.Millisecond))
	sb := newSandbox(t, c)
	resp, err := sb.HTTP(context.Background(), HTTPRequest{Port: 8080, Method: "GET", Path: "slow", Timeout: 5 * time.Second})
	if err != nil || !resp.OK() {
		t.Fatalf("resp = %+v err = %v", resp, err)
	}
}

func TestContextDeadlineBeatsLongerClientTimeout(t *testing.T) {
	c, _ := setup(t, WithTimeout(10*time.Second))
	sb := newSandbox(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := sb.HTTP(ctx, HTTPRequest{Port: 8080, Method: "GET", Path: "slow"})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Fatal("deadline was not honored")
	}
}

func TestCallerCancellationIsContextCanceledNotTimeout(t *testing.T) {
	c, _ := setup(t)
	sb := newSandbox(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	_, err := sb.HTTP(ctx, HTTPRequest{Port: 8080, Method: "GET", Path: "slow"})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestAlreadyCancelledContextSendsNothing(t *testing.T) {
	c, st := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ListSandboxes(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if st.reqCount() != 0 {
		t.Fatal("no request should have been sent")
	}
}

func TestRunWaitsLongerThanClientTimeoutForGuestLimit(t *testing.T) {
	// The HTTP wait is exec timeout + slack, not the (short) client default.
	c, st := setup(t, WithTimeout(50*time.Millisecond))
	sb := newSandbox(t, c)
	st.execDelay = 300 * time.Millisecond
	res, err := sb.Run(context.Background(), "echo slow", WithExecTimeout(2*time.Second))
	if err != nil || res.Stdout != "slow\n" {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

func TestConnectionRefusedMapsToErrConnection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	_, err = NewClient("http://" + addr).ListSandboxes(context.Background())
	if !errors.Is(err, ErrConnection) || errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestWithHTTPClientIsCopiedNotMutated(t *testing.T) {
	custom := &http.Client{Timeout: 3 * time.Second}
	c, _ := setup(t, WithHTTPClient(custom))
	if custom.CheckRedirect != nil {
		t.Fatal("caller's http.Client must not be modified")
	}
	if _, err := c.ListSandboxes(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBaseURLTrailingSlashIsTrimmed(t *testing.T) {
	srv, st := newMock()
	defer srv.Close()
	c := NewClient(srv.URL+"///", WithToken(adminToken))
	if _, err := c.ListSandboxes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := st.last().Path; got != "/v1/sandboxes" {
		t.Fatalf("path = %s", got)
	}
}
