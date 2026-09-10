// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/controller"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/fluxvm"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/metrics"
)

var version = "dev"

func main() {
	var (
		nodeName          = flag.String("node-name", env("NODE_NAME", ""), "Kubernetes node name managed by this controller")
		interval          = flag.Duration("interval", envDuration("RECONCILE_INTERVAL", 5*time.Second), "full reconciliation interval")
		kubeURL           = flag.String("kube-api", env("KUBE_API", ""), "Kubernetes API URL; defaults to in-cluster service")
		kubeToken         = flag.String("kube-token-file", env("KUBE_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"), "Kubernetes bearer token file")
		kubeCA            = flag.String("kube-ca-file", env("KUBE_CA_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"), "Kubernetes CA bundle")
		kubeInsecure      = flag.Bool("kube-insecure-skip-verify", envBool("KUBE_INSECURE_SKIP_VERIFY", false), "skip Kubernetes TLS verification (not recommended)")
		fluxURL           = flag.String("fluxvm-url", env("FLUXVM_URL", "http://127.0.0.1:7788"), "node-local FluxVM API URL")
		fluxToken         = flag.String("fluxvm-token-file", env("FLUXVM_TOKEN_FILE", ""), "FluxVM bearer token file")
		fluxCA            = flag.String("fluxvm-ca-file", env("FLUXVM_CA_FILE", ""), "FluxVM CA bundle for HTTPS")
		fluxInsecure      = flag.Bool("fluxvm-insecure-skip-verify", envBool("FLUXVM_INSECURE_SKIP_VERIFY", false), "skip FluxVM TLS verification (not recommended)")
		maxAddresses      = flag.Int("max-addresses", envInt("MAX_ADDRESSES", 12000), "maximum exact allow-address entries per Pod")
		includeServiceIPs = flag.Bool("include-service-clusterips", envBool("INCLUDE_SERVICE_CLUSTERIPS", false), "conservatively include ClusterIPs whose selected backends are all allowed peers")
		globalAudit       = flag.Bool("audit", envBool("POLICY_AUDIT", false), "set generated FluxVM Pod policies to audit/log-and-allow mode")
		metricsAddr       = flag.String("metrics-listen", env("METRICS_LISTEN", ":9090"), "health/readiness/metrics listen address")
		showVersion       = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *nodeName == "" {
		fmt.Fprintln(os.Stderr, "--node-name or NODE_NAME is required")
		os.Exit(2)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	kubeClient, err := kube.NewClient(kube.Options{
		BaseURL: *kubeURL, TokenFile: *kubeToken, CAFile: *kubeCA,
		InsecureSkipVerify: *kubeInsecure, Timeout: 10 * time.Second, PageSize: 500,
	})
	if err != nil {
		logger.Error("create Kubernetes client", "error", err)
		os.Exit(1)
	}
	fluxClient, err := fluxvm.NewClient(fluxvm.Options{
		BaseURL: *fluxURL, TokenFile: *fluxToken, CAFile: *fluxCA,
		InsecureSkipVerify: *fluxInsecure, Timeout: 5 * time.Second,
	})
	if err != nil {
		logger.Error("create FluxVM client", "error", err)
		os.Exit(1)
	}

	m := metrics.New()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	healthServer := startHealthServer(*metricsAddr, *interval, m, logger)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = healthServer.Shutdown(shutdownCtx)
	}()

	ctrl := &controller.Controller{
		Kube: kubeClient, FluxVM: fluxClient, Metrics: m, Logger: logger,
		NodeName: *nodeName, Interval: *interval, MaxAddresses: *maxAddresses,
		IncludeServiceClusterIPs: *includeServiceIPs, GlobalAudit: *globalAudit,
	}
	logger.Info("starting FluxVM NetworkPolicy controller", "version", version, "node", *nodeName, "interval", interval.String(), "fluxvm_url", *fluxURL)
	if err := ctrl.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("controller stopped", "error", err)
		os.Exit(1)
	}
}

func startHealthServer(addr string, interval time.Duration, m *metrics.Metrics, logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		maxAge := 3*interval + 30*time.Second
		if !m.Ready(maxAge) {
			http.Error(w, "no recent successful reconciliation", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		m.WritePrometheus(w)
	})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("health server stopped", "error", err)
		}
	}()
	return server
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "TRUE", "yes", "YES", "on", "ON":
		return true
	case "0", "false", "FALSE", "no", "NO", "off", "OFF":
		return false
	default:
		return fallback
	}
}
func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
