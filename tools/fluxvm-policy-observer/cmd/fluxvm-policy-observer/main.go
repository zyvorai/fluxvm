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

	"github.com/zyvorai/fluxvm/tools/fluxvm-policy-observer/internal/metrics"
	"github.com/zyvorai/fluxvm/tools/fluxvm-policy-observer/internal/observer"
)

var version = "dev"

func main() {
	listen := flag.String("listen", env("LISTEN", ":9091"), "HTTP listen address for /metrics, /healthz and /readyz")
	pinRoot := flag.String("pin-root", env("FLUXVM_BPF_PIN_ROOT", observer.DefaultPinRoot), "FluxVM bpffs pin root")
	metaRoot := flag.String("meta-root", env("FLUXVM_BPF_META_ROOT", observer.DefaultMetaRoot), "FluxVM per-VM eBPF metadata root")
	interval := flag.Duration("interval", envDuration("SCRAPE_INTERVAL", 5*time.Second), "collection interval")
	timeout := flag.Duration("command-timeout", envDuration("COMMAND_TIMEOUT", 2*time.Second), "per-VM command timeout")
	bpftool := flag.String("bpftool", env("BPFTOOL", "bpftool"), "bpftool executable")
	tc := flag.String("tc", env("TC", "tc"), "tc executable")
	once := flag.Bool("once", false, "collect once, write Prometheus metrics to stdout, and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	collector := observer.Collector{PinRoot: *pinRoot, MetaRoot: *metaRoot, BPFTool: *bpftool, TC: *tc, Timeout: *timeout}
	store := metrics.New()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *once {
		store.Update(collector.Collect(ctx))
		store.WritePrometheus(os.Stdout)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !store.Ready(3**interval + 10*time.Second) {
			http.Error(w, "no recent scrape", 503)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		store.WritePrometheus(w)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http server", "error", err)
			stop()
		}
	}()

	collect := func() {
		snap := collector.Collect(ctx)
		store.Update(snap)
		errs := len(snap.Errors)
		for _, vm := range snap.VMs {
			errs += len(vm.Errors)
		}
		log.Info("policy telemetry collected", "vms", len(snap.VMs), "errors", errs)
	}
	collect()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdown)
			return
		case <-ticker.C:
			collect()
		}
	}
}
func env(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}
func envDuration(k string, f time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return f
	}
	d, e := time.ParseDuration(v)
	if e != nil || d <= 0 {
		return f
	}
	return d
}
