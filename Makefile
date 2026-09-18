# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0

# Remote deploy: make deploy HOST=80.79.5.173 USER=sus
HOST ?=
USER ?= sus
DEPLOY_FLAGS ?= --key

.PHONY: help build release install test fmt fmt-check clippy \
	test-policy bpf preflight check test-devops test-packetflow test-microvm \
	test-fc deploy deploy-quick deploy-verify deploy-preflight \
	test-h1-snap evidence-s8

help:
	@echo "FluxVM — common targets"
	@echo "  build / release / install   local cargo + optional /usr/local install"
	@echo "  test / test-fc / check      unit / FC adoption / gate suite"
	@echo "  test-h1-snap                FLUXKVM1 virtio v3 round-trip unit test"
	@echo "  evidence-s8                 Policy Observer scrape evidence script"
	@echo "  preflight                   scripts/preflight.sh"
	@echo "  deploy HOST=<ip> [USER=sus] full remote deploy (scripts/deploy-remote.sh)"
	@echo "  deploy-quick HOST=<ip>      rsync + remote rebuild only"
	@echo "  deploy-verify HOST=<ip>     remote preflight only"
	@echo "  deploy-preflight HOST=<ip>  SSH connectivity / disk / sudo checks"

build:
	cargo build --workspace --all-targets

release:
	cargo build --release -p fluxctl -p fluxvm-guest-agent \
		-p fluxvm-hypervisor -p fluxvm-microvm -p fluxvm-kube

install: release
	install -m755 target/release/fluxctl /usr/local/bin/fluxctl
	ln -sfn fluxctl /usr/local/bin/fluxvm
	install -m755 target/release/fluxvm-hypervisor /usr/local/bin/fluxvm-hypervisor
	install -m755 target/release/fluxvm-microvm /usr/local/bin/fluxvm-microvm
	install -m755 target/release/fluxvm-kube /usr/local/bin/fluxvm-kube
	@test -f /etc/fluxvm.toml || install -m644 config.example.toml /etc/fluxvm.toml

test:
	cargo test --workspace

# FC1–FC3 adoption unit tests (cpu_template, rate limiters, jailer config).
test-fc:
	cargo test -p fluxvm-scheduler --lib cpu_template
	cargo test -p fluxvm-firecracker --lib rate_limiter
	cargo test -p fluxvm-core --lib

test-h1-snap:
	cargo test -p fluxvm-hypervisor --lib virtio_v3_round_trip

evidence-s8:
	bash scripts/evidence-policy-observer-scrape.sh

# Deliberately not `--all`: that also sweeps in local path dependencies
# outside this workspace (e.g. the sibling guestkit repo some crates
# reference), which isn't this repo's code to format-check. Plain `cargo
# fmt` scopes to this workspace's own declared members only.
fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy --workspace --no-deps

test-microvm:
	bash scripts/test-microvm.sh

test-policy:
	python3 scripts/test-security-groups.py
	python3 scripts/test-network-policy.py
	python3 scripts/test-production-dataplane.py
	python3 scripts/test-project-production.py

test-packetflow:
	bash scripts/test-hubble-ui.sh
	python3 scripts/test-packetflow.py
	@echo "Rust packetflow tests: cargo test -p fluxvm-network packetflow"

bpf:
	./scripts/build-ebpf.sh

preflight:
	./scripts/preflight.sh

test-devops:
	cd examples/devops && python3 -m unittest test_contract.py test_examples.py -v
	bash scripts/test-devops-gate.sh
	bash scripts/test-upgrade-snapshot.sh

check: fmt-check clippy test-policy preflight test-devops test-packetflow

# --- remote deploy (scripts/deploy-remote.sh) ---------------------------------

define require-host
	@test -n "$(HOST)" || (echo "HOST required, e.g. make $@ HOST=80.79.5.173 USER=sus"; exit 1)
endef

deploy:
	$(require-host)
	./scripts/deploy-remote.sh "$(HOST)" "$(USER)" $(DEPLOY_FLAGS)

deploy-quick:
	$(require-host)
	./scripts/deploy-remote.sh "$(HOST)" "$(USER)" $(DEPLOY_FLAGS) --quick

deploy-verify:
	$(require-host)
	./scripts/deploy-remote.sh "$(HOST)" "$(USER)" $(DEPLOY_FLAGS) --verify-only

deploy-preflight:
	$(require-host)
	./scripts/deploy-remote.sh "$(HOST)" "$(USER)" $(DEPLOY_FLAGS) --preflight-only
