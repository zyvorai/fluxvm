# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0

.PHONY: build test fmt fmt-check clippy test-policy bpf preflight check test-devops test-packetflow test-microvm

build:
	cargo build --workspace --all-targets

test:
	cargo test --workspace

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
