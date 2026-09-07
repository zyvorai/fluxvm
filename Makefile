# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0

.PHONY: build test test-policy bpf preflight check test-devops test-packetflow

build:
	cargo build --workspace --all-targets

test:
	cargo test --workspace

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

check: test-policy preflight test-devops test-packetflow
