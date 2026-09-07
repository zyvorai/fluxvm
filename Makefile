# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0

.PHONY: build test test-policy bpf preflight check

build:
	cargo build --workspace --all-targets

test:
	cargo test --workspace

test-policy:
	python3 scripts/test-security-groups.py
	python3 scripts/test-network-policy.py
	python3 scripts/test-production-dataplane.py
	python3 scripts/test-project-production.py

bpf:
	./scripts/build-ebpf.sh

preflight:
	./scripts/preflight.sh

check: test-policy preflight
