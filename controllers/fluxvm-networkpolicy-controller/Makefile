# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0

VERSION ?= dev
IMAGE ?= ghcr.io/zyvorai/fluxvm-networkpolicy-controller:$(VERSION)

.PHONY: test build vet race docker

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/fluxvm-networkpolicy-controller ./cmd/fluxvm-networkpolicy-controller

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .
