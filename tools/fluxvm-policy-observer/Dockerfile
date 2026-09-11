# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
FROM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/fluxvm-policy-observer ./cmd/fluxvm-policy-observer

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends bpftool iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/fluxvm-policy-observer /usr/local/bin/fluxvm-policy-observer
USER 0:0
ENTRYPOINT ["/usr/local/bin/fluxvm-policy-observer"]
