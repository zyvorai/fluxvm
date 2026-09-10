# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/fluxvm-networkpolicy-controller \
    ./cmd/fluxvm-networkpolicy-controller

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fluxvm-networkpolicy-controller /usr/local/bin/fluxvm-networkpolicy-controller
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fluxvm-networkpolicy-controller"]
