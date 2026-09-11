.PHONY: test vet race build

test:
	go test -count=1 ./...

race:
	go test -count=1 -race ./...

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -trimpath -o bin/fluxvm-policy-observer ./cmd/fluxvm-policy-observer
