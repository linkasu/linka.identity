.PHONY: build test test-race test-integration vet schema run

build:
	go build ./...

test:
	go test ./...

test-race:
	go test -race ./...

test-integration:
	go test -tags=integration -p 1 ./...

vet:
	go vet ./...

schema:
	go run ./cmd/schema

run:
	go run ./cmd/identity
