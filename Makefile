.PHONY: build test test-integration vet migrate run

build:
	go build ./...

test:
	go test ./...

test-integration:
	go test -tags=integration ./...

vet:
	go vet ./...

migrate:
	go run ./cmd/migrate

run:
	go run ./cmd/identity
