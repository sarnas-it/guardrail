.PHONY: build test vet

build:
	go build -o guardrail ./cmd/guardrail

test:
	go test ./...

vet:
	go vet ./...
