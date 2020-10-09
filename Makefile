.PHONY: build test

test:
	go test ./...

build:
	go build -o bin/keyrecovery ./cmd/keyrecovery/main.go
