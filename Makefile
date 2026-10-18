.PHONY: build test test-short e2e hooks lint

build:
	go build -o bin/curd ./cmd/curd

test:
	go test ./...

test-short:
	go test -short ./...

# Full end-to-end tests, including ones that launch Chrome/Chromium.
e2e: build
	go test -count=1 ./e2e/...

hooks:
	git config core.hooksPath .githooks

lint:
	gofmt -l .
	go vet ./...
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go vet ./...
