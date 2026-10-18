.PHONY: build sign test test-short e2e hooks lint

build:
	go build -o bin/curd ./cmd/curd

# Sign with a stable identity and the hardened runtime (spec 5.6); the
# keychain ACL survives rebuilds only while IDENTITY stays the same.
sign: build
	@test -n "$(IDENTITY)" || { echo 'usage: make sign IDENTITY="<codesigning identity>"'; exit 1; }
	codesign --force --options runtime --identifier org.domnit.curd --sign "$(IDENTITY)" bin/curd
	codesign -dv --entitlements - bin/curd

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
