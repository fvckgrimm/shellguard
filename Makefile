BINARY     := shellguard
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -ldflags "-X github.com/shellguard/shellguard/cmd/shellguard.Version=$(VERSION) \
                         -X github.com/shellguard/shellguard/cmd/shellguard.Commit=$(COMMIT)   \
                         -X github.com/shellguard/shellguard/cmd/shellguard.BuildDate=$(BUILD_DATE) \
                         -s -w"

# Directories
BUILD_DIR  := ./dist
RULES_DIR  := ./rules

# Install target dir
PREFIX     ?= /usr/local
BINDIR     := $(PREFIX)/bin
RULESDIR   := $(PREFIX)/share/shellguard/rules

.PHONY: all build install uninstall clean test lint fmt vet rules-validate release

all: build

## Build binary
build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./main.go
	@echo "✓ Built $(BUILD_DIR)/$(BINARY)"

## Build for all platforms
release:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux  GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64   ./main.go
	GOOS=linux  GOARCH=arm64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64   ./main.go
	GOOS=darwin GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  ./main.go
	GOOS=darwin GOARCH=arm64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  ./main.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe ./main.go
	@echo "✓ Release binaries in $(BUILD_DIR)/"

## Install binary + rules to PREFIX
install: build
	install -d $(BINDIR) $(RULESDIR)/builtin $(RULESDIR)/community
	install -m 755 $(BUILD_DIR)/$(BINARY) $(BINDIR)/$(BINARY)
	cp -r $(RULES_DIR)/builtin/*.yaml   $(RULESDIR)/builtin/
	cp -r $(RULES_DIR)/community/*.yaml $(RULESDIR)/community/ 2>/dev/null || true
	@echo "✓ Installed $(BINARY) to $(BINDIR)"
	@echo "  Rules installed to $(RULESDIR)"
	@echo "  Run 'shellguard config init' to set up your config"

## Uninstall
uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -rf $(RULESDIR)
	@echo "✓ Uninstalled $(BINARY)"

## Run tests
test:
	go test ./... -v -race -count=1

## Validate all built-in rule packs
rules-validate: build
	$(BUILD_DIR)/$(BINARY) rules validate $(RULES_DIR)/

## Run go vet
vet:
	go vet ./...

## Run golangci-lint (install: https://golangci-lint.run/usage/install/)
lint:
	golangci-lint run ./...

## Format code
fmt:
	gofmt -s -w .
	goimports -w .

## Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "✓ Cleaned"

## Show help
help:
	@echo "shellguard Makefile targets:"
	@echo "  build          - Build binary to ./dist/"
	@echo "  install        - Install binary and rules to PREFIX (default /usr/local)"
	@echo "  uninstall      - Remove installed files"
	@echo "  release        - Build release binaries for all platforms"
	@echo "  test           - Run tests"
	@echo "  rules-validate - Validate all built-in rule packs"
	@echo "  vet            - Run go vet"
	@echo "  lint           - Run golangci-lint"
	@echo "  fmt            - Format code"
	@echo "  clean          - Remove build artifacts"
	@echo ""
	@echo "  PREFIX=$(PREFIX)   (override with: make install PREFIX=~/.local)"
