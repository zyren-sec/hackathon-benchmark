.PHONY: build test clean install deps fmt lint help docker-build check-go-version

# Variables
BINARY_NAME := waf-benchmark
MODULE := github.com/waf-hackathon/benchmark
VERSION := 2.1.0
BUILD_DIR := ./bin
GO_MIN_VERSION := 1.21
GO_VERSION := $(shell go env GOVERSION 2>/dev/null | sed 's/^go//')
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)"

# Default target
all: build

## help: Show this help message
help:
	@echo "Available targets:"
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## /  /'

## check-go-version: Validate the installed Go toolchain version
check-go-version:
	@if ! command -v go >/dev/null 2>&1; then \
		echo "Error: Go is not installed. Install Go $(GO_MIN_VERSION)+ or use 'docker build -t waf-benchmark .'"; \
		exit 1; \
	fi
	@printf '%s\n%s\n' "$(GO_MIN_VERSION)" "$(GO_VERSION)" | sort -V -C || { \
		echo "Error: Go $(GO_MIN_VERSION)+ is required, found $(GO_VERSION)."; \
		echo "Install a newer Go release, then run 'make deps && make build' again."; \
		echo "Docker fallback: docker build -t waf-benchmark ."; \
		exit 1; \
	}
	@echo "Using Go $(GO_VERSION)"

## build: Build the binary
build: check-go-version
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/waf-benchmark
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

## test: Run all tests
test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...
	@echo "Coverage report: coverage.out"

## test-short: Run short tests (exclude integration)
test-short:
	@echo "Running short tests..."
	go test -v -short ./...

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) coverage.out reports/
	@go clean -cache

## install: Install the binary to GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/$(BINARY_NAME) 2>/dev/null || cp $(BUILD_DIR)/$(BINARY_NAME) $(HOME)/go/bin/$(BINARY_NAME) 2>/dev/null || echo "Please add $(BUILD_DIR) to your PATH"

## deps: Download and verify dependencies
deps: check-go-version
	@echo "Downloading dependencies..."
	go mod download
	go mod verify
	@echo "Dependencies ready"

## tidy: Clean up go.mod and go.sum
tidy:
	@echo "Tidying modules..."
	go mod tidy

## fmt: Format all Go files
fmt:
	@echo "Formatting..."
	go fmt ./...

## lint: Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## run: Build and run with default config
run: build
	$(BUILD_DIR)/$(BINARY_NAME) --config=benchmark_config.yaml

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t waf-benchmark:$(VERSION) -t waf-benchmark:latest .

## docker-run: Run Docker container
docker-run: docker-build
	@echo "Running Docker container..."
	docker run --rm -v $(PWD)/reports:/root/reports waf-benchmark:latest

## coverage: Show test coverage in browser
coverage: test
	go tool cover -html=coverage.out -o coverage.html
	@echo "Open coverage.html in your browser"
