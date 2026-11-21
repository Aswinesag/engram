BINARY_NAME ?= engram
BIN_DIR     ?= bin
PYTHON      ?= python3

ifeq ($(OS),Windows_NT)
	BINARY_EXT := .exe
	PYTHON     := python
else
	BINARY_EXT :=
endif

BINARY_PATH := $(BIN_DIR)/$(BINARY_NAME)$(BINARY_EXT)

.PHONY: all ui build wheel test test-go test-python test-ui release-snapshot clean help

all: build wheel ## Build embedded UI, single Go binary, and Python compiler wheel

ui: ## Install UI dependencies (if needed) and build Vite SPA into ui/dist/
	@if [ ! -d ui/node_modules ]; then \
		cd ui && (npm ci || npm install); \
	fi
	cd ui && npm run build

build: ui ## Compile single cross-platform Go binary with embedded UI assets
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BINARY_PATH) ./cmd/engram

wheel: ## Build pure-Python engram-compiler wheel via uv
	cd compiler && uv build

test: test-go test-python test-ui ## Run Go, Python compiler, and UI typecheck test suites

test-go: ## Run all Go unit and integration tests
	go test -v ./...

test-python: ## Run Python Evolution Compiler unit and shadow-replay tests
	cd compiler && $(PYTHON) -m unittest discover -s tests -v

test-ui: ## Typecheck React/TypeScript dashboard
	cd ui && npm run typecheck

release-snapshot: ui wheel ## Build local GoReleaser cross-platform snapshot without publishing
	goreleaser release --snapshot --clean

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) dist compiler/dist

help: ## Show available build targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'