.DEFAULT_GOAL := help
.PHONY: all build build-bpf build-go test integration e2e bench clean install \
        docker-build docker-push k8s-deploy k8s-delete fmt vet lint tidy help

KERNEL_VERSION   ?= $(shell uname -r)
GOARCH           ?= $(shell go env GOARCH 2>/dev/null || echo amd64)
BUILD_DIR        := bin
BPF_BUILD_DIR    := build/bpf
VERSION          ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD            ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS          := -s -w -X main.Version=$(VERSION) -X main.Build=$(BUILD)
CLANG            ?= clang
LLC              ?= llc
STRIP            ?= llvm-strip
BPFTOOL          ?= bpftool
DOCKER_REGISTRY  := ghcr.io
DOCKER_REPO      := gokul-dev47/ebpf-sentinel
DOCKER_TAG       ?= $(VERSION)

all: build

## build: Build BPF programs and Go binaries
build: build-bpf build-go

## build-bpf: Compile all BPF programs
build-bpf:
	@echo "\033[36m[BUILD]\033[0m Compiling BPF programs..."
	@mkdir -p $(BPF_BUILD_DIR)
	$(MAKE) -C bpf/detector \
	    OUTPUT_DIR=$(abspath $(BPF_BUILD_DIR)) \
	    CLANG=$(CLANG) LLC=$(LLC) STRIP=$(STRIP) BPFTOOL=$(BPFTOOL)
	@echo "\033[32m[OK]\033[0m BPF objects in $(BPF_BUILD_DIR)/"

## build-go: Compile Go binaries
build-go:
	@echo "\033[36m[BUILD]\033[0m Compiling Go binaries..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build \
	    -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/sentinel ./cmd/sentinel
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build \
	    -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/sentinel-agent ./cmd/agent
	@echo "\033[32m[OK]\033[0m Binaries in $(BUILD_DIR)/"

## test: Run unit tests
test:
	go test -v -race -count=1 ./pkg/... ./cmd/... ./internal/...

## integration: Run integration tests (requires root + BPF)
integration: build
	sudo go test -v -count=1 -timeout=120s ./test/integration/...

## e2e: Run end-to-end tests (requires root + built binary)
e2e: build
	sudo go test -v -count=1 -timeout=300s ./test/e2e/...

## bench: Run performance benchmarks
bench: build
	sudo scripts/benchmark.sh

## fmt: Format Go code
fmt:
	go fmt ./...

## vet: Run go vet
vet:
	go vet ./...

## lint: Run golangci-lint
lint:
	golangci-lint run --timeout=5m ./...

## tidy: Tidy Go module
tidy:
	go mod tidy

## install: Install binaries and BPF objects
install: build
	install -Dm755 $(BUILD_DIR)/sentinel /usr/local/bin/sentinel
	install -Dm755 $(BUILD_DIR)/sentinel-agent /usr/local/bin/sentinel-agent
	mkdir -p /usr/lib/sentinel/bpf
	install -m644 $(BPF_BUILD_DIR)/*.bpf.o /usr/lib/sentinel/bpf/
	@echo "\033[32m[OK]\033[0m Installed"

## docker-build: Build Docker image
docker-build:
	docker build \
	    --build-arg VERSION=$(VERSION) \
	    --build-arg BUILD=$(BUILD) \
	    -t $(DOCKER_REGISTRY)/$(DOCKER_REPO):$(DOCKER_TAG) \
	    -f deployments/docker/Dockerfile .

## docker-push: Push Docker image
docker-push: docker-build
	docker push $(DOCKER_REGISTRY)/$(DOCKER_REPO):$(DOCKER_TAG)

## k8s-deploy: Deploy to Kubernetes
k8s-deploy:
	kubectl apply -f deployments/kubernetes/configmap.yaml
	kubectl apply -f deployments/kubernetes/daemonset.yaml

## k8s-delete: Remove from Kubernetes
k8s-delete:
	kubectl delete -f deployments/kubernetes/daemonset.yaml --ignore-not-found
	kubectl delete -f deployments/kubernetes/configmap.yaml --ignore-not-found

## clean: Remove all build artifacts
clean:
	rm -rf $(BUILD_DIR) $(BPF_BUILD_DIR) build/ coverage/ benchmark_results/
	$(MAKE) -C bpf/detector clean OUTPUT_DIR=$(abspath $(BPF_BUILD_DIR)) 2>/dev/null || true

## help: Show this help
help:
	@echo "\033[36m╔══════════════════════════════════════╗\033[0m"
	@echo "\033[36m║    eBPF Sentinel - Makefile           ║\033[0m"
	@echo "\033[36m╚══════════════════════════════════════╝\033[0m"
	@grep -E '^## ' Makefile | sed 's/## /  /' | column -t -s':'
