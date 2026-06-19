# eBPF Sentinel - Multi-stage Docker build

# Stage 1: BPF Builder
FROM ubuntu:22.04 AS bpf-builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-headers-generic \
    linux-tools-common linux-tools-generic make wget \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY bpf/ ./bpf/
COPY Makefile ./
RUN mkdir -p build/bpf && make build-bpf BUILD_DIR=/build/build/bpf

# Stage 2: Go Builder
FROM golang:1.21-bullseye AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY --from=bpf-builder /build/build/bpf/ ./build/bpf/
COPY . .
ARG VERSION=dev
ARG BUILD=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Build=${BUILD}" \
    -o /bin/sentinel ./cmd/sentinel
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Build=${BUILD}" \
    -o /bin/sentinel-agent ./cmd/agent

# Stage 3: Runtime
FROM alpine:3.18
RUN apk add --no-cache ca-certificates && rm -rf /var/cache/apk/*
COPY --from=go-builder /bin/sentinel /usr/local/bin/sentinel
COPY --from=go-builder /bin/sentinel-agent /usr/local/bin/sentinel-agent
COPY --from=bpf-builder /build/build/bpf/*.bpf.o /usr/lib/sentinel/bpf/
RUN chmod 755 /usr/local/bin/sentinel /usr/local/bin/sentinel-agent && \
    mkdir -p /var/lib/sentinel /etc/sentinel
VOLUME ["/sys/kernel/btf", "/proc", "/sys/fs/bpf"]
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/sentinel-agent"]
CMD ["--api-addr", ":8080", "--metrics-addr", ":9090"]
