# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o waf-benchmark ./cmd/waf-benchmark/

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/waf-benchmark .

# Copy shared files
COPY --from=builder /app/shared ./shared
COPY --from=builder /app/testdata ./testdata

# Copy default config
COPY --from=builder /app/benchmark_config.yaml .

# Create reports directory
RUN mkdir -p /root/reports

# Expose no ports (client tool)

ENTRYPOINT ["./waf-benchmark"]
CMD ["--help"]
