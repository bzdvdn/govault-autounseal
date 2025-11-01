# Build stage
FROM golang:1.24-alpine AS builder

# Install git and ca-certificates (needed for HTTPS requests)
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY src/ ./src/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o govault-autounseal ./src

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/govault-autounseal .

# Copy config example
COPY config.example.yaml .

# Change ownership to non-root user
RUN chown appuser:appgroup govault-autounseal config.example.yaml

# Switch to non-root user
USER appuser

# Expose port (if needed for health checks, though this is a CLI app)
# EXPOSE 8080

# Set the binary as entrypoint
ENTRYPOINT ["./govault-autounseal"]

# Default command (can be overridden)
CMD ["--help"]