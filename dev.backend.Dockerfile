# Backend image for either crypto engine (byte-for-byte equivalent, see docs/security/cryptography.md):
#   ENGINE=openssl  libcrypto 3.5 LTS from Debian trixie through cgo (default)
#   ENGINE=native   Go standard library crypto, static binary, CGO disabled
# Go 1.27.4+ carries the crypto/x509 fix (GO-2026-6809) and the net/http MaxBytesReader fix (GO-2026-6859).
ARG ENGINE=openssl

FROM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS builder
ARG ENGINE

# OpenSSL headers come from Debian's signed packages (no source download to verify by hand)
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first for layer caching; go.sum pins and verifies every module
COPY backend/go.mod backend/go.sum ./
RUN go mod download && go mod verify

COPY backend/ .

# Reproducible, stripped binary (RULES.md §14.1); the engine is fixed at compile time
RUN case "$ENGINE" in \
      openssl) CGO_ENABLED=1 go build -tags openssl -trimpath -buildvcs=false -ldflags="-s -w" -o /out/elyrn ./cmd/server ;; \
      native)  CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/elyrn ./cmd/server ;; \
      *) echo "ENGINE must be openssl or native (got '$ENGINE')" >&2; exit 1 ;; \
    esac

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG ENGINE

# libssl3t64 only for the OpenSSL engine; wget serves the compose healthcheck
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates wget $([ "$ENGINE" = openssl ] && echo libssl3t64) \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin elyrn

COPY --from=builder /out/elyrn /usr/local/bin/elyrn

LABEL org.opencontainers.image.title="elyrn backend" \
      elyrn.crypto-engine="${ENGINE}"

USER 10001:10001
EXPOSE 8080

CMD ["/usr/local/bin/elyrn"]
