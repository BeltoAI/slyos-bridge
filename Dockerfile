# syntax=docker/dockerfile:1
#
# The bridge, built from the REPO ROOT as ONE static linux/amd64 binary in a
# distroless image (ADR 0093; the Signal addendum of 2026-10-22 has the exact
# build and deploy commands). Signal needs libsignal's Rust FFI linked in with
# cgo, the way mautrix-signal builds it; nobody publishes a prebuilt
# libsignal_ffi.a for Linux, so stage 1 compiles it.
#
#   docker buildx build --platform linux/amd64 -f services/bridge/Dockerfile \
#     -t <registry>/<image>:<tag> --load .
#
# Published alone (scripts/publish-bridge-source.sh), the tree's root is this
# directory and SRC below is "." — build it with `-f Dockerfile .` there.
#
# The app's secrets are the owner's to set; nothing here sets or reads them.

# MUST equal signalversion.Version in the go.mau.fi/mautrix-signal that go.mod
# pins (TestTheImagePinsTheLibsignalSignalmeowWants reads both).
ARG LIBSIGNAL_VERSION=v0.105.0
# Where the bridge's source sits in the build context.
ARG SRC=.

# ── 1. libsignal_ffi.a (Rust), exactly as mautrix-signal's build-rust.sh ─────
FROM --platform=linux/amd64 rust:1-alpine AS rust
ARG LIBSIGNAL_VERSION
RUN apk add --no-cache git make cmake protoc musl-dev g++ clang-dev protobuf-dev
WORKDIR /build
RUN git clone --depth 1 --branch "${LIBSIGNAL_VERSION}" https://github.com/signalapp/libsignal.git
WORKDIR /build/libsignal
RUN RUSTFLAGS="-Ctarget-feature=-crt-static" RUSTC_WRAPPER="" \
      cargo build -p libsignal-ffi --profile=release \
 && cp target/release/libsignal_ffi.a /libsignal_ffi.a

# ── 2. the bridge (Go + cgo), linked fully static against musl ───────────────
FROM --platform=linux/amd64 golang:1.27-alpine AS build
ARG SRC
RUN apk add --no-cache build-base zlib-static
WORKDIR /src
COPY ${SRC}/go.mod ${SRC}/go.sum ./
RUN go mod download
COPY ${SRC}/ ./
COPY --from=rust /libsignal_ffi.a /usr/local/lib/libsignal_ffi.a
# `libsignal` compiles the real Signal client in (internal/signal/real.go);
# without it Signal is simply not served, which is how `go test` runs.
RUN CGO_ENABLED=1 LIBRARY_PATH=/usr/local/lib go build -trimpath \
      -tags libsignal,netgo,osusergo \
      -ldflags='-s -w -linkmode external -extldflags "-static"' \
      -o /bridge ./cmd/bridge

# ── 3. what runs ─────────────────────────────────────────────────────────────
FROM --platform=linux/amd64 gcr.io/distroless/static-debian12:nonroot
COPY --from=build /bridge /bridge
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/bridge"]
