FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /rootfs/usr/local/bin/t3-mesh-hub ./cmd/t3-mesh-hub \
    && mkdir -p /rootfs/run/t3-mesh

# The hub listens on 8443 (agents, enrollment), 8080 (viewers) and 9090 (probes
# and status). /run/t3-mesh holds the admin socket used by `t3-mesh-hub
# enroll-token`; in Kubernetes mount an emptyDir there (with fsGroup 65532 so the
# nonroot user can write to it). The root filesystem can stay read-only.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build --chown=65532:65532 /rootfs/ /
USER 65532:65532
EXPOSE 8443 8080 9090
ENTRYPOINT ["/usr/local/bin/t3-mesh-hub"]
LABEL org.opencontainers.image.source="https://github.com/zekihan/t3-mesh" \
      org.opencontainers.image.title="t3-mesh hub" \
      org.opencontainers.image.description="Hub of the t3-mesh private mesh between T3 machines"
