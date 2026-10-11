# syntax=docker/dockerfile:1
#
# Multi-stage build: compile a static binary (CGO_ENABLED=0, NFR4), then copy
# it into a distroless image with no shell, no package manager, and a
# non-root user. The final image is about 20 MB.
#
#   docker build -t csg:0.6.0-beta --build-arg VERSION=0.6.0-beta .
#   docker run --rm csg:0.6.0-beta version
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/out:/out" csg:0.6.0-beta \
#       run --sample --report /out/report.html

FROM golang:1.26 AS build
WORKDIR /src
# Download modules first so this layer is cached until go.mod or go.sum change.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/csg ./cmd/csg

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="CloudSpendGuard" \
      org.opencontainers.image.description="Unified FinOps and cloud security posture CLI for AWS" \
      org.opencontainers.image.source="https://github.com/wisnuanggoro/cloudspendguard" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/csg /usr/local/bin/csg
# The default database path is relative to the working directory, which is not
# writable for the non-root user, so keep the local store in /tmp.
ENV CSG_DB=/tmp/csg.db
WORKDIR /data
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/csg"]
CMD ["help"]
