ARG BUILD_IMAGE=docker.io/library/golang:1.26.10
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot
FROM --platform=$BUILDPLATFORM ${BUILD_IMAGE} AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api api
COPY internal internal
COPY cmd cmd
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /cmtc ./cmd/cmtc
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /lab-identity-init ./cmd/lab-identity-init
# The registrar reports this revision on --version; the deployment check compares it with the image's source. Declared
# here, not at the top, so a new revision does not rebuild the layers above.
ARG SOURCE_REVISION=development
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X main.sourceRevision=${SOURCE_REVISION}" -o /cmtc-spire-registrar ./cmd/cmtc-spire-registrar

# docker build --target registrar: the SPIRE registrar sidecar. It runs as 1000:1000, the owner of the SPIRE server's
# private API socket (1000:1000, mode 770).
FROM ${RUNTIME_IMAGE} AS registrar
COPY --from=build /cmtc-spire-registrar /cmtc-spire-registrar
USER 1000:1000
ENTRYPOINT ["/cmtc-spire-registrar"]

# The default target (last stage): the CMTC controller and node agent, one binary selected by --mode.
FROM ${RUNTIME_IMAGE} AS cmtc
COPY --from=build /cmtc /cmtc
COPY --from=build /lab-identity-init /lab-identity-init
USER 65532:65532
ENTRYPOINT ["/cmtc"]
