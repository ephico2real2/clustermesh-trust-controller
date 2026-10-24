FROM --platform=$BUILDPLATFORM golang:1.26.10 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api api
COPY internal internal
COPY cmd cmd
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /cmtc ./cmd/cmtc
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /lab-ca-init ./cmd/lab-ca-init
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /lab-identity-init ./cmd/lab-identity-init
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /cmtc /cmtc
COPY --from=build /lab-ca-init /lab-ca-init
COPY --from=build /lab-identity-init /lab-identity-init
USER 65532:65532
ENTRYPOINT ["/cmtc"]
