FROM --platform=$BUILDPLATFORM docker.io/library/golang@sha256:162be5298a40ed317005c8339c6de4d10d3eef336d66dc8e9259b03ab9d3a6d2 AS build
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
FROM gcr.io/distroless/static-debian13@sha256:ed4ec1de07c43dc8d073221ee9e545cf54e12f7a4d451a4ee7d7bb3ce6165d52
COPY --from=build /cmtc /cmtc
COPY --from=build /lab-ca-init /lab-ca-init
COPY --from=build /lab-identity-init /lab-identity-init
USER 65532:65532
ENTRYPOINT ["/cmtc"]
