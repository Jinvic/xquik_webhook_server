# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod ./
COPY . .

ARG TARGETARCH=amd64
RUN go mod download \
  && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/xquik_webhook_server .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/xquik_webhook_server /xquik_webhook_server

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/xquik_webhook_server"]
