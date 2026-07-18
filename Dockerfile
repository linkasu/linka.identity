# syntax=docker/dockerfile:1.7
FROM golang:1.24.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/identity ./cmd/identity && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/schema ./cmd/schema

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /out/identity /usr/local/bin/identity
COPY --from=build /out/schema /usr/local/bin/schema
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/identity"]
