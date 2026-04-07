FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /relay ./cmd/relay/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /relay /relay
ENTRYPOINT ["/relay"]
