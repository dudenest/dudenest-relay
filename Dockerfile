FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /relay ./cmd/relay/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates wget
COPY --from=builder /relay /relay
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /var/lib/dudenest/maps /var/lib/dudenest/thumbs /etc/dudenest
ENTRYPOINT ["/entrypoint.sh"]
