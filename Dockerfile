FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download -mod=mod
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -ldflags="-s -w" -o /relay ./cmd/relay/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /relay /relay
ENTRYPOINT ["/relay"]
