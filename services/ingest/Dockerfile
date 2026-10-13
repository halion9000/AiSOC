FROM golang:1.25-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o /ingest-service ./main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /ingest-service .
# The push inbox (/v1/inbox/*) maps each vendor payload with these YAML templates; INBOX_TEMPLATES_DIR defaults to /app/templates.
COPY --from=builder /app/internal/normalizer/templates ./templates

EXPOSE 8080

CMD ["./ingest-service"]
