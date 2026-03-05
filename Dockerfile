FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/xidentity ./cmd/xidentity

FROM scratch

COPY --from=builder /bin/xidentity /xidentity

EXPOSE 50051

ENTRYPOINT ["/xidentity"]
