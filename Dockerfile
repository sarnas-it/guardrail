FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/guardrail ./cmd/guardrail

FROM alpine:3.21
RUN apk add --no-cache git ca-certificates
RUN git config --system --add safe.directory /github/workspace
COPY --from=build /out/guardrail /usr/local/bin/guardrail
WORKDIR /github/workspace
ENTRYPOINT ["/usr/local/bin/guardrail"]
