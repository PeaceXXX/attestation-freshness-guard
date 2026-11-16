# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY internal/ internal/
COPY cmd/ cmd/
RUN CGO_ENABLED=0 go build -o /out/freshguard ./cmd/freshguard

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/freshguard /app/freshguard
COPY data/ /app/data/
EXPOSE 8080
ENTRYPOINT ["/app/freshguard"]
CMD ["serve", "--addr", ":8080", "--policy", "/app/data/policy.json", "--store", "/app/data/replay.json"]
