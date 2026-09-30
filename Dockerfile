# Set this to the `go` version in your go.mod (run `go version` if unsure).
ARG GO_VERSION=1.26

# ---- shared base: deps cached, source copied ----
FROM golang:${GO_VERSION} AS base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# ---- tests (docker compose --profile test run --rm test) ----
FROM base AS test
ENV CGO_ENABLED=1
CMD ["go", "test", "-race", "-count=1", "./..."]

# ---- build a static binary ----
FROM base AS build
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/app
# create /data here: distroless has no shell, and a named volume
# copies this directory's ownership the first time it is created
RUN mkdir /data

# ---- final image: no shell, no package manager, non-root ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
COPY --from=build --chown=65532:65532 /data /data
ENV DB_PATH=/data/app.db
USER 65532:65532
ENTRYPOINT ["/app"]