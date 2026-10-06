# envoy-headers-sanitise-filter

Envoy HTTP filter (Go, via Envoy's [golang filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/golang_filter)) that removes every header **not** in a configured allow list.

## Config (`plugin_config`, an `xds.type.v3.TypedStruct`)

| field | meaning |
|---|---|
| `allowed_headers` | request headers to keep; omit to leave requests untouched |
| `response_allowed_headers` | response headers to keep; omit to leave responses untouched |

- At least one field is required; unknown fields are rejected.
- Names are case-insensitive.
- Pseudo headers (`:path`, `:status`, …) are never removed. Note `host` is a regular header in HTTP/1.1, so list it if needed.
- An empty list removes all regular headers.
- Route-level config overrides the filter-level config per direction.

See `envoy.example.yaml`.

## Build / test

    go test ./...
    go build -buildmode=c-shared -o sanitise.so .

Requires cgo and an Envoy build with the golang contrib filter (version must match the `github.com/envoyproxy/envoy` module in `go.mod`, v1.33.0).
