# mvnet

[![CI](https://github.com/mainvec/mvnet/actions/workflows/ci.yml/badge.svg)](https://github.com/mainvec/mvnet/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mainvec/mvnet.svg)](https://pkg.go.dev/github.com/mainvec/mvnet)

`mvnet` is a collection of standard-library-only Go networking utilities for NAT
traversal, hole punching, and connectivity testing. Each package can be imported
independently, so applications only need to adopt the pieces they use.

## Requirements

- Go 1.24 or newer
- No third-party runtime dependencies

## Installation

```sh
go get github.com/mainvec/mvnet@latest
```

Then import the package you need. For example:

```go
package main

import (
	"context"
	"fmt"

	"github.com/mainvec/mvnet/stun"
)

func main() {
	result, err := stun.QuerySTUNServer("stun.l.google.com:19302")
	if err != nil {
		fmt.Println("STUN query failed:", err)
		return
	}
	fmt.Printf("Public address: %s\n", result.PublicAddr)
}
```

## Packages

| Package | Purpose |
| --- | --- |
| [`stun`](./stun) | Minimal STUN (RFC 5389) client — discovers the public reflexive address. |
| [`nat`](./nat) | Detects NAT behavior (Open, Easy, Hard, Symmetric, Blocked) and recommends traversal strategies. |
| [`hpunch`](./hpunch) | High-level hole puncher — auto-detects NAT type, then performs UDP hole punching. |
| [`punch`](./punch) | Full state-machine UDP hole-punching protocol with handshake, keepalive, and connection verification. |
| [`ice`](./ice) | ICE (Interactive Connectivity Establishment) agent — gathers candidates, runs STUN checks, nominates best pair. |
| [`upnp`](./upnp) | UPnP-IGD and NAT-PMP client — discovers gateway, adds/removes port mappings. |
| [`speedtest`](./speedtest) | Bidirectional throughput benchmark over an established connection. |

API details and examples are available on
[pkg.go.dev](https://pkg.go.dev/github.com/mainvec/mvnet).

## Stability

The project currently uses `v0` releases. APIs may change between minor
versions until `v1.0.0`; release tags follow semantic versioning.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the development workflow and
required checks. Please report security issues according to
[SECURITY.md](./SECURITY.md).

## License

This project is available under the [MIT License](./LICENSE).
