<h1>
  <br>
  Taurus (Bachelor Thesis)
  <br>
</h1>
<div align="center">
  <img src="https://coconucos.cs.hhu.de/lehre/bigdata/resources/img/hhu-logo.svg" width=300>
</div>

<h4>A self made implementation of <a href="https://datatracker.ietf.org/doc/html/rfc9000">QUIC</a> Version 1 in Rust following RFC 9000 and 9001, accompanied by my bachelors thesis. For now, this is purely a research project and in no way intended for commercial use!</h4>

## Bachelor Thesis (Completed)
This repository contains my bachelor thesis from Heinrich-Heine Universität Düsseldorf, Germany. It has the title <b>"Development Of A Minimal QUIC Implementation In Rust: An Introduction To Next Generation Networking"</b>, is written in english, and covers the design and connection mechanics of QUIC as well as details of my implementation as of the submit date. The rendered pdf can be found in the `document` subdirectory. It may also be helpful to those who simply want to get started with QUIC without using the RFCs directly. Since publishing the document a lot of work has happened in the code which means that some of the referenced code parts may not exist anymore.

## Key Features

The QUIC library is still under active development and some features are not yet implemented. As I lack the resources of the likes of Amazon, Cloudflare and co, and I am actively studying and working, development may only progress slowly. The API may undergo breaking changes regularly until I reach a stable state. The following features are implemented:

* QUIC 1-RTT handshake
* QUIC stream implementation
* QUIC flow control
* QUIC congestion control
* Sophisticated io layer ontop of core lib with fast paths for macos and linux, polling backend for linux and macos, io_uring backend for linux (wip), gso/gro support under both linux backends, custom runtime, offload thread pool and sharded endpoint design for server applications
* Full TLS 1.3 integration using <a href="https://github.com/rustls/rustls">rustls</a>
* Server and Client API (see docs)

## Platform support

Taurus targets Linux and macOS.

**macOS:** requires at least version 10.15 as the backend relies on the private api functions `recvmsg_x`/`sendmsg_x`. No gso/gro is supported.

**Linux (minimum supported kernel version):**

| Configuration                         | Minimum kernel |
|---------------------------------------|----------------|
| Default backend                       | 3.9            |
| Default backend, gso enabled          | 4.18           |
| Default backend, gro enabled          | 5.0            |
| `uring_backend` feature (wip)         | 6.0            |

GSO/GRO are opt-in and off by default. Enabling gro on a kernel older than 5.0 is handled silently. Enabling gso on a kernel older than 4.18 will produce as a send error.

> **Note**
> Windows is not supported.

## Testing

Most of QUIC's key features in my implementation are split into logical domains, each in their own module. These include, but are not limited to, connection ids, socket io, streams, packet header functions, transport parameters, congestion control, and flow control. Each functional module is tested extensively through unit tests to ensure it complies with the standard. Run them via:

```bash
$ cd taurus/project/ && cargo test
```

## Documentation

I am currently working on an extensive documentation for the whole API and important code parts including examples. You can acces the documentation via:

```bash
$ cd taurus/project/ && cargo build && cargo doc
```

There are numerous decisions I made to ensure the library runs as fast as possible on both a mac and on various unix systems. I have decided to document them in ARCHITECTURE.md.

## Extensions

Once the basic QUIC spec is implemented and taurus fully complies with [RFC 9000](https://datatracker.ietf.org/doc/rfc9000), [RFC 9001](https://datatracker.ietf.org/doc/rfc9001), [RFC 9002](https://datatracker.ietf.org/doc/rfc9002), and [RFC 8999](https://datatracker.ietf.org/doc/rfc8999), the following extensions are planned:

* QUIC datagrams, [RFC 9221](https://datatracker.ietf.org/doc/rfc9221)
* QUIC version negotiation, [RFC 9368](https://www.rfc-editor.org/info/rfc9368)
* QUIC Version 2, [RFC 9369](https://datatracker.ietf.org/doc/rfc9369/)
* QUIC Grease bit, [RFC 9287](https://datatracker.ietf.org/doc/rfc9287/)
* QUIC ACK Frequency, [draft](https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/)
* QUIC multipath [draft](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/)
* QUIC BDP frames [draft](https://datatracker.ietf.org/doc/draft-kuhn-quic-bdpframe-extension/)

## Contributing

Feel free to open a <a href="https://github.com/ilumary/taurus/pulls">pull request</a> or report an <a href="https://github.com/ilumary/taurus/issues">issue</a>. All contributions are welcome!

## Build

Building requires a recent version of rustc (>=1.95.0):

```bash
# Clone & Build
$ git clone https://github.com/ilumary/taurus.git
$ cd taurus/project/ && cargo build
```

### Custom Features

#### io_uring (wip)

By default the library uses a portable (p)poll + sendmmsg/recvmmsg polling based io backend that runs on both linux and macOS. On linux you can opt into an io_uring backend instead by enabling the uring_backend feature. Its implicitly linux only and requires linux 6.0 or newer, since teardown relies on synchronous cancellation (IORING_REGISTER_SYNC_CANCEL). I chose to make it optional as it had a lot of vulnerabilities since it was introduced. Enable it like this:

```toml
[dependencies]
quic = { version = "0.1", features = ["uring_backend"] }
```

Your mileage may vary but it should increase performance under high load drastically.

## Run

You can find both a [`server`](./project/examples/server.rs) and a [`client`](./project/examples/client.rs) example in the examples folder. They require to load certificates which you may either provide yourself or you can generate simple self-signed ones via the provided [`gencert`](./project/examples/gencert.rs).

```bash
# Generate certificates
~/taurus/project/ $ cargo run --example gencert

# Start Server
~/taurus/project/ $ cargo run --example server
```

```bash
# Start Client
~/taurus/project/ $ cargo run --example client
```

You may also use an external QUIC implementation as Client. I recommend [quinn](https://github.com/quinn-rs/quinn).

## Collaborators

[ilumary](https://github.com/ilumary) - Me

## License

MIT
