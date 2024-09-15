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
This repository contains my bachelor thesis from Heinrich-Heine Universität Düsseldorf, Germany. It has the title <b>"Development Of A Minimal QUIC Implementation In Rust: An Introduction To Next Generation Networking"</b>, is written in english, and covers the design and connection mechanics of QUIC as well as details of my implementation as of the submit date. The rendered pdf can be found in the `document` subdirectory. It may also be helpful to those who simply want to get started with QUIC without using the RFCs directly.

## Key Features

The QUIC library is still in a very early development stage and a majority of the features required for any kind of meaningful use are not yet implemented. As I lack the resources of the likes of Amazon, Cloudflare and co, development may only progress slowly. Currently availible are:

* QUIC 1-RTT Handshake
* Full TLS 1.3 Integration using <a href="https://github.com/rustls/rustls">rustls</a>
* Server API for easy integration with HTTP/3 or other Application Protocols

The current implementation works with <a href="https://github.com/quinn-rs/quinn">quinn's</a> example client implementation as described in the `Run` section. The handshake is completed successfully and the client-initiated bidirectional stream is successfully proccessed on my side.

Though it may seem to work fine for now, the async library design is still only in its infant stage. Currently in development are:

* Async wrapper for quic library
* QUIC stream implementation (with async wrapper)
* Congestion and flow control
  
The Server API design (Client API coming sometime in the future) is heavily inspired by <a href="https://github.com/aws/s2n-quic">Amazons QUIC API design</a>. As of now it is still in development and neither fully functional nor feature complete.

I am also only learning the deep ends of Rust through this project so dont expect top-notch Rust code.

## Contributing

Feel free to open a <a href="https://github.com/ilumary/taurus/pulls">pull request</a> or report an <a href="https://github.com/ilumary/taurus/issues">issue</a>. All contributions are welcome!

## Build

Building requires a recent version of rustc (>=1.80.0):

```bash
# Clone & Build
$ git clone https://github.com/ilumary/taurus.git
$ cd taurus/project/ && cargo build
```

> **Note**
> Windows can't be officially supported. Rust should work cross platform though.

## Run

Currently the Client API is not yet implemented. Therefore one has to use an external QUIC implementation to act as Client. I recommend [quinn](https://github.com/quinn-rs/quinn). The local server implementation can be found in [`main.rs`](./project/src/main.rs).

```bash
# Start the server
~/taurus/project/ $ cargo run
```

```bash
# Start client
~/quinn/ $ cargo run --example client https://localhost:4433/Cargo.toml
```

## Credits

Taurus uses the following open source packages:

- [rustls](https://github.com/rustls/rustls/)
- [octets](https://docs.rs/octets/latest/octets/)
- [ring](https://github.com/briansmith/ring/)

## Collaborators

[ilumary](https://github.com/ilumary) - Me

## License

MIT
