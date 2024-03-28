<h1>
  <br>
  <br>
  Taurus (Bachelor Thesis)
  <br>
</h1>
<div align="center">
  <img src="https://coconucos.cs.hhu.de/lehre/bigdata/resources/img/hhu-logo.svg" width=300>
</div>

<h4>A self made implementation of <a href="https://datatracker.ietf.org/doc/html/rfc9000">QUIC</a> in Rust following RFC 9000 and 9001, accompanied by my bachelors thesis.</h4>

<p>
  <a href="#key-features">Key Features</a> |
  <a href="#how-to-use">Build</a> |
  <a href="#credits">Credits</a> |
  <a href="#related">Related</a> |
  <a href="#license">License</a>
</p>

## Bachelor Thesis (Completed)
This repository contains my bachelor thesis. It has the title "Development Of A Minimal QUIC Implementation In Rust: An Introduction To Next Generation Networking" and covers the design and connection mechanics of QUIC as well as details of my implementation as of the submit date. The rendered pdf can be found in the `document` subdirectory.

## Key Features (In Development)

* QUIC 1-RTT Handshake 
* Full TLS 1.3 Integration using <a href="https://github.com/rustls/rustls">rustls</a>  
* Server and Client API for easy integration with HTTP/3 or other Application Protocols

## Build

Building requires a recent version of rustc (1.72.0):

```bash
# Clone this repository
$ git clone https://github.com/ilumary/taurus.git
$ cd taurus/project/

# Run
$ cargo run
```

> **Note**
> Windows can't be officially supported. Rust should work cross platform though.

## Credits

This software uses the following open source packages:

- [rustls](https://github.com/rustls/rustls/)
- [octets](https://docs.rs/octets/latest/octets/)

## Collaborators

[ilumary](https://github.com/ilumary) - Me

## License

MIT
