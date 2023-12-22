<h1>
  <br>
  <br>
  Taurus
  <br>
</h1>

<h4>A self made implementation of <a href="https://datatracker.ietf.org/doc/html/rfc9000">QUIC</a> in Rust following RFC 9000 and 9001.</h4>

<p>
  <a href="#key-features">Key Features</a> |
  <a href="#how-to-use">Build</a> |
  <a href="#credits">Credits</a> |
  <a href="#related">Related</a> |
  <a href="#license">License</a>
</p>


## Key Features (In Development)

* QUIC 1-RTT Handshake 
* 0-RTT Connection Resumption
* Full TLS 1.3 Integration using <a href="https://github.com/rustls/rustls">rustls</a>  
* Server and Client API for easy integration with HTTP/3 or other Application Protocols

## Build

Building requires a recent version of rustc (1.72.0) :

```bash
# Clone this repository
$ git clone https://github.com/ilumary/taurus
$ cd taurus

# Run
$ cargo run
```

> **Note**
> Due to me not having access to a Windows computer, Windows can't officially be supported. But this being Rust, one can expect this to run normal under Windows.

## Credits

This software uses the following open source packages:

- [rustls](https://github.com/rustls/rustls/)
- [octets](https://docs.rs/octets/latest/octets/)

## Collaborators

[ilumary](https://github.com/ilumary) - Me

## Support

<a href="paypal.me/christophbritsch">
	<img src="https://www.paypalobjects.com/webstatic/de_DE/i/de-pp-logo-150px.png" width="150">
</a>


## License

MIT
