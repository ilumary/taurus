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

The QUIC library is still in an early development stage and a majority of the features required for any kind of meaningful use are not yet implemented. As I lack the resources of the likes of Amazon, Cloudflare and co, development may only progress slowly. The following features are implemented:

* QUIC 1-RTT handshake
* QUIC stream implementation
* QUIC flow control
* QUIC congestion control (wip)
* Performant async socket io wrapper
* Full TLS 1.3 integration using <a href="https://github.com/rustls/rustls">rustls</a>
* Server API for easy integration with HTTP/3 or other application protocols
* Client API

## Testing

Most of QUIC's key features in my implementation are split into logical domains, each in their own module. These include, but are not limited to, connection ids, socket io, streams, packet header functions, transport parameters, congestion control, and flow control. Each functional module is tested extensively through unit tests to ensure it complies with the standard. My implementation has reached a stage where I also require system/integration tests to validate the overall functionality. I am currently working on implementing these tests which poses some challenges.

## Performance

Taurus is still not able to provide robust communication over a lossy network which means I cannot really test performance. What I can do is test the performance of single modules for now which I do.

### Sent Packet Tracking In Congestion Control

In the congestion control module, I want to be able to keep track of sent packets. My initial idea was to use a `VecDequeue<SentPacket>`. Extensive benchmarking then inidicated that this is indeed the fasest solution for tracking a few hundred packets. If the tracked packages went above 1000, it was notably faster to use a `BTreeMap<u64, (usize, SmallVec<[SentPacket; 256]>)>,`, which is a chunked list essentially. Cache locality on larger packet numbers was great but with lower packet numbers it was notably slower than the `VecDequeue<SentPacket>`. After tinkering around for a few days I found the reason: for higher packet numbers and randomized input for removing ranges, the `VecDequeue<SentPacket>` has to shift for every removal thats not optimal, i.e. taking from the end. This means a lot of copying which is slow. Seems logical in hindsight but I was genuinely scratching my head. To solve this I added a "Gravestone", so a placeholder that prevents shifting: `VecDequeue<Option<SentPacket>>`. Now I just remove from the beginning and append to the end, both of which should just reduce to pointer shifting and the occasional allocation in the beginning (which can also be reduced by just reserving space). This way, removal of a range, even for thousands of active packets, stays in the nanosecond area.

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

> **Note**
> Windows is not supported.

## Run

Until the Client API is fully implemented and bug free, one may have to use an external QUIC implementation as Client. I recommend [quinn](https://github.com/quinn-rs/quinn). An example local server implementation using taurus as counterpart can be found in [`main.rs`](./project/src/main.rs).

```bash
# Start the server
~/taurus/project/ $ cargo run
```

```bash
# Start client
~/quinn/ $ cargo run --example client https://localhost:4433/Cargo.toml
```

## Collaborators

[ilumary](https://github.com/ilumary) - Me

## License

MIT
