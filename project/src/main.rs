use quic::Endpoint;

fn main() -> std::io::Result<()> {
    let mut server = Endpoint::local_server("127.0.0.1:34254");
    server.recv();
    Ok(())
}
