use quic::{Endpoint, Event};

fn main() -> std::io::Result<()> {
    let mut server = Endpoint::local_server("127.0.0.1:34254");
    let event = server.recv();
    match event {
        Ok(event) => match event {
            Event::NewConnection(ch) => {
                //maybe check if server can handle more connections
                let _ = server.handle_connection(ch);
            }
            Event::Handshaking(ch) => {
                let _ = server.handle_connection(ch);
            }
            _ => (),
        },
        Err(error) => eprint!("{}", error),
    }
    Ok(())
}
