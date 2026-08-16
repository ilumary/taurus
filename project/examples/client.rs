use quic::connection::ClientConfig;
use quic::terror;
use tracing_subscriber::filter::EnvFilter;

fn main() -> Result<(), terror::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("quic=trace")),
        )
        .with_target(false)
        .init();

    ClientConfig::new("cert/cert.der")
        .with_supported_protocols(vec!["hq-29".to_owned()])
        .listen_on("[::1]:0")
        .run(|client| async move {
            let Some(connection) = client.connect("[::1]:4433".parse().unwrap()).await else {
                eprintln!("handshake failed");
                return;
            };
            println!("connected!");

            let Ok((send, _recv)) = connection.open_bidirectional_stream().await else {
                eprintln!("could not open stream");
                return;
            };
            println!("opened bidi stream");

            let bytes = "Hello World!".as_bytes();
            match send.write(bytes, true).await {
                Ok(written) => println!("wrote {written} bytes to stream!"),
                Err(e) => eprintln!("write failed: {e}"),
            }

            if let Err(err) = send.finish().await {
                println!("error waiting for stream finish: {}", err);
            }

            println!("send stream finished");
        })
}
