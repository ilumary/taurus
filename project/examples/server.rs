use quic::connection::ServerConfig;
use quic::terror;
use tracing_subscriber::filter::EnvFilter;

fn main() -> Result<(), terror::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("quic=trace")),
        )
        .with_target(false)
        .init();

    // blocks until shutdown
    ServerConfig::new("[::1]:4433", "cert/cert.der", "cert/key.der")
        .with_supported_protocols(vec!["hq-29".to_owned()])
        .with_workers(1)
        .run(|connection| async move {
            println!("new connection!");

            while let Ok((recv, _send)) = connection.accept_bidirectional_stream().await {
                // one task per stream, still on this connection's shard
                connection.spawn(|_| async move {
                    println!("new bidirectional stream");
                    let mut data = [0u8; 1024];
                    while let Ok(Some(read)) = recv.read(&mut data).await {
                        println!("read stream data: \"{:?}\"", std::str::from_utf8(&data[..read]));
                    }
                });
            }
        })
}
