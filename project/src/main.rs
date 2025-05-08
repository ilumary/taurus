use quic::terror;

use tracing::Level;
use tracing_subscriber::FmtSubscriber;

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let _ = run_server();
}

#[tokio::main]
async fn run_server() -> Result<(), terror::Error> {
    let mut cert_path = std::env::current_dir().unwrap();
    cert_path.push("cert");
    cert_path.push("cert.der");

    let mut key_path = std::env::current_dir().unwrap();
    key_path.push("cert");
    key_path.push("key.der");

    let mut server = quic::connection::ServerConfig::new(
        "[::1]:4433",
        "/Users/christophbritsch/Library/Application Support/org.quinn.quinn-examples/cert.der",
        "/Users/christophbritsch/Library/Application Support/org.quinn.quinn-examples/key.der",
    )
    .with_supported_protocols(vec!["hq-29".to_owned()])
    .build()
    .await?;

    let mut data = [0u8; 1024];

    while let Some(connection) = server.accept().await {
        println!("new connection!");

        tokio::spawn(async move {
            while let Ok((recv, _send)) = connection.accept_bidirectional_stream().await {
                tokio::spawn(async move {
                    println!("NEW BIDIRECTIONAL STREAM FROM MAIN!");

                    while let Ok(Some(read)) = recv.read(&mut data).await {
                        println!("read stream data: {:?}", std::str::from_utf8(&data[..read]));
                    }
                });
            }
        });
    }

    Ok(())
}

#[tokio::main]
async fn run_client() -> Result<(), terror::Error> {
    let mut client = quic::connection::ClientConfig::new(
        "/Users/christophbritsch/Library/Application Support/org.quinn.quinn-examples/cert.der",
    )
    .with_supported_protocols(vec!["hq-29".to_owned()])
    .listen_on("[::1]:4433")
    .build()
    .await?;

    if let Some(connection) = client.connect("[::1]:4444".parse().unwrap()).await {
        println!("NEW CONNECTION ESTABLISHED");
        tokio::spawn(async move {
            if let Ok((_recv, send)) = connection.open_bidirectional_stream().await {
                tokio::spawn(async move {
                    println!("OPENED BIDI STREAM");

                    if let Ok(written) = send.write(&[0x12, 0x34, 0x56], false).await {
                        println!("WROTE {written} BYTES TO STREAM");
                    }
                });
            }
        });
    }

    Ok(())
}
