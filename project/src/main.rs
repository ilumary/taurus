use quic::{terror, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), terror::Error> {
    let mut cert_path = std::env::current_dir().unwrap();
    cert_path.push("cert");
    cert_path.push("cert.der");

    let mut key_path = std::env::current_dir().unwrap();
    key_path.push("cert");
    key_path.push("key.der");

    let mut server = ServerConfig::new(
        "[::1]:4433",
        "/Users/christophbritsch/Library/Application Support/org.quinn.quinn-examples/cert.der",
        "/Users/christophbritsch/Library/Application Support/org.quinn.quinn-examples/key.der",
    )
    .with_supported_protocols(vec!["hq-29".to_owned()])
    .build()
    .await?;

    while let Some(_connection) = server.accept().await {
        println!("new connection!");
    }

    server.stop().await;

    Ok(())
}
