use quic::{quic_error, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), quic_error::Error> {
    let mut server = ServerConfig::local_server("127.0.0.1:34254")
        .build()
        .await?;

    while let Some(_connection) = server.accept().await {
        println!("new connection!");
    }

    Ok(())
}
