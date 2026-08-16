//! generates a self-signed cert + key in DER for local development

use rcgen::{CertificateParams, KeyPair};
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];

    let mut params = CertificateParams::new(names)?;

    // macOS refuses to trust a leaf valid for more than 825 days
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(800);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;

    std::fs::create_dir_all("cert")?;
    std::fs::write("cert/cert.der", cert.der())?;
    std::fs::write("cert/key.der", key.serialize_der())?;

    println!("wrote cert/cert.der, cert/key.der (+ .pem copies)");
    Ok(())
}
