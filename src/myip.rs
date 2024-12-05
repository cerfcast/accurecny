use std::net::IpAddr;
use std::time::Duration;
use serde::Deserialize;
use slog::{info, Logger};

#[derive(Debug, Clone, Deserialize)]
struct IpIfyResult {
    ip: IpAddr,
}

pub async fn what_is_my_ip(logger: Logger) -> Result<IpAddr, std::io::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .build()
        .map_err(std::io::Error::other)?;

    info!(logger, "Starting to query for my IP address.");
    let result = client
        .get("https://api.ipify.org?format=json")
        .send()
        .await
        .map_err(std::io::Error::other)?;

    info!(logger, "Done querying for my IP address.");

    let body = result.text().await.map_err(std::io::Error::other)?;

    let ip: IpIfyResult = serde_json::from_str(&body).map_err(std::io::Error::other)?;

    Ok(ip.ip)
}
