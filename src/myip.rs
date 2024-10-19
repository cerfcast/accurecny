use std::io::Error;
use std::net::IpAddr;

use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct IpIfyResult {
    ip: IpAddr,
}

pub async fn what_is_my_ip() -> Result<IpAddr, std::io::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .build()
        .map_err(|e| std::io::Error::other(e))?;

    let result = client
        .get("https://api.ipify.org?format=json")
        .send().await
        .map_err(|e| std::io::Error::other(e))?;

    let body = result.text().await.map_err(|e| std::io::Error::other(e))?;

    let ip: IpIfyResult = serde_json::from_str(&body).map_err(|e| std::io::Error::other(e))?;

    Ok(ip.ip)
}