use std::net::IpAddr;

use serde::{Serialize, Serializer};

use crate::quic_ecn::SerializableTransportParams;
pub const RESULT_CSV_HEADER: &str = "source, rank, url, tcp_ip, tcp_success, tcp_supported, tcp_flags, quic_ip, quic_success, transport_params\n";

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccurecnyTcpResult {
    pub ip: Option<IpAddr>,
    pub success: bool,
    pub supported: bool,
    pub flags: Option<String>,
}

impl AccurecnyTcpResult {
    pub fn new() -> Self {
        Self {
            ip: None,
            success: false,
            supported: false,
            flags: None,
        }
    }
}
#[derive(Debug, Clone)]
pub struct AccurecnyQuicResult {
    pub ip: Option<IpAddr>,
    pub success: bool,
    pub params: Option<SerializableTransportParams>,
}

fn serialize_default_u64<S>(v: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let v = v.unwrap_or_default();
    u64::serialize(&v, serializer)
}

#[derive(Debug, Clone, Serialize)]
pub struct AccurecnyResult {
    pub source: IpAddr,
    #[serde(serialize_with = "serialize_default_u64")]
    pub rank: Option<u64>,
    pub url: String,
    pub tcp: AccurecnyTcpResult,
    pub quic: AccurecnyQuicResult,
}

impl AccurecnyResult {
    pub fn new(
        rank: Option<u64>,
        url: String,
        source: IpAddr,
        tcp: AccurecnyTcpResult,
        quic: AccurecnyQuicResult,
    ) -> Self {
        Self {
            rank,
            url,
            source,
            tcp,
            quic,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccurecnyResults {
    results: Vec<AccurecnyResult>,
}

impl AccurecnyResults {
    pub fn new() -> Self {
        AccurecnyResults {
            results: Vec::<AccurecnyResult>::new(),
        }
    }

    pub fn add(&mut self, result: AccurecnyResult) {
        self.results.push(result);
    }

    pub fn get(&self) -> Vec<AccurecnyResult> {
        self.results.clone()
    }
}
