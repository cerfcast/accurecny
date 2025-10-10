use std::fmt::{Debug, Display};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use mio::net::UdpSocket;
use quiche::{Config, ConnectionId, TransportParams};
use ring::rand::{SecureRandom, SystemRandom};
use serde::ser::SerializeStruct;
use serde::Serialize;
use slog::{error, info, Logger};
use std::string::ToString;

use crate::{get_unspecified_local_ip, FlexibleIp, Mode};

#[derive(Debug, Clone)]
struct SerializableTransportParams(TransportParams);

#[derive(Debug, Clone)]
pub struct AccurecnyQuicResult {
    ip: Option<IpAddr>,
    success: bool,
    params: Option<SerializableTransportParams>,
}

impl Serialize for AccurecnyQuicResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("AccurecnyQuicResult", 3)?;
        s.serialize_field("ip", &self.ip)?;
        s.serialize_field("success", &self.success)?;
        s.serialize_field(
            "params",
            &self
                .params
                .as_ref()
                .map(|params| params.to_string())
                .unwrap_or("NA".to_string()),
        )?;
        s.end()
    }
}
impl Display for SerializableTransportParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = &self.0;
        write!(f, "{{")?;
        write!(
            f,
            "\"original_destination_connection_id\": \"{}\",",
            &v.original_destination_connection_id
                .as_ref()
                .map(|conn| format!("{conn:x?}"))
                .unwrap_or("".to_string())
        )?;
        write!(f, "\"max_idle_timeout\": \"{}\",", &v.max_idle_timeout)?;
        write!(
            f,
            "\"stateless_reset_token\": \"{}\",",
            &v.stateless_reset_token
                .map(|f| format!("{f:x}"))
                .unwrap_or("".to_string())
        )?;
        write!(
            f,
            "\"max_udp_payload_size\": \"{}\",",
            &v.max_udp_payload_size
        )?;
        write!(f, "\"initial_max_data\": \"{}\",", &v.initial_max_data)?;

        write!(
            f,
            "\"initial_max_stream_data_bidi_local\": \"{}\",",
            &v.initial_max_stream_data_bidi_local,
        )?;
        write!(
            f,
            "\"initial_max_stream_data_bidi_remote\": \"{}\",",
            &v.initial_max_stream_data_bidi_remote
        )?;
        write!(
            f,
            "\"initial_max_stream_data_uni\": \"{}\",",
            &v.initial_max_stream_data_uni
        )?;
        write!(
            f,
            "\"initial_max_streams_bidi\": \"{}\",",
            &v.initial_max_streams_bidi
        )?;
        write!(
            f,
            "\"initial_max_streams_uni\": \"{}\",",
            &v.initial_max_streams_uni
        )?;
        write!(f, "\"ack_delay_exponent\": \"{}\",", &v.ack_delay_exponent)?;
        write!(f, "\"max_ack_delay\": \"{}\",", &v.max_ack_delay)?;
        write!(
            f,
            "\"disable_active_migration\": \"{}\",",
            &v.disable_active_migration
        )?;
        write!(
            f,
            "\"active_conn_id_limit\": \"{}\",",
            &v.active_conn_id_limit
        )?;

        write!(
            f,
            "\"initial_source_connection_id\": \"{}\",",
            &v.initial_source_connection_id
                .as_ref()
                .map(|conn| format!("{conn:?}"))
                .unwrap_or("".to_string())
        )?;

        write!(
            f,
            "\"retry_source_connection_id\": \"{}\",",
            &v.retry_source_connection_id
                .as_ref()
                .map(|conn| format!("{conn:?}"))
                .unwrap_or("".to_string())
        )?;
        write!(
            f,
            "\"max_datagram_frame_size\": \"{}\",",
            &v.max_datagram_frame_size.unwrap_or_default()
        )?;

        write!(
            f,
            "\"version_information\": \"{}\",",
            &v.version_information
                .as_ref()
                .map(|(a, b)| format!(
                    "{:x}, [{}]",
                    a,
                    b.as_ref()
                        .map(|f| f
                            .iter()
                            .map(|f| format!("{:x}", f))
                            .collect::<Vec<_>>()
                            .join(","))
                        .unwrap_or_default()
                ))
                .unwrap_or("".to_string())
        )?;
        write!(
            f,
            "\"unknown_params\": {{ {} }}",
            &v.unknown_params
                .as_ref()
                .map(|conn| {
                    conn.parameters
                        .iter()
                        .fold("".to_string(), |existing, next| {
                            let serialized_unknown_param =
                                format!("\"{:x?}\": {:?}", next.id, next.value);
                            if !existing.is_empty() {
                                format!("{existing}, {serialized_unknown_param}")
                            } else {
                                serialized_unknown_param
                            }
                        })
                })
                .unwrap_or_default()
        )?;
        write!(f, "}}")
    }
}

impl AccurecnyQuicResult {
    pub fn new() -> Self {
        Self {
            ip: None,
            success: false,
            params: None,
        }
    }
}

/// Used to accept qlog output after serialization and generate
/// EventData after deserialization.
#[derive(Clone, Debug)]
struct QlogRoundtripper {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for QlogRoundtripper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.bytes.lock().unwrap().flush()
    }
}

fn send_entire_packet(
    connection: &UdpSocket,
    to: SocketAddr,
    pkt: &[u8],
    logger: Logger,
) -> Result<usize, std::io::Error> {
    let mut sent_so_far = 0usize;
    while sent_so_far < pkt.len() {
        match connection.send_to(&pkt[sent_so_far..], to) {
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    info!(
                        logger,
                        "{} -> {}: send() would block",
                        connection.local_addr().unwrap(),
                        to
                    );
                } else {
                    error!(
                        logger,
                        "Error occurred when attempting to send the initial packet: {}", e
                    );
                    return Err(e);
                }
            }
            Ok(just_wrote) => {
                sent_so_far += just_wrote;
            }
        }
    }
    Ok(sent_so_far)
}

pub async fn accurate_ecn_quic(
    ip: &FlexibleIp,
    name: &str,
    logger: slog::Logger,
) -> AccurecnyQuicResult {
    fn generate_quic_config() -> Config {
        let mut config = quiche::Config::new(1).unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.verify_peer(false);
        config.set_max_idle_timeout(10000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10000000);
        config.set_initial_max_stream_data_bidi_local(1000000);
        config.set_initial_max_stream_data_bidi_remote(1000000);
        config.set_initial_max_stream_data_uni(1000000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.set_active_connection_id_limit(2);
        config.set_max_connection_window(25165824);
        config.set_max_stream_window(16777216);
        config.enable_track_unknown_transport_parameters(1024);
        config.set_version_information(Some((1, Some(vec![1]))));
        config.log_keys();
        config
    }

    fn generate_scid<'a>() -> ConnectionId<'a> {
        let rng = SystemRandom::new();
        let scid = {
            let mut conn_id = [0; quiche::MAX_CONN_ID_LEN];
            rng.fill(&mut conn_id[..]).unwrap();
            conn_id.to_vec()
        };

        quiche::ConnectionId::from_vec(scid)
    }

    let mut quic_test_result = AccurecnyQuicResult::new();
    quic_test_result.ip = Some((*ip).clone().into());

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let source: SocketAddr = get_unspecified_local_ip(&Mode::Ipv4).into();

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut connection_socket = match mio::net::UdpSocket::bind(source) {
        Err(e) => {
            error!(
                logger,
                "There was an error binding to the UDP socket for the host: {}; failing test.", e
            );
            return quic_test_result;
        }
        Ok(c) => c,
    };

    poll.registry()
        .register(
            &mut connection_socket,
            mio::Token(0),
            mio::Interest::READABLE,
        )
        .unwrap();

    let mut config = generate_quic_config();
    let scid = generate_scid();

    let local_addr = connection_socket.local_addr().unwrap();
    let server_addr: SocketAddr = ((*ip).clone(), 443).into();

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(Some(name), &scid, local_addr, server_addr, &mut config).unwrap();

    let keylog_writer = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("quic.key")
        .unwrap();
    conn.set_keylog(Box::new(keylog_writer));

    let qlog_data: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(vec![]));
    let round_tripper = std::boxed::Box::new(QlogRoundtripper {
        bytes: qlog_data.clone(),
    });
    conn.set_qlog(
        round_tripper,
        format!("Connection to {}", server_addr).to_string(),
        "Events related to creating a test connection".to_string(),
    );

    // Get the first packet that quiche wants to send to the peer as part of connection establishment.
    let mut initial_pkt_buf = [0; 1350];
    match conn.send(&mut initial_pkt_buf) {
        Err(e) => {
            error!( logger, "There was an error making the initial send on the QUIC connection: {}; failing test.", e);
            return quic_test_result;
        }
        Ok((initial_send_size, initial_send_info)) => {
            match send_entire_packet(
                &connection_socket,
                initial_send_info.to,
                &initial_pkt_buf[..initial_send_size],
                logger.clone(),
            ) {
                Err(e) => {
                    error!(
                        logger,
                        "Error occurred when attempting to send the initial packet: {}", e
                    );
                    return quic_test_result;
                }
                Ok(sent_size) => {
                    if sent_size != initial_send_size {
                        error!(
                        logger,
                        "Error occurred when attempting to send the initial packet: Did not send entire initial packet."
                    );
                        return quic_test_result;
                    }
                }
            }
        }
    }

    // Loop until there is a connection established ...
    loop {
        if !conn.is_in_early_data() {
            poll.poll(&mut events, conn.timeout()).unwrap();
        }

        // If the event loop reported no events, it means that the timeout
        // has expired, so handle it without attempting to read packets. We
        // will then proceed with the send loop.
        if events.is_empty() {
            info!(logger, "timed out");

            conn.on_timeout();
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        for event in &events {
            let socket = match event.token() {
                mio::Token(0) => &connection_socket,
                _ => unreachable!(),
            };

            loop {
                let mut recvd_pkt = [0u8; 65536];
                let (recvd_pkt_len, from) = match socket.recv_from(&mut recvd_pkt) {
                    Ok(v) => v,

                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // There are no more UDP packets to read on this socket.
                        // Process subsequent events.
                        info!(logger, "{}: recv() would block", local_addr);
                        break;
                    }
                    Err(e) => {
                        error!(logger, "There was an error reading additional data on a socket: {}; Failing the test.", e);
                        return quic_test_result;
                    }
                };

                info!(logger, "{}: got {} bytes", local_addr, recvd_pkt_len);

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process the network-received packets through quiche.
                let read = match conn.recv(&mut recvd_pkt[..recvd_pkt_len], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!(logger, "{}: recv failed: {:?}", local_addr, e);
                        return quic_test_result;
                    }
                };

                info!(logger, "{}: processed {} bytes", local_addr, read);
            }
        }

        info!(logger, "done reading");

        // If the connection is closed, then we are in trouble. Just abort.
        if conn.is_closed() {
            info!(
                logger,
                "connection closed, {:?} {:?}; failing the test.",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                error!(logger, "connection timed out; failing the test.");
            }
            return quic_test_result;
        }

        // If there are any packets that need to be sent, send them now.
        loop {
            let mut send_buf = [0u8; 1350];
            let (send_size, send_info) = match conn.send(&mut send_buf) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    info!(logger, "{}: no more packets to send!", local_addr);
                    break;
                }

                Err(e) => {
                    conn.close(false, 0x1, b"fail").ok();
                    error!(
                        logger,
                        "There was an error sending bytes on a connection: {}; Failing the test.",
                        e
                    );
                    return quic_test_result;
                }
            };

            match send_entire_packet(
                &connection_socket,
                send_info.to,
                &send_buf[..send_size],
                logger.clone(),
            ) {
                Err(e) => {
                    error!(
                        logger,
                        "Error occurred when attempting to send a packet: {}", e
                    );
                    return quic_test_result;
                }
                Ok(sent_size) => {
                    if sent_size != send_size {
                        error!(
                        logger,
                        "Error occurred when attempting to send a packet: Did not send it entirely."
                    );
                        return quic_test_result;
                    }
                }
            }
            info!(
                logger,
                "{} -> {}: written {}", local_addr, send_info.to, send_size
            );
        }

        if conn.is_established() {
            info!(logger, "The connection is established.");
            break;
        }
    }

    let events = conn.qlog_streamer().unwrap();
    events.finish_log().unwrap();

    if conn.is_established() {
        quic_test_result.success = true;

        quic_test_result.params = conn
            .peer_transport_params()
            .map(|f| SerializableTransportParams(f.clone()));
    }

    conn.close(false, 0x0, "Test complete.".as_bytes()).unwrap();

    quic_test_result
}
