use std::io::{BufReader, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use nix::sys::socket::SockaddrLike;
use qlog::events::connectivity::TransportOwner;
use qlog::events::quic::TransportParametersSet;
use qlog::events::{self, EventData};
use qlog::reader::{Event, QlogSeqReader};
use quiche::{Config, ConnectionId};
use ring::rand::{SecureRandom, SystemRandom};
use slog::{error, info};

use crate::{get_unspecified_local_ip, FlexibleIp, Mode};

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccurecnyQuicResult {
    ip: Option<IpAddr>,
    success: bool,
    supported: bool,
}

impl AccurecnyQuicResult {
    pub fn new() -> Self {
        Self {
            ip: None,
            success: false,
            supported: false,
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

    let mut buf = [0; 65535];
    let mut out = [0; 1350];

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let source: SocketAddr = get_unspecified_local_ip(&Mode::Ipv4).into();

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let maybe_connection_socket = mio::net::UdpSocket::bind(source);
    if let Err(e) = &maybe_connection_socket {
        error!(
            logger,
            "There was an error binding to the UDP socket for the host: {}; failing test.", e
        );
        return quic_test_result;
    }
    let mut connection_socket = maybe_connection_socket.unwrap();

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
    let mut server_addr: SocketAddr = (*ip).clone().into();
    server_addr.set_port(443);

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(Some(name), &scid, local_addr, server_addr, &mut config).unwrap();

    let qlog_data: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(vec![]));
    let round_tripper = std::boxed::Box::new(QlogRoundtripper {
        bytes: qlog_data.clone(),
    });
    conn.set_qlog(round_tripper, "Testing".to_string(), "Testing".to_string());
    // Send the packet, and follow up with additional sends, if necessary.
    //let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    let initial_send_result = conn.send(&mut out);
    if let Err(e) = initial_send_result {
        error!(
            logger,
            "There was an error making the initial send on the QUIC connection: {}; failing test.",
            e
        );
        return quic_test_result;
    };

    let (write, send_info) = initial_send_result.unwrap();
    while let Err(e) = connection_socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            info!(
                logger,
                "{} -> {}: send() would block",
                connection_socket.local_addr().unwrap(),
                send_info.to
            );
            continue;
        }
        error!(
            logger,
            "Error occurred when attempting to send the initial packet: {}", e
        );
        return quic_test_result;
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

            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read on this socket.
                        // Process subsequent events.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            info!(logger, "{}: recv() would block", local_addr);
                            break 'read;
                        }

                        error!(logger, "There was an error reading additional data on a socket: {}; Failing the test.", e);
                        return quic_test_result;
                    }
                };

                info!(logger, "{}: got {} bytes", local_addr, len);

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets.
                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!(logger, "{}: recv failed: {:?}", local_addr, e);
                        continue 'read;
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

        // If there are any packets that need to be sent for any of
        // the paths that are active, send them now.
        loop {
            let (write, send_info) =
                match conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        info!(logger, "{}: no more packets to send!", local_addr);
                        break;
                    }

                    Err(e) => {
                        conn.close(false, 0x1, b"fail").ok();
                        error!(
                            logger,
                            "There was an error sending bytes on a path: {}; Failing the test.", e
                        );
                        return quic_test_result;
                    }
                };

            if let Err(e) = connection_socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    info!(
                        logger,
                        "{} -> {}: send() would block", local_addr, send_info.to
                    );
                    break;
                }
                error!(
                    logger,
                    "There was an error sending additional data on a socket: {}; Failing the test.",
                    e
                );
                return quic_test_result;
            }

            info!(
                logger,
                "{} -> {}: written {}", local_addr, send_info.to, write
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

        let event_bytes = qlog_data.lock().unwrap().to_vec();
        let reader = BufReader::new(event_bytes.as_slice());
        let bx_reader = std::boxed::Box::new(reader);
        let qlog_reader = QlogSeqReader::new(bx_reader).unwrap();

        for i in qlog_reader {
            if let Event::Qlog(events::Event {
                data:
                    EventData::TransportParametersSet(
                        TransportParametersSet {
                            owner: Some(TransportOwner::Remote),
                            unknown_parameters: unknown,
                            ..
                        },
                        ..,
                    ),
                ..
            }) = i
            {
                for unk in unknown {
                    println!("Unknown: {:?}", unk);
                    if unk.id == 0x2051a5fa8648af {
                        info!(logger, "Found that {} supports Accurate ECN over quic.\n", server_addr);
                        quic_test_result.supported = true;
                    }
                }
            }
        }
    }

    conn.close(false, 0x0, "Test complete.".as_bytes()).unwrap();

    quic_test_result
}
