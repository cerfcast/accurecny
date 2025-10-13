/*
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

use std::fmt::Debug;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::os::fd::AsRawFd;

use clap::Parser;
use clap_derive::Args;
use myip::what_is_my_ip;
use nix::errno::Errno;
use nix::libc::{
    epoll_create, epoll_ctl, epoll_event, epoll_wait, setsockopt, EPOLLERR, EPOLLHUP, EPOLLIN,
    EPOLLPRI, EPOLLRDHUP, EPOLL_CTL_ADD, IPPROTO_IP, IPTOS_ECN_ECT1, IP_TOS,
};
use nix::sys::socket::AddressFamily::Inet;
use nix::sys::socket::SockProtocol::{self, Tcp as TcpProto};
use nix::sys::socket::{
    bind, getsockname, listen, sendto, socket, Backlog, MsgFlags, SockFlag, SockaddrLike,
};
use nix::sys::socket::{connect, recv, SockaddrIn};
use pnet::packet::tcp::{ipv4_checksum, Tcp, TcpFlags, TcpOption, TcpOptionPacket, TcpPacket};
use quic_ecn::accurate_ecn_quic;
use rand::distr::{Distribution, Uniform};

use std::time::Duration;

use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags::{ACK, SYN};
use pnet::packet::FromPacket;
use slog::{error, info, warn, Drain, Logger};

use crate::flexible::{FlexibleAddr, FlexibleIp};
use crate::result::{AccurecnyResult, AccurecnyResults, AccurecnyTcpResult, RESULT_CSV_HEADER};

mod flexible;
mod myip;
mod quic_ecn;
mod result;

#[allow(dead_code)]
enum AccurecnyError {
    Errno(Errno),
    Other(std::io::Error),
}

impl Debug for AccurecnyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccurecnyError::Errno(errno) => write!(f, "Accurecny error occurred: Errno {}", errno),
            AccurecnyError::Other(e) => write!(f, "Accurecny uncategorized error occurred: {}", e),
        }
    }
}

#[derive(Debug, Clone)]
enum Target {
    Ip(FlexibleIp),
    Name(String),
}

#[derive(Debug, Clone)]
struct IpRangeRatio {
    pub start: FlexibleIp,
    pub stop: FlexibleIp,
    pub ratio: f64,
}

#[derive(Debug, Clone)]
enum TargetDescriptor {
    Range(IpRangeRatio),
    Ip(FlexibleIp),
    Name(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ip(flexible_ip) => write!(f, "{:?}", flexible_ip),
            Target::Name(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Clone)]
enum Mode {
    #[allow(unused)]
    Ipv6,
    Ipv4,
}

fn parse_target(arg: &str) -> Result<TargetDescriptor, String> {
    // First, if the target has a - and an @ in it, then we will try to parse it as a range.
    // It might turn out to be a filename, but we'll try it this way!
    match if let Some((one, two, three)) = arg.split_once("@").and_then(|v| {
        v.0.split_once("-")
            .map(|sv| (sv.0.to_string(), sv.1.to_string(), v.1.to_string()))
    }) {
        println!("Contains?");
        Some((one.parse::<IpAddr>(), two.parse::<IpAddr>(), three.parse()))
    } else {
        None
    } {
        Some((Ok(start), Ok(stop), Ok(ratio))) => {
            println!("Found a range!");
            Ok(TargetDescriptor::Range(IpRangeRatio {
                start: start.into(),
                stop: stop.into(),
                ratio,
            }))
        }
        _ => match arg.parse() {
            Ok(addr) => match addr {
                IpAddr::V4(addr) => Ok(TargetDescriptor::Ip(FlexibleIp::Ipv4(addr))),
                IpAddr::V6(addr) => Ok(TargetDescriptor::Ip(FlexibleIp::Ipv6(addr))),
            },
            Err(_) => Ok(TargetDescriptor::Name(arg.to_string())),
        },
    }
}

fn parse_duration(arg: &str) -> Result<Duration, String> {
    match arg.parse() {
        Ok(duration) => Ok(Duration::from_secs(duration)),
        Err(e) => Err(format!("Could not convert {} into seconds: {}", arg, e).to_string()),
    }
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Configure additional logging; repeat for more verbose output.
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Override automatic detection of local IP address (only used for inclusion in results)
    #[arg(long)]
    myip: Option<IpAddr>,

    /// Set the port on which to attempt HTTP and QUIC connections.
    #[arg(long, default_value_t = 443u16)]
    port: u16,

    /// Set ect1 on the outgoing packets.
    #[arg(long, default_value_t = false)]
    ecn: bool,

    /// The name of a file to store the results.
    #[arg(long, value_parser = clap::value_parser!(clio::ClioPath))]
    output: Option<clio::ClioPath>,

    #[command(flatten)]
    target: TargetArgs,

    /// Wait a certain number of seconds between running each test.
    #[arg(long, value_parser=parse_duration)]
    interval: Option<Duration>,

    /// Specify the maximum number of hosts to test for Accurate ECN support.
    #[arg(long)]
    max: Option<usize>,
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct TargetArgs {
    /// A single hostname or IP address to test for Accurate ECN support.
    #[arg(long, value_parser = parse_target)]
    target: Option<TargetDescriptor>,

    /// The path to the file containing  list of hostnames or IP addresses to test for Accurate ECN support.
    #[clap(long, value_parser = clap::value_parser!(clio::ClioPath).exists())]
    top_sites: Option<clio::ClioPath>,
}

#[derive(Debug, serde::Deserialize)]
struct PopularSite {
    rank: u64,
    url: String,
}

fn extract_popular_sites(path: &std::path::Path) -> Result<Vec<PopularSite>, std::io::Error> {
    let mut results = Vec::<PopularSite>::new();
    let mut rdr = csv::ReaderBuilder::new()
        .trim(csv::Trim::Fields)
        .has_headers(false)
        .from_path(path)?;
    for result in rdr.deserialize() {
        let record: PopularSite = result?;
        results.push(record);
    }
    Ok(results)
}

fn resolve_target(target: Target, logger: slog::Logger) -> Result<Vec<FlexibleIp>, std::io::Error> {
    match target {
        Target::Name(name) => {
            let mut resolution_result: Result<Vec<FlexibleIp>, std::io::Error> =
                Err(std::io::ErrorKind::ConnectionRefused.into());

            // Loop here -- we will try to resolve the www subdomain if a bare domain name does not
            // work.
            for subdomain in ["", "www."] {
                let hostname = format!("{}{}", subdomain, name.clone());
                let hostname_with_dummy_port = format!("{}:80", hostname.clone());

                let server_ips = hostname_with_dummy_port.to_socket_addrs();

                if let Err(resolution_error) = server_ips {
                    error!(
                        logger,
                        "Error resolving target {}: {:?}", hostname, resolution_error
                    );
                    resolution_result = Err(std::io::ErrorKind::ConnectionRefused.into());
                } else {
                    let result: Vec<_> = server_ips
                        .unwrap_or_default()
                        .map(|ip| match ip.ip() {
                            IpAddr::V4(addr) => FlexibleIp::Ipv4(addr),
                            IpAddr::V6(addr) => FlexibleIp::Ipv6(addr),
                        })
                        .collect();

                    if result.len() > 1 {
                        warn!(
                            logger,
                            "Warning: There were multiple IP addresses resolved from {:?}: {:?}.",
                            name.clone(),
                            result,
                        );
                    }
                    resolution_result = Ok(result);
                    break;
                }
            }
            resolution_result
        }
        Target::Ip(ip) => Ok(vec![ip]),
    }
}

fn get_unspecified_local_ip_addr(mode: &Mode) -> FlexibleAddr {
    match mode {
        Mode::Ipv4 => FlexibleAddr {
            ip: FlexibleIp::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
        },
        Mode::Ipv6 => panic!("Ipv6 is not supported at this time."),
    }
}

fn accurate_ecn_tcp(
    test_target: &FlexibleAddr,
    ecn: bool,
    _: &String,
    logger: slog::Logger,
) -> AccurecnyTcpResult {
    let mut tcp_test_result = AccurecnyTcpResult::new();

    let (domain, protocol) = match test_target.ip {
        FlexibleIp::Ipv4(_) => {
            info!(logger, "Matching mode v4 to set protocol!");
            (Inet, TcpProto)
        }
        FlexibleIp::Ipv6(_) => {
            error!(logger, "Ipv6 is not supported!");
            return tcp_test_result;
        }
    };

    tcp_test_result.ip = Some(test_target.clone().ip.into());

    // We know that we are ipv4 now!

    let maybe_raw_socket = socket(
        domain,
        nix::sys::socket::SockType::Raw,
        SockFlag::empty(),
        protocol,
    );

    if let Err(errno) = maybe_raw_socket {
        error!(
            logger,
            "Attempting to make the raw socket failed (error number {})", errno
        );
        return tcp_test_result;
    }
    let raw_socket = maybe_raw_socket.unwrap();

    let destination: Box<dyn SockaddrLike> = (*test_target).clone().into();
    let source: Box<dyn SockaddrLike> = (get_unspecified_local_ip_addr(&Mode::Ipv4)).into();

    // This placeholder socket is not directly used. It helps us ask the operating
    // system for exclusive access to an ephemeral port.
    let maybe_tcp_placeholder = socket(
        domain,
        nix::sys::socket::SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    );

    if let Err(errno) = maybe_tcp_placeholder {
        error!(
            logger,
            "Attempting to make the socket for reserving a source port failed (error number {})",
            errno
        );
        return tcp_test_result;
    }
    let tcp_placeholder = maybe_tcp_placeholder.unwrap();

    if let Err(errno) = bind(tcp_placeholder.as_raw_fd(), &*source) {
        error!(
            logger,
            "Attempting to bind the socket for reserving a source port failed (error number {})",
            errno
        );
        return tcp_test_result;
    }

    if let Err(errno) = listen(&tcp_placeholder, Backlog::new(0).unwrap()) {
        error!(
            logger,
            "Attempting to bind the socket for reserving a source port failed (error number {})",
            errno
        );
        return tcp_test_result;
    }

    if let Err(errno) = bind(raw_socket.as_raw_fd(), &*source) {
        error!(
            logger,
            "Attempting to bind the socket for TCP transmission/reception failed (error number {})",
            errno
        );
        return tcp_test_result;
    }

    if let Err(errno) = connect(raw_socket.as_raw_fd(), &*destination) {
        error!(logger, "Attempting to connect the socket for TCP transmission/reception failed (error number {})", errno);
        return tcp_test_result;
    }

    let source = {
        let tcp_placeholder_name = getsockname::<SockaddrIn>(tcp_placeholder.as_raw_fd()).unwrap();
        let raw_source_name = getsockname::<SockaddrIn>(raw_socket.as_raw_fd()).unwrap();
        SockaddrIn::from(SocketAddrV4::new(
            raw_source_name.ip(),
            tcp_placeholder_name.port(),
        ))
    };

    let tcp_options = [
        TcpOption::sack_perm(),
        TcpOption::wscale(7),
        TcpOption::mss(1460),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::nop(),
    ];

    let options_size = tcp_options
        .iter()
        .fold(0, |acc, elem| TcpOptionPacket::packet_size(elem) + acc);

    let mut pseudo_packet_bytes =
        vec![0u8; pnet::packet::tcp::TcpPacket::minimum_packet_size() + options_size];
    let mut pseudo_packet = MutableTcpPacket::new(&mut pseudo_packet_bytes).unwrap();

    let mut packet_tcp = Tcp {
        source: source.port(),
        destination: test_target.port,
        sequence: chrono::Local::now().timestamp_subsec_nanos(),
        acknowledgement: 0,
        data_offset: 8,
        reserved: 1,
        flags: SYN | TcpFlags::CWR | TcpFlags::ECE,
        window: 0xfaf0,
        checksum: 0,
        urgent_ptr: 0,
        options: tcp_options.to_vec(),
        payload: Vec::new(),
    };

    // Make a pseudo packet for the calculation of the checksum.
    pseudo_packet.populate(&packet_tcp);
    let csum = match test_target.ip {
        FlexibleIp::Ipv4(v4) => {
            ipv4_checksum(&pseudo_packet.consume_to_immutable(), &source.ip(), &v4)
        }
        FlexibleIp::Ipv6(_) => {
            panic!("Ipv6 is not supported.");
        }
    };

    let mut packet_bytes =
        vec![0u8; pnet::packet::tcp::TcpPacket::minimum_packet_size() + options_size];
    let mut packet = MutableTcpPacket::new(&mut packet_bytes).unwrap();
    packet_tcp.checksum = csum;
    packet.populate(&packet_tcp);

    if ecn {
        unsafe {
            let result = setsockopt(
                raw_socket.as_raw_fd(),
                IPPROTO_IP,
                IP_TOS,
                &IPTOS_ECN_ECT1 as *const u8 as *const std::ffi::c_void,
                1,
            );

            if result < 0 {
                error!(logger, "Failed to set ECN on socket.");
                return tcp_test_result;
            }
        }
    }

    if let Err(e) = sendto(
        raw_socket.as_raw_fd(),
        &packet_bytes,
        &*destination,
        MsgFlags::empty(),
    ) {
        error!(
            logger,
            "Failed to send SYN packet to {:?}: {}", test_target, e
        );
        return tcp_test_result;
    }

    unsafe {
        // using an IIFE so that we can bail out early but still close
        // the epoll control handle. A hack version of defer!
        if let Some(to_close) = (|| {
            let epoller = epoll_create(1);
            if epoller < 0 {
                return None;
            }

            let mut event = epoll_event {
                events: (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLPRI | EPOLLRDHUP) as u32,
                u64: raw_socket.as_raw_fd() as u64,
            };

            epoll_ctl(
                epoller,
                EPOLL_CTL_ADD,
                raw_socket.as_raw_fd(),
                &mut event as *mut epoll_event,
            );

            let event = epoll_event { events: 0, u64: 0 };
            let mut events = vec![event; 1];

            info!(logger, "About to start waiting for an event!");
            let wait_result = epoll_wait(epoller, events.as_mut_ptr(), 1, 3000);
            info!(logger, "Done waiting for an event!");

            // Whether the result was bad because it was a timeout or an error, it doesn't really matter.
            // We'll just move on.
            if wait_result == 0 {
                warn!(
                    logger,
                    "There was a timeout waiting for an event on the raw socket."
                );
                return Some(epoller);
            }

            let happened_event = events[0];
            let happened_event_socket = happened_event.u64;

            info!(logger, "Happened event socket: {}", happened_event_socket);
            info!(logger, "Raw socket FD: {}", raw_socket.as_raw_fd());

            assert!(happened_event_socket as i32 == raw_socket.as_raw_fd());
            if happened_event.events & (EPOLLIN as u32) != 0 {
                let mut result_bytes = vec![0u8; 1500];

                let result =
                    recv(raw_socket.as_raw_fd(), &mut result_bytes, MsgFlags::empty()).unwrap();

                tcp_test_result.success = true;
                let tcp_bytes = result_bytes
                    [pnet::packet::ipv4::Ipv4Packet::minimum_packet_size()..result]
                    .to_vec();

                let tcp_packet = TcpPacket::owned(tcp_bytes).unwrap();

                let tcp: Tcp = TcpPacket::from_packet(&tcp_packet);

                info!(logger, "The resulting reserved: {:x}", tcp.reserved);
                info!(logger, "The resulting flags: {:x}", tcp.flags);
                tcp_test_result.flags =
                    Some(format!("0x{:02x}{:02x}", tcp.reserved, tcp.flags).to_string());

                // Turn off clippy here because this syntax/formatting is intentional.
                #[allow(clippy::nonminimal_bool)]
                if tcp.flags & ACK != 0 &&                                           //                   2^7 2^6
                    (                                                                //                AE CWR ECE (Expected output in results file)
                        ((tcp.reserved & 0x1) == 0 && (tcp.flags & 0xc0) == 0x80) || // Table Row 1:    0   1   0 (0x0092)
                        ((tcp.reserved & 0x1) == 0 && (tcp.flags & 0xc0) == 0xc0) || // Table Row 2:    0   1   1 (0x00d2)
                        ((tcp.reserved & 0x1) == 1 && (tcp.flags & 0xc0) == 0x00) || // Table Row 3:    1   0   0 (0x0112)
                        ((tcp.reserved & 0x1) == 1 && (tcp.flags & 0xc0) == 0x80)    // Table Row 4:    1   1   0 (0x0192)
                                                                                     //                               ^ ^
                                                                                     //                              AE SYN
                                                                                     //                                ^
                                                                                     //                               CWR/ECE/URG/ACK (always odd because of the ACK)
                                                                                     //                               1   0   0   1    = 9
                                                                                     //                               1   1   0   1    = d
                                                                                     //                               0   0   0   1    = 1
                                                                                     //                               1   0   0   1    = 9

                    )
                {
                    tcp_test_result.supported = true;
                }
            }

            Some(epoller)
        })() {
            info!(logger, "Closing the epoller!");
            if let Err(e) = nix::unistd::close(to_close) {
                error!(
                    logger,
                    "There was an error closing the epoller handle: {:?}", e
                );
            }
        }
    }
    tcp_test_result
}

fn generate_targets_from_range(
    range: IpRangeRatio,
    logger: Logger,
) -> Result<Vec<(Option<u64>, Target)>, std::io::Error> {
    info!(logger, "Generating targets from a range!");
    match range {
        IpRangeRatio {
            start: FlexibleIp::Ipv4(start),
            stop: FlexibleIp::Ipv4(stop),
            ratio,
        } => {
            let startn = u32::from_be_bytes(start.octets());
            let stopn = u32::from_be_bytes(stop.octets());

            let between = Uniform::try_from(0f64..=1f64).unwrap();
            let mut rng = rand::rng();
            Ok((startn..stopn)
                .filter(|v| {
                    let r: f64 = between.sample(&mut rng);
                    if r < ratio {
                        info!(
                            logger,
                            "Keeping {} because {r} < {ratio}",
                            Into::<IpAddr>::into(v.to_be_bytes())
                        );
                        true
                    } else {
                        //info!(logger, "Skipping {v} because {r} < {ratio}");
                        false
                    }
                })
                .map(|v| {
                    (
                        None,
                        Target::Ip(Into::<IpAddr>::into(v.to_be_bytes()).into()),
                    )
                })
                .collect())
        }
        IpRangeRatio {
            start: FlexibleIp::Ipv6(_),
            stop: FlexibleIp::Ipv6(_),
            ratio: _,
        } => {
            error!(logger, "IPv6 is not implemented.\n");
            Err(std::io::ErrorKind::AddrNotAvailable.into())
        }
        IpRangeRatio {
            start: _,
            stop: _,
            ratio: _,
        } => {
            error!(logger, "Cannot mix Ipv4 and IPv6 addresses in range.\n");
            Err(std::io::ErrorKind::AddrNotAvailable.into())
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let log_level = if args.debug > 2 {
        slog::Level::Info
    } else if args.debug > 1 {
        slog::Level::Debug
    } else {
        slog::Level::Error
    };

    let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let drain = slog_term::FullFormat::new(decorator)
        .build()
        .filter_level(log_level)
        .fuse();
    let logger = slog::Logger::root(drain, slog::o!("version" => "0.5"));

    let potential_targets = if let Some(user_target) = args.target.target {
        match user_target {
            TargetDescriptor::Ip(a) => Ok(vec![(None, Target::Ip(a))]),
            TargetDescriptor::Name(b) => Ok(vec![(None, Target::Name(b))]),
            TargetDescriptor::Range(r) => generate_targets_from_range(r, logger.clone()),
        }
    } else {
        let top_sites_path = args.target.top_sites.unwrap();
        extract_popular_sites(&top_sites_path)
            .map(|list| {
                list.into_iter()
                    .map(|x| (Some(x.rank), Target::Name(x.url)))
            })
            .map(|list| list.collect::<Vec<(Option<u64>, Target)>>())
    };

    if let Err(e) = potential_targets {
        error!(
            logger,
            "Could not create a list of potential targets: {}", e
        );
        return;
    }

    let myip = match args.myip {
        Some(ip) => ip,
        None => {
            if let Ok(addr) = what_is_my_ip(logger.clone()).await {
                addr
            } else {
                get_unspecified_local_ip_addr(&Mode::Ipv4).ip.into()
            }
        }
    };

    let potential_targets = potential_targets.unwrap();

    let mut results = AccurecnyResults::new();

    for (targets_complete, (rank, target)) in potential_targets.iter().enumerate() {
        if args.max.is_some() && targets_complete >= args.max.unwrap() {
            info!(
                logger,
                "Stopping all work after checking {} targets.", targets_complete
            );
            break;
        }

        if targets_complete != 0 && args.interval.is_some() {
            info!(
                logger,
                "Waiting {:?} as requested between checks.",
                args.interval.unwrap()
            );
            std::thread::sleep(args.interval.unwrap());
        }

        let canonical_target = target.to_string();
        let resolution_result = resolve_target(target.clone(), logger.clone());

        if let Err(e) = resolution_result {
            error!(
                logger,
                "There was an error resolving a target to an IP address: {}", e
            );
            continue;
        }

        let target = resolution_result.unwrap();

        for target in target.into_iter() {
            if let FlexibleIp::Ipv4(_) = target {
                let target = &FlexibleAddr {
                    ip: target,
                    port: args.port,
                };
                let tcp_result = accurate_ecn_tcp(target, args.ecn, &canonical_target, logger.clone());
                let quic_result =
                    accurate_ecn_quic(target, args.ecn, &canonical_target, logger.clone()).await;

                results.add(AccurecnyResult::new(
                    *rank,
                    canonical_target.clone(),
                    myip,
                    tcp_result,
                    quic_result,
                ));
            } else {
                info!(
                    logger,
                    "Skipping IPv6 address ({:?}) for {}", target, canonical_target
                );
            }
        }
    }

    let mut csv_writer = csv::WriterBuilder::new()
        .has_headers(false)
        .quote_style(csv::QuoteStyle::Never)
        .from_writer(vec![]);
    let accurecny_results = results.get();
    accurecny_results.iter().for_each(|r| {
        info!(logger, "Serializing result: {:x?}", r);
        csv_writer.serialize(r).unwrap();
    });
    let printable_results = String::from_utf8(csv_writer.into_inner().unwrap()).unwrap();

    if let Some(output) = args.output {
        let output_path = output.path();

        let mut output = std::fs::OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(output_path)
            .unwrap();
        output.write_all(RESULT_CSV_HEADER.as_bytes()).unwrap();
        output.write_all(printable_results.as_bytes()).unwrap();
    } else {
        print!("{}", RESULT_CSV_HEADER);
        println!("{}", printable_results);
    }
}
