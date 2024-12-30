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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::str::FromStr;

use clap::Parser;
use clap_derive::Args;
use myip::what_is_my_ip;
use nix::errno::Errno;
use nix::libc::{
    epoll_create, epoll_ctl, epoll_event, epoll_wait, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLPRI,
    EPOLLRDHUP, EPOLL_CTL_ADD,
};
use nix::sys::socket::AddressFamily::Inet;
use nix::sys::socket::SockProtocol::{self, Tcp as TcpProto};
use nix::sys::socket::{
    bind, getsockname, listen, sendto, socket, Backlog, MsgFlags, SockFlag, SockaddrIn6,
    SockaddrLike,
};
use nix::sys::socket::{connect, recv, SockaddrIn};
use pnet::packet::tcp::{ipv4_checksum, Tcp, TcpFlags, TcpOption, TcpOptionPacket, TcpPacket};
use quic_ecn::{accurate_ecn_quic, AccurecnyQuicResult};

use std::time::Duration;

use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags::{ACK, SYN};
use pnet::packet::FromPacket;
use slog::{error, info, warn, Drain};

mod myip;
mod quic_ecn;

#[derive(Debug, Clone)]
enum FlexibleIp {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl From<SockaddrIn> for FlexibleIp {
    fn from(value: SockaddrIn) -> Self {
        FlexibleIp::Ipv4(value.ip())
    }
}

impl From<SockaddrIn6> for FlexibleIp {
    fn from(value: SockaddrIn6) -> Self {
        FlexibleIp::Ipv6(value.ip())
    }
}

impl From<IpAddr> for FlexibleIp {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(v4) => FlexibleIp::Ipv4(v4),
            IpAddr::V6(v6) => FlexibleIp::Ipv6(v6),
        }
    }
}

impl From<FlexibleIp> for IpAddr {
    fn from(value: FlexibleIp) -> Self {
        match value {
            FlexibleIp::Ipv4(v4) => IpAddr::V4(v4),
            FlexibleIp::Ipv6(v6) => IpAddr::V6(v6),
        }
    }
}

impl<'a> From<FlexibleIp> for Box<dyn SockaddrLike + 'a> {
    fn from(value: FlexibleIp) -> Box<dyn SockaddrLike + 'a> {
        match value {
            FlexibleIp::Ipv4(v4) => Box::new(SockaddrIn::from(SocketAddrV4::new(v4, 0))),
            FlexibleIp::Ipv6(v6) => Box::new(SockaddrIn6::from(SocketAddrV6::new(v6, 0, 0, 0))),
        }
    }
}

impl From<FlexibleIp> for SocketAddr {
    fn from(value: FlexibleIp) -> Self {
        match value {
            FlexibleIp::Ipv4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, 0)),
            FlexibleIp::Ipv6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, 0, 0, 0)),
        }
    }
}

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

fn parse_target(arg: &str) -> Result<Target, String> {
    match arg.parse() {
        Ok(addr) => match addr {
            IpAddr::V4(addr) => Ok(Target::Ip(FlexibleIp::Ipv4(addr))),
            IpAddr::V6(addr) => Ok(Target::Ip(FlexibleIp::Ipv6(addr))),
        },
        Err(_) => Ok(Target::Name(arg.to_string())),
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
    target: Option<Target>,

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

#[derive(Debug, Clone, serde::Serialize)]
struct AccurecnyTcpResult {
    ip: Option<IpAddr>,
    success: bool,
    supported: bool,
    flags: Option<String>,
}

impl AccurecnyTcpResult {
    fn new() -> Self {
        Self {
            ip: None,
            success: false,
            supported: false,
            flags: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct AccurecnyResult {
    source: IpAddr,
    rank: u64,
    url: String,
    tcp: AccurecnyTcpResult,
    quic: AccurecnyQuicResult,
}

const RESULT_CSV_HEADER: &str = "source, rank, url, tcp_ip, tcp_success, tcp_supported, tcp_flags, quic_ip, quic_success, quic_supported\n";

impl AccurecnyResult {
    fn new(
        rank: u64,
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
struct AccurecnyResults {
    results: Vec<AccurecnyResult>,
}

impl AccurecnyResults {
    fn new() -> Self {
        AccurecnyResults {
            results: Vec::<AccurecnyResult>::new(),
        }
    }

    fn add(&mut self, result: AccurecnyResult) {
        self.results.push(result);
    }

    fn get(&self) -> Vec<AccurecnyResult> {
        self.results.clone()
    }
}

fn resolve_target(target: Target, logger: slog::Logger) -> Result<FlexibleIp, std::io::Error> {
    match target {
        Target::Name(name) => {
            let mut resolution_result: Result<FlexibleIp, std::io::Error> =
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
                    let mut sv: Vec<SocketAddr> = vec![];
                    server_ips.unwrap().for_each(|f| sv.push(f));

                    let resolution_result_count = sv.len();
                    let server_ip = sv[0];
                    if resolution_result_count > 1 {
                        warn!(
                        logger,
                        "Warning: There were multiple IP addresses resolved from {:?}; using {:?}",
                        name.clone(),
                        server_ip.ip()
                    );
                    }
                    resolution_result = match server_ip.ip() {
                        IpAddr::V4(addr) => Ok(FlexibleIp::Ipv4(addr)),
                        IpAddr::V6(addr) => Ok(FlexibleIp::Ipv6(addr)),
                    };
                    break;
                }
            }
            resolution_result
        }
        Target::Ip(ip) => Ok(ip),
    }
}

fn get_unspecified_local_ip(mode: &Mode) -> FlexibleIp {
    match mode {
        Mode::Ipv4 => FlexibleIp::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
        Mode::Ipv6 => panic!("Ipv6 is not supported at this time."),
    }
}

fn accurate_ecn_tcp(
    test_target_ip: &FlexibleIp,
    _: &String,
    logger: slog::Logger,
) -> AccurecnyTcpResult {
    let mut tcp_test_result = AccurecnyTcpResult::new();

    let (domain, protocol) = match test_target_ip {
        FlexibleIp::Ipv4(_) => {
            info!(logger, "Matching mode v4 to set protocol!");
            (Inet, TcpProto)
        }
        FlexibleIp::Ipv6(_) => {
            error!(logger, "Ipv6 is not supported!");
            return tcp_test_result;
        }
    };

    tcp_test_result.ip = Some((*test_target_ip).clone().into());

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

    let destination: Box<dyn SockaddrLike> = (*test_target_ip).clone().into();
    let source: Box<dyn SockaddrLike> = (get_unspecified_local_ip(&Mode::Ipv4)).into();

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
        destination: 443,
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
    let csum = match test_target_ip {
        FlexibleIp::Ipv4(v4) => {
            ipv4_checksum(&pseudo_packet.consume_to_immutable(), &source.ip(), v4)
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

    if let Err(e) = sendto(
        raw_socket.as_raw_fd(),
        &packet_bytes,
        &*destination,
        MsgFlags::empty(),
    ) {
        error!(
            logger,
            "Failed to send SYN packet to {}: {}",
            Into::<IpAddr>::into((*test_target_ip).clone()),
            e
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
                    (                                                                //                AE CWR ECE
                        ((tcp.reserved & 0x1) == 0 && (tcp.flags & 0xc0) == 0x80) || // Table Row 1:    0   1   0
                        ((tcp.reserved & 0x1) == 0 && (tcp.flags & 0xc0) == 0xc0) || // Table Row 2:    0   1   1
                        ((tcp.reserved & 0x1) == 1 && (tcp.flags & 0xc0) == 0x00) || // Table Row 3:    1   0   0
                        ((tcp.reserved & 0x1) == 1 && (tcp.flags & 0xc0) == 0x80)    // Table Row 4:    1   1   0
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
    tcp_test_result.success = true;
    tcp_test_result
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

    let myip = match args.myip {
        Some(ip) => ip,
        None => {
            if let Ok(addr) = what_is_my_ip(logger.clone()).await {
                addr
            } else {
                get_unspecified_local_ip(&Mode::Ipv4).into()
            }
        }
    };

    let potential_targets = if let Some(single_target) = args.target.target {
        Ok(vec![(0u64, single_target)])
    } else {
        let top_sites_path = args.target.top_sites.unwrap();
        extract_popular_sites(&top_sites_path)
            .map(|list| list.into_iter().map(|x| (x.rank, Target::Name(x.url))))
            .map(|list| list.collect::<Vec<(u64, Target)>>())
    };

    if let Err(e) = potential_targets {
        error!(
            logger,
            "Could not create a list of potential targets: {}", e
        );
        return;
    }

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

        let tcp_result = accurate_ecn_tcp(&target.clone(), &canonical_target, logger.clone());
        let quic_result =
            accurate_ecn_quic(&target.clone(), &canonical_target, logger.clone()).await;

        results.add(AccurecnyResult::new(
            *rank,
            canonical_target,
            myip,
            tcp_result,
            quic_result,
        ));
    }

    let mut csv_writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(vec![]);
    let accurecny_results = results.get();
    accurecny_results.iter().for_each(|r| {
        info!(logger, "Serializing result: {:?}", r);
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
