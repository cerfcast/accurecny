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


use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::os::fd::AsRawFd;

use clap::Parser;
use clap_derive::Args;
use nix::libc::{
    epoll_create, epoll_ctl, epoll_event, epoll_wait, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLPRI,
    EPOLLRDHUP, EPOLL_CTL_ADD,
};
use nix::sys::socket::AddressFamily::Inet;
use nix::sys::socket::SockProtocol::{self, Tcp as TcpProto};
use nix::sys::socket::{bind, getsockname, listen, sendto, socket, Backlog, MsgFlags, SockFlag};
use nix::sys::socket::{connect, recv, SockaddrIn};
use pnet::packet::tcp::{ipv4_checksum, Tcp, TcpFlags, TcpOption, TcpOptionPacket, TcpPacket};
use std::time::Duration;

use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags::{ACK, SYN};
use pnet::packet::FromPacket;
use slog::{error, info, warn, Drain};

#[derive(Debug, Clone)]
enum Target {
    Ipv6(Ipv6Addr),
    Ipv4(Ipv4Addr),
    Name(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ipv6(v6) => write!(f, "{}", v6),
            Target::Ipv4(v4) => write!(f, "{}", v4),
            Target::Name(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Clone)]
enum Mode {
    Ipv6,
    Ipv4,
}

fn parse_target(arg: &str) -> Result<Target, String> {
    match arg.parse() {
        Ok(addr) => match addr {
            IpAddr::V4(addr) => Ok(Target::Ipv4(addr)),
            IpAddr::V6(addr) => Ok(Target::Ipv6(addr)),
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
struct AccurecnyResult {
    rank: u64,
    url: String,
    ip: Option<IpAddr>,
    success: bool,
    supported: bool,
    flags: Option<String>,
}

impl AccurecnyResult {
    fn new(rank: u64, url: String) -> Self {
        Self {
            rank,
            url,
            ip: None,
            success: false,
            supported: false,
            flags: None,
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

fn main() {
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

        let mut accurecny_result = AccurecnyResult::new(*rank, target.to_string());

        (|| {
            let (target, mode) = match target {
                Target::Name(name) => {
                    let hostname_with_dummy_port = name.clone() + ":80";

                    let server_ips = hostname_with_dummy_port.to_socket_addrs();

                    if let Err(resolution_error) = server_ips {
                        error!(
                            logger,
                            "Error resolving target {}: {:?}", name, resolution_error
                        );
                        return vec![];
                    }

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
                    match server_ip.ip() {
                        IpAddr::V4(addr) => (IpAddr::V4(addr), Mode::Ipv4),
                        IpAddr::V6(addr) => (IpAddr::V6(addr), Mode::Ipv6),
                    }
                }
                Target::Ipv4(addr) => (IpAddr::V4(*addr), Mode::Ipv4),
                Target::Ipv6(addr) => (IpAddr::V6(*addr), Mode::Ipv6),
            };

            let (domain, protocol) = match mode {
                Mode::Ipv4 => {
                    info!(logger, "Matching mode v4 to set protocol!");
                    (Inet, TcpProto)
                }
                Mode::Ipv6 => {
                    error!(logger, "Matching mode v6 to set protocol!");
                    return vec![];
                }
            };

            accurecny_result.ip = Some(target);

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
                return vec![];
            }
            let raw_socket = maybe_raw_socket.unwrap();

            let destination = if let IpAddr::V4(v4) = target {
                SockaddrIn::from(SocketAddrV4::new(v4, 443))
            } else {
                error!(logger, "Ipv6 is not supported.");
                return vec![raw_socket];
            };
            let source = SockaddrIn::new(0, 0, 0, 0, 0);

            // This placeholder socket is not directly used. It helps us ask the operating
            // system for exclusive access to an ephemeral port.
            let maybe_tcp_placeholder = socket(
                domain,
                nix::sys::socket::SockType::Stream,
                SockFlag::empty(),
                SockProtocol::Tcp,
            );

            if let Err(errno) = maybe_tcp_placeholder {
                error!(logger, "Attempting to make the socket for reserving a source port failed (error number {})", errno);
                return vec![raw_socket];
            }
            let tcp_placeholder = maybe_tcp_placeholder.unwrap();

            if let Err(errno) = bind(tcp_placeholder.as_raw_fd(), &source) {
                error!(logger, "Attempting to bind the socket for reserving a source port failed (error number {})", errno);
                return vec![tcp_placeholder, raw_socket];
            }

            if let Err(errno) = listen(&tcp_placeholder, Backlog::new(0).unwrap()) {
                error!(logger, "Attempting to bind the socket for reserving a source port failed (error number {})", errno);
                return vec![tcp_placeholder, raw_socket];
            }

            if let Err(errno) = bind(raw_socket.as_raw_fd(), &source) {
                error!(logger, "Attempting to bind the socket for TCP transmission/reception failed (error number {})", errno);
                return vec![tcp_placeholder, raw_socket];
            }

            if let Err(errno) = connect(raw_socket.as_raw_fd(), &destination) {
                error!(logger, "Attempting to connect the socket for TCP transmission/reception failed (error number {})", errno);
                return vec![tcp_placeholder, raw_socket];
            }

            let source = {
                let tcp_placeholder_name =
                    getsockname::<SockaddrIn>(tcp_placeholder.as_raw_fd()).unwrap();
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
            let csum = ipv4_checksum(
                &pseudo_packet.consume_to_immutable(),
                &source.ip(),
                &destination.ip(),
            );

            let mut packet_bytes =
                vec![0u8; pnet::packet::tcp::TcpPacket::minimum_packet_size() + options_size];
            let mut packet = MutableTcpPacket::new(&mut packet_bytes).unwrap();
            packet_tcp.checksum = csum;
            packet.populate(&packet_tcp);

            if let Err(e) = sendto(
                raw_socket.as_raw_fd(),
                &packet_bytes,
                &destination,
                MsgFlags::empty(),
            ) {
                error!(
                    logger,
                    "Failed to send SYN packet to {}: {}", destination, e
                );
                return vec![tcp_placeholder, raw_socket];
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

                    let wait_result = epoll_wait(epoller, events.as_mut_ptr(), 1, 3000);

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
                            recv(raw_socket.as_raw_fd(), &mut result_bytes, MsgFlags::empty())
                                .unwrap();

                        let tcp_bytes = result_bytes
                            [pnet::packet::ipv4::Ipv4Packet::minimum_packet_size()..result]
                            .to_vec();

                        let tcp_packet = TcpPacket::owned(tcp_bytes).unwrap();

                        let tcp: Tcp = TcpPacket::from_packet(&tcp_packet);

                        info!(logger, "The resulting flags: {:x}", tcp.flags);
                        accurecny_result.flags = Some(format!("0x{:x}{:x}", tcp.reserved, tcp.flags).to_string());
                        if tcp.flags & ACK != 0 && tcp.reserved & 0x1 != 0 {
                            accurecny_result.supported = true;
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
            accurecny_result.success = true;
            vec![tcp_placeholder, raw_socket]
        })().iter().for_each(|socket_to_close| {
        if let Err(e) = nix::unistd::close(socket_to_close.as_raw_fd()) {
            error!(
                logger,
                "There was an error closing the raw socket handle: {:?}", e
            );
        }

        });

        results.add(accurecny_result);
    }

    let mut csv_writer = csv::Writer::from_writer(vec![]);
    let accurecny_results = results.get();
    accurecny_results.iter().for_each(|r| {
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

        output.write_all(printable_results.as_bytes()).unwrap();
    } else {
        println!("{}", printable_results);
    }
}
