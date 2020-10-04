use anyhow::{Context, Result};

use pnet::{
    packet::{
        icmp::{
            echo_reply::{EchoReplyPacket, IcmpCodes},
            echo_request, IcmpTypes,
        },
        icmpv6::{Icmpv6Types, MutableIcmpv6Packet},
        ip::IpNextHeaderProtocols,
    },
    transport::{
        icmp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
        TransportProtocol::Ipv6,
    },
    util,
};
use pnet_macros_support::packet::Packet;
use rand::random;
use std::iter::Iterator;
use std::net::ToSocketAddrs;
use std::time::Instant;

#[derive(Debug)]
enum PingError {
    DnsLookupError {
        addr: String,
        io_error: std::io::Error,
    },
    FailedToGetIPV4RequestPacket,
    FailedtoSendIPV4 {
        io_error: std::io::Error,
    },
    ErrorWhileWaitingForIPV4 {
        io_error: std::io::Error,
    },
    IPV4Timeout,
    IPV4DestinationUnreachable,
    IgnoringIPV4PacketOfType {
        icmp_type: pnet::packet::icmp::IcmpType,
    },
    IgnoringIPV4PacketWithInvalidICMP {
        icmp_code: pnet::packet::icmp::IcmpCode,
    },
    InvalidIPV4PingSize,
    FailedtoSendIPV6 {
        io_error: std::io::Error,
    },
    FailedToGetIPV6RequestPacket,
    ErrorWhileWaitingForIPV6 {
        io_error: std::io::Error,
    },
    IPV6Timeout,
    DNSLookupDidNotReturnAnyAddresses,
}

impl PingError {
    fn foo(&self) -> () {
        println!("in foo");
    }
}

fn main() -> Result<()> {
    let g: PingError = PingError::FailedToGetIPV4RequestPacket;
    g.foo();

    for addr in std::env::args().skip(1) {
        println!("Address to ping: {}", &addr);

        loop {
            match ping(addr.to_string()) {
                //we use addr.to_string as we want to reuse the same value
                Ok(time) => println!(
                    "ping time in main {} ms",
                    (time.as_nanos() as f32) / 1_000_000.0
                ),
                Err(error) => println!("Error in main {:?}", error),
            };
            std::thread::sleep(std::time::Duration::from_secs(4));
        }
    }
    Ok(())
}

fn ping(addr: String) -> Result<std::time::Duration, PingError> {
    const PING_WAIT_TIME: std::time::Duration = std::time::Duration::from_secs(4);
    const IPV4_BUFFER_SIZE: usize = 64;
    const IPV6_BUFFER_SIZE: usize = 120;

    let (mut txv4, mut rxv4) =
        transport_channel(IPV4_BUFFER_SIZE, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
            .context("Failed to get transport channel. You need root priviledges")
            .unwrap();
    let (mut txv6, mut rxv6) = transport_channel(
        IPV6_BUFFER_SIZE,
        Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )
    .context("Failed to get transport channel. You need root priviledges")
    .unwrap();
    let dns_result = (addr.as_str(), 0).to_socket_addrs(); // 0 is the port number, which is needed but not used

    let ip_addresses = match dns_result {
        Ok(interation_of_addresses) => interation_of_addresses, // this will match if DNS lookup works, in which case the program continues
        Err(io_error) => {
            //DNS lookup failed, so we get here. As we have an early return, the match returns the desired iteration
            return Err(PingError::DnsLookupError { addr, io_error });
        }
    }; // this let statment is the equivalent of "if dns_result is a failure, return early", otherwise the iteration ip_addresses is extracted from dns_result.

    for ip_addr in ip_addresses {
        let destination_addr = ip_addr.ip(); //used by IP V4 & V6
        let mut time: std::time::Duration; // this will be the time we send the Ping packet
        match ip_addr {
            std::net::SocketAddr::V4(_) => {
                let sequence_number = random();
                let identifier = random();
                let mut buffer = [0_u8; 16];

                match echo_request::MutableEchoRequestPacket::new(&mut buffer[..]) {
                    Option::None => return Err(PingError::FailedToGetIPV4RequestPacket),
                    Option::Some(mut echo_packet) => {
                        echo_packet.set_sequence_number(sequence_number);
                        echo_packet.set_identifier(identifier);
                        echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
                        echo_packet.set_checksum(util::checksum(echo_packet.packet(), 1));
                        // 1 is the size

                        match txv4.send_to(echo_packet, destination_addr) {
                            Err(io_error) => return Err(PingError::FailedtoSendIPV4 { io_error }),
                            Ok(_number_of_bytes_sent) => {
                                let now = Instant::now(); // note when the packet was sent
                                let mut packet_iter = icmp_packet_iter(&mut rxv4);
                                //  Result<Option<(IcmpPacket, IpAddr)>, std::io::Error>
                                loop {
                                    match packet_iter.next_with_timeout(PING_WAIT_TIME) {
                                        Result::Err(io_error) => {
                                            return Err(PingError::ErrorWhileWaitingForIPV4 {
                                                io_error,
                                            })
                                        }
                                        Result::Ok(Option::None) => {
                                            return Err(PingError::IPV4Timeout)
                                        }
                                        Result::Ok(Option::Some(packet_received)) => {
                                            time = Instant::now().saturating_duration_since(now);
                                            let (icmp_packet, addr_of_sender) = packet_received;
                                            println!(
                                                "address of sender of IP v4 packet is {} {:?}",
                                                addr_of_sender, icmp_packet
                                            );
                                            match icmp_packet.get_icmp_type() {
                                                IcmpTypes::EchoReply => (),
                                                IcmpTypes::DestinationUnreachable => {
                                                    return Err(
                                                        PingError::IPV4DestinationUnreachable,
                                                    );
                                                }
                                                icmp_type => {
                                                    return Err(
                                                        PingError::IgnoringIPV4PacketOfType {
                                                            icmp_type,
                                                        },
                                                    );
                                                }
                                            }
                                            if icmp_packet.get_icmp_code() != IcmpCodes::NoCode {
                                                return Err(
                                                    PingError::IgnoringIPV4PacketWithInvalidICMP {
                                                        icmp_code: icmp_packet.get_icmp_code(),
                                                    },
                                                );
                                            }
                                            if destination_addr != addr_of_sender {
                                                println!(
                                                    "Unexpected ping response from {:<16}:",
                                                    addr_of_sender
                                                );
                                                continue;
                                            }
                                            match EchoReplyPacket::new(icmp_packet.packet()) {
                                                Some(echo_reply) => {
                                                    if sequence_number
                                                        != echo_reply.get_sequence_number()
                                                    {
                                                        println!("Sequence number: Request - {} ; Response - {}", sequence_number,
                                                                        echo_reply.get_sequence_number() // checked works by manually pinging at same time
                                                                    ); // we got a ping response from ping request we did not send; so ignore this response & wait for one we did send
                                                    }
                                                    if identifier != echo_reply.get_identifier() {
                                                        println!("Got ping with incorrect IP V4 Identifier: Request - {} ; Response - {}",
                                                        identifier, echo_reply.get_identifier());
                                                        // checked works by manually pinging at same time
                                                    }
                                                }
                                                None => return Err(PingError::InvalidIPV4PingSize),
                                            }
                                            println!(
                                                "IP V4 response time {}",
                                                time.as_micros() as f32 / 1000.0
                                            );
                                            return Ok(time);
                                            // commented out so we can check the IP v6 stuff                return Ok(time);
                                            //break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            std::net::SocketAddr::V6(_) => {
                //let sequence_number = random();
                //let identifier = random();
                let mut buffer = [0_u8; 16];

                match MutableIcmpv6Packet::new(&mut buffer[..]) {
                    None => return Err(PingError::FailedToGetIPV6RequestPacket),
                    Some(mut echo_packet) => {
                        //echo_packet.set_sequence_number(sequence_number);
                        //echo_packet.set_identifier(identifier);
                        echo_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                        echo_packet.set_checksum(util::checksum(echo_packet.packet(), 1));
                        // 1 is the size
                        println!("About to send following IP V6 packet{:?}", echo_packet);
                        match txv6.send_to(echo_packet, destination_addr) {
                            Err(io_error) => return Err(PingError::FailedtoSendIPV6 { io_error }),
                            Ok(_number_of_bytes_sent) => {
                                let now = Instant::now(); // note when the packet was sent
                                let mut packet_iter = icmp_packet_iter(&mut rxv6);
                                loop {
                                    match packet_iter.next_with_timeout(PING_WAIT_TIME) {
                                        Err(io_error) => {
                                            return Err(PingError::ErrorWhileWaitingForIPV6 {
                                                io_error,
                                            })
                                        }
                                        Ok(Option::None) => return Err(PingError::IPV6Timeout),
                                        Ok(Option::Some(packet_received)) => {
                                            // this matches the case where we receive a packet; we do not need to explicitly match the case Ok(None), as that is caught by the previous match statement
                                            time = Instant::now().saturating_duration_since(now);
                                            let (icmp_packet, addr_of_sender) = packet_received;
                                            println!(
                                                "Address of sender of IP v6 packet is {} {:?}",
                                                addr_of_sender, icmp_packet
                                            );
                                            if addr_of_sender == destination_addr {
                                                println!("IP V6 reponse time {}", time.as_millis());
                                                return Ok(time);
                                            } else if addr_of_sender.is_loopback() {
                                                println!("IP V6 is loopback")
                                            // so ignoring it
                                            } else if addr_of_sender.to_string()[0..6]
                                                == "fe80::".to_string()
                                            {
                                                println!("got link local address")
                                            // so ignoring it
                                            } else {
                                                println!(
                                                    "got packet from address {} with contents {:?}",
                                                    addr_of_sender, icmp_packet
                                                );
                                            };
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Err(PingError::DNSLookupDidNotReturnAnyAddresses)
}
/*
127.0.0.0                       // returns Failed to send  IP V4 ping. Got error \'Os { code: 13, kind: PermissionDenied, message: \"Permission denied\" }\'
f                               // When doing DNS lookup on address f got error \"failed to lookup address information: Name or service not known
192.68.0.55                     // returns "Destination Unreachable"
192.168.0.11                    // returns "Ignorring packet of type \'IcmpType(8)\'"
dub08s01-in-f164.1e100.net      // returns IP v4 time
2a00:1450:4009:81c::2004        // returns IP v6 time
2a00:1450:4009:81c::20          // IPV6Timeout
*/
