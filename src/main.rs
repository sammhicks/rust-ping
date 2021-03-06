//use anyhow::Context;

use pnet::{
    packet::{
        icmp::{
            echo_reply::{EchoReplyPacket, IcmpCodes},
            echo_request, IcmpType, IcmpTypes,
        },
        icmpv6::{Icmpv6Type, Icmpv6Types},
        ip::IpNextHeaderProtocols,
    },
    transport::{
        icmp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
        TransportProtocol::Ipv6, TransportReceiver, TransportSender,
    },
};

use pnet_macros_support::packet::Packet;
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
    IgnoringIPV6PacketWithInvalidContents,
    ErrorWhileWaitingForIPV6 {
        io_error: std::io::Error,
    },
    IPV6Timeout,
    IgnoringIPV6PacketOfType {
        icmp_type: pnet::packet::icmpv6::Icmpv6Type,
    },
    DNSLookupDidNotReturnAnyAddresses,
}

fn main() {
    let mut pinger = Pinger::new().unwrap();

    for addr in std::env::args().skip(1) {
        println!("Address to ping: {}", &addr);

        loop {
            match pinger.ping(addr.to_string()) {
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
}
#[derive(Debug)]
struct NeedsToBeRunWithRootPriviledges;

impl std::convert::From<std::io::Error> for NeedsToBeRunWithRootPriviledges {
    fn from(_: std::io::Error) -> Self {
        Self
    }
}

struct Pinger {
    txv4: pnet::transport::TransportSender,
    rxv4: TransportReceiver,
    txv6: TransportSender,
    rxv6: TransportReceiver,
}

impl Pinger {
    fn new() -> Result<Pinger, NeedsToBeRunWithRootPriviledges> {
        const IPV4_BUFFER_SIZE: usize = 64;
        const IPV6_BUFFER_SIZE: usize = 120;
        let (txv4, rxv4) =
            transport_channel(IPV4_BUFFER_SIZE, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))?;
        //if it fails, transport_channel returns an error of type <std::io::Error>, but earlier, we have said covert this error to one of type
        //NeedsToBeRunWithRootPriviledges, so, if we get the error returned to us, we return the error NeedsToBeRunWithRootPriviledges
        //The error reported by the OS is  'PermissionDenied, message: "Operation not permitted"'

        let (txv6, rxv6) = transport_channel(
            IPV6_BUFFER_SIZE,
            Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6)),
        )?;

        // a longer version of the previous statement
        // let (txv6, rxv6) =
        //     match transport_channel(IPV6_BUFFER_SIZE, Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6))) {
        //         Ok(channel) => channel,
        //         Err(_) => return Err(NeedsToBeRunWithRootPriviledges),
        //     };

        // in the commented out version, we explicitly map the error to be of type
        /*let (txv6, rxv6) =
        transport_channel(IPV6_BUFFER_SIZE, Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6)))
            .map_err(|_| NeedsToBeRunWithRootPriviledges)?; */

        Ok(Pinger {
            txv4,
            rxv4,
            txv6,
            rxv6,
        })
    }

    fn ping(&mut self, addr: String) -> Result<std::time::Duration, PingError> {
        const PING_WAIT_TIME: std::time::Duration = std::time::Duration::from_secs(4);
        let ip_addresses = (addr.as_str(), 0) // 0 is the port number, which is needed but not used
            .to_socket_addrs()
            .map_err(|io_error| PingError::DnsLookupError { addr, io_error })?;

        for ip_addr in ip_addresses {
            let destination_addr = ip_addr.ip(); //used by IP V4 & V6
            match ip_addr {
                std::net::SocketAddr::V4(_) => {
                    let sequence_number = rand::random();
                    let identifier = rand::random();
                    let mut buffer = [0_u8; 16];

                    /*let mut echo_packet =
                    match echo_request::MutableEchoRequestPacket::new(&mut buffer[..]) {
                        Option::None => return Err(PingError::FailedToGetIPV4RequestPacket),
                        Option::Some(echo_packet) => echo_packet,
                    };*/

                    let mut echo_packet =
                        echo_request::MutableEchoRequestPacket::new(&mut buffer[..])
                            .ok_or(PingError::FailedToGetIPV4RequestPacket)?;

                    echo_packet.set_sequence_number(sequence_number);
                    echo_packet.set_identifier(identifier);
                    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
                    echo_packet.set_checksum(pnet::util::checksum(echo_packet.packet(), 1));
                    // 1 is the size

                    let mut packet_iter = icmp_packet_iter(&mut self.rxv4);

                    while packet_iter   //read & dump packets that are previously in the receive buffer, if there are any. The Should not be, but, if we timed out & eventually the packet turned up late, there could be a packet
                        .next_with_timeout(std::time::Duration::from_micros(1))         //1 us is the shortest non-zero time allowed 
                        .map_err(|io_error| PingError::ErrorWhileWaitingForIPV4 { io_error })?
                        .is_some()
                    {/* do nothing except loop round & get the next packet, until the buffer is empty */}

                    self.txv4
                        .send_to(echo_packet, destination_addr)
                        .map_err(|io_error| PingError::FailedtoSendIPV4 { io_error })?;

                    let now = Instant::now(); // note when the packet was sent
                    let mut packet_iter = icmp_packet_iter(&mut self.rxv4);
                    loop {
                        let packet_received = packet_iter
                            .next_with_timeout(PING_WAIT_TIME)
                            .map_err(|io_error| PingError::ErrorWhileWaitingForIPV4 { io_error })?
                            .ok_or(PingError::IPV4Timeout)?;

                        let time = Instant::now().saturating_duration_since(now);
                        let (icmp_packet, addr_of_sender) = packet_received;
                        //println!("address of sender of IP v4 packet is {} {:?}", addr_of_sender, icmp_packet);
                        match icmp_packet.get_icmp_type() {
                            IcmpTypes::EchoReply => (),
                            IcmpTypes::DestinationUnreachable => {
                                return Err(PingError::IPV4DestinationUnreachable);
                            }
                            icmp_type => {
                                return Err(PingError::IgnoringIPV4PacketOfType { icmp_type });
                            }
                        }
                        if icmp_packet.get_icmp_code() != IcmpCodes::NoCode {
                            return Err(PingError::IgnoringIPV4PacketWithInvalidICMP {
                                icmp_code: icmp_packet.get_icmp_code(),
                            });
                        }
                        if destination_addr != addr_of_sender {
                            println!("Unexpected ping response from {:<16}:", addr_of_sender);
                            continue;
                        }

                        let echo_reply = EchoReplyPacket::new(icmp_packet.packet())
                            .ok_or(PingError::InvalidIPV4PingSize)?;

                        if sequence_number != echo_reply.get_sequence_number() {
                            println!(
                                "Got invalid Sequence number: Request: {}; Response: {}",
                                sequence_number,
                                echo_reply.get_sequence_number() // checked works by manually pinging at same time
                            ); // we got a ping response from ping request we did not send; so ignore this response & wait for one we did send
                        } else if identifier != echo_reply.get_identifier() {
                            println!("Got ping with incorrect IP V4 Identifier: Request - {} ; Response - {}",
                                                        identifier, echo_reply.get_identifier());
                        // checked works by manually pinging at same time
                        } else {
                            println!("IP V4 response time {}", time.as_micros() as f32 / 1000.0);
                            return Ok(time);
                            // commented out so we can check the IP v6 stuff                return Ok(time);
                            //break;
                        }
                    }
                }
                std::net::SocketAddr::V6(_) => {
                    let mut buffer = [0_u8; 16];
                    let mut echo_packet =
                        echo_request::MutableEchoRequestPacket::new(&mut buffer[..])
                            .ok_or(PingError::FailedToGetIPV4RequestPacket)?;

                    echo_packet.set_sequence_number(7);
                    echo_packet.set_identifier(9);
                    echo_packet.set_icmp_type(IcmpType::new(Icmpv6Types::EchoRequest.0));
                    echo_packet.set_checksum(pnet::util::checksum(echo_packet.packet(), 1));

                    /*let mut echo_packet =
                        pnet::packet::icmpv6::MutableIcmpv6Packet::new(&mut buffer[..])
                            .ok_or(PingError::FailedToGetIPV6RequestPacket)?;
                    //echo_packet.set_sequence_number(sequence_number);
                    //echo_packet.set_identifier(identifier);
                    echo_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                    echo_packet.set_checksum(pnet::util::checksum(echo_packet.packet(), 1));*/
                    // 1 is the size
                    println!("About to send following IP V6 packet{:?}", echo_packet);

                    self.txv6
                        .send_to(echo_packet, destination_addr)
                        .map_err(|io_error| PingError::FailedtoSendIPV6 { io_error })?;
                    let now = Instant::now(); // note when the packet was sent
                    let mut packet_iter = icmp_packet_iter(&mut self.rxv6);
                    loop {
                        let packet_received = packet_iter
                            .next_with_timeout(PING_WAIT_TIME)
                            .map_err(|io_error| PingError::ErrorWhileWaitingForIPV6 { io_error })?
                            .ok_or(PingError::IPV6Timeout)?;
                        let time = Instant::now().saturating_duration_since(now);
                        let (icmp_packet, addr_of_sender) = packet_received;

                        let echo_reply = EchoReplyPacket::new(icmp_packet.packet())
                            .ok_or(PingError::InvalidIPV4PingSize)?;
                        println!("IPV6 Response: {:?}", echo_reply);
                        println!("TY{:?}", echo_reply.get_icmp_type());

                        match Icmpv6Type::new(icmp_packet.get_icmp_type().0) {
                            Icmpv6Types::EchoReply => (),
                            Icmpv6Types::DestinationUnreachable => {
                                return Err(PingError::IPV4DestinationUnreachable);
                            }
                            icmp_type => {
                                return Err(PingError::IgnoringIPV6PacketOfType { icmp_type });
                            }
                        }

                        if echo_reply.get_identifier() != 9 || echo_reply.get_sequence_number() != 7
                        //the library forces both the identifier & sequence number sent to be 0
                        {
                            return Err(PingError::IgnoringIPV6PacketWithInvalidContents);
                        } else if addr_of_sender == destination_addr {
                            return Ok(time);
                        } else if addr_of_sender.is_loopback() {
                            println!("IP V6 is loopback")
                        // so ignoring it
                        } else if addr_of_sender.to_string()[0..6] == "fe80::".to_string() {
                            println!("got link local address")
                        // so ignoring it
                        } else {
                            println!(
                                "Got IP V6 packet from address {} with contents {:?}",
                                addr_of_sender, icmp_packet
                            );
                        };
                    }
                }
            }
        }
        Err(PingError::DNSLookupDidNotReturnAnyAddresses)
    }
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
