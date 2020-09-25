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

fn main() -> Result<()> {
    for addr in std::env::args().skip(1) {
        println!("Address to ping: {}", addr);

        let res = ping(addr);
        match res {
            Ok(time) => println!(
                "ping time in main {} ms",
                (time.as_nanos() as f32) / 1_000_000.0
            ),
            Err(error) => println!("Error in main {:?}", error),
        };
    }
    Ok(())
}

fn ping(addr: String) -> Result<std::time::Duration, String> {
    const PING_WAIT_TIME: u64 = 5;
    const IPV4_BUFFER_SIZE: usize = 64;
    const IPV6_BUFFER_SIZE: usize = 120;

    let (mut txv4, mut rxv4) =
        transport_channel(IPV4_BUFFER_SIZE, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
            .with_context(|| "Failed to get transport channel. You need root priviledges")
            .unwrap();
    let (mut txv6, mut rxv6) = transport_channel(
        IPV6_BUFFER_SIZE,
        Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )
    .context("Failed to get transport channel. You need root priviledges")
    .unwrap();
    let dns_result = (addr.as_str(), 0).to_socket_addrs(); // 0 is the port number, which is needed but not used
    match dns_result {
        Err(error) => {
            return Err(format!(
                "When doing DNS lookup on address {} got error {:?}",
                addr,
                error.to_string()
            ));
        }
        Ok(ip_addresses) => {
            for ip_addr in ip_addresses {
                let destination_addr = ip_addr.ip(); //used by IP V4 & V6
                let mut time: std::time::Duration; // this will be the time we send the Ping packet
                if ip_addr.is_ipv4() {
                    let sequence_number = random();
                    let identifier = random();
                    let mut buffer = [0_u8; 16];

                    let mut echo_packet =
                        echo_request::MutableEchoRequestPacket::new(&mut buffer[..])
                            .context("Failed to get IP V4 request packet")
                            .unwrap();
                    echo_packet.set_sequence_number(sequence_number);
                    echo_packet.set_identifier(identifier);
                    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
                    echo_packet.set_checksum(util::checksum(echo_packet.packet(), 1)); // 1 is the size

                    let txv4_send_result = txv4.send_to(echo_packet, destination_addr);
                    match txv4_send_result {
                        Err(error) => {
                            return Err(format!(
                                "Failed to send  IP V4 ping. Got error '{:?}'",
                                error
                            ))
                        }
                        Ok(_number_of_bytes_sent) => {
                            let now = Instant::now(); // note when the packet was sent
                            println!("trying to receive ipv4");
                            let mut packet_iter = icmp_packet_iter(&mut rxv4);
                            loop {
                                match packet_iter
                                    .next_with_timeout(std::time::Duration::from_secs(PING_WAIT_TIME))
                                {
                                    Err(error) => return Err (format!("Got the following error when trying to receive an IP V4 packets{:?}", error)),
                                    Ok(None) => return Err (format!("Timed out when trying to receive an IP V4 packet")),
                                    Ok(packet_received_option) => {
                                        match packet_received_option{
                                            Some(packet_received) => {
                                                time = Instant::now().saturating_duration_since(now);
                                                let (icmp_packet, addr_of_sender) = packet_received;
                                                println!(
                                                    "address of sender of IP v4 packet is {} {:?}",
                                                    addr_of_sender, icmp_packet
                                                );
                                                match icmp_packet.get_icmp_type() {
                                                    IcmpTypes::EchoReply => (),
                                                    IcmpTypes::DestinationUnreachable => {
                                                        return Err("Destination Unreachable".to_string());
                                                    }
                                                    icmp_type => {
                                                        return Err(format!(
                                                            "Ignorring packet of type '{:?}'",
                                                            icmp_type
                                                        ));
                                                    }
                                                }
                                                if icmp_packet.get_icmp_code() != IcmpCodes::NoCode {
                                                    return Err(format!(
                                                        "Ignorring packet with invalid ICMP code: {:?}",
                                                        icmp_packet.get_icmp_code()
                                                    ));
                                                }
                                                if destination_addr != addr_of_sender {
                                                    println!(
                                                        "Unexpected ping response from {:<16}:",
                                                        addr_of_sender
                                                    );
                                                    continue;
                                                }

                                                let echo_reply_response =  EchoReplyPacket::new(icmp_packet.packet());
                                                    match echo_reply_response{
                                                    Some (echo_reply) => {
                                                        if sequence_number != echo_reply.get_sequence_number() {
                                                            println!(
                                                                "Sequence number: Request - {} ; Response - {}",
                                                                sequence_number,
                                                                echo_reply.get_sequence_number() // checked works by manually pinging at same time
                                                            ); // we got a ping response from ping request we did not send; so ignore this response & wait for one we did send
                                                        }
                                                        if identifier != echo_reply.get_identifier() {
                                                            println!(
                                                                "Got ping with incorrect IP V4 Identifier: Request - {} ; Response - {}",
                                                                identifier,
                                                                echo_reply.get_identifier() // checked works by manually pinging at same time
                                                            );
                                                        }
                                                    },
                                                    None => return Err (format! ("Received ping response with the incorrect size")),
                                                    }
                                                println!("IP V4 response time {}", time.as_micros() as f32 /1000.0);
                                                //return Ok(time);
                                                // commented out so we can check the IP v6 stuff                return Ok(time);
                                                break;
                                            },
                                            None => println!("Why is this line needed??????!!!!!!!"),
                                        }
                                    }
                                };
                            }
                        }
                    }
                } else {
                    //let sequence_number = random();
                    //let identifier = random();
                    let mut buffer = [0_u8; 16];
                    let mut echo_packet = MutableIcmpv6Packet::new(&mut buffer[..])
                        .context("Failed to get IP V6 request packet")
                        .unwrap();
                    echo_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                    //echo_packet.set_sequence_number(sequence_number);
                    //echo_packet.set_identifier(identifier);
                    echo_packet.set_checksum(util::checksum(echo_packet.packet(), 1));
                    println!("About to send following IP V6 packet{:?}", echo_packet);
                    let txv6_send_result = txv6.send_to(echo_packet, destination_addr);
                    match txv6_send_result {
                        Err(error) => {
                            return Err(format!(
                                "Failed to send  IP V6 ping. Got error '{:?}'",
                                error
                            ))
                        }
                        Ok(_number_of_bytes_sent) => {
                            let now = Instant::now(); // note when the packet was sent
                            println!("trying to receive IP V6");
                            let mut packet_iter = icmp_packet_iter(&mut rxv6);

                            loop {
                                match packet_iter
                                    .next_with_timeout(std::time::Duration::from_secs(PING_WAIT_TIME))
                                {
                                    Err(error) => return Err (format!("Got the following error when trying to receive an IP V6 packets{:?}", error)),
                                    Ok(None) => return Err (format!("Timed out when trying to receive an IP V6 packet")),
                                    Ok(packet_received_option) => {
                                        match packet_received_option{
                                            Some(packet_received) => {
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
                                                    println!("IP V6 is loopback") // so ignoring it
                                                } else if addr_of_sender.to_string()[0..6] == "fe80::".to_string() {
                                                    println!("got link local address") // so ignoring it
                                                } else {
                                                    println!(
                                                        "got packet from address {} with contents {:?}",
                                                        addr_of_sender, icmp_packet
                                                    );
                                                };
                                            },
                                            None => println!("Why is this line needed??????!!!!!!!"),
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

    Err("DNS lookup did not return any addresses".to_string())
}
/*
127.0.0.0                       // returns Failed to send  IP V4 ping. Got error \'Os { code: 13, kind: PermissionDenied, message: \"Permission denied\" }\'
f                               // When doing DNS lookup on address f got error \"failed to lookup address information: Name or service not known
192.68.0.55                     // returns "Destination Unreachable"
192.168.0.11                    // returns "Ignorring packet of type \'IcmpType(8)\'"
dub08s01-in-f164.1e100.net      // returns IP v4 time
2a00:1450:4009:81c::2004        // returns IP v6 time
*/
