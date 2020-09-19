use anyhow::{Context, Result};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::{
    packet::{
        icmp::{
            echo_reply::{EchoReplyPacket, IcmpCodes},
            echo_request, IcmpTypes,
        },
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
        let (mut txv4, mut rxv4) = transport_channel(64, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
            .context("Failed to get transport channel. You need root priviledges")?;
        let (mut txv6, mut rxv6) =
            transport_channel(120, Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6)))
                .context("Failed to get transport channel. You need root priviledges")?;

        for addr in (addr.as_str(), 0).to_socket_addrs() {
            println!("add {:?}", addr);
        }

        for addr in (addr.as_str(), 0)
            .to_socket_addrs()
            .context("Failed to get addresses")?
        {
            if addr.is_ipv4() {
                let destination_addr = addr.ip();
                let sequence_number = random();
                let identifier = random();

                let mut buffer = [0_u8; 16];
                let mut echo_packet = echo_request::MutableEchoRequestPacket::new(&mut buffer[..])
                    .context("Failed to get request packet")?;
                echo_packet.set_sequence_number(sequence_number);
                echo_packet.set_identifier(identifier);
                echo_packet.set_icmp_type(IcmpTypes::EchoRequest);

                echo_packet.set_checksum(util::checksum(echo_packet.packet(), 1));

                txv4.send_to(echo_packet, destination_addr)
                    .context("Failed to send IPv4 packet")?;
                let now = Instant::now();
                println!("trying to receive ipv4");
                let mut packet_iter = icmp_packet_iter(&mut rxv4);

                while let Some((packet, addr_of_sender)) = packet_iter
                    .next_with_timeout(std::time::Duration::from_secs(6))
                    .context("failed to get IP V4 packet")?
                {
                    println!("{} {:?}", addr_of_sender, packet);

                    match packet.get_icmp_type() {
                        IcmpTypes::EchoReply => (),
                        IcmpTypes::DestinationUnreachable => {
                            println!("Destination Unreachable");
                            break;
                        }
                        icmp_type => {
                            println!("Not a reply: {:?}", icmp_type);
                            break;
                        }
                    }

                    if packet.get_icmp_code() != IcmpCodes::NoCode {
                        println!("Invalid ICMP code: {:?}", packet.get_icmp_code());
                        break;
                    }

                    let echo_reply = EchoReplyPacket::new(packet.packet())
                        .context("Packet of incorrect size")?;

                    if destination_addr != addr_of_sender {
                        println!("Unexpected ping response from {:<16}:", addr_of_sender);
                        continue;
                    }

                    if sequence_number != echo_reply.get_sequence_number() {
                        println!(
                            "Sequence number: Request - {} ; Response - {}",
                            sequence_number,
                            echo_reply.get_sequence_number() // checked works by manually pinging at same time
                        );
                    }

                    if identifier != echo_reply.get_identifier() {
                        println!(
                            "Identifier: Request - {} ; Response - {}",
                            identifier,
                            echo_reply.get_identifier() // checked works by manually pinging at same time
                        );
                    }
                    println!(
                        "IP V4 reponse time {}",
                        Instant::now().saturating_duration_since(now).as_micros()
                    );
                    break;
                }
            } else {
                let destination_addr = addr.ip();
                //let sequence_number = random();
                //let identifier = random();

                let mut buffer = [0_u8; 16];
                let mut echo_packet = MutableIcmpv6Packet::new(&mut buffer[..])
                    .context("Failed to get request packet")?;
                echo_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                //echo_packet.set_sequence_number(sequence_number);
                //echo_packet.set_identifier(identifier);

                echo_packet.set_checksum(util::checksum(echo_packet.packet(), 1));
                println!("About to send following IP V6 packet{:?}", echo_packet);

                txv6.send_to(echo_packet, destination_addr)
                    .context("Failed to send IPv6 packet")?;
                // start the timer
                let now = Instant::now();

                let mut packet_iter = icmp_packet_iter(&mut rxv6);
                while let Some((packet, addr_of_sender)) = packet_iter
                    .next_with_timeout(std::time::Duration::from_secs(6))
                    .context("failed to get IP V6 packet")?
                {
                    if addr_of_sender == destination_addr {
                        println!(
                            "IP V6 reponse time {}",
                            Instant::now().saturating_duration_since(now).as_micros()
                        );
                        break;
                    } else if addr_of_sender.is_loopback() {
                        println!("IP V6 is loopback") // so ignoring it
                    } else if addr_of_sender.to_string()[0..6] == "fe80::".to_string() {
                        println!("got link local address")
                    } else {
                        println!(
                            "got packet from address {} with contents {:?}",
                            addr_of_sender, packet
                        );
                    };
                }
            }
        }
    }
    Ok(())
}
