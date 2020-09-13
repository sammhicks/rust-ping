use anyhow::{Context, Result};
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
    },
    util,
};
use pnet_macros_support::packet::Packet;
use rand::random;
use std::iter::Iterator;
use std::net::ToSocketAddrs;

fn main() -> Result<()> {
    for addr in std::env::args().skip(1) {
        println!("Address: {}", addr);
        let (mut tx, mut rx) = transport_channel(64, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
            .context("Failed to get transport channel. You need root priviledges")?;
        for addr in (addr.as_str(), 0)
            .to_socket_addrs()
            .context("Failed to get addresses")?
        {
            if !addr.is_ipv4() {
                println!("Got IPV6 address");
                continue;
            }

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

            println!("Sending {:?} to {}", echo_packet, destination_addr);

            tx.send_to(echo_packet, destination_addr)
                .context("Failed to send packet")?;

            let mut packet_iter = icmp_packet_iter(&mut rx);
            while let Some((packet, addr_of_sender)) = packet_iter
                .next_with_timeout(std::time::Duration::from_secs(50))
                .context("failed to get packet")?
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

                let echo_reply =
                    EchoReplyPacket::new(packet.packet()).context("Packet of incorrect size")?;

                if destination_addr != addr_of_sender {
                    println!("Unexpected ping response from {:<16}:", addr_of_sender);
                    continue;
                }

                if sequence_number != echo_reply.get_sequence_number() {
                    println!(
                        "Sequence number: Request - {} ; Response - {}",
                        sequence_number,
                        echo_reply.get_sequence_number()
                    );
                }

                if identifier != echo_reply.get_identifier() {
                    println!(
                        "Identifier: Request - {} ; Response - {}",
                        identifier,
                        echo_reply.get_identifier()
                    );
                }

                break;
            }
        }
    }
    Ok(())
}
