use anyhow::{Context, Result};
use pnet::{
    packet::{
        icmp::{echo_request, IcmpTypes},
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
    let (mut tx, mut rx) = transport_channel(64, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
        .context("Failed to get transport channel")?;

    for addr in std::env::args().skip(1) {
        println!("Address: {}", addr);
        for addr in (addr.as_str(), 0)
            .to_socket_addrs()
            .context("Failed to get addresses")?
        {
            if !addr.is_ipv4() {
                continue;
            }

            let addr = addr.ip();

            let mut buffer = [0_u8; 16];
            let mut echo_packet = echo_request::MutableEchoRequestPacket::new(&mut buffer[..])
                .context("Failed to get request packet")?;
            echo_packet.set_sequence_number(random::<u16>());
            echo_packet.set_identifier(random::<u16>());
            echo_packet.set_icmp_type(IcmpTypes::EchoRequest);

            echo_packet.set_checksum(util::checksum(echo_packet.packet(), 1));

            println!("Sending {:?} to {}", echo_packet, addr);

            tx.send_to(echo_packet, addr)
                .context("Failed to send packet")?;
        }
    }

    let mut packet_iter = icmp_packet_iter(&mut rx);

    while let Some((packet, addr)) = packet_iter
        .next_with_timeout(std::time::Duration::from_secs(5))
        .context("failed to get packet")?
    {
        println!("{:<16}: {:?}", addr, packet);
    }

    Ok(())
}
