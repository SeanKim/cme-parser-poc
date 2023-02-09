// TODO: understand SBE
// TODO: use SBE instead of nom
// TODO: understand CME MDP 3.0
// TODO: understand CME Market Dynamics (Circuit Breakers, Security Status, Implied Market State, Market Status, etc)
// NOTE: One packet may contains two different events.
// One event may disseminates over multiple packets.
// https://www.cmegroup.com/confluence/display/EPICSANDBOX/MDP+3.0+-+Packet+Structure+with+Event+Based+Messaging

use flate2::read::GzDecoder;
use nom::combinator::map;
use nom::number::streaming::{le_u16, le_u32, le_u64};
use nom::sequence::tuple;
use nom::IResult;
use pcap_file::pcap::PcapReader;
use serde::{Deserialize, Serialize};
use std::fs::File;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct Packet {
    packet_header: PacketHeader,
    message_header: MessageHeader,
    message_body: MessageBody,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct PacketHeader {
    msg_seq_num: u32,
    sending_time: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct MessageHeader {
    msg_size: u16,
    block_length: u16,
    template_id: u16,
    schema_id: u16,
    version: u16,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
enum MessageBody {
    AdminHeartBeat,
}

fn packet_header(input: &[u8]) -> IResult<&[u8], PacketHeader> {
    map(tuple((le_u32, le_u64)), |(msg_seq_num, sending_time)| {
        PacketHeader {
            msg_seq_num,
            sending_time,
        }
    })(input)
}

fn message_header(input: &[u8]) -> IResult<&[u8], MessageHeader> {
    map(
        tuple((le_u16, le_u16, le_u16, le_u16, le_u16)),
        |(msg_size, block_length, template_id, schema_id, version)| MessageHeader {
            msg_size,
            block_length,
            template_id,
            schema_id,
            version,
        },
    )(input)
}

fn packet(input: &[u8]) -> IResult<&[u8], Packet> {
    map(
        tuple((packet_header, message_header)),
        |(packet_header, message_header)| {
            let message_body = match message_header.template_id {
                12 => MessageBody::AdminHeartBeat,
                _ => todo!(),
            };
            Packet {
                packet_header,
                message_header,
                message_body,
            }
        },
    )(input)
}

fn main() -> anyhow::Result<()> {
    let file_in = GzDecoder::new(File::open("data/cme_globex30_Incr_310_A_20221125.pcap.gz")?);

    let mut pcap_reader = PcapReader::new(file_in)?;

    let mut c1 = 0;
    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt?;
        let timestamp = pkt.timestamp;
        // NOTE: Skip Ethernet(14 Bytes), IPv4 (20 Bytes), UDP headers (8 Bytes)
        // NOTE: Ethernet Header become 18 Bytes on VLAN, However, it does not apply to this scenario.
        // NOTE: IPv4 Header can be extended with the `Options` field, However, the options field is not often used.
        // because packets containing some options may be considered as dangerous by some routers and be blocked
        let data = &pkt.data[42..];
        let mut msgs = vec![];
        let mut c2 = 0;
        // NOTE: Packets may contain a single or multiple MDP messages.
        // https://www.cmegroup.com/confluence/display/EPICSANDBOX/MDP+3.0+-+Packet+Structure+with+Event+Based+Messaging
        loop {
            let (remain, msg) = packet(data).unwrap();
            println!("{c1}, {c2}, {}", remain.len());
            msgs.push(msg);
            if remain.is_empty() {
                break;
            }
            c2 += 1;
        }
        c1 += 1;
    }
    Ok(())
}
