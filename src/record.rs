// Answers

use std::io::Result;
use std::net::Ipv4Addr;
use crate::buffer::BytePacketParser;
use crate::query_type::QueryType;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,   // Which domain this record is for
        qtype: u16,       // The numeric record type
        data_len: u16,    // How much data follows
        ttl: u32,         // How long to cache this (seconds)
    },
    /// IPv4 address record
    A {
        domain: String,   // Which domain this is for
        addr: Ipv4Addr,   // The IP address (like 216.58.211.142)
        ttl: u32,         // Cache time in seconds
    },
}

impl DnsRecord {
    // Read the DNS record from the packet buffer
    // Format in packet: [NAME][TYPE][CLASS][TTL][LENGTH][RDATA]
    pub fn read(buffer: &mut BytePacketParser) -> Result<DnsRecord> {
        // Read the domain name with compression support
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        // Read the record metadata
        let qtype_num = buffer.read_u16()?; // Record type number
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?; // Class (ignore, always 1)
        let ttl = buffer.read_u32()?; // time to live
        let data_len = buffer.read_u16()?; // Length of the data section

        // Now parse the actual data based on the record type
        match qtype {
            QueryType::A => {
                // A record : 4 bytes representing an IPv4 address
                let raw_addr = buffer.read_u32()?;

                // Convert the 32-bit number to an IPv4 format
                // Example: 0xD83AD38E becomes 216.58.211.142
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,  // First byte
                    ((raw_addr >> 16) & 0xFF) as u8,  // Second byte
                    ((raw_addr >> 8) & 0xFF) as u8,   // Third byte
                    ((raw_addr >> 0) & 0xFF) as u8,   // Fourth byte
                );

                Ok(DnsRecord::A {domain, addr, ttl})
            }
            QueryType::UNKNOWN(_) => {
                // For unknown record types, just skip the data
                buffer.step(data_len as usize)?;
                
                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }

    }
}