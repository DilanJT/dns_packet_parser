use std::io::Result;
use crate::buffer::BytePacketParser;
use crate::query_type::QueryType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String, // Domain name being queried
    pub qtype: QueryType, // What type of record is being asked for (e.g., A, AAAA, CNAME)
}

impl DnsQuestion {
    /// Create a new question
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    // Read a question from the packet buffer
    // Format in packet: [NAME][TYPE][CLASS]
    pub fn read(&mut self, buffer: &mut BytePacketParser) -> Result<()> {
        // Read the domain name  (this handles the complex label//compression stuff)
        buffer.read_qname(&mut self.name)?;

        // Read the query type (2 bytes)
        self.qtype = QueryType::from_num(buffer.read_u16()?);

        // Read the class (2 bytes) - this is almost always 1 (IN for Internet)
        let _ = buffer.read_u16()?; 

        Ok(())
    }

}