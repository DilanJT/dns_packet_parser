// The packet's brain

use std::io::Result;
use crate::buffer::BytePacketParser;
use crate::result_code::ResultCode;

#[derive(Clone, Debug)]
pub struct DnsHeader {
    // First 2 bytes :  packet ID (tracking number)
    pub id: u16,

    // These all flags packed into the next 2 bytes
    pub recursion_desired: bool, // Please ask other servers if you don't know
    pub truncated_message: bool, // This message was cut off
    pub authoritative_answer: bool, // I am the official source of this information
    pub opcode: u8, // Type of query (usually 0 for standard query)
    pub response: bool, // Is this a question (false) or an answer (true)

    pub rescode: ResultCode, // Did the query succeed ?
    pub checking_disabled: bool, // DNSSEC related
    pub authed_data: bool, // DNSSEC related
    pub z: bool, // Reserved for future use
    pub recursion_available: bool, // Can I ask other servers if I don't know

    // Last 8 bytes: How many things are in each section
    pub questions: u16, // How many questions in this packet
    pub answers: u16, // How many answers in this packet
    pub authoritative_entries: u16, // How many authoritative entries in this packet
    pub resource_entries: u16, // How many additional records
}

impl DnsHeader {
    /// Create a new empty header
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    // Read a header from the buffer
    // This is where the bit manipulation happens

    pub fn read(&mut self, buffer: &mut BytePacketParser) -> Result<()> {

        // First 2 bytes: packet ID
        self.id = buffer.read_u16()?;
        
        // Next 2 bytes: flags 
        let flags = buffer.read_u16()?;

        // Split the 16 bit flags into two 8-bit parts
        let a = (flags >> 8) as u8; // First 8 bits
        let b = (flags & 0xFF) as u8; // second 8 bits

        // Pase first byte: |QR|OPCODE|AA|TC|RD|
        // We use bit masks to extract each flag
        self.recursion_desired = (a & (1 << 0)) > 0;     // Bit 0
        self.truncated_message = (a & (1 << 1)) > 0;     // Bit 1  
        self.authoritative_answer = (a & (1 << 2)) > 0;  // Bit 2
        self.opcode = (a >> 3) & 0x0F;                   // Bits 3-6
        self.response = (a & (1 << 7)) > 0;              // Bit 7

        // Parse second byte: |RA|Z|AD|CD|RCODE|
        self.rescode = ResultCode::from_num(b & 0x0F);   // Bits 0-3
        self.checking_disabled = (b & (1 << 4)) > 0;     // Bit 4
        self.authed_data = (b & (1 << 5)) > 0;           // Bit 5
        self.z = (b & (1 << 6)) > 0;                     // Bit 6
        self.recursion_available = (b & (1 << 7)) > 0;   // Bit 7

        // Last 8 bytes: section counts (4 × 16-bit numbers)
        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())

    }

}