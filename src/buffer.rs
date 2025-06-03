use std::io::Result;

pub struct BytePacketParser {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketParser {
    pub fn new() -> BytePacketParser {
        BytePacketParser {
            buf: [0; 512],
            pos: 0,
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }


    // skip positions
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }

    // jump to a specific position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    // read one byte and move forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer reached".into());
        }

        let res = self.buf[self.pos];
        self.pos += 1; 
        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("Position out of bounds".into());
        }
        Ok(self.buf[pos])
    }

    // get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("Range out of bounds".into());
        }
        Ok(&self.buf[start..start + len])
    }

    // reading two bytes, stepping two steps forward
    /// use: DNS uses 16 bit numbers for things like packet IDs, record types, and counts. 
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    // Read four bytes, stepping four steps forward
    // We need this for : DNS uses 32-bit numbers for TTL values and IPv4 addresses. 
    // DNS context: Time-to-Live (how long to cache) and IP addresses are 32 bit values
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);
        Ok(res)
    }

    /// Use: Reads a domain name from the DNS packet, handling compression. 
    /// Why: DNS domain names have a special format and can be compressed.
    /// 
    /// The Challenge: DNS Domain Name Format
        // Normal text: "google.com"
        // DNS format: [6]google[3]com[0]

        // 6 = "next 6 bytes are a label"
        // google = the actual text
        // 3 = "next 3 bytes are a label"
        // com = the actual text
        // 0 = "end of domain name"

        // The Compression Problem
        // Packet:
        // Position 12: [6]google[3]com[0]     ← Original "google.com"
        // Position 35: [0xC0][0x0C]           ← Pointer saying "look at position 12"
        // Instead of storing "google.com" twice, DNS uses a pointer!

    // Read a qname
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos(); // to remember where we started

        //track  whether or not we have jumped

        let mut jumped = false; // Did we follow any pointers ?
        let max_jumps = 5; // Safety limit
        let mut jumps_performed =0; // count jumps to prevent loops

        /// Our delimiter which we append for each label. Since we dont want a 
        /// dot at the beginning of the domain name we'll leave it empty for now
        /// and set it to "." at the end of the first iteration
        let mut delim = ""; // seperator between labels
        loop {
            // DNS packets are untrusted data, so we need to be paranoid. Someone can
            // craft a packet with a cycle in the jump instructions. This guard against such packets

            if jumps_performed > max_jumps {
                return Err(format!("Too many jumps in qname, max is {}", max_jumps).into());
            }

            // At this point we are always at the beginning of a label, Recall that labels start with a length byte
            let len = self.get(pos)?;

            // If len has the two most significant but are set, it represents a jump to some other offset in the packet.
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calaculate offset and perform the jump by updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = ((len as u16) ^ 0xC0) << 8 | b2;
                pos = offset as usize;

                // Indicate that the jump was performed
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we are reading a single label and appending it to the output
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0, so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to out output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = "."; // Set the delimiter to "." for the next label

                // Move forward the full length of the label.
                pos += len as usize;

            }

        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}


/// End goal 
/// [HEADER 12 bytes][QUESTION][ANSWER][AUTHORITY][ADDITIONAL]