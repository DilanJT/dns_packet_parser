
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16), // for records we don't know about
    A, // IPv4 address ( current implementation )
    // Future additions could be:
    // AAAA,       // IPv6 address  
    // CNAME,      // Canonical name (alias)
    // MX,         // Mail exchange
    // NS,         // Name server
    // TXT,        // Text records
}

impl QueryType {
    /// Convert our enum to the number DNS expects
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1, // A record is 1 in DNS
            // Future: QueryType::AAAA => 28,
            // Future: QueryType::CNAME => 5,
        }
    }

    /// Convert a number from DNS packet to our enum
    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A, // A record is 1 in DNS
            // Future: 28 => QueryType::AAAA,
            // Future: 5 => QueryType::CNAME,
            _ => QueryType::UNKNOWN(num), // Unknown type
        }
    }
}