
pub enum ResultCode {
    NOERROR = 0, // Scuccess
    FORMERR = 1, // Your question is malformed
    SERVFAIL = 2, // Sorry, server had an error
    NXDOMAIN = 3, // That domain does not exist
    NOTIMP = 4, // I dont know how to answer that
    REFUSED = 5, // I wont answer that
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR, // Default to NOERROR for success
        }
    }
}