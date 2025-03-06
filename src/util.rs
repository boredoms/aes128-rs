use std::{fmt::Write, num::ParseIntError};

pub fn read_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .inspect(|i| println!("{:02x?}", i))
        .collect()
}

pub fn write_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len());

    for b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }

    s
}
