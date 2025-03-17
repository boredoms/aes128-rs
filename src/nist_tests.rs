use std::str::FromStr;

use crate::aes::{AESKey, AESState, AESIV};

#[derive(Debug)]
pub struct NISTTest {
    count: u32,
    key: AESKey,
    iv: AESIV,
    plaintext: AESState,
    ciphertext: AESState,
}

impl NISTTest {
    fn parse_line<'a, T: FromStr>(s: &'a str) -> Result<(&'a str, T), String> {
        s.split_once("=")
            .map(|(keyword, value)| {
                let keyword = keyword.trim();
                let value = value.trim().parse::<T>();

                value.map(|v| (keyword, v)).map_err(|_| {
                    format!(
                        "error parsing the value {} as {}",
                        keyword,
                        std::any::type_name::<T>()
                    )
                })
            })
            .ok_or_else(|| "missing '=' in line".to_string())?
    }
}

impl FromStr for NISTTest {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut line_iterator = s.lines();

        let (kw, count) =
            Self::parse_line::<u32>(line_iterator.next().ok_or("could not get line for COUNT")?)?;

        if kw != "COUNT" {
            return Err(format!("expected keyword COUNT got {}", kw));
        }

        let (kw, key) =
            Self::parse_line::<AESKey>(line_iterator.next().ok_or("could not get line for KEY")?)?;

        if kw != "KEY" {
            return Err(format!("expected keyword KEY got {}", kw));
        }

        let (kw, iv) =
            Self::parse_line::<AESIV>(line_iterator.next().ok_or("could not get line for IV")?)?;

        if kw != "IV" {
            return Err(format!("expected keyword IV got {}", kw));
        }

        let (kw, plaintext) = Self::parse_line::<AESState>(
            line_iterator
                .next()
                .ok_or("could not get line for PLAINTEXT")?,
        )?;
        if kw != "PLAINTEXT" {
            return Err(format!("expected keyword PLAINTEXT got {}", kw));
        }

        let (kw, ciphertext) = Self::parse_line::<AESState>(
            line_iterator
                .next()
                .ok_or("could not get line for CIPHERTEXT")?,
        )?;
        if kw != "CIPHERTEXT" {
            return Err(format!("expected keyword CIPHERTEXT got {}", kw));
        }

        Ok(NISTTest {
            count,
            key,
            iv,
            plaintext,
            ciphertext,
        })
    }
}

pub struct NISTTestFile {
    tests: Vec<NISTTest>,
}

#[cfg(test)]
mod test {
    use super::NISTTest;

    #[test]
    fn can_parse_line() {
        let l =
            NISTTest::parse_line::<u32>("COUNT = 1").expect("Should be able to parse this line!");

        assert_eq!(l.1, 1);
    }

    #[test]
    fn can_parse_test_specification() {
        let t = "COUNT = 0
KEY = 00000000000000000000000000000000
IV = 00000000000000000000000000000000
PLAINTEXT = 00000000000000000000000000000000
CIPHERTEXT = 00000000000000000000000000000000"
            .parse::<NISTTest>()
            .expect("valid test spec must be parsed");

        assert_eq!(t.count, 0);
    }

    #[test]
    fn does_not_parse_short_key() {
        let t = "COUNT = 0
KEY = 00
IV = 00000000000000000000000000000000
PLAINTEXT = 00000000000000000000000000000000
CIPHERTEXT = 00000000000000000000000000000000"
            .parse::<NISTTest>();

        assert_eq!(
            t.err(),
            Some("error parsing the value KEY as blockbreakers::aes::AESKey".to_string())
        );
    }
}
