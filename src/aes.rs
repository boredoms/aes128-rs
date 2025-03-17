use std::{
    fmt::Display,
    ops::{Index, IndexMut},
    str::FromStr,
};

use crate::aes_lookup_table;
use crate::util::read_hex;

// Compute the rcon function using math
// The current implementation iteratively multiplies by x and then takes modulos as necessary.
// There could be a faster version but this may be pointless since the lookup table is always gonna
// be faster
fn rcon_math(x: u8) -> u8 {
    if x == 0 {
        return 0x8d;
    }

    let mut p = 1;

    for _ in 1..x {
        if p < 0x80 {
            p <<= 1;
        } else {
            p <<= 1;
            p ^= 0x1b;
        }
    }

    p
}

#[derive(Debug, Default)]
pub struct AESIV {
    bytes: [u8; 16],
}

impl FromStr for AESIV {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = read_hex(s)
            .map_err(|_| "could not parse bytes")?
            .try_into()
            .map_err(|_| "keys must have 16 bytes")?;

        Ok(Self { bytes })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct AESKey {
    bytes: [u8; 16],
    pub round: u8,
}

impl AESKey {
    #[inline]
    fn rot_word(x: &mut [u8]) {
        x.rotate_left(1);
    }

    #[inline]
    fn sub_word(xs: &mut [u8]) {
        for x in xs {
            *x = aes_lookup_table::SUB_TABLE[*x as usize];
        }
    }

    #[inline]
    fn rcon(x: u8) -> [u8; 4] {
        [aes_lookup_table::RCON_TABLE[x as usize], 0x00, 0x00, 0x00]
    }

    pub fn from_hex(s: &str) -> Self {
        AESKey {
            bytes: read_hex(s).unwrap().try_into().unwrap(),
            round: 0,
        }
    }

    pub fn new() -> Self {
        AESKey {
            bytes: [0; 16],
            round: 0,
        }
    }

    pub fn set_round(&mut self, r: u8) {
        self.round = r;
    }

    pub fn next_round_key(&self) -> Self {
        // get the last four bytes
        let mut bytes: [u8; 16] = [0; 16];
        bytes[0..4].clone_from_slice(&self.bytes[12..]);

        Self::rot_word(&mut bytes[0..4]);
        Self::sub_word(&mut bytes[0..4]);

        for i in 0..4 {
            bytes[i] ^= self.bytes[i];
        }

        let rcon = Self::rcon(self.round + 1);

        for i in 0..4 {
            bytes[i] ^= rcon[i];
        }

        for i in 4..16 {
            bytes[i] = bytes[i - 4] ^ self.bytes[i]
        }

        AESKey {
            bytes,
            round: self.round + 1,
        }
    }

    pub fn prev_round_key(&self) -> Self {
        let mut bytes = [0; 16];

        for i in (4..16).rev() {
            bytes[i] = self.bytes[i] ^ self.bytes[i - 4];
        }

        for i in 0..4 {
            bytes[i] = bytes[i + 12];
        }

        Self::rot_word(&mut bytes[0..4]);
        Self::sub_word(&mut bytes[0..4]);

        let rcon = Self::rcon(self.round);

        for i in 0..4 {
            bytes[i] ^= rcon[i] ^ self.bytes[i];
        }

        AESKey {
            bytes,
            round: self.round - 1,
        }
    }
}

impl Index<usize> for AESKey {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.bytes.index(index)
    }
}

impl FromStr for AESKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = read_hex(s)
            .map_err(|_| "could not parse bytes")?
            .try_into()
            .map_err(|_| "keys must have 16 bytes")?;

        Ok(Self { bytes, round: 0 })
    }
}

impl IndexMut<usize> for AESKey {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.bytes.index_mut(index)
    }
}

fn aes_field_mul2(x: u8) -> u8 {
    if x < 0x80 {
        x << 1
    } else {
        (x << 1) ^ 0x1b
    }
}

fn aes_field_mul3(x: u8) -> u8 {
    aes_field_mul2(x) ^ x
}

fn mix_column(a: &mut [u8]) {
    if let [a0, a1, a2, a3, ..] = *a {
        let b0 = aes_lookup_table::MUL_2_TABLE[a0 as usize]
            ^ aes_lookup_table::MUL_3_TABLE[a1 as usize]
            ^ a2
            ^ a3;
        let b1 = a0
            ^ aes_lookup_table::MUL_2_TABLE[a1 as usize]
            ^ aes_lookup_table::MUL_3_TABLE[a2 as usize]
            ^ a3;
        let b2 = a0
            ^ a1
            ^ aes_lookup_table::MUL_2_TABLE[a2 as usize]
            ^ aes_lookup_table::MUL_3_TABLE[a3 as usize];
        let b3 = aes_lookup_table::MUL_3_TABLE[a0 as usize]
            ^ a1
            ^ a2
            ^ aes_lookup_table::MUL_2_TABLE[a3 as usize];

        a[0] = b0;
        a[1] = b1;
        a[2] = b2;
        a[3] = b3;
    } else {
        panic!("columns can only be mixed if they have at least 4 elements");
    }
}

fn unmix_column(a: &mut [u8]) {
    if let [a0, a1, a2, a3, ..] = *a {
        let b0 = aes_lookup_table::MUL_14_TABLE[a0 as usize]
            ^ aes_lookup_table::MUL_11_TABLE[a1 as usize]
            ^ aes_lookup_table::MUL_13_TABLE[a2 as usize]
            ^ aes_lookup_table::MUL_9_TABLE[a3 as usize];
        let b1 = aes_lookup_table::MUL_9_TABLE[a0 as usize]
            ^ aes_lookup_table::MUL_14_TABLE[a1 as usize]
            ^ aes_lookup_table::MUL_11_TABLE[a2 as usize]
            ^ aes_lookup_table::MUL_13_TABLE[a3 as usize];
        let b2 = aes_lookup_table::MUL_13_TABLE[a0 as usize]
            ^ aes_lookup_table::MUL_9_TABLE[a1 as usize]
            ^ aes_lookup_table::MUL_14_TABLE[a2 as usize]
            ^ aes_lookup_table::MUL_11_TABLE[a3 as usize];
        let b3 = aes_lookup_table::MUL_11_TABLE[a0 as usize]
            ^ aes_lookup_table::MUL_13_TABLE[a1 as usize]
            ^ aes_lookup_table::MUL_9_TABLE[a2 as usize]
            ^ aes_lookup_table::MUL_14_TABLE[a3 as usize];

        a[0] = b0;
        a[1] = b1;
        a[2] = b2;
        a[3] = b3;
    } else {
        panic!("columns can only be mixed if they have at least 4 elements");
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct AESState {
    bytes: [u8; 16],
}

impl Index<usize> for AESState {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.bytes[index]
    }
}

impl FromStr for AESState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = read_hex(s)
            .map_err(|_| "could not parse bytes")?
            .try_into()
            .map_err(|_| "states must have 16 bytes")?;

        Ok(AESState { bytes })
    }
}

impl AESState {
    pub fn from_slice(bytes: &[u8]) -> Self {
        AESState {
            bytes: bytes.try_into().unwrap(),
        }
    }

    pub fn from_str(s: &str) -> Self {
        AESState {
            bytes: s.bytes().collect::<Vec<u8>>().try_into().unwrap(),
        }
    }

    pub fn from_hex(s: &str) -> Self {
        AESState {
            bytes: read_hex(s).unwrap().try_into().unwrap(),
        }
    }

    pub fn sub_bytes(&mut self) -> &mut Self {
        for b in &mut self.bytes {
            *b = aes_lookup_table::SUB_TABLE[*b as usize];
        }

        self
    }

    pub fn unsub_bytes(&mut self) -> &mut Self {
        for b in &mut self.bytes {
            *b = aes_lookup_table::UNSUB_TABLE[*b as usize];
        }

        self
    }

    pub fn shift_rows(&mut self) -> &mut Self {
        // rotate every row by its index
        for i in 1..4 {
            for _ in 0..i {
                let a = self.bytes[i];

                self.bytes[i] = self.bytes[4 + i];
                self.bytes[4 + i] = self.bytes[8 + i];
                self.bytes[8 + i] = self.bytes[12 + i];
                self.bytes[12 + i] = a;
            }
        }

        self
    }

    pub fn unshift_rows(&mut self) -> &mut Self {
        for i in 1..4 {
            for _ in 0..4 - i {
                let a = self.bytes[i];

                self.bytes[i] = self.bytes[4 + i];
                self.bytes[4 + i] = self.bytes[8 + i];
                self.bytes[8 + i] = self.bytes[12 + i];
                self.bytes[12 + i] = a;
            }
        }

        self
    }

    pub fn mix_columns(&mut self) -> &mut Self {
        for i in 0..4 {
            mix_column(&mut self.bytes[4 * i..4 * i + 4]);
        }

        self
    }

    pub fn unmix_columns(&mut self) -> &mut Self {
        for i in 0..4 {
            unmix_column(&mut self.bytes[4 * i..4 * i + 4]);
        }

        self
    }

    pub fn add_round_key(&mut self, key: &AESKey) -> &mut Self {
        for i in 0..16 {
            self.bytes[i] ^= key.bytes[i];
        }

        self
    }
}

impl Display for AESState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = &self.bytes;
        for i in 0..4 {
            writeln!(
                f,
                "{:02x} {:02x} {:02x} {:02x}",
                bytes[i],
                bytes[4 + i],
                bytes[8 + i],
                bytes[12 + i]
            )
            .expect("can write to formatter");
        }
        Ok(())
    }
}

// pre whiten the given aes state
pub fn pre_whiten(state: &mut AESState, key: &AESKey) {
    state.add_round_key(key);
}

// run one round of full encryption
pub fn aes_one_round(state: &mut AESState, key: &AESKey) {
    state
        .sub_bytes()
        .shift_rows()
        .mix_columns()
        .add_round_key(key);
}

pub fn aes_finalize(state: &mut AESState, key: &AESKey) {
    state.sub_bytes().shift_rows().add_round_key(key);
}

pub fn encrypt(plaintext: &AESState, mut key: AESKey, rounds: u8) -> AESState {
    let mut state = *plaintext;

    pre_whiten(&mut state, &key);

    for _ in 0..rounds - 1 {
        key = key.next_round_key();
        aes_one_round(&mut state, &key);
    }

    key = key.next_round_key();
    aes_finalize(&mut state, &key);

    state
}

fn AES128_encrypt(text: &[u8], key: &[u8]) -> Vec<u8> {
    // 10 ronuds
    todo!()
}

pub fn decrypt(ciphertext: &AESState, key: &AESKey, rounds: u8) -> AESState {
    let mut state = *ciphertext;
    // first compute the round keys
    let mut keys = Vec::with_capacity((rounds + 1) as usize);

    keys.push(*key);
    for _ in 0..rounds {
        keys.push(keys.last().unwrap().next_round_key());
    }

    // last round:
    state
        .add_round_key(keys.last().unwrap())
        .unshift_rows()
        .unsub_bytes();

    for i in (1..=rounds - 1).rev() {
        state
            .add_round_key(&keys[i as usize])
            .unmix_columns()
            .unshift_rows()
            .unsub_bytes();
    }

    state.add_round_key(&keys[0]);

    state
}

#[cfg(test)]
mod tests {
    use crate::{
        aes::{
            aes_field_mul2, aes_field_mul3, aes_lookup_table::MUL_2_TABLE,
            aes_lookup_table::MUL_3_TABLE, aes_lookup_table::RCON_TABLE, rcon_math, AESKey,
        },
        util::write_hex,
    };

    use super::{decrypt, encrypt, AESState};

    #[test]
    fn can_compute_rcon() {
        for i in 0u8..=255 {
            println!("{i}: {:x} == {:x}", rcon_math(i), RCON_TABLE[i as usize]);
            assert_eq!(rcon_math(i), RCON_TABLE[i as usize]);
        }
    }

    #[test]
    fn aes_key_can_create_next() {
        let mut key = AESKey::from_hex("2b7e151628aed2a6abf7158809cf4f3c");

        for _ in 0..10 {
            key = key.next_round_key();

            println!("{:02x?}", key);
        }

        assert_eq!(write_hex(&key.bytes), "d014f9a8c9ee2589e13f0cc8b6630ca6");
    }

    #[test]
    fn aes_key_can_reverse() {
        let key = AESKey::from_hex("2b7e151628aed2a6abf7158809cf4f3c");
        let reverse = key.next_round_key().prev_round_key();

        assert_eq!(write_hex(&key.bytes), write_hex(&reverse.bytes));
    }

    #[test]
    fn aes_state_can_create() {
        let state = AESState::from_str("this is one text");

        assert_eq!(
            format!("{state}"),
            "74 20 6f 74
68 69 6e 65
69 73 65 78
73 20 20 74
"
        );
    }

    #[test]
    fn aes_state_can_sub_bytes() {
        let mut state = AESState::from_hex("000102030405060708090a0b0c0d0e0f");

        state.sub_bytes();

        assert_eq!(write_hex(&state.bytes), "637c777bf26b6fc53001672bfed7ab76");
    }

    #[test]
    fn aes_state_can_shift_rows() {
        let mut state = AESState::from_hex("000102030405060708090a0b0c0d0e0f");

        state.sub_bytes().shift_rows();

        println!("{state}");

        assert_eq!(write_hex(&state.bytes), "636b6776f201ab7b30d777c5fe7c6f2b");
    }

    #[test]
    fn aes_state_can_mix_columns() {
        let mut state = AESState::from_hex("000102030405060708090a0b0c0d0e0f");

        state.sub_bytes().shift_rows().mix_columns();

        println!("{state}");

        assert_eq!(write_hex(&state.bytes), "6a6a5c452c6d3351b0d95d61279c215c");
    }

    #[test]
    fn aes_state_can_add_round_key() {
        let mut state = AESState::from_hex("000102030405060708090a0b0c0d0e0f");

        state
            .sub_bytes()
            .shift_rows()
            .mix_columns()
            .add_round_key(&AESKey::from_hex("d6aa74fdd2af72fadaa678f1d6ab76fe"));

        println!("{state}");

        assert_eq!(write_hex(&state.bytes), "bcc028b8fec241ab6a7f2590f13757a2");
    }

    #[test]
    fn can_encrypt() {
        let plaintext = AESState::from_str("theblockbreakers");
        let key = AESKey::from_hex("2b7e151628aed2a6abf7158809cf4f3c");
        let ciphertext = encrypt(&plaintext, key, 10);

        assert_eq!(
            format!("{}", ciphertext),
            "c6 02 23 2f
9f 5a 93 05
25 9e f6 b7
d0 f3 3e 47
"
        );
    }

    #[test]
    fn can_decrypt() {
        let plaintext = AESState::from_str("theblockbreakers");
        let key = AESKey::from_hex("2b7e151628aed2a6abf7158809cf4f3c");
        let ciphertext = encrypt(&plaintext, key, 10);
        let decrypted = decrypt(&ciphertext, &key, 10);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn can_multiply_by_two() {
        for x in 0u8..=255 {
            assert_eq!(aes_field_mul2(x), MUL_2_TABLE[x as usize]);
        }
    }

    #[test]
    fn can_multiply_by_three() {
        for x in 0u8..=255 {
            assert_eq!(aes_field_mul3(x), MUL_3_TABLE[x as usize]);
        }
    }
}
