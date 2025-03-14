// this file contains an implementation of the square attack on block ciphers

use crate::{
    aes::{self, AESState},
    util::read_hex,
};

// TODO: create aes that lets me access only the inner rounds, not the last step

fn create_delta_set() -> Vec<AESState> {
    let mut delta_set = Vec::new();
    let random_byte = rand::random::<u8>();
    let mut plaintext: [u8; 16] = [random_byte; 16];

    for i in 0..=255 {
        plaintext[0] = i;

        delta_set.push(AESState::from_slice(&plaintext));
    }

    delta_set
}

fn is_delta_set(set: &Vec<AESState>, idx: usize) -> bool {
    if set.len() != 256 {
        return false;
    }

    let mut present = [false; 256];

    for state in set {
        let b = state[idx] as usize;

        if !present[b] {
            present[b] = true;
        } else {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod test {
    use crate::{
        aes::{aes_one_round, encrypt, pre_whiten, AESKey},
        square::is_delta_set,
    };

    use super::create_delta_set;

    #[test]
    fn can_test_delta_set() {
        let delta_set = create_delta_set();

        assert!(is_delta_set(&delta_set, 0));
    }

    #[test]
    fn few_rounds_of_aes_preserves_delta_set() {
        let mut delta_set = create_delta_set();
        let mut key = AESKey::from_hex("2b7e151628aed2a6abf7158809cf4f3c");

        // pre white all states
        for state in &mut delta_set {
            pre_whiten(state, &key);
        }

        // then perform one round of encryption
        key = key.next_round_key();
        for state in &mut delta_set {
            aes_one_round(state, &key);
        }

        for i in 0..4 {
            assert!(is_delta_set(&delta_set, i));
        }

        key = key.next_round_key();
        for state in &mut delta_set {
            aes_one_round(state, &key);
        }

        for i in 0..16 {
            assert!(is_delta_set(&delta_set, i));
        }
    }

    #[test]
    fn persistent_structure_in_three_rounds() {
        let mut delta_set = create_delta_set();
        let mut key = AESKey::from_hex("2b7e151628aed2a6abf7158809cf4f3c");

        // pre white all states
        for state in &mut delta_set {
            pre_whiten(state, &key);
        }

        // then perform three rounds of encryption
        for _ in 0..3 {
            key = key.next_round_key();
            for state in &mut delta_set {
                aes_one_round(state, &key);
            }
        }

        // now the first bit must xor to 0
        let mut res = [0u8; 16];
        for state in delta_set {
            (0..16).for_each(|i| {
                res[i] ^= state[0];
            });
        }

        assert!(res.iter().all(|b| *b == 0));
    }
}
