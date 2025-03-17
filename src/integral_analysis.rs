// this file contains an implementation of the square attack on block ciphers

use crate::{
    aes::{self, aes_finalize, aes_one_round, encrypt, pre_whiten, AESKey, AESState},
    aes_lookup_table::UNSUB_TABLE,
    util::read_hex,
};

pub fn create_delta_set() -> Vec<AESState> {
    let mut delta_set = Vec::new();
    let random_byte = rand::random::<u8>();
    let mut plaintext: [u8; 16] = [random_byte; 16];

    for i in 0..=255 {
        plaintext[0] = i;

        delta_set.push(AESState::from_slice(&plaintext));
    }

    delta_set
}

pub fn setup(key: &AESKey) -> Vec<AESState> {
    let mut delta_set = create_delta_set();

    delta_set
        .iter_mut()
        .for_each(|state| *state = encrypt(state, *key, 4));

    delta_set
}

pub fn is_delta_set(set: &Vec<AESState>, idx: usize) -> bool {
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

fn reverse_byte(b: u8, guess: u8) -> u8 {
    UNSUB_TABLE[(b ^ guess) as usize]
}

fn reduce_reverse(delta_set: &[AESState], guess: u8, pos: usize) -> u8 {
    delta_set
        .iter()
        .fold(0, |acc, e| reverse_byte(e[pos], guess) ^ acc)
}

fn check_key_guess(delta_set: &[AESState], guess: u8, pos: usize) -> bool {
    reduce_reverse(delta_set, guess, pos) == 0
}

pub fn generate_candidates(delta_set: &[AESState], pos: usize) -> Vec<u8> {
    let mut candidates = Vec::with_capacity(256);

    for b in 0..=255 {
        if check_key_guess(delta_set, b, pos) {
            candidates.push(b);
        }
    }

    candidates
}

pub fn guess_key(key: &AESKey) -> AESKey {
    let mut delta_set = setup(key);

    let mut key_guess = AESKey::new();

    for pos in 0..16 {
        let mut candidates = generate_candidates(&delta_set, pos);
        let mut buffer = Vec::new();

        while candidates.len() > 1 {
            delta_set = setup(key);

            // check if candidate is valid with new delta set
            for c in &candidates {
                if check_key_guess(&delta_set, *c, pos) {
                    buffer.push(*c);
                }
            }

            std::mem::swap(&mut candidates, &mut buffer);
        }

        key_guess[pos] = candidates[0];
    }

    // reverse the aes key expansion to get the original key
    key_guess.round = 4;

    while key_guess.round > 0 {
        key_guess = key_guess.prev_round_key();
    }

    key_guess
}

#[cfg(test)]
mod test {
    use crate::{
        aes::{aes_finalize, aes_one_round, encrypt, pre_whiten, AESKey},
        integral_analysis::{check_key_guess, generate_candidates, guess_key, is_delta_set, setup},
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

    #[test]
    fn can_guess_first_candidate_four_rounds() {
        // perform four round aes
        let key = AESKey::from_hex("2b7e151628aed2a6abf7158809cf4f3c");

        println!(
            "{:?}",
            key.next_round_key()
                .next_round_key()
                .next_round_key()
                .next_round_key()
        );

        let guess = guess_key(&key);

        println!("{:?}", guess);

        assert_eq!(key, guess);
    }
}
