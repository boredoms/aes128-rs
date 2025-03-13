use blockbreakers::aes;

fn main() {
    let plaintext = aes::AESState::from_str("theblockbreakers");
    let key = aes::AESKey::from_hex("2b7e151628aed2a6abf7158809cf4f3c");
    let ciphertext = aes::encrypt(&plaintext, key, 10);
    let decrypted = aes::decrypt(&ciphertext, &key, 10);

    println!("plaintext: {plaintext}\nciphertext: {ciphertext}\ndecrypted: {decrypted}");
}
