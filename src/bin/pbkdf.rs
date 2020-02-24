extern crate pbkdf2;

use pbkdf2::pbkdf_hmac_sha512;

fn main() {
    println!("Welcome to the PBKDF2 implementation in Rust!");

    let password = vec![0xac; 8];
    let salt = vec![0xb; 64];
    let key_length: u32 = 512;
    let iter_count: u32 = 2;
    let mut mk: Vec<u8> = Vec::new(); //vec![0u8; (key_length / 8) as usize];

    // generate the master key
    pbkdf_hmac_sha512(&password, &salt, iter_count, key_length, &mut mk);
    println!("mk is {:?}", mk);
}
