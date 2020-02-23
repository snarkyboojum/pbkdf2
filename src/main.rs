extern crate hmac_sha;

use hmac_sha::{hmac_sha512, Hash512};

// TODO: make this configurable
const ITERATION_COUNT: u32 = 10;

fn pbkdf(password: &[u8], salt: &[u8], key_length: u32, mk: &mut [u8]) {
    println!("Running key derivation function");

    // TODO: unnecessary cast to u64
    if key_length as u64 > (std::u32::MAX - 1) as u64 * Hash512::DigestSize as u64 {
        panic!("Key length too large");
    }

    // we need the ceiling value - does this do the right thing?
    let len = key_length / (Hash512::DigestSize as u32);
    let r = key_length - (len - 1) * (Hash512::DigestSize as u32);

    /*
    for i in 1 .. len {
        let T = 0;
        let U = salt || i;

        for j in 1 .. ITERATION_COUNT {
            U = hmac_sha512(password, U);
            T ^= U;
        }
        [mk, T].concat()[0..r-1];
    }
    */
}

fn main() {
    println!("Welcome to the PBKDF2 implementation in Rust!");

    let password = vec![0xa; 16];
    let salt = vec![0x0; 16];
    let key_length: u32 = 512;
    let mut mk = vec![0u8; (key_length / 8) as usize];

    // generate the master key
    let mk = pbkdf(&password, &salt, key_length, &mut mk);
}
