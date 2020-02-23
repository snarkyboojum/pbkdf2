extern crate hmac_sha;

use hmac_sha::{hmac_sha512, Hash512};
use byteorder::{BigEndian, ByteOrder};

// TODO: make this configurable - should be at least 10,000 probably
const ITERATION_COUNT: u32 = 10;

fn pbkdf(password: &[u8], salt: &[u8], key_length: u32, mk: &mut [u8]) {
    println!("Running key derivation function");

    // TODO: unnecessary cast to u64
    if key_length as u64 > (std::u32::MAX - 1) as u64 * Hash512::DigestSize as u64 {
        panic!("Key length too large");
    }

    // TODO: we need the ceiling value - does this do the right thing?
    let len = key_length / (Hash512::DigestSize as u32);
    let r = (key_length - (len - 1) * (Hash512::DigestSize as u32)) as usize;

    println!("len: {}, r: {}", len, r);

    // I think the salt needs to be the same length as the output of SHA512
    assert_eq!(salt.len(), Hash512::DigestSize as usize / 8);

    let mut master_key = vec![0u8; mk.len()];

    for i in 1 .. len {
        // T needs to be 512 bits wide
        let mut T = vec![0u64; 8];
        let mut i_bytes = [0u8; 4];
        BigEndian::write_u32(&mut i_bytes, i);

        // U = salt || Int(i)
        let U = [salt, &i_bytes].concat();
        println!("U is {:?}", U);

        for j in 1 .. ITERATION_COUNT {
            let mac = hmac_sha512(password, &U);
            println!("mac is {:?}", mac);
            for (i, hash) in mac.iter().enumerate() {
                T[i] ^= hash;
            }
            println!("T is {:?}", T);
        }
        // convert T to u8
        let mut t_bytes = vec![0u8; (T.len() * 8) as usize];
        BigEndian::write_u64_into(&T, &mut t_bytes);

        master_key.extend(&t_bytes);    // [0..r];
        println!("master_key is {:?}", master_key);
    }
    mk.clone_from_slice(&master_key[0..r/8]);
    println!("mk is {:?}", mk);
}

fn main() {
    println!("Welcome to the PBKDF2 implementation in Rust!");

    let password = vec![0xa; 16];
    let salt = vec![0x0; 64];
    let key_length: u32 = 1024;
    let mut mk = vec![0u8; (key_length / 8) as usize];

    // generate the master key
    pbkdf(&password, &salt, key_length, &mut mk);
    println!("{:?}", mk);
}
