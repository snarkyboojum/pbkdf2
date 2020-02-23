extern crate hmac_sha;

use hmac_sha::hmac_sha512;

fn pbkdf(password: &[u8], salt: &[u8], kLen: u32, mk: &mut [u8]) {
    println!("Running key derivation function");

}

fn main() {
    println!("Welcome to the PBKDF2 implementation in Rust!");

    let password = vec![0xa; 16];
    let salt = vec![0x0; 16];
    let length: u32 = 512;
    let mut mk = vec![0u8; (length / 8) as usize];

    let mk = pbkdf(&password, &salt, length, &mut mk);
}
