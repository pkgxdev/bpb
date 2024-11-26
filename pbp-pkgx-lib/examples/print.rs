extern crate ed25519_dalek as dalek;
extern crate pbp_pkgx;
extern crate rand;
extern crate sha2;

use dalek::SigningKey;
use pbp_pkgx::{KeyFlags, PgpKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};

fn main() {
    let mut cspring = [0u8; 32];
    OsRng.fill_bytes(&mut cspring);
    let keypair = SigningKey::from_bytes(&mut cspring);

    let key = PgpKey::from_dalek::<Sha256, Sha512>(&keypair, KeyFlags::NONE, 0, "withoutboats");
    println!("{}", key);
}
