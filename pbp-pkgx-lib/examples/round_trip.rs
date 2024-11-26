extern crate ed25519_dalek as dalek;
extern crate pbp_pkgx;
extern crate rand;
extern crate sha2;

use dalek::{SigningKey, VerifyingKey};
use pbp_pkgx::{KeyFlags, PgpKey, PgpSig, SigType};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};

const DATA: &[u8] = b"How will I ever get out of this labyrinth?";

fn main() {
    let mut cspring = [0u8; 32];
    OsRng.fill_bytes(&mut cspring);
    let keypair = SigningKey::from_bytes(&mut cspring);

    let key = PgpKey::from_dalek::<Sha256, Sha512>(&keypair, KeyFlags::SIGN, 0, "withoutboats");
    let sig = PgpSig::from_dalek::<Sha256, Sha512>(
        &keypair,
        DATA,
        key.fingerprint(),
        SigType::BinaryDocument,
        0,
    );
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(DATA);
    let public_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
    if sig.verify_dalek::<Sha256, Sha512>(&public_key, keypair.verifying_key().into()) {
        println!("Verified successfully.");
    } else {
        println!("Could not verify.");
    }
}
