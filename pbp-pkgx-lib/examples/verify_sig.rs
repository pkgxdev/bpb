extern crate pbp_pkgx;
extern crate sha2;

use std::env;
use std::fs;
use std::path::PathBuf;

use pbp_pkgx::{PgpKey, PgpSig};
use sha2::{Sha256, Sha512};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let props = root.join("examples").join("props");

    let sig: String = fs::read_to_string(props.join("sig.txt")).unwrap();
    let key: String = fs::read_to_string(props.join("key.txt")).unwrap();
    let data: String = fs::read_to_string(props.join("data.txt")).unwrap();

    let sig = PgpSig::from_ascii_armor(&sig).unwrap();
    let key = PgpKey::from_ascii_armor(&key).unwrap();

    if sig.verify_dalek::<Sha256, Sha512>(data.as_bytes().into(), &key.to_dalek().unwrap()) {
        println!("Verified signature.");
    } else {
        println!("Could not verify signature.");
    }
}
