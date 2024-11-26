#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;

mod config;
mod key_data;
mod keychain;
mod tests;

use std::time::SystemTime;
use std::fs;

use ed25519_dalek as ed25519;
use failure::Error;
use keychain::add_keychain_item;
use rand::RngCore;

use crate::config::Config;
use crate::key_data::KeyData;

fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    match args.next().as_ref().map(|s| &s[..]) {
        Some("init") => {
            if let Some(userid) = args.next() {
                generate_keypair(userid)
            } else {
                bail!("Must specify a userid argument, e.g.: `bpb init \"username <email>\"`")
            }
        }
        Some("upgrade") => upgrade(),
        Some("print") => print_public_key(),
        Some("--help") => print_help_message(),
        Some(arg) if gpg_sign_arg(arg) => verify_commit(),
        _ => {
            if args.any(|arg| gpg_sign_arg(&arg)) {
                verify_commit()
            } else {
                delegate()
            }
        }
    }
}

fn gpg_sign_arg(arg: &str) -> bool {
    arg == "--sign" || (arg.starts_with("-") && !arg.starts_with("--") && arg.contains("s"))
}

fn print_help_message() -> Result<(), Error> {
    println!("bpb: boats's personal barricade\n");
    println!("This is a program for signing your git commits.\n");
    println!("Arguments:");
    println!("    init <userid>:    (Re)initialize bpb, generate a new keypair.");
    println!("    print:            Print the current bpb public key, in OpenPGP format.\n");
    println!("See https://github.com/withoutboats/bpb for more information.");
    Ok(())
}

fn generate_keypair(userid: String) -> Result<(), Error> {
    let keys_file = keys_file();
    if std::fs::metadata(&keys_file).is_ok() {
        eprintln!(
            "A bpb_keys.toml already exists. If you want to reinitialize your state\n\
                   delete the file at `{}` first",
            keys_file
        );
        return Ok(());
    }
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let mut rng = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut rng[0..32]);
    let keypair = ed25519::SigningKey::from_bytes(&rng);
    let key_data = KeyData::create(keypair, userid, timestamp);
    let config = Config::create(&key_data)?;

    config.write()?;
    println!("{}", key_data.public());
    Ok(())
}

fn print_public_key() -> Result<(), Error> {
    let config = Config::load()?;
    let keypair = KeyData::load(&config)?;
    println!("{}", keypair.public());
    Ok(())
}

fn verify_commit() -> Result<(), Error> {
    use std::io::Read;

    let mut commit = String::new();
    let mut stdin = std::io::stdin();
    stdin.read_to_string(&mut commit)?;

    let config = Config::load()?;
    let keypair = KeyData::load(&config)?;

    let sig = keypair.sign(commit.as_bytes())?;

    eprintln!("\n[GNUPG:] SIG_CREATED ");
    println!("{}", sig);
    Ok(())
}

fn delegate() -> ! {
    use std::process;

    let mut cmd = process::Command::new("gpg");
    cmd.args(std::env::args().skip(1));
    let status = cmd.status().unwrap().code().unwrap();
    process::exit(status)
}

fn upgrade() -> Result<(), Error> {
  let mut file = std::fs::File::open(keys_file())?;
  let config = Config::legacy_load(&mut file)?;
  config.write()?;
  fs::remove_file(keys_file()).map_err(|e| failure::err_msg(e.to_string()))
}

fn keys_file() -> String {
    std::env::var("BPB_KEYS")
        .unwrap_or_else(|_| format!("{}/.bpb_keys.toml", std::env::var("HOME").unwrap()))
}
