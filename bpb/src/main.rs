#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;

mod config;
mod key_data;
mod keychain;
mod legacy_config;
mod tests;

use ed25519_dalek as ed25519;
use failure::Error;
use keychain::{add_keychain_item, get_keychain_item};
use rand::RngCore;
use std::time::SystemTime;

use crate::config::Config;
use crate::key_data::KeyData;
use crate::legacy_config::LegacyConfig;

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
        Some("import") => import(),
        Some("upgrade") => upgrade(),
        Some("print") => print_public_key(),
        Some("timestamp") => print_timestamp(),
        Some("restore") => {
            // Check for force flag
            let mut force = false;
            let mut remaining_args = Vec::new();

            for arg in args {
                if arg == "-f" || arg == "--force" {
                    force = true;
                } else {
                    remaining_args.push(arg);
                }
            }

            let mut remaining_iter = remaining_args.into_iter();

            if let Some(private_key) = remaining_iter.next() {
                if let Some(user_id) = remaining_iter.next() {
                    let timestamp_str = remaining_iter.next();
                    let timestamp = if let Some(ts_str) = timestamp_str {
                        match ts_str.parse::<u64>() {
                            Ok(ts) => Some(ts),
                            Err(_) => {
                                eprintln!("Warning: Invalid timestamp format. Using current time instead.");
                                None
                            }
                        }
                    } else {
                        None
                    };
                    restore_from_private_key(private_key, user_id, timestamp, force)
                } else {
                    bail!("Must specify both a 64-character private key AND a user ID, e.g.: `bpb restore [-f] YOUR_PRIVATE_KEY \"Name <email@example.com>\" [TIMESTAMP]`")
                }
            } else {
                bail!("Must specify a 64-character private key and a user ID, e.g.: `bpb restore [-f] YOUR_PRIVATE_KEY \"Name <email@example.com>\" [TIMESTAMP]`")
            }
        }
        Some("fingerprint") => print_fingerprint(),
        Some("key-id") => print_key_id(),
        Some("sign-hex") => {
            if let Some(hex) = args.next() {
                sign_from_hex(hex)
            } else {
                bail!("Must specify a hex string to sign, e.g.: `bpb sign-hex 1234abcd`")
            }
        }
        Some("--help") => print_help_message(),
        Some(arg) if gpg_sign_arg(arg) => verify_commit(),
        None => {
            print_help_message()?;
            std::process::exit(3)
        }
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
    arg == "--sign" || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('s'))
}

fn print_help_message() -> Result<(), Error> {
    println!("bpb: boats's personal barricade");
    println!();
    println!("A program for signing git commits.");
    println!();
    println!("Arguments:");
    println!("    init <userid>:    Generate a keypair and store in the keychain.");
    println!("    import <key>:     Import a key from the command line.");
    println!("    print:            Print public key in OpenPGP format.");
    println!("    fingerprint:      Print the fingerprint of the public key.");
    println!("    key-id:           Print the key ID of the public key.");
    println!("    sign-hex <hex>:   Sign a hex string and print the signature and public key.");
    println!("    timestamp:        Print the timestamp of the current key.");
    println!("    restore [-f] <key> <userid> [timestamp]:");
    println!("        Restore a key from a 64-character private key.");
    println!("        [timestamp] can be used to generate the same public key format.");
    println!("        Use the -f flag to forcibly override any existing key.");
    println!();
    println!("See https://github.com/pkgxdev/bpb for more information.");
    Ok(())
}

fn generate_keypair(userid: String) -> Result<(), Error> {
    if let Ok(_config) = Config::load() {
        eprintln!(
            "A keypair already exists. If you (really) want to reinitialize your state\n\
                   run `security delete-generic-password -s {}` first.",
            _config.service()
        );
        return Ok(());
    }

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let mut rng = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut rng[0..32]);
    let keypair = ed25519::SigningKey::from_bytes(&rng);

    let public_key = hex::encode(keypair.verifying_key().as_bytes());
    let config = Config::create(public_key, userid, timestamp)?;
    config.write()?;

    let service = config.service();
    let account = config.user_id();
    let hex = hex::encode(keypair.to_bytes());
    add_keychain_item(service, account, &hex)?;

    let keydata = KeyData::load(&config, keypair.to_bytes())?;
    println!("{}", keydata.public());

    Ok(())
}

// Does most of the initial setup
// used for quite a few of the subcommands
//
// - Loads the config
// - Gets the keypair from the keychain
fn get_keypair() -> Result<KeyData, Error> {
    let config = Config::load()?;
    let service = config.service();
    let account = config.user_id();
    let secret_str = get_keychain_item(service, account)?;
    let secret = to_32_bytes(&secret_str)?;

    KeyData::load(&config, secret)
}

fn print_public_key() -> Result<(), Error> {
    let keypair = get_keypair()?;
    println!("{}", keypair.public());
    Ok(())
}

fn get_fingerprint() -> Result<pbp::Fingerprint, Error> {
    let keypair = get_keypair()?;
    Ok(keypair.fingerprint())
}

// Prints the fingerprint (sha256 hash of the public key -- 20 bytes)
fn print_fingerprint() -> Result<(), Error> {
    println!("{}", pretty_print_hex_string(&get_fingerprint()?));
    Ok(())
}

// Prints the long key ID (the last 8 bytes of the fingerprint)
fn print_key_id() -> Result<(), Error> {
    println!("{}", pretty_print_hex_string(&get_fingerprint()?[12..]));
    Ok(())
}

fn verify_commit() -> Result<(), Error> {
    use std::io::Read;

    let mut commit = String::new();
    let mut stdin = std::io::stdin();
    stdin.read_to_string(&mut commit)?;

    let keypair = get_keypair()?;

    let sig = keypair.sign(commit.as_bytes())?;

    eprintln!("\n[GNUPG:] SIG_CREATED ");
    println!("{sig}");
    Ok(())
}

// Signs a hex string and prints the signature
fn sign_from_hex(hex: String) -> Result<(), Error> {
    let keypair = get_keypair()?;
    // remove any leading 0x prefix
    let hex = hex.trim().to_lowercase();
    let hex = hex.trim_start_matches("0x");
    let data = hex::decode(hex)?;

    let signed = keypair.sign(&data)?;
    let signature = hex::encode(signed.as_bytes());

    let public_key = hex::encode_upper(keypair.public().as_bytes());
    println!("signature:\n\n{signature}\n");
    println!("public key:\n\n{public_key}\n");
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
    let mut file = std::fs::File::open(legacy_keys_file())?;
    let (config, secret) = LegacyConfig::convert(&mut file)?;
    let service = config.service();
    let account = config.user_id();
    let hex = hex::encode(secret);
    add_keychain_item(service, account, &hex)?;
    config.write()
}

fn import() -> Result<(), Error> {
    let config = Config::load()?;
    let service = config.service();
    let account = config.user_id();

    if let Some(key) = std::env::args().nth(2) {
        add_keychain_item(service, account, &key)
    } else {
        bail!("Must specify a key to import, e.g.: `bpb import YOUR_PRIVATE_KEY`")
    }
}

fn legacy_keys_file() -> String {
    std::env::var("BPB_KEYS")
        .unwrap_or_else(|_| format!("{}/.bpb_keys.toml", std::env::var("HOME").unwrap()))
}

fn to_32_bytes(slice: &String) -> Result<[u8; 32], Error> {
    let vector = hex::decode(slice)?;
    let mut array = [0u8; 32];
    let len = std::cmp::min(vector.len(), 32);
    array[..len].copy_from_slice(&vector[..len]);
    Ok(array)
}

fn restore_from_private_key(
    private_key: String,
    user_id: String,
    timestamp_opt: Option<u64>,
    force: bool,
) -> Result<(), Error> {
    // Check for existing configuration and handle force flag
    let existing_config = Config::load().ok();

    if let Some(config) = &existing_config {
        if !force {
            let config_path = config::keys_file();
            eprintln!(
                "A keypair already exists. Use -f flag to override or manually perform these steps:\n\n1. Run `security delete-generic-password -s {}`\n2. Delete the config file at `{}`",
                config.service(),
                config_path.display()
            );
            return Ok(());
        } else {
            // Force flag is set, we'll remove existing config and keychain entry
            println!("Force flag set: overriding existing key");

            // 1. Remove keychain entry
            let service = config.service();
            let account = config.user_id();
            println!(
                "Removing existing keychain entry for service: {}, account: {}",
                service, account
            );

            let _ = std::process::Command::new("security")
                .args(["delete-generic-password", "-s", service])
                .output();

            // 2. Delete config file
            let config_path = config::keys_file();
            if config_path.exists() {
                println!("Removing existing config file: {}", config_path.display());
                let _ = std::fs::remove_file(config_path);
            }
        }
    }

    // Trim whitespace and newlines from the private key
    let private_key = private_key.trim();

    // Validate the private key format
    if private_key.len() != 64 {
        bail!(
            "Invalid private key length: expected 64 characters, got {}",
            private_key.len()
        );
    }

    // Try to decode the hex string to get the private key bytes
    let secret_bytes = match hex::decode(private_key) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                bail!(
                    "Invalid private key decoded length: expected 32 bytes, got {}",
                    bytes.len()
                );
            }
            bytes
        }
        Err(_) => bail!("Failed to decode private key. It should be a valid hex string."),
    };

    // Convert to 32-byte array
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    // Create keypair from private key
    let keypair = ed25519::SigningKey::from_bytes(&secret);

    // Get or use provided timestamp
    let timestamp = if let Some(ts) = timestamp_opt {
        println!("Using provided timestamp: {}", ts);
        ts
    } else {
        let current_ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        println!("Using current timestamp: {}", current_ts);
        current_ts
    };

    // Validate user ID
    if user_id.is_empty() {
        bail!("User ID cannot be empty");
    }

    // Get public key from keypair
    let public_key = hex::encode(keypair.verifying_key().as_bytes());

    // Create and save config
    let config = Config::create(public_key, user_id, timestamp)?;
    config.write()?;

    // Store private key in keychain
    let service = config.service();
    let account = config.user_id();
    let hex = hex::encode(keypair.to_bytes());
    add_keychain_item(service, account, &hex)?;

    // Print the public key
    let keydata = KeyData::load(&config, keypair.to_bytes())?;
    println!("Key has been successfully restored.");
    println!("{}", keydata.public());

    Ok(())
}

fn print_timestamp() -> Result<(), Error> {
    // Load the configuration file
    let config = Config::load()?;

    // Get the timestamp
    let timestamp = config.timestamp();

    println!("{}", timestamp);

    Ok(())
}

// iterates over a hex array and prints space-separated groups of four characters
fn pretty_print_hex_string(hex: &[u8]) -> String {
    hex.chunks(2)
        .map(hex::encode_upper)
        .collect::<Vec<String>>()
        .join(" ")
}
