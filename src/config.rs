use std::io::{Read, Write};

use failure::Error;

use crate::key_data::KeyData;

use crate::keychain::get_keychain_item;
use crate::keychain::add_keychain_item;

#[derive(Serialize, Deserialize)]
pub struct Config {
    public: PublicKey,
    secret: SecretKey,
}

impl Config {
    pub fn create(key_data: &KeyData) -> Result<Config, Error> {
        let keypair = key_data.keypair();
        let userid = key_data.user_id().to_owned();
        let timestamp = key_data.timestamp();
        Ok(Config {
            public: PublicKey {
                key: hex::encode(keypair.verifying_key().as_bytes()),
                userid,
                timestamp,
            },
            secret: SecretKey {
                key: Some(hex::encode(keypair.as_bytes())),
                program: None,
            },
        })
    }

    pub fn load(file: &mut impl Read) -> Result<Config, Error> {
        let service: &str = "xyz.tea.BASE.bpb";
        let account: &str = "example_account";
        let str = get_keychain_item(service, account).unwrap();
        Ok(toml::from_str(&str)?)
    }

    pub fn write(&self, file: &mut impl Write) -> Result<(), Error> {
        let secret = toml::to_string(self)?;
        let service = "xyz.tea.BASE.bpb";
        let account = "example_account"; //self.user_id();
        add_keychain_item(service, account, &secret)
    }

    pub fn timestamp(&self) -> u64 {
        self.public.timestamp
    }

    pub fn user_id(&self) -> &str {
        &self.public.userid
    }

    pub fn secret(&self) -> Result<[u8; 32], Error> {
        self.secret.secret()
    }
}

#[derive(Serialize, Deserialize)]
struct PublicKey {
    key: String,
    userid: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize)]
struct SecretKey {
    key: Option<String>,
    program: Option<String>,
}

impl SecretKey {
    fn secret(&self) -> Result<[u8; 32], Error> {
      if let Some(key) = &self.key {
        to_32_bytes(key)
      } else {
          bail!("No secret key or program specified")
      }
    }
}

fn to_32_bytes(slice: &String) -> Result<[u8; 32], Error> {
    let vector = hex::decode(slice)?;
    let mut array = [0u8; 32];
    let len = std::cmp::min(vector.len(), 32);
    array[..len].copy_from_slice(&vector[..len]);
    Ok(array)
}
