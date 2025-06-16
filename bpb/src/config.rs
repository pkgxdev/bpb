use std::io::{Read, Write};

use failure::Error;
use lazy_static::lazy_static;

lazy_static! {
    static ref SERVICE_NAME: String = option_env!("BPB_SERVICE_NAME")
        .unwrap_or("xyz.tea.BASE.bpb")
        .to_string();
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    public: PublicKey,
}

impl Config {
    pub fn create(public_key: String, user_id: String, timestamp: u64) -> Result<Config, Error> {
        let userid = user_id.to_owned();
        let key = public_key;
        Ok(Config {
            public: PublicKey {
                key,
                userid,
                timestamp,
            },
        })
    }

    pub fn load() -> Result<Config, Error> {
        let mut file = std::fs::File::open(keys_file())?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;
        Ok(toml::from_slice(&buf)?)
    }

    pub fn write(&self) -> Result<(), Error> {
        let path = keys_file();
        std::fs::create_dir_all(path.parent().unwrap())?;
        let mut file = std::fs::File::create(path)?;
        Ok(file.write_all(&toml::to_vec(self)?)?)
    }

    pub fn timestamp(&self) -> u64 {
        self.public.timestamp
    }

    pub fn user_id(&self) -> &str {
        &self.public.userid
    }

    pub fn service(&self) -> &str {
        &SERVICE_NAME
    }
}

#[derive(Serialize, Deserialize)]
struct PublicKey {
    key: String,
    userid: String,
    timestamp: u64,
}

pub fn keys_file() -> std::path::PathBuf {
    // for archaic reasons we first check the config path
    // however this is an error, we shouldn’t store this as config seeing as it is
    // tied to the private key which is likely a host setting and should not thus be
    // synced between machines

    let config_path = if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        std::path::PathBuf::from(config_home).join("pkgx/bpb.toml")
    } else {
        std::path::PathBuf::from(std::env::var("HOME").unwrap()).join(".config/pkgx/bpb.toml")
    };

    if config_path.exists() {
        config_path
    } else if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(data_home).join("pkgx/bpb.toml")
    } else {
        std::path::PathBuf::from(std::env::var("HOME").unwrap()).join(".local/share/pkgx/bpb.toml")
    }
}
