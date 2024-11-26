use std::io::{Read, Write};

use failure::Error;

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
}

#[derive(Serialize, Deserialize)]
struct PublicKey {
    key: String,
    userid: String,
    timestamp: u64,
}

fn keys_file() -> std::path::PathBuf {
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        std::path::PathBuf::from(config_home).join("pkgx/bpb.toml")
    } else {
        std::path::PathBuf::from(std::env::var("HOME").unwrap()).join(".config/pkgx/bpb.toml")
    }
}
