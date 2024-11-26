use failure::Error;
use std::io::Read;

use crate::config::Config;

#[derive(Serialize, Deserialize)]
pub struct LegacyConfig {
    public: PublicKey,
    secret: SecretKey,
}

impl LegacyConfig {
    pub fn convert(file: &mut impl Read) -> Result<(Config, [u8; 32]), Error> {
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;
        let config: LegacyConfig = toml::from_slice(&buf)?;
        Ok((
            Config::create(
                config.public.key,
                config.public.userid,
                config.public.timestamp,
            )?,
            config.secret.secret()?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct PublicKey {
    pub key: String,
    pub userid: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize)]
struct SecretKey {
    key: Option<String>,
    program: Option<String>,
}

impl SecretKey {
    pub fn secret(&self) -> Result<[u8; 32], Error> {
        if let Some(key) = &self.key {
            to_32_bytes(key)
        } else if let Some(_program) = &self.program {
            bail!("unsupported program configuration")
        } else {
            bail!("no secret key found")
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
