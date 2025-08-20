use crate::{Error, Result};
use configparser::ini::Ini;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use std::fs;

pub struct AuthConfig {
    pub user: String,
    pub fingerprint: String,
    pub tenancy: String,
    pub region: String,
    pub keypair: PKey<Private>,
}

impl AuthConfig {
    pub fn new(
        user: String,
        key_file: String,
        fingerprint: String,
        tenancy: String,
        region: String,
        passphrase: String,
    ) -> Result<AuthConfig> {
        let key =
            fs::read_to_string(&key_file).map_err(|_| Error::FileNotFound(key_file.clone()))?;

        let keypair = Rsa::private_key_from_pem_passphrase(key.as_bytes(), passphrase.as_bytes())
            .map_err(Error::Signing)?;
        let keypair = PKey::from_rsa(keypair).map_err(Error::Signing)?;

        Ok(AuthConfig {
            user,
            fingerprint,
            tenancy,
            region,
            keypair,
        })
    }

    pub fn from_file(
        file_path: Option<String>,
        profile_name: Option<String>,
    ) -> Result<AuthConfig> {
        let pn = profile_name.unwrap_or("DEFAULT".to_string());

        let fp = if let Some(path) = file_path {
            path
        } else {
            let home_dir_path = home::home_dir().ok_or(Error::BadHomeDir)?;

            format!(
                "{}/.oci/config",
                home_dir_path.to_str().ok_or(Error::BadHomeDir)?
            )
        };

        let config_content =
            fs::read_to_string(&fp).map_err(|_| Error::FileNotFound(fp.clone()))?;

        let mut config = Ini::new();
        config
            .read(config_content)
            .map_err(|_| Error::BadConfigFile(fp.clone()))?;

        AuthConfig::new(
            config
                .get(&pn, "user")
                .ok_or_else(|| Error::ConfigFieldNotFound("user".to_string()))?,
            config
                .get(&pn, "key_file")
                .ok_or_else(|| Error::ConfigFieldNotFound("key_file".to_string()))?,
            config
                .get(&pn, "fingerprint")
                .ok_or_else(|| Error::ConfigFieldNotFound("fingerprint".to_string()))?,
            config
                .get(&pn, "tenancy")
                .ok_or_else(|| Error::ConfigFieldNotFound("tenancy".to_string()))?,
            config
                .get(&pn, "region")
                .ok_or_else(|| Error::ConfigFieldNotFound("region".to_string()))?,
            config.get(&pn, "passphrase").unwrap_or("".to_string()),
        )
    }
}
