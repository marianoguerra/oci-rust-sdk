use crate::{Error, Result};
use configparser::ini::Ini;
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use std::fs;

pub struct AuthConfig {
    pub user: String,
    pub fingerprint: String,
    pub tenancy: String,
    pub region: String,
    pub keypair: RsaPrivateKey,
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

        let keypair = if passphrase.is_empty() {
            // No passphrase - try PKCS#8 first, then PKCS#1
            if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(&key) {
                key
            } else {
                RsaPrivateKey::from_pkcs1_pem(&key).map_err(Error::Pkcs1)?
            }
        } else {
            // With passphrase - try encrypted PKCS#8 first, then PKCS#1
            if let Ok(key) = RsaPrivateKey::from_pkcs8_encrypted_pem(&key, passphrase.as_bytes()) {
                key
            } else {
                RsaPrivateKey::from_pkcs1_pem(&key).map_err(Error::Pkcs1)?
            }
        };

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
