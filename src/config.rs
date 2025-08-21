use crate::{Error, Result};
use configparser::ini::Ini;
use expanduser::expanduser;
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use std::fs;
/// Expands tilde (~) in file paths to the user's home directory
fn expand_tilde_in_path(path: &str) -> String {
    expanduser(path)
        .unwrap_or_else(|_| path.into())
        .to_string_lossy()
        .to_string()
}

/// Cleans PEM content by removing any content after the END boundary
fn clean_pem_content(pem_content: &str) -> String {
    let lines: Vec<&str> = pem_content.lines().collect();
    let mut cleaned_lines = Vec::new();
    let mut inside_pem = false;

    for line in lines {
        if line.starts_with("-----BEGIN") {
            inside_pem = true;
            cleaned_lines.push(line);
        } else if line.starts_with("-----END") && inside_pem {
            cleaned_lines.push(line);
            break; // Stop processing after the first END boundary
        } else if inside_pem {
            cleaned_lines.push(line);
        }
    }

    cleaned_lines.join("\n")
}

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
        let expanded_key_file = expand_tilde_in_path(&key_file);
        let key_content = fs::read_to_string(&expanded_key_file)
            .map_err(|_| Error::FileNotFound(key_file.clone()))?;
        let key = clean_pem_content(&key_content);

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
        config_path: Option<String>,
        provided_profile_name: Option<String>,
    ) -> Result<AuthConfig> {
        let profile_name = provided_profile_name.unwrap_or("DEFAULT".to_string());
        let file_path =
            expand_tilde_in_path(&config_path.unwrap_or_else(|| "~/.oci/config".to_string()));

        let config_content =
            fs::read_to_string(&file_path).map_err(|_| Error::FileNotFound(file_path.clone()))?;

        let mut config = Ini::new();
        config
            .read(config_content)
            .map_err(|_| Error::BadConfigFile(file_path.clone()))?;

        let key_file = config
            .get(&profile_name, "key_file")
            .ok_or_else(|| Error::ConfigFieldNotFound("key_file".to_string()))?;

        AuthConfig::new(
            config
                .get(&profile_name, "user")
                .ok_or_else(|| Error::ConfigFieldNotFound("user".to_string()))?,
            expand_tilde_in_path(&key_file),
            config
                .get(&profile_name, "fingerprint")
                .ok_or_else(|| Error::ConfigFieldNotFound("fingerprint".to_string()))?,
            config
                .get(&profile_name, "tenancy")
                .ok_or_else(|| Error::ConfigFieldNotFound("tenancy".to_string()))?,
            config
                .get(&profile_name, "region")
                .ok_or_else(|| Error::ConfigFieldNotFound("region".to_string()))?,
            config
                .get(&profile_name, "passphrase")
                .unwrap_or("".to_string()),
        )
    }
}
