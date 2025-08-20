use crate::config::AuthConfig;
use crate::{Error, Result};
use base64::prelude::*;
use reqwest::header::HeaderMap;
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::signature::RandomizedSigner;
use sha2::{Digest, Sha256};
use signature::SignatureEncoding;

pub fn encode_body(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let result = hasher.finalize();

    BASE64_STANDARD.encode(result)
}

pub fn oci_signer(
    config: &AuthConfig,
    headers: &mut HeaderMap,
    method: String,
    path: &str,
    host: &str,
) -> Result<()> {
    let date = headers
        .get("date")
        .ok_or_else(|| Error::HeaderNotFound("date".to_string()))?;
    let date = date
        .to_str()
        .map_err(|_| Error::HeaderTypeMismatch("date".to_string()))?;

    let host = host.replace("http://", "").replace("https://", "");

    let mut data = format!(
        "date: {}\n(request-target): {} {}\nhost: {}",
        date, method, path, host
    );

    let mut headers_auth = String::from("date (request-target) host");

    if headers.contains_key("content-length") {
        let content_length = headers
            .get("content-length")
            .ok_or_else(|| Error::HeaderNotFound("content-length".to_string()))?;
        let content_length = content_length
            .to_str()
            .map_err(|_| Error::HeaderTypeMismatch("content-length".to_string()))?;
        data = format!("{}\ncontent-length: {}", data, content_length);
        headers_auth = format!("{} content-length", headers_auth)
    }

    if headers.contains_key("content-type") {
        let content_type = headers
            .get("content-type")
            .ok_or_else(|| Error::HeaderNotFound("content-type".to_string()))?;
        let content_type = content_type
            .to_str()
            .map_err(|_| Error::HeaderTypeMismatch("content-type".to_string()))?;
        data = format!("{}\ncontent-type: {}", data, content_type);
        headers_auth = format!("{} content-type", headers_auth);
    }

    if headers.contains_key("x-content-sha256") {
        let content_sha256 = headers
            .get("x-content-sha256")
            .ok_or_else(|| Error::HeaderNotFound("x-content-sha256".to_string()))?;
        let content_sha256 = content_sha256
            .to_str()
            .map_err(|_| Error::HeaderTypeMismatch("x-content-sha256".to_string()))?;
        data = format!("{}\nx-content-sha256: {}", data, content_sha256);
        headers_auth = format!("{} x-content-sha256", headers_auth);
    }

    let signing_key = SigningKey::<Sha256>::new(config.keypair.clone());
    let mut rng = rand::thread_rng();
    let signature: Signature = signing_key.sign_with_rng(&mut rng, data.as_bytes());
    let b64 = BASE64_STANDARD.encode(signature.to_bytes().as_ref());
    let key_id = format!("{}/{}/{}", config.tenancy, config.user, config.fingerprint);
    let authorization = format!(
        "Signature algorithm=\"rsa-sha256\",headers=\"{}\",keyId=\"{}\",signature=\"{}\",version=\"1\"",
        headers_auth, key_id, b64
    );

    headers.insert(
        "authorization",
        authorization
            .parse()
            .map_err(|_| Error::HeaderTypeMismatch("authorization".to_string()))?,
    );
    Ok(())
}
