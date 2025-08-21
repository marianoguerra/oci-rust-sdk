use crate::config::AuthConfig;
use crate::{Error, Result};
use base64::prelude::*;
use chrono::{DateTime, Utc};
use reqwest::header::HeaderMap;
use reqwest::{Method, RequestBuilder, Response};
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

fn setup_headers(
    config: &AuthConfig,
    method: &Method,
    host: &str,
    path: &str,
    date: DateTime<Utc>,
    headers: &mut HeaderMap,
    body: Option<&str>,
) -> Result<()> {
    let date_value = date.to_rfc2822().replace("+0000", "GMT");
    headers.insert(
        "date",
        date_value
            .parse()
            .map_err(|e| Error::InvalidHeaderValueFormat(format!("date: {}", e)))?,
    );
    let mut body_data = "".to_string();
    let mut body_headers_auth = "".to_string();
    if let Some(body_content) = body.as_ref() {
        let x_content_sha256 = encode_body(body_content);
        headers.insert(
            "x-content-sha256",
            x_content_sha256
                .parse()
                .map_err(|e| Error::InvalidHeaderValueFormat(format!("x-content-sha256: {}", e)))?,
        );
        let content_length_value = body_content.len().to_string();
        headers.insert(
            "content-length",
            content_length_value
                .parse()
                .map_err(|e| Error::InvalidHeaderValueFormat(format!("content-length: {}", e)))?,
        );
        headers.insert(
            "content-type",
            String::from("application/json")
                .parse()
                .map_err(|e| Error::InvalidHeaderValueFormat(format!("content-type: {}", e)))?,
        );

        body_data = format!(
            "\nx-content-sha256: {x_content_sha256}\ncontent-length: {content_length_value}\ncontent-type: application/json"
        );
        body_headers_auth = " x-content-sha256 content-length content-type".into();
    }

    let method_name = method.to_string().to_lowercase();
    let data = format!(
        "date: {date_value}\n(request-target): {method_name} {path}\nhost: {host}{body_data}"
    );
    let headers_auth = format!("date (request-target) host{body_headers_auth}");

    let signing_key = SigningKey::<Sha256>::new(config.keypair.clone());
    let mut rng = rand::thread_rng();
    let signature: Signature = signing_key.sign_with_rng(&mut rng, data.as_bytes());
    let b64 = BASE64_STANDARD.encode(signature.to_bytes().as_ref());
    let key_id = format!("{}/{}/{}", config.tenancy, config.user, config.fingerprint);
    let authorization = format!(
        "Signature algorithm=\"rsa-sha256\",headers=\"{headers_auth}\",keyId=\"{key_id}\",signature=\"{b64}\",version=\"1\""
    );

    headers.insert(
        "authorization",
        authorization
            .parse()
            .map_err(|_| Error::HeaderTypeMismatch("authorization".to_string()))?,
    );

    Ok(())
}

fn build_request(
    client: &reqwest::Client,
    method: Method,
    secure: bool,
    host: &str,
    path: &str,
    headers: HeaderMap,
    body: Option<String>,
) -> RequestBuilder {
    let scheme = if secure { "https" } else { "http" };
    let path_no_leading_slash = path.strip_prefix('/').unwrap_or(path);
    let url = format!("{scheme}://{host}/{path_no_leading_slash}");
    let base_request = client.request(method, url).headers(headers);

    if let Some(body_content) = body {
        base_request.body(body_content)
    } else {
        base_request
    }
}

pub async fn json_request(
    config: &AuthConfig,
    method: Method,
    secure: bool,
    host: &str,
    path: &str,
    mut headers: HeaderMap,
    body: Option<String>,
    date: DateTime<Utc>,
) -> Result<Response> {
    let client = reqwest::Client::new();
    setup_headers(
        config,
        &method,
        host,
        path,
        date,
        &mut headers,
        body.as_deref(),
    )?;
    let request = build_request(&client, method, secure, host, path, headers, body);
    let response = request.send().await?;
    Ok(response)
}

pub async fn post_raw_json(
    config: &AuthConfig,
    secure: bool,
    host: &str,
    path: &str,
    headers: HeaderMap,
    body: Option<String>,
) -> Result<Response> {
    let now: DateTime<Utc> = Utc::now();
    json_request(config, Method::POST, secure, host, path, headers, body, now).await
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
