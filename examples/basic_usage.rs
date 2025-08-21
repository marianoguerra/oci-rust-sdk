use oci_sdk::{Result, base_client::json_request, config::AuthConfig};
use reqwest::{Method, header::HeaderMap};

#[tokio::main]
async fn main() -> Result<()> {
    let auth_config = AuthConfig::from_file(
        Some("~/.oci/config".to_string()),
        Some("DEFAULT".to_string()),
    )?;
    let host = format!(
        "identity.{region}.oci.oraclecloud.com",
        region = &auth_config.region
    );
    let path = format!("/20160918/users/{user}", user = &auth_config.user);
    let headers = HeaderMap::new();
    let now = chrono::Utc::now();
    let response = json_request(
        &auth_config,
        Method::GET,
        true,
        &host,
        &path,
        headers,
        None,
        now,
    )
    .await?;
    let body = response.text().await?;

    println!("{}", body);
    // {
    //     "compartment_id": "ocid1.tenancy.oc1...",
    //     "description": "Test user",
    //     "id": "ocid1.user.oc1...",
    //     "inactive_status": null,
    //     "lifecycle_state": "ACTIVE",
    //     "name": "test-user@corp.com",
    //     "time_created": "2016-08-30T23:46:44.680000+00:00"
    // }
    //

    Ok(())
}
