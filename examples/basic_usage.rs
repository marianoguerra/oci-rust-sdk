use oci_sdk::{Result, config::AuthConfig, identity::Identity};

#[tokio::main]
async fn main() -> Result<()> {
    // Set up auth config
    let auth_config = AuthConfig::from_file(
        Some("~/.oci/config".to_string()),
        Some("DEFAULT".to_string()),
    )?;
    // Create a service client
    let identity = Identity::new(auth_config, None);
    //# Get the current user
    let response = identity.get_current_user().await?;
    // parse information
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

    Ok(())
}
