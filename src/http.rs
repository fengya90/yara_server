use reqwest::Client;

/// Download content from a URL and return the response body as bytes.
pub async fn download_url_to_bytes(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response = Client::new()
        .get(url)
        .send()
        .await?
        .error_for_status()?; // This returns error for non-2xx responses

    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}
