use anyhow::{anyhow, Result};
use reqwest::Client;

use super::models::{ProgramData, ProgramList, ScopeData, ScopeList};

#[derive(Clone)]
pub struct H1Client {
    client: Client,
    username: String,
    api_token: String,
    base_url: String,
}

impl H1Client {
    pub fn new(username: &str, api_token: &str) -> Self {
        Self {
            client: Client::new(),
            username: username.to_string(),
            api_token: api_token.to_string(),
            base_url: "https://api.hackerone.com".to_string(),
        }
    }

    pub fn new_with_base_url(username: &str, api_token: &str, base_url: &str) -> Self {
        Self {
            client: Client::new(),
            username: username.to_string(),
            api_token: api_token.to_string(),
            base_url: base_url.to_string(),
        }
    }

    pub async fn fetch_all_programs(&self) -> Result<Vec<ProgramData>> {
        let mut all_programs = Vec::new();
        let mut url = format!("{}/v1/hackers/programs", self.base_url);

        loop {
            let response = self.get_with_retry(&url).await?;
            let program_list: ProgramList = response;
            all_programs.extend(program_list.data);

            match program_list.links.and_then(|l| l.next) {
                Some(next_url) => url = next_url,
                None => break,
            }
        }

        Ok(all_programs)
    }

    pub async fn fetch_scopes(&self, handle: &str) -> Result<Vec<ScopeData>> {
        let mut all_scopes = Vec::new();
        let mut url = format!(
            "{}/v1/hackers/programs/{}/structured_scopes",
            self.base_url, handle
        );

        loop {
            let response = self.get_with_retry(&url).await?;
            let scope_list: ScopeList = response;
            all_scopes.extend(scope_list.data);

            match scope_list.links.and_then(|l| l.next) {
                Some(next_url) => url = next_url,
                None => break,
            }
        }

        Ok(all_scopes)
    }

    async fn get_with_retry<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let max_retries = 5;

        for attempt in 0..=max_retries {
            let resp = self
                .client
                .get(url)
                .basic_auth(&self.username, Some(&self.api_token))
                .send()
                .await?;

            let status = resp.status();

            if status == 429 {
                if attempt < max_retries {
                    // Exponential backoff: 2s, 4s, 8s, 16s, 32s
                    let delay = std::time::Duration::from_secs(2u64.pow(attempt as u32));
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(anyhow!("Rate limited after {} retries", max_retries));
            }

            if status == 401 {
                return Err(anyhow!("Authentication failed (401)"));
            }

            if !status.is_success() {
                return Err(anyhow!("HTTP error: {}", status));
            }

            let body = resp.json::<T>().await?;
            return Ok(body);
        }

        Err(anyhow!("Max retries exceeded"))
    }
}
