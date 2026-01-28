/* Created on 2025.12.03 */
/* Copyright Youcef Lemsafer, all rights reserved */

use ureq::{RequestBuilder, http::StatusCode};

use crate::error::Error;
use core::time;
use std::time::Duration;

#[derive(Clone)]
pub(crate) struct Server {
    /// Url of the server
    url: String,
    agent: ureq::Agent,
}

impl Server {
    /// Constructs an instance given the URL of the server
    pub fn new(url: String, timeout: std::time::Duration) -> Self {
        let agent = ureq::Agent::config_builder()
            //.timeout_global(Some(timeout))
            .timeout_connect(Some(Duration::from_secs(10)))
            .max_idle_connections_per_host(32)
            .build()
            .into();
        Self { url, agent }
    }

    /// Uses 'GET /ping' to see whether server is alive and well
    pub fn ping(&self) -> Result<(), Error> {
        let mut ping_url = self.url.clone();
        ping_url.push_str("/ping");
        let result = self.agent.get(ping_url).call();
        if result.is_err() {
            return Err(Error::ServerError(result.unwrap_err().to_string()));
        }
        let response = result.unwrap();
        if response.status() != StatusCode::OK {
            return Err(Error::ServerError(format!("error {}", response.status())));
        }
        Ok(())
    }

    pub fn upload(&self, bytes: &[u8]) -> Result<String, Error> {
        let mut upload_url = self.url.clone();
        upload_url.push_str("/api/upload");

        let req = http::Request::builder()
            .method("POST")
            .uri(upload_url)
            .header("Content-Type", "application/octet-stream")
            .body(bytes)
            .map_err(|e| Error::ServerError(e.to_string()))?;

        let response = self
            .agent
            .run(req)
            .map_err(|e| Error::ServerError(e.to_string()))?;
        let body_string = response
            .into_body()
            .read_to_string()
            .map_err(|e| Error::ServerError(e.to_string()))?;

        #[derive(serde::Deserialize)]
        struct Response {
            id: String,
        };

        let json: Response = serde_json::from_str(&body_string)
            .map_err(|e| Error::ServerError(format!("JSON parsing failed: {}", e.to_string())))?;
        Ok(json.id)
    }

    pub fn download(&self, id: &String) -> Result<Vec<u8>, Error> {
        let mut download_url = self.url.clone();
        download_url.push_str(&format!("/api/download/{}", id));

        let req = http::Request::builder()
            .method("GET")
            .uri(download_url)
            .body(())
            .map_err(|e| Error::ServerError(e.to_string()))?;

        let response = self
            .agent
            .run(req)
            .map_err(|e| Error::ServerError(e.to_string()))?;
        response
            .into_body()
            .with_config()
            .limit(512 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| Error::ServerError(e.to_string()))
    }
}
