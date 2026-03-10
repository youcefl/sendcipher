/* Created on 2025.12.03 */
/* Copyright Youcef Lemsafer, all rights reserved */

use ureq::http::StatusCode;

use crate::error::Error;
use chrono::{DateTime, Utc};
use core::time;
use sendcipher_common::*;
use std::time::Duration;

#[derive(Clone)]
pub(crate) struct Server {
    /// URL of the server
    url: String,
    agent: ureq::Agent,
    /// URL of ping
    ping_url: String,
    /// URL of the start_upload API
    start_upload_url: String,
    /// URL of the upload API
    upload_url: String,
    /// URL of the upload commit API
    commit_upload_url: String,
    /// URL of download API
    download_url: String,
}

impl Server {
    /// Constructs an instance given the URL of the server
    pub fn new(url: String, timeout: std::time::Duration) -> Self {
        let clean_url = url.trim_end_matches('/').to_string();
        let agent = ureq::Agent::config_builder()
            //.timeout_global(Some(timeout))
            .timeout_connect(Some(Duration::from_secs(10)))
            .max_idle_connections_per_host(32)
            .build()
            .into();
        Self {
            url: clean_url.clone(),
            agent,
            ping_url: clean_url.clone() + "/ping",
            start_upload_url: clean_url.clone() + "/api/start_upload",
            upload_url: clean_url.clone() + "/api/upload",
            commit_upload_url: clean_url.clone() + "/api/commit_upload",
            download_url: clean_url.clone() + "/api/download",
        }
    }

    /// Uses 'GET /ping' to see whether server is alive and well
    pub fn ping(&self) -> Result<(), Error> {
        let result = self.agent.get(&self.ping_url).call();
        if result.is_err() {
            return Err(Error::ServerError(result.unwrap_err().to_string()));
        }
        let response = result.unwrap();
        if response.status() != StatusCode::OK {
            return Err(Error::ServerError(format!("error {}", response.status())));
        }
        Ok(())
    }

    ///
    pub fn start_upload(&self, token: &str, file_size: u64) -> Result<String, Error> {
        let req_body = StartUploadRequest {
            size_in_bytes: file_size,
        };
        let body = serde_json::to_vec(&req_body)?;
        let resp = self.agent.post(&self.start_upload_url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .content_type("application/json")
            .send(&body).map_err(|e| Error::ServerError(e.to_string()))?
            .into_body()
            .read_to_vec().map_err(|e| Error::ServerError(e.to_string()))?;
        let response: ResponseToStartUploadReq = serde_json::from_slice(&resp)?;
        if !response.success {
            return Err(Error::ServerError(response.message));
        }
        Ok(response.session_id.ok_or(Error::MissingUploadSessionId(
            "Server did not return an upload session id".to_string(),
        ))?)
    }

    pub fn upload(&self, token: &str, session_id: &str, bytes: &[u8]) -> Result<String, Error> {
        let upload_url = self.upload_url.clone() + "/" + session_id;

        let req = http::Request::builder()
            .method("POST")
            .uri(upload_url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", format!("Bearer {}", token))
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

        let json: UploadResponse = serde_json::from_str(&body_string)
            .map_err(|e| Error::ServerError(format!("JSON parsing failed: {}", e.to_string())))?;
        Ok(json.id)
    }

    pub fn commit_upload(
        &self,
        token: &str,
        upload_session_id: &str,
        file_size: u64,
        chunk_ids: Vec<String>,
        manifest_id: &str,
    ) -> Result<DateTime<Utc>, Error> {
        let post_upload_info = PostUploadInfo {
            size_in_bytes: file_size,
            upload_session_id: upload_session_id.to_string(),
            expiration_time_hours: 7 * 24,
            chunks: chunk_ids,
            manifest: manifest_id.to_string(),
        };
        let body = serde_json::to_vec(&post_upload_info)?;

        let resp = self.agent.post(self.commit_upload_url.clone())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .send(body).map_err(|e| Error::ServerError(e.to_string()))?
            .into_body()
            .read_to_vec().map_err(|e| Error::ServerError(e.to_string()))?;
        
        let response: UploadCommitResponse = serde_json::from_slice(&resp)?;
        if response.success {
            return Ok(response.expiration_date);
        }
        Err(Error::ServerError(
            format!(
                "Error committing upload for file {}: {}",
                manifest_id, response.message
            )
            .to_string(),
        ))
    }

    pub fn download(&self, id: &String) -> Result<Vec<u8>, Error> {
        let download_url = self.download_url.clone() + "/" + id;

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
