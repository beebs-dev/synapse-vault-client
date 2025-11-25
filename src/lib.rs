use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, io, stream};
use futures_util::{StreamExt, TryStreamExt};
use reqwest::Body;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::Deref, sync::Arc};
use synapse_iam_client::{Client as IamClient, JwtLike};
use tokio::sync::mpsc;
use uuid::Uuid;

pub struct ClientInner {
    client: reqwest::Client,
    endpoint: String,
    jwt: Option<JwtLike>,
    iam: Option<IamClient>,
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

#[derive(Clone)]
pub struct BasicAuth {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone)]
pub enum Auth {
    BasicAuth(BasicAuth),
    AccessToken(String),
}

impl Deref for Client {
    type Target = ClientInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Client {
    pub fn new(endpoint: &str) -> Self {
        Self::new_with_jwt(endpoint, None)
    }

    pub fn new_with_jwt(endpoint: &str, jwt: Option<JwtLike>) -> Self {
        let client = reqwest::Client::new();
        let inner = ClientInner {
            client,
            endpoint: endpoint.to_string(),
            jwt,
            iam: None,
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn new_with_iam(endpoint: &str, iam: IamClient) -> Self {
        let client = reqwest::Client::new();
        let inner = ClientInner {
            client,
            endpoint: endpoint.to_string(),
            jwt: iam.jwt.clone(),
            iam: Some(iam),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    fn add_auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(jwt) = &self.jwt {
            rb.bearer_auth(&jwt.access_token)
        } else {
            rb
        }
    }

    /// Stream a full file to any `AsyncWrite`.
    pub async fn download<W>(&self, req: &DownloadRequest, mut writer: W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let resp = self
            .add_auth(
                self.inner
                    .client
                    .get(&format!("{}/download", self.endpoint)),
            )
            .query(req)
            .send()
            .await
            .context("Failed to send download request")?
            .error_for_status()
            .context("Received error status")?;

        // On WASM, reqwest exposes a stream of `Bytes` backed by Fetch/Streams API.
        let mut stream = resp
            .bytes_stream()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            writer.write_all(&chunk).await?;
        }
        writer.flush().await?;
        Ok(())
    }

    /// Stream a chunk response directly into `writer`.
    pub async fn download_chunk_to<W>(
        &self,
        req: &DownloadChunkRequest,
        mut writer: W,
    ) -> Result<u64>
    where
        W: AsyncWrite + Unpin,
    {
        let resp = self
            .add_auth(
                self.inner
                    .client
                    .get(&format!("{}/download/chunk", self.endpoint)),
            )
            .query(req)
            .send()
            .await
            .context("Failed to send download request")?
            .error_for_status()
            .context("Received error status")?;

        let mut total: u64 = 0;
        let mut stream = resp
            .bytes_stream()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            total += chunk.len() as u64;
            writer.write_all(&chunk).await?;
        }
        writer.flush().await?;
        Ok(total)
    }

    pub async fn download_chunk(&self, req: &DownloadChunkRequest) -> Result<Bytes> {
        self.add_auth(
            self.inner
                .client
                .get(&format!("{}/download/chunk", self.endpoint)),
        )
        .query(req)
        .send()
        .await
        .context("Failed to send download request")?
        .error_for_status()
        .context("Received error status")?
        .bytes()
        .await
        .context("Failed to read chunk data")
    }

    pub async fn download_chunk_with_progress<T>(
        &self,
        req: &DownloadChunkRequest,
        writer: &mut T,
        tx: mpsc::Sender<DownloadProgress>,
    ) -> Result<()>
    where
        T: std::io::Write,
    {
        let resp = self
            .add_auth(
                self.inner
                    .client
                    .get(&format!("{}/download/chunk", self.endpoint)),
            )
            .query(req)
            .send()
            .await
            .context("Failed to send download request")?
            .error_for_status()
            .context("Received error status")?;
        let total_size = resp.content_length().unwrap_or(0);
        let mut stream = resp.bytes_stream();
        let mut downloaded = 0u64;
        let started_at = chrono::Utc::now().timestamp_millis();
        let mut tx = Some(tx);
        while let Some(item) = stream.next().await {
            let buf = item.context("Failed to read stream body")?;
            writer
                .write_all(&buf)
                .context("Failed to pipe stream body")?;
            downloaded += buf.len() as u64;
            if let Some(t) = &tx {
                let ev = DownloadProgress {
                    workspace_id: req.workspace_id,
                    file_hash: req.file_hash.clone(),
                    downloaded_bytes: downloaded,
                    total_bytes: total_size,
                    chunk_no: req.chunk_no,
                    started_at,
                };
                if t.send(ev).await.is_err() {
                    // Receiver was dropped; stop further attempts
                    tx = None;
                }
            }
        }
        Ok(())
    }

    /// Upload from an `AsyncRead`. On WASM we buffer to Vec<u8> (Fetch doesn't let us stream arbitrary Rust readers).
    pub async fn upload<R>(&self, req: &UploadRequest, mut reader: R) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + Sync + 'static,
    {
        // WASM-friendly: read into memory, then Body::from(vec)
        // (If you already chunk uploads with `upload_chunk`, prefer that for large files.)
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;
        let body = Body::from(buf);

        self.add_auth(self.inner.client.post(&format!("{}/upload", self.endpoint)))
            .query(req)
            .body(body)
            .send()
            .await
            .context("Failed to send upload request")?
            .error_for_status()
            .context("Upload request returned error status")?;
        Ok(())
    }

    pub async fn upload_chunk_with_progress(
        &self,
        upload_id: Uuid,
        chunk_no: usize,
        chunk: Vec<u8>,
        tx: mpsc::Sender<UploadProgress>,
    ) -> Result<UploadChunkResponse> {
        let chunk_len = chunk.len() as u64;
        let started_at = chrono::Utc::now();
        let started_at_ms = started_at.timestamp_millis();
        const SLICE: usize = 128 * 1024; // 128 KiB

        // -----------------------
        // Non-WASM: true streaming
        // -----------------------
        #[cfg(not(target_arch = "wasm32"))]
        let req = {
            use std::io;

            // keep this local so wasm build doesn't see it
            let tx_opt = Some(tx);

            let stream = stream::unfold((chunk, 0usize, 0u64, tx_opt), move |state| {
                let (data, mut off, mut sent, mut tx_opt_inner) = state;
                async move {
                    if off >= data.len() {
                        return None;
                    }

                    let end = (off + SLICE).min(data.len());
                    let slice = Bytes::copy_from_slice(&data[off..end]);
                    off = end;
                    sent += slice.len() as u64;
                    let uploaded_bytes = sent;

                    if let Some(tx) = tx_opt_inner.as_ref() {
                        if tx
                            .send(UploadProgress {
                                upload_id,
                                uploaded_bytes,
                                chunk_no,
                                started_at: started_at_ms,
                                elapsed: chrono::Utc::now()
                                    .signed_duration_since(started_at)
                                    .num_milliseconds(),
                                total_bytes: chunk_len,
                            })
                            .await
                            .is_err()
                        {
                            // receiver dropped -> stop sending progress
                            tx_opt_inner = None;
                        }
                    }

                    Some((
                        Ok::<Bytes, io::Error>(slice),
                        (data, off, sent, tx_opt_inner),
                    ))
                }
            });

            self.add_auth(self.inner.client.post(&format!(
                "{}/upload/{}/chunk/{}",
                self.endpoint, upload_id, chunk_no
            )))
            .body(reqwest::Body::wrap_stream(stream))
        };

        // --------------------------------
        // WASM: single body + local progress
        // --------------------------------
        #[cfg(target_arch = "wasm32")]
        let req = {
            let mut sent: u64 = 0;
            let mut offset: usize = 0;

            // We *simulate* progress based on how much of the buffer
            // we've "prepared" – the browser fetch call itself is opaque.
            while offset < chunk.len() {
                let end = (offset + SLICE).min(chunk.len());
                offset = end;
                sent = end as u64;

                // ignore error if receiver is gone
                let _ = tx
                    .send(UploadProgress {
                        upload_id,
                        uploaded_bytes: sent,
                        chunk_no,
                        started_at: started_at_ms,
                        elapsed: chrono::Utc::now()
                            .signed_duration_since(started_at)
                            .num_milliseconds(),
                        total_bytes: chunk_len,
                    })
                    .await;
            }

            self.add_auth(self.inner.client.post(&format!(
                "{}/upload/{}/chunk/{}",
                self.endpoint, upload_id, chunk_no
            )))
            // On wasm, reqwest's Body accepts Vec<u8> directly; no streaming.
            .body(chunk)
        };

        // common send/parse path
        let resp = req
            .send()
            .await
            .context("Failed to send upload request")?
            .error_for_status()
            .context("Upload request returned error status")?;

        let parsed = resp
            .json::<UploadChunkResponse>()
            .await
            .context("Failed to parse upload chunk response")?;

        Ok(parsed)
    }

    pub async fn upload_chunk(
        &self,
        upload_id: Uuid,
        chunk_no: usize,
        chunk: Vec<u8>,
    ) -> Result<UploadChunkResponse> {
        self.add_auth(self.inner.client.post(&format!(
            "{}/upload/{}/chunk/{}",
            self.endpoint, upload_id, chunk_no
        )))
        .body(chunk)
        .send()
        .await
        .context("Failed to send upload request")?
        .error_for_status()
        .context("Upload request returned error status")?
        .json()
        .await
        .context("Failed to parse upload chunk response")
    }

    pub async fn start_upload(
        &self,
        upload_id: Uuid,
        req: &StartUploadRequest,
    ) -> Result<StartUploadResponse> {
        self.add_auth(
            self.inner
                .client
                .post(&format!("{}/upload/{}/start", self.endpoint, upload_id)),
        )
        .json(req)
        .send()
        .await
        .context("Failed to send upload request")?
        .error_for_status()
        .context("Server returned error status")?
        .json()
        .await
        .context("Failed to parse response")
    }

    pub async fn complete_upload(
        &self,
        upload_id: Uuid,
        chunk_hashes: Vec<String>,
        force_dispatch: bool,
    ) -> Result<CompleteUploadResponse> {
        anyhow::ensure!(!chunk_hashes.is_empty(), "Number of chunks cannot be zero");
        self.add_auth(
            self.inner
                .client
                .post(&format!("{}/upload/{}/complete", self.endpoint, upload_id)),
        )
        .json(&CompleteUploadRequest {
            chunk_hashes,
            force_dispatch,
        })
        .send()
        .await
        .context("Failed to send upload request")?
        .error_for_status()
        .context("Upload request returned error status")?
        .json()
        .await
        .context("Failed to parse response")
    }

    pub async fn free_upload(&self, upload_id: Uuid) -> Result<()> {
        self.cancel_upload(upload_id).await
    }

    pub async fn cancel_upload(&self, upload_id: Uuid) -> Result<()> {
        self.add_auth(
            self.inner
                .client
                .post(&format!("{}/upload/{}/cancel", self.endpoint, upload_id)),
        )
        .send()
        .await
        .context("Failed to send upload request")?
        .error_for_status()
        .context("Upload request returned error status")?;
        Ok(())
    }

    pub async fn download_chunk_info(&self, req: &DownloadRequest) -> Result<FileMeta> {
        self.add_auth(
            self.inner
                .client
                .get(&format!("{}/download/chunk_info", self.endpoint)),
        )
        .query(req)
        .send()
        .await
        .context("Failed to send download request")?
        .error_for_status()
        .context("Received error status")?
        .json()
        .await
        .context("Failed to parse chunk info response")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DownloadRequest {
    #[serde(rename = "w")]
    pub workspace_id: Uuid,

    #[serde(rename = "h", skip_serializing_if = "Option::is_none")]
    pub file_hash: Option<String>,

    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,

    #[serde(rename = "n", skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DownloadChunkRequest {
    #[serde(rename = "w")]
    pub workspace_id: Uuid,

    #[serde(rename = "h")]
    pub file_hash: String,

    #[serde(rename = "c")]
    pub chunk_no: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UploadRequest {
    #[serde(rename = "w")]
    pub workspace_id: Uuid,

    #[serde(rename = "c")]
    pub creator_id: Option<Uuid>,

    #[serde(rename = "p")]
    pub path: String,

    #[serde(rename = "h")]
    pub hash: String,

    #[serde(rename = "m")]
    pub mime_type: Option<String>,

    #[serde(rename = "n")]
    pub origin_file_name: String,

    #[serde(rename = "s")]
    pub size: i64,

    #[serde(rename = "a", skip_serializing_if = "Option::is_none")]
    pub annotations: Option<String>,

    #[serde(rename = "f", default)]
    pub force_dispatch: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StartUploadRequest {
    pub workspace_id: Uuid,

    pub uploader_id: Uuid,

    pub path: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    pub origin_file_name: String,

    pub file_size: usize,

    pub file_hash: String,

    #[serde(default)]
    pub force: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum UploadState {
    Started,
    InProgress(HashMap<usize, String>),
    Completed(usize),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StartUploadResponse {
    pub chunk_size: usize,
    pub num_chunks: usize,
    pub state: UploadState,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UploadChunkResponse {
    pub chunk_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompleteUploadResponse {
    pub file_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompleteUploadRequest {
    pub chunk_hashes: Vec<String>,
    pub force_dispatch: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileMeta {
    pub origin_file_name: String,
    pub mime_type: Option<String>,
    pub size: usize,
    pub total_chunks: usize,
    pub hash: String,
    pub chunk_hashes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DownloadProgress {
    pub workspace_id: Uuid,
    pub file_hash: String,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub chunk_no: usize,
    pub started_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UploadProgress {
    pub upload_id: Uuid,
    pub uploaded_bytes: u64,
    pub total_bytes: u64,
    pub chunk_no: usize,
    pub started_at: i64,
    pub elapsed: i64,
}

pub struct UploadProgressTrackerInner {
    pub upload_id: Uuid,
    pub workspace_id: Uuid,
    pub file_hash: String,
    pub total_uploaded_bytes: usize,
    pub file_size: usize,
}

#[derive(Clone)]
pub struct UploadProgressTracker {
    inner: Arc<UploadProgressTrackerInner>,
}

impl Deref for UploadProgressTracker {
    type Target = UploadProgressTrackerInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl UploadProgressTracker {
    pub fn new(upload_id: Uuid, workspace_id: Uuid, file_hash: String, file_size: usize) -> Self {
        let inner = UploadProgressTrackerInner {
            file_size,
            upload_id,
            workspace_id,
            file_hash,
            total_uploaded_bytes: 0,
        };
        Self {
            inner: Arc::new(inner),
        }
    }
}
