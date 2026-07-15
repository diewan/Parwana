//! Transport abstraction for the remote-dispatch client.
//!
//! [`RemoteTransport`] carries an encoded request envelope to the host and
//! returns the encoded response envelope. It is deliberately byte-in / byte-out
//! so the envelope encoding stays owned by `csv-wire` and so the same client
//! adapter can run over HTTP in production and over an in-process channel in
//! tests.

use async_trait::async_trait;
use csv_chain_ports::AdapterError;

/// Sends an encoded remote-dispatch request to the host and returns the encoded
/// response. Must be fully asynchronous — no blocking, no `block_on`.
#[async_trait]
pub trait RemoteTransport: Send + Sync {
    /// Deliver `request` (canonical-CBOR [`csv_wire::remote::RemoteRequest`]) to
    /// the host and return the raw response bytes.
    ///
    /// A transport-level failure (unreachable host, auth rejection, non-success
    /// status) must be surfaced as a typed [`AdapterError`] so the caller fails
    /// closed.
    async fn send(&self, request: Vec<u8>) -> Result<Vec<u8>, AdapterError>;
}

/// The reqwest client, wrapped so the transport is `Send + Sync` on every
/// target. On native the client is already `Send + Sync`; on wasm the fetch
/// backend's client is `!Send`, so it is held in a [`send_wrapper::SendWrapper`]
/// — sound because wasm is single-threaded.
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
type ReqwestClient = reqwest::Client;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
type ReqwestClient = send_wrapper::SendWrapper<reqwest::Client>;

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
fn make_client() -> ReqwestClient {
    reqwest::Client::new()
}
#[cfg(all(feature = "http", target_arch = "wasm32"))]
fn make_client() -> ReqwestClient {
    send_wrapper::SendWrapper::new(reqwest::Client::new())
}

/// HTTP(S) transport backed by `reqwest`.
///
/// `reqwest`'s fetch backend keeps this wasm-clean; on native it uses the
/// standard async client. The host is a user-owned service, so requests are
/// authenticated with a bearer token (see [`HttpTransport::with_bearer_token`]).
/// mTLS is the alternative for deployments that terminate TLS themselves; this
/// transport carries the bearer token and leaves TLS/mTLS to the reqwest client
/// and the network. The transport is fully asynchronous — it never blocks and
/// never calls `block_on`.
#[cfg(feature = "http")]
pub struct HttpTransport {
    client: ReqwestClient,
    url: String,
    auth_token: Option<String>,
}

#[cfg(feature = "http")]
impl HttpTransport {
    /// Create a transport that POSTs to `url` with no bearer token.
    ///
    /// Only appropriate when the host authenticates the client another way
    /// (e.g. mTLS or a localhost-only socket). Prefer
    /// [`HttpTransport::with_bearer_token`] otherwise.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            client: make_client(),
            url: url.into(),
            auth_token: None,
        }
    }

    /// Create a transport that authenticates every request with `token` as an
    /// HTTP `Authorization: Bearer` header.
    pub fn with_bearer_token(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: make_client(),
            url: url.into(),
            auth_token: Some(token.into()),
        }
    }

    /// Perform the actual request. On wasm this future is `!Send` (it touches
    /// the fetch backend); [`RemoteTransport::send`] wraps it so the public
    /// future stays `Send`.
    async fn do_send(&self, request: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        let mut builder = self
            .client
            .post(&self.url)
            .header("content-type", "application/cbor")
            .body(request);
        if let Some(token) = &self.auth_token {
            builder = builder.bearer_auth(token);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| AdapterError::NetworkError(format!("remote host request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            return Err(AdapterError::NetworkError(format!(
                "remote host returned status {status}"
            )));
        }

        let bytes = response.bytes().await.map_err(|e| {
            AdapterError::NetworkError(format!("failed to read remote host response: {e}"))
        })?;
        Ok(bytes.to_vec())
    }
}

#[cfg(feature = "http")]
#[async_trait]
impl RemoteTransport for HttpTransport {
    async fn send(&self, request: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.do_send(request).await
        }
        // wasm: the fetch future is `!Send`; SendWrapper makes it `Send` so the
        // async_trait-boxed future satisfies the port's `Send` bound. Sound
        // because wasm runs on a single thread.
        #[cfg(target_arch = "wasm32")]
        {
            send_wrapper::SendWrapper::new(self.do_send(request)).await
        }
    }
}
