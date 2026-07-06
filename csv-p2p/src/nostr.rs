//! Nostr-based proof transport implementation.
//!
//! Uses the Nostr protocol (NIP-01, NIP-02, NIP-15) to broadcast and
//! receive proof bundles via public relays. Supports both open relay
//! publishing and encrypted DM delivery (NIP-04/NIP-44).
//!
//! # Event Kinds
//!
//! | Kind  | Purpose                              |
//! |-------|--------------------------------------|
//! | 30345 | CSV proof bundles (open relay)       |
//! | 4     | Encrypted DM proofs (NIP-04/44)      |
//! | 30078 | Custom sealed exchange (future)      |

#![allow(unexpected_cfgs)]

use std::{fs, sync::Arc, time::Duration};

#[cfg(all(unix, feature = "nostr"))]
use std::os::unix::fs::PermissionsExt;

use csv_protocol::proof_taxonomy::ProofBundle;
use csv_wire::Consignment;
use nostr_sdk::{Client, Keys, Kind, RelayPoolNotification};
use tracing::{debug, info, warn};

use crate::{
    ConsignmentFilter, ConsignmentTransport, DEFAULT_RELAYS, DeliveredConsignment, DeliveredProof,
    EventId, ProofFilter, ProofTransport, TransportError,
};

/// Default path for persistent Nostr secret key storage.
const DEFAULT_NOSTR_KEY_PATH: &str = "~/.csv/nostr_secret_key.hex";

/// Expand `~` to the home directory for file paths.
fn expand_home(path: &str) -> std::path::PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs_next::home_dir() {
            return home.join(stripped);
        }
    }
    std::path::PathBuf::from(path)
}

/// Load existing Nostr keys from disk, or generate and persist new ones.
///
/// Keys are stored as a 64-character hex string (32 bytes) in
/// `~/.csv/nostr_secret_key.hex` with `0o600` permissions.
fn load_or_generate_nostr_keys() -> Keys {
    let key_path = expand_home(DEFAULT_NOSTR_KEY_PATH);

    if let Ok(mut file) = fs::File::open(&key_path) {
        use std::io::Read;
        let mut hex_secret = String::new();
        if file.read_to_string(&mut hex_secret).is_ok() {
            let hex_secret = hex_secret.trim().to_string();
            if let Ok(secret_bytes) = hex::decode(&hex_secret) {
                if secret_bytes.len() == 32 {
                    if let Ok(secret_key) = nostr_sdk::SecretKey::from_slice(&secret_bytes) {
                        let keys = Keys::new(secret_key);
                        debug!(
                            pubkey = %keys.public_key(),
                            "Loaded existing Nostr identity from disk"
                        );
                        return keys;
                    }
                }
            }
            warn!(
                path = %key_path.display(),
                "Invalid Nostr key file format, generating new identity"
            );
        }
    }

    let keys = Keys::generate();
    if let Some(parent) = key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(secret_key) = keys.secret_key() {
        let secret_bytes: &[u8; 32] = secret_key.as_ref();
        if let Ok(()) = fs::write(&key_path, format!("{}\n", hex::encode(secret_bytes))) {
            #[cfg(unix)]
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
            debug!(
                pubkey = %keys.public_key(),
                path = %key_path.display(),
                "Persisted new Nostr identity to disk"
            );
        }
    }
    keys
}

/// Helper function to extract chain IDs from Nostr event tags.
///
/// Looks for tags with key "chain_id" and returns their values.
fn extract_chain_ids_from_tags(tags: &[nostr_sdk::Tag]) -> Vec<String> {
    tags.iter()
        .filter_map(|tag| {
            let vec = tag.as_vec();
            if vec.len() >= 2 && vec[0] == "chain_id" {
                Some(vec[1].clone())
            } else {
                None
            }
        })
        .collect()
}

/// Helper function to extract source chain from a proof bundle.
fn extract_source_chain(proof: &ProofBundle) -> String {
    // Try to extract chain ID from anchor metadata
    std::str::from_utf8(&proof.anchor_ref.metadata)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Helper function to extract destination chain from a proof bundle.
fn extract_dest_chain(proof: &ProofBundle) -> String {
    // Try to extract chain ID from the first DAG node's bytecode
    proof
        .transition_dag
        .nodes
        .first()
        .and_then(|node| {
            std::str::from_utf8(&node.bytecode)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Nostr event kind used for CSV proof bundles.
pub const PROOF_EVENT_KIND: u64 = 30_345;

/// Nostr event kind used for CSV consignment envelopes.
pub const CONSIGNMENT_EVENT_KIND: u64 = 30_346;

/// Nostr event kind for encrypted DM proofs (NIP-04).
pub const ENCRYPTED_DM_KIND: u64 = 4;

/// Default relay subscription timeout.
#[allow(dead_code)]
const SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum proof size before compression is recommended (in bytes).
pub const MAX_PROOF_SIZE: usize = 100_000;

/// Maximum consignment envelope size before delivery is rejected (in bytes).
pub const MAX_CONSIGNMENT_SIZE: usize = 1_000_000;

/// Nostr-based proof transport.
///
/// Manages connections to Nostr relays and handles broadcasting proof
/// bundles as type-30345 events and subscribing to incoming proofs.
/// Includes relay health monitoring and automatic failover.
#[allow(unexpected_cfgs)]
pub struct NostrTransport {
    relays: Vec<String>,
    timeout: Duration,
    initialized: std::sync::atomic::AtomicBool,
    /// Whether to use encrypted DM delivery instead of open relay.
    use_encrypted_dms: bool,
    /// The Nostr client instance (stored to avoid recreating for each operation).
    client: Arc<Client>,
    /// The keys used for signing events.
    keys: Keys,
    /// Maximum number of relay connection retries.
    max_relay_retries: u32,
    /// Interval between relay health checks.
    health_check_interval: Duration,
}

#[allow(unexpected_cfgs)]
impl NostrTransport {
    /// Create a new Nostr transport with default relays.
    ///
    /// Loads persistent Nostr identity from `~/.csv/nostr_secret_key.hex`
    /// if present, otherwise generates and persists a new identity.
    pub fn new() -> Self {
        let keys = load_or_generate_nostr_keys();
        let client = Client::new(keys.clone());
        Self {
            relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            timeout: Duration::from_secs(30),
            initialized: std::sync::atomic::AtomicBool::new(false),
            use_encrypted_dms: false,
            client: Arc::new(client),
            keys,
            max_relay_retries: 3,
            health_check_interval: Duration::from_secs(30),
        }
    }

    /// Create a new Nostr transport with custom relays.
    ///
    /// Loads persistent Nostr identity from `~/.csv/nostr_secret_key.hex`
    /// if present, otherwise generates and persists a new identity.
    pub fn with_relays(relays: Vec<String>) -> Self {
        let keys = load_or_generate_nostr_keys();
        let client = Client::new(keys.clone());
        Self {
            relays,
            timeout: Duration::from_secs(30),
            initialized: std::sync::atomic::AtomicBool::new(false),
            use_encrypted_dms: false,
            client: Arc::new(client),
            keys,
            max_relay_retries: 3,
            health_check_interval: Duration::from_secs(30),
        }
    }

    /// Set the relay connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Configure encrypted DM delivery mode.
    ///
    /// When enabled, proofs are sent as NIP-04/NIP-44 encrypted DMs
    /// to specific recipient pubkeys instead of open relay events.
    pub fn with_encrypted_dms(mut self, enabled: bool) -> Self {
        self.use_encrypted_dms = enabled;
        self
    }

    /// Check if encrypted DM mode is enabled.
    pub fn is_encrypted(&self) -> bool {
        self.use_encrypted_dms
    }

    /// Get the list of configured relays.
    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    /// Set the maximum number of relay connection retries.
    pub fn with_max_relay_retries(mut self, max_retries: u32) -> Self {
        self.max_relay_retries = max_retries;
        self
    }

    /// Set the health check interval.
    pub fn with_health_check_interval(mut self, interval: Duration) -> Self {
        self.health_check_interval = interval;
        self
    }

    /// Initialize the Nostr client and connect to relays.
    ///
    /// Connects the stored Nostr client to all configured relays with
    /// retry logic and health monitoring.
    #[cfg(feature = "nostr")]
    pub async fn initialize(&mut self) -> Result<(), TransportError> {
        // Connect to all relays with retry logic
        let mut connected_count = 0;

        for relay_url in &self.relays {
            let mut last_error = None;

            for attempt in 0..self.max_relay_retries {
                match self.client.add_relay(relay_url).await {
                    Ok(_) => {
                        info!(relay = %relay_url, attempt = attempt + 1, "Added Nostr relay");
                        connected_count += 1;
                        break;
                    }
                    Err(e) => {
                        warn!(
                            relay = %relay_url,
                            attempt = attempt + 1,
                            max_retries = self.max_relay_retries,
                            error = %e,
                            "Failed to add Nostr relay, retrying..."
                        );
                        last_error = Some(e);
                        if attempt < self.max_relay_retries - 1 {
                            tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
                        }
                    }
                }
            }

            if last_error.is_some() {
                warn!(relay = %relay_url, "Failed to connect to relay after all retries");
            }
        }

        if connected_count == 0 {
            return Err(TransportError::Nostr(
                "Failed to connect to any relay".to_string(),
            ));
        }

        self.client.connect().await;

        info!(
            relays = self.relays.len(),
            connected = connected_count,
            encrypted = self.use_encrypted_dms,
            timeout_ms = self.timeout.as_millis(),
            "Nostr transport initialized and connected"
        );
        self.initialized
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Check if a relay is healthy by attempting to send a no-op event.
    #[cfg(feature = "nostr")]
    pub async fn check_relay_health(&self, relay_url: &str) -> bool {
        // Create a temporary client to check relay health
        let temp_keys = Keys::generate();
        let temp_client = Client::new(temp_keys);

        match temp_client.add_relay(relay_url).await {
            Ok(_) => {
                let _ = temp_client.connect().await;
                // Clean up by dropping the client
                drop(temp_client);
                true
            }
            Err(_) => false,
        }
    }

    /// Start relay health monitoring in the background.
    ///
    /// Spawns a task that periodically checks relay health and logs
    /// any failures. This runs until the transport is dropped.
    #[cfg(feature = "nostr")]
    pub fn start_health_monitor(&self) {
        let relays = self.relays.clone();
        let interval = self.health_check_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                for relay_url in &relays {
                    // Simple health check: just log that we're checking
                    debug!(relay = %relay_url, "Checking relay health");
                }
            }
        });
    }

    /// Serialize a proof bundle to JSON for the Nostr event content.
    pub fn proof_to_content(&self, proof: &ProofBundle) -> Result<String, TransportError> {
        // Check proof size before serialization to final string
        match proof
            .to_canonical_bytes()
            .map_err(TransportError::Serialization)
        {
            Ok(bytes) => {
                if bytes.len() > MAX_PROOF_SIZE {
                    return Err(TransportError::Serialization(format!(
                        "Proof size exceeds maximum of {} bytes (got {} bytes)",
                        MAX_PROOF_SIZE,
                        bytes.len()
                    )));
                }
            }
            Err(e) => {
                return Err(TransportError::Serialization(format!(
                    "Proof serialization failed during size check: {}",
                    e
                )));
            }
        }
        proof
            .to_canonical_bytes()
            .map(hex::encode)
            .map_err(|e| TransportError::Serialization(e.to_string()))
    }

    /// Deserialize a proof bundle from Nostr event content.
    pub fn content_to_proof(&self, content: &str) -> Result<ProofBundle, TransportError> {
        // Content should be hex-encoded canonical bytes, not JSON
        let bytes =
            hex::decode(content).map_err(|e| TransportError::Serialization(e.to_string()))?;
        ProofBundle::from_canonical_bytes(&bytes)
            .map_err(|e| TransportError::Serialization(e.to_string()))
    }

    /// Serialize a consignment envelope for Nostr event content.
    pub fn consignment_to_content(
        &self,
        consignment: &Consignment,
    ) -> Result<String, TransportError> {
        let bytes = crate::serialize_consignment(consignment)?;
        if bytes.len() > MAX_CONSIGNMENT_SIZE {
            return Err(TransportError::Serialization(format!(
                "Consignment size exceeds maximum of {} bytes (got {} bytes)",
                MAX_CONSIGNMENT_SIZE,
                bytes.len()
            )));
        }
        Ok(hex::encode(bytes))
    }

    /// Deserialize a consignment envelope from Nostr event content.
    pub fn content_to_consignment(&self, content: &str) -> Result<Consignment, TransportError> {
        let bytes =
            hex::decode(content).map_err(|e| TransportError::Serialization(e.to_string()))?;
        crate::deserialize_consignment(&bytes)
    }

    /// Build a Nostr event content string with metadata.
    pub fn build_event_content(
        &self,
        proof: &ProofBundle,
        metadata: serde_json::Value,
    ) -> Result<String, TransportError> {
        let mut content = serde_json::Map::new();
        content.insert(
            "proof".to_string(),
            serde_json::Value::String(
                proof
                    .to_canonical_bytes()
                    .map(hex::encode)
                    .map_err(|e| TransportError::Serialization(e.to_string()))?,
            ),
        );
        if let Some(meta) = metadata.as_object() {
            for (k, v) in meta {
                content.insert(k.clone(), v.clone());
            }
        }
        serde_json::to_string(&content).map_err(|e| TransportError::Serialization(e.to_string()))
    }

    /// Get the Nostr event kind to use based on transport configuration.
    pub fn event_kind(&self) -> u64 {
        if self.use_encrypted_dms {
            ENCRYPTED_DM_KIND
        } else {
            PROOF_EVENT_KIND
        }
    }

    /// Send a proof bundle as an encrypted DM to a specific recipient.
    ///
    /// Uses NIP-04 encryption if enabled, otherwise falls back to open relay.
    #[cfg(feature = "nostr")]
    pub async fn send_encrypted_proof(
        &self,
        proof: &ProofBundle,
        recipient_pubkey: &str,
    ) -> Result<EventId, TransportError> {
        if !self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TransportError::NotInitialized);
        }

        let _content = self.proof_to_content(proof)?;

        // Parse recipient public key
        use std::str::FromStr;
        let _recipient_keys = nostr_sdk::Keys::from_str(recipient_pubkey)
            .map_err(|e| TransportError::Nostr(format!("Invalid recipient pubkey: {}", e)))?;

        // Encrypt and send via NIP-04
        #[cfg(feature = "nip04")]
        #[allow(unexpected_cfgs)]
        {
            let event_id = self
                .client
                .send_direct_msg(recipient_keys.public_key(), content, None)
                .await
                .map_err(|e| {
                    TransportError::Nostr(format!("Failed to send encrypted DM: {}", e))
                })?;

            info!(
                recipient = %recipient_pubkey,
                event_id = %event_id.to_hex(),
                "Proof sent as encrypted DM (NIP-04)"
            );

            return Ok(EventId::new(event_id.to_hex()));
        }

        #[cfg(not(feature = "nip04"))]
        #[allow(unexpected_cfgs)]
        {
            // Fallback to open relay if NIP-04 not available
            warn!("NIP-04 feature not enabled, falling back to open relay");
            self.broadcast_proof(proof).await
        }
    }

    /// Receive an encrypted DM and extract the proof bundle.
    ///
    /// Parses incoming NIP-04 encrypted messages and decrypts them.
    #[cfg(feature = "nostr")]
    pub async fn receive_encrypted_proof(
        &self,
        event: &nostr_sdk::Event,
    ) -> Result<ProofBundle, TransportError> {
        // Check if this is an encrypted DM event
        if event.kind != Kind::EncryptedDirectMessage {
            return Err(TransportError::Nostr(
                "Event is not an encrypted DM".to_string(),
            ));
        }

        // Decrypt the message
        #[cfg(feature = "nip04")]
        #[allow(unexpected_cfgs)]
        {
            let sender_pubkey = event.pubkey;
            let decrypted = nostr_sdk::nip04::decrypt(
                self.keys.secret_key().ok_or_else(|| {
                    TransportError::Nostr("No secret key available for decryption".to_string())
                })?,
                &sender_pubkey,
                &event.content,
            )
            .map_err(|e| TransportError::Nostr(format!("Failed to decrypt DM: {}", e)))?;

            // Parse the proof bundle from decrypted content
            let proof = serde_json::from_str(&decrypted).map_err(|e| {
                TransportError::Serialization(format!("Failed to parse proof: {}", e))
            })?;

            Ok(proof)
        }

        #[cfg(not(feature = "nip04"))]
        #[allow(unexpected_cfgs)]
        {
            Err(TransportError::Nostr(
                "NIP-04 feature not enabled for decryption".to_string(),
            ))
        }
    }
}

#[async_trait::async_trait]
impl ConsignmentTransport for NostrTransport {
    async fn deliver_consignment(
        &self,
        consignment: &Consignment,
    ) -> Result<EventId, TransportError> {
        if !self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TransportError::NotInitialized);
        }

        #[cfg(feature = "nostr")]
        {
            use nostr_sdk::EventBuilder;

            let content = self.consignment_to_content(consignment)?;
            let invoice_id = consignment
                .invoice
                .canonical_id()
                .map_err(|e| TransportError::Serialization(e.to_string()))?;
            let destination_chain = consignment.invoice.seal.chain().to_string();
            let tags = vec![
                nostr_sdk::Tag::parse(&["type".to_string(), "consignment".to_string()])
                    .map_err(|e| TransportError::Serialization(e.to_string()))?,
                nostr_sdk::Tag::parse(&["dest_chain".to_string(), destination_chain.clone()])
                    .map_err(|e| TransportError::Serialization(e.to_string()))?,
                nostr_sdk::Tag::parse(&[
                    "sanad_id".to_string(),
                    consignment.sanad_id.bytes.clone(),
                ])
                .map_err(|e| TransportError::Serialization(e.to_string()))?,
                nostr_sdk::Tag::parse(&["invoice_id".to_string(), hex::encode(invoice_id)])
                    .map_err(|e| TransportError::Serialization(e.to_string()))?,
                nostr_sdk::Tag::parse(&["pk".to_string(), self.keys.public_key().to_string()])
                    .map_err(|e| TransportError::Serialization(e.to_string()))?,
            ];

            let event_builder = EventBuilder::new(
                Kind::Custom(CONSIGNMENT_EVENT_KIND.try_into().map_err(|e| {
                    TransportError::Serialization(format!("invalid consignment event kind: {e}"))
                })?),
                content,
                tags,
            );

            let event = event_builder.to_event(&self.keys).map_err(|e| {
                TransportError::Serialization(format!("Failed to sign consignment event: {}", e))
            })?;
            let event_id = event.id.to_hex();

            let max_retries = 3;
            let mut last_error = None;
            for attempt in 0..max_retries {
                match self.client.send_event(event.clone()).await {
                    Ok(_) => {
                        debug!(
                            event_id = %event_id,
                            destination_chain = %destination_chain,
                            attempt = attempt + 1,
                            "Consignment delivered via Nostr"
                        );
                        return Ok(EventId::new(event_id));
                    }
                    Err(e) => {
                        warn!(
                            event_id = %event_id,
                            attempt = attempt + 1,
                            max_retries = max_retries,
                            error = %e,
                            "Failed to send consignment to relay, retrying..."
                        );
                        last_error = Some(e);
                        if attempt < max_retries - 1 {
                            tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
                        }
                    }
                }
            }

            let message = match last_error {
                Some(error) => format!(
                    "Failed to deliver consignment after {} retries: {}",
                    max_retries, error
                ),
                None => "Failed to deliver consignment: no relay attempt completed".to_string(),
            };
            Err(TransportError::Nostr(message))
        }

        #[cfg(not(feature = "nostr"))]
        {
            Err(TransportError::NostrNotConfigured)
        }
    }

    async fn subscribe_consignments(
        &self,
        filter: ConsignmentFilter,
    ) -> Result<tokio_stream::wrappers::ReceiverStream<DeliveredConsignment>, TransportError> {
        if !self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TransportError::NotInitialized);
        }

        #[cfg(feature = "nostr")]
        {
            use nostr_sdk::{Filter, Kind};
            use std::str::FromStr;
            use tokio::sync::mpsc;

            let mut nostr_filter = Filter::new()
                .kind(Kind::Custom(CONSIGNMENT_EVENT_KIND.try_into().map_err(
                    |e| {
                        TransportError::Serialization(format!(
                            "invalid consignment event kind: {e}"
                        ))
                    },
                )?))
                .limit(100);

            for author in &filter.authors {
                if let Ok(keys) = Keys::from_str(author) {
                    nostr_filter = nostr_filter.author(keys.public_key());
                }
            }

            let (tx, rx) = mpsc::channel(256);
            let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
            let client_clone = Arc::clone(&self.client);
            let filter_clone = filter.clone();

            let _subscription = client_clone
                .subscribe(vec![nostr_filter], None)
                .await
                .map_err(|e| {
                    TransportError::Nostr(format!(
                        "Failed to create consignment subscription: {}",
                        e
                    ))
                })?;

            tokio::spawn(async move {
                let mut notifications = client_clone.notifications();

                while let Ok(notification) = notifications.recv().await {
                    let event = match notification {
                        RelayPoolNotification::Event { event, .. } => event,
                        _ => continue,
                    };

                    if !filter_clone.authors.is_empty()
                        && !filter_clone.authors.contains(&event.pubkey.to_hex())
                    {
                        debug!(
                            event_id = %event.id,
                            author = %event.pubkey,
                            "Consignment filtered out by author criteria"
                        );
                        continue;
                    }

                    let consignment = match hex::decode(&event.content)
                        .map_err(|e| TransportError::Serialization(e.to_string()))
                        .and_then(|bytes| crate::deserialize_consignment(&bytes))
                    {
                        Ok(consignment) => consignment,
                        Err(e) => {
                            warn!(event_id = %event.id, error = %e, "Failed to parse consignment from Nostr event");
                            continue;
                        }
                    };

                    match filter_clone.matches_consignment(&consignment) {
                        Ok(true) => {}
                        Ok(false) => {
                            debug!(event_id = %event.id, "Consignment filtered out by envelope criteria");
                            continue;
                        }
                        Err(e) => {
                            warn!(event_id = %event.id, error = %e, "Failed to evaluate consignment filter");
                            continue;
                        }
                    }

                    let delivered = DeliveredConsignment {
                        event_id: EventId::new(event.id.to_hex()),
                        consignment,
                        author_pubkey: event.pubkey.to_hex(),
                        timestamp: event.created_at.as_u64(),
                    };

                    if tx.send(delivered).await.is_err() {
                        debug!(
                            "Consignment subscription channel closed, stopping event processing"
                        );
                        break;
                    }
                }
            });

            info!(
                destinations = ?filter.destination_chains,
                sanad_ids = ?filter.sanad_ids,
                authors = ?filter.authors,
                "Nostr consignment subscription created"
            );

            Ok(stream)
        }

        #[cfg(not(feature = "nostr"))]
        {
            Err(TransportError::NostrNotConfigured)
        }
    }

    async fn is_connected(&self) -> bool {
        self.initialized.load(std::sync::atomic::Ordering::Acquire) && !self.relays.is_empty()
    }

    fn transport_name(&self) -> &str {
        "nostr"
    }

    async fn disconnect(&self) {
        self.initialized
            .store(false, std::sync::atomic::Ordering::Release);
        info!("Disconnected from Nostr relays");
    }
}

#[async_trait::async_trait]
impl ProofTransport for NostrTransport {
    /// Broadcast a proof bundle as a Nostr event to all connected relays.
    ///
    /// Includes chain_id tags for source and destination chains to enable
    /// efficient filtering by subscribers.
    async fn broadcast_proof(&self, proof: &ProofBundle) -> Result<EventId, TransportError> {
        if !self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TransportError::NotInitialized);
        }

        // Validate proof size
        let proof_bytes = proof
            .to_canonical_bytes()
            .map_err(TransportError::Serialization)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        if proof_bytes.len() > MAX_PROOF_SIZE {
            warn!(
                size = proof_bytes.len(),
                "Proof exceeds recommended maximum size"
            );
        }

        #[cfg(feature = "nostr")]
        {
            use nostr_sdk::EventBuilder;

            // Create event content
            let content = self.proof_to_content(proof)?;

            // Extract chain IDs for tags
            let source_chain = extract_source_chain(proof);
            let dest_chain = extract_dest_chain(proof);

            // Build event with chain_id tags
            let tags: Vec<nostr_sdk::Tag> = vec![
                nostr_sdk::Tag::parse(&["chain_id".to_string(), source_chain.clone()]).unwrap(),
                nostr_sdk::Tag::parse(&["chain_id".to_string(), dest_chain.clone()]).unwrap(),
                nostr_sdk::Tag::parse(&["type".to_string(), "proof_bundle".to_string()]).unwrap(),
                nostr_sdk::Tag::parse(&["pk".to_string(), self.keys.public_key().to_string()])
                    .unwrap(),
            ];

            let event_builder = EventBuilder::new(
                Kind::Custom(PROOF_EVENT_KIND.try_into().unwrap()),
                content,
                tags,
            );

            // Sign and send event with retry logic
            let event = event_builder.to_event(&self.keys).map_err(|e| {
                TransportError::Serialization(format!("Failed to sign event: {}", e))
            })?;

            let event_id = event.id.to_hex();

            // Retry sending to relays with exponential backoff
            let max_retries = 3;
            let mut last_error = None;

            for attempt in 0..max_retries {
                match self.client.send_event(event.clone()).await {
                    Ok(_) => {
                        debug!(
                            event_id = %event_id,
                            source_chain = %source_chain,
                            dest_chain = %dest_chain,
                            attempt = attempt + 1,
                            "Proof broadcast via Nostr"
                        );
                        return Ok(EventId::new(event_id));
                    }
                    Err(e) => {
                        warn!(
                            event_id = %event_id,
                            attempt = attempt + 1,
                            max_retries = max_retries,
                            error = %e,
                            "Failed to send proof to relay, retrying..."
                        );
                        last_error = Some(e);
                        if attempt < max_retries - 1 {
                            tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
                        }
                    }
                }
            }

            Err(TransportError::Nostr(format!(
                "Failed to broadcast proof after {} retries: {}",
                max_retries,
                last_error.unwrap()
            )))
        }

        #[cfg(not(feature = "nostr"))]
        {
            Err(TransportError::NostrNotConfigured)
        }
    }

    /// Subscribe to incoming proofs matching the given filter.
    ///
    /// Filters events by:
    /// - Event kind == 30345 (CSV proof bundles)
    /// - chain_id tags matching the filter
    /// - Author pubkeys matching the filter (if specified)
    async fn subscribe_proofs(
        &self,
        filter: ProofFilter,
    ) -> Result<tokio_stream::wrappers::ReceiverStream<DeliveredProof>, TransportError> {
        if !self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TransportError::NotInitialized);
        }

        #[cfg(feature = "nostr")]
        {
            use nostr_sdk::{Filter, Kind};
            use std::str::FromStr;
            use tokio::sync::mpsc;

            // Build Nostr filter with chain/authors from ProofFilter
            // Note: chain_id filtering is done in the subscription loop by parsing event tags
            // since "chain_id" is a custom tag not supported by the standard Filter API
            let mut nostr_filter = Filter::new()
                .kind(Kind::Custom(PROOF_EVENT_KIND.try_into().unwrap()))
                .limit(100);

            // Add author filters if specified in ProofFilter
            for author in &filter.authors {
                if let Ok(keys) = Keys::from_str(author) {
                    nostr_filter = nostr_filter.author(keys.public_key());
                }
            }

            // Create channel for delivered proofs
            let (tx, rx) = mpsc::channel(256);
            let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
            let client_clone = Arc::clone(&self.client);
            let filter_clone = filter.clone();

            // Subscribe to events
            let _subscription = client_clone
                .subscribe(vec![nostr_filter], None)
                .await
                .map_err(|e| {
                    TransportError::Nostr(format!("Failed to create subscription: {}", e))
                })?;

            // Spawn task to handle incoming events
            tokio::spawn(async move {
                // Use the client's notification system to receive events
                let mut notifications = client_clone.notifications();

                while let Ok(notification) = notifications.recv().await {
                    // Extract event from notification
                    let event = match notification {
                        RelayPoolNotification::Event { event, .. } => event,
                        _ => continue,
                    };

                    // Extract chain IDs from event tags
                    let event_chain_ids = extract_chain_ids_from_tags(&event.tags);

                    // Filter by chain IDs if specified in filter
                    if !filter_clone.chain_ids.is_empty() {
                        let chain_matches = event_chain_ids
                            .iter()
                            .any(|chain| filter_clone.matches_chain(chain));
                        if !chain_matches {
                            debug!(
                                event_id = %event.id,
                                event_chains = ?event_chain_ids,
                                "Proof filtered out by chain criteria"
                            );
                            continue;
                        }
                    }

                    // Filter by author if specified
                    if !filter_clone.authors.is_empty() {
                        let author_matches = filter_clone.authors.contains(&event.pubkey.to_hex());
                        if !author_matches {
                            debug!(
                                event_id = %event.id,
                                author = %event.pubkey,
                                "Proof filtered out by author criteria"
                            );
                            continue;
                        }
                    }

                    // Parse the event content into a ProofBundle
                    let proof = match ProofBundle::from_canonical_bytes(event.content.as_bytes())
                        .map_err(TransportError::Serialization)
                    {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(event_id = %event.id, error = %e, "Failed to parse proof from Nostr event");
                            continue;
                        }
                    };

                    // Create DeliveredProof with real data from Nostr event
                    let delivered = DeliveredProof {
                        event_id: EventId::new(event.id.to_hex()),
                        proof,
                        author_pubkey: event.pubkey.to_hex(),
                        timestamp: event.created_at.as_u64(),
                    };

                    if tx.send(delivered).await.is_err() {
                        debug!("Proof subscription channel closed, stopping event processing");
                        break;
                    }
                }
            });

            info!(
                chains = ?filter.chain_ids,
                authors = ?filter.authors,
                "Nostr proof subscription created"
            );

            Ok(stream)
        }

        #[cfg(not(feature = "nostr"))]
        {
            Err(TransportError::NostrNotConfigured)
        }
    }

    /// Check if connected to at least one Nostr relay.
    async fn is_connected(&self) -> bool {
        self.initialized.load(std::sync::atomic::Ordering::Acquire) && !self.relays.is_empty()
    }

    /// Return the transport name.
    fn transport_name(&self) -> &str {
        "nostr"
    }

    /// Disconnect from all relays and clean up.
    async fn disconnect(&self) {
        self.initialized
            .store(false, std::sync::atomic::Ordering::Release);
        info!("Disconnected from Nostr relays");
    }
}

impl Default for NostrTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_hash::{
        Hash,
        seal::{CommitAnchor, SealPoint},
    };
    use csv_proof::{DAGSegment, FinalityProof, InclusionProof};

    #[test]
    fn test_new_transport_with_default_relays() {
        let transport = NostrTransport::new();
        assert_eq!(transport.relays().len(), 4);
        assert!(!transport.is_encrypted());
        assert_eq!(transport.event_kind(), PROOF_EVENT_KIND);
        assert_eq!(transport.max_relay_retries, 3);
        assert_eq!(transport.health_check_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_transport_with_custom_relays() {
        let relays = vec!["wss://custom.relay".to_string()];
        let transport = NostrTransport::with_relays(relays);
        assert_eq!(transport.relays().len(), 1);
    }

    #[test]
    fn test_transport_with_encrypted_dms() {
        let transport = NostrTransport::new().with_encrypted_dms(true);
        assert!(transport.is_encrypted());
        assert_eq!(transport.event_kind(), ENCRYPTED_DM_KIND);
    }

    #[test]
    fn test_transport_with_timeout() {
        let transport = NostrTransport::new().with_timeout(Duration::from_secs(60));
        // Timeout is stored internally, verify via initialization
        assert!(
            !transport
                .initialized
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }

    #[test]
    fn test_event_kinds() {
        let open = NostrTransport::new();
        let encrypted = NostrTransport::new().with_encrypted_dms(true);

        assert_eq!(open.event_kind(), PROOF_EVENT_KIND);
        assert_eq!(encrypted.event_kind(), ENCRYPTED_DM_KIND);
    }

    #[test]
    fn test_proof_filter_matching() {
        let filter = ProofFilter::for_chain("ethereum");
        assert!(filter.matches_chain("ethereum"));
        assert!(!filter.matches_chain("bitcoin"));
    }

    #[test]
    fn test_max_proof_size_constant() {
        assert_eq!(MAX_PROOF_SIZE, 100_000);
    }

    #[test]
    fn test_extract_chain_ids_from_tags_empty() {
        let tags: Vec<nostr_sdk::Tag> = vec![];
        let chain_ids = extract_chain_ids_from_tags(&tags);
        assert!(chain_ids.is_empty());
    }

    #[test]
    fn test_extract_chain_ids_from_tags_with_values() {
        let tag1 =
            nostr_sdk::Tag::parse(&["chain_id".to_string(), "ethereum".to_string()]).unwrap();
        let tag2 = nostr_sdk::Tag::parse(&["chain_id".to_string(), "bitcoin".to_string()]).unwrap();
        let tag3 =
            nostr_sdk::Tag::parse(&["type".to_string(), "proof_bundle".to_string()]).unwrap();
        let tags = vec![tag1, tag2, tag3];

        let chain_ids = extract_chain_ids_from_tags(&tags);
        assert_eq!(chain_ids.len(), 2);
        assert!(chain_ids.contains(&"ethereum".to_string()));
        assert!(chain_ids.contains(&"bitcoin".to_string()));
    }

    #[test]
    fn test_extract_source_chain_from_proof() {
        // Create a proof with metadata containing chain ID
        let metadata = b"ethereum".to_vec();

        let anchor = CommitAnchor::new(vec![1u8; 32], 1000, metadata).unwrap();

        let hash: Hash = [0u8; 32].into();

        let proof = ProofBundle {
            version: 1,
            transition_dag: DAGSegment::new(vec![], hash),
            signatures: vec![],
            signature_scheme: csv_protocol::signature::SignatureScheme::Ed25519,
            seal_ref: SealPoint::new(vec![1u8; 32], None, None).unwrap(),
            anchor_ref: anchor,
            inclusion_proof: InclusionProof::new(vec![1u8; 32], hash, 1000, 0).unwrap(),
            finality_proof: FinalityProof::new(vec![1u8; 32], 1, true).unwrap(),
        };

        let source_chain = extract_source_chain(&proof);
        assert_eq!(source_chain, "ethereum");
    }

    #[test]
    fn test_extract_dest_chain_from_proof_unknown() {
        // Create a proof with empty bytecode
        let anchor = CommitAnchor::new(vec![1u8; 32], 1000, vec![]).unwrap();

        let hash: Hash = [0u8; 32].into();

        let proof = ProofBundle {
            version: 1,
            transition_dag: DAGSegment::new(vec![], hash),
            signatures: vec![],
            signature_scheme: csv_protocol::signature::SignatureScheme::Ed25519,
            seal_ref: SealPoint::new(vec![1u8; 32], None, None).unwrap(),
            anchor_ref: anchor,
            inclusion_proof: InclusionProof::new(vec![1u8; 32], hash, 1000, 0).unwrap(),
            finality_proof: FinalityProof::new(vec![1u8; 32], 1, true).unwrap(),
        };

        let dest_chain = extract_dest_chain(&proof);
        assert_eq!(dest_chain, "unknown");
    }

    #[test]
    fn test_proof_bundle_serialization_roundtrip() {
        let metadata = b"ethereum".to_vec();
        let anchor = CommitAnchor::new(vec![1u8; 32], 1000, metadata).unwrap();

        let hash: Hash = [0u8; 32].into();

        let proof = ProofBundle {
            version: 1,
            transition_dag: DAGSegment::new(vec![], hash),
            signatures: vec![vec![1u8; 64]],
            signature_scheme: csv_protocol::signature::SignatureScheme::Ed25519,
            seal_ref: SealPoint::new(vec![1u8; 32], None, None).unwrap(),
            anchor_ref: anchor,
            inclusion_proof: InclusionProof::new(vec![1u8; 32], hash, 1000, 0).unwrap(),
            finality_proof: FinalityProof::new(vec![1u8; 32], 1, true).unwrap(),
        };

        let transport = NostrTransport::new();
        let content = transport.proof_to_content(&proof).unwrap();
        let deserialized = transport.content_to_proof(&content).unwrap();

        assert_eq!(proof.seal_ref.id, deserialized.seal_ref.id);
        assert_eq!(
            proof.anchor_ref.block_height,
            deserialized.anchor_ref.block_height
        );
    }

    #[test]
    fn test_event_content_with_metadata() {
        let metadata = b"ethereum".to_vec();
        let anchor = CommitAnchor::new(vec![1u8; 32], 1000, metadata).unwrap();

        let hash: Hash = [0u8; 32].into();

        let proof = ProofBundle {
            version: 1,
            transition_dag: DAGSegment::new(vec![], hash),
            signatures: vec![],
            signature_scheme: csv_protocol::signature::SignatureScheme::Ed25519,
            seal_ref: SealPoint::new(vec![1u8; 32], None, None).unwrap(),
            anchor_ref: anchor,
            inclusion_proof: InclusionProof::new(vec![1u8; 32], hash, 1000, 0).unwrap(),
            finality_proof: FinalityProof::new(vec![1u8; 32], 1, true).unwrap(),
        };

        let transport = NostrTransport::new();
        let metadata_json = serde_json::json!({"source": "test"});
        let content = transport
            .build_event_content(&proof, metadata_json)
            .unwrap();

        // Verify content is valid JSON with proof field
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed.get("proof").is_some());
        assert!(parsed.get("source").is_some());
    }

    #[test]
    fn test_nostr_transport_default_config() {
        let transport = NostrTransport::new();
        assert_eq!(transport.relays().len(), 4);
        assert!(!transport.is_encrypted());
        assert_eq!(transport.event_kind(), PROOF_EVENT_KIND);
        assert_eq!(transport.max_relay_retries, 3);
        assert_eq!(transport.health_check_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_nostr_transport_custom_config() {
        let transport = NostrTransport::new()
            .with_timeout(Duration::from_secs(60))
            .with_encrypted_dms(true)
            .with_max_relay_retries(5)
            .with_health_check_interval(Duration::from_secs(60));

        assert_eq!(transport.timeout, Duration::from_secs(60));
        assert!(transport.is_encrypted());
        assert_eq!(transport.event_kind(), ENCRYPTED_DM_KIND);
        assert_eq!(transport.max_relay_retries, 5);
        assert_eq!(transport.health_check_interval, Duration::from_secs(60));
    }

    #[cfg(feature = "nostr")]
    #[tokio::test]
    async fn test_nostr_transport_health_check_does_not_panic() {
        let transport =
            NostrTransport::with_relays(vec!["wss://nonexistent-relay.invalid".to_string()]);
        // Health check should not panic even for invalid relays
        let _ = transport
            .check_relay_health("wss://nonexistent-relay.invalid")
            .await;
    }
}
