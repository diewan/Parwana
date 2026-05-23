//! Encrypted IndexedDB storage for sensitive seal nullifier data
//!
//! CRITICAL FIX: Replaces unencrypted localStorage with AES-GCM encrypted IndexedDB.
//! All seal nullifiers and sensitive state are encrypted at rest with HMAC integrity.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use csv_core::mcp::{FixAction, HasErrorSuggestion, error_codes};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::state::StorageError;

/// HMAC-SHA256 type alias
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
type HmacSha256 = Hmac<Sha256>;

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const INDEX_KEY: &str = "__csv_encrypted_index";

/// Encryption error types
#[derive(Debug, thiserror::Error)]
pub enum EncryptedStorageError {
    /// Encryption/decryption error
    #[error("Crypto error: {0}")]
    CryptoError(String),
    /// Browser API error
    #[error("Browser API error: {0}")]
    BrowserError(String),
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializeError(String),
    /// Not found
    #[error("Not found: {0}")]
    NotFound(String),
    /// Integrity check failed
    #[error("Integrity check failed: {0}")]
    IntegrityError(String),
}

impl From<EncryptedStorageError> for StorageError {
    fn from(e: EncryptedStorageError) -> Self {
        StorageError::SerializeError(e.to_string())
    }
}

impl HasErrorSuggestion for EncryptedStorageError {
    fn error_code(&self) -> &'static str {
        error_codes::WALLET_BROWSER_STORAGE
    }

    fn description(&self) -> String {
        self.to_string()
    }

    fn suggested_fix(&self) -> String {
        match self {
            EncryptedStorageError::CryptoError(_) => "Encryption/decryption failed. \
                 Check: 1) Browser supports WebCrypto API, \
                 2) Storage key hasn't been corrupted. \
                 You may need to re-import your wallet."
                .to_string(),
            EncryptedStorageError::IntegrityError(_) => "Data integrity check failed. \
                 This could indicate tampering or storage corruption. \
                 Do not proceed with transactions - verify your system security."
                .to_string(),
            EncryptedStorageError::BrowserError(_) => "IndexedDB error. Check: \
                 1) Browser storage is enabled, \
                 2) Not in private/incognito mode, \
                 3) Storage quota available."
                .to_string(),
            EncryptedStorageError::SerializeError(_) => "Data serialization failed. \
                 Ensure data format is valid."
                .to_string(),
            EncryptedStorageError::NotFound(key) => {
                format!("Item '{}' not found in encrypted storage.", key)
            }
        }
    }

    fn docs_url(&self) -> String {
        error_codes::docs_url(self.error_code())
    }

    fn fix_action(&self) -> Option<FixAction> {
        match self {
            EncryptedStorageError::CryptoError(_) => Some(FixAction::CheckState {
                url: "https://docs.csv.dev/wallet/encrypted-storage".to_string(),
                what: "Verify WebCrypto API is available".to_string(),
            }),
            EncryptedStorageError::IntegrityError(_) => Some(FixAction::CheckState {
                url: "https://docs.csv.dev/wallet/security".to_string(),
                what: "SECURITY WARNING: Verify system integrity".to_string(),
            }),
            _ => None,
        }
    }
}

/// Encrypted envelope for stored data
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
struct EncryptedEnvelope {
    /// AES-GCM ciphertext
    ciphertext: Vec<u8>,
    /// Nonce (12 bytes for AES-GCM)
    nonce: Vec<u8>,
    /// HMAC-SHA256 for integrity
    hmac: Vec<u8>,
    /// Version for future compatibility
    version: u32,
}

impl EncryptedEnvelope {
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    const CURRENT_VERSION: u32 = 1;

    /// Create new envelope from plaintext
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Self, EncryptedStorageError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| EncryptedStorageError::CryptoError(format!("Key init failed: {}", e)))?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| EncryptedStorageError::CryptoError(format!("Encryption failed: {}", e)))?;

        // Compute HMAC for integrity
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|e| EncryptedStorageError::CryptoError(format!("HMAC init failed: {}", e)))?;
        mac.update(&ciphertext);
        mac.update(nonce.as_slice());
        let hmac = mac.finalize().into_bytes().to_vec();

        Ok(EncryptedEnvelope {
            ciphertext,
            nonce: nonce.as_slice().to_vec(),
            hmac,
            version: Self::CURRENT_VERSION,
        })
    }

    /// Decrypt envelope to plaintext
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    fn decrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>, EncryptedStorageError> {
        // Verify HMAC first. `verify_slice` performs a constant-time comparison.
        <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|e| EncryptedStorageError::CryptoError(format!("HMAC init failed: {}", e)))?
            .chain_update(&self.ciphertext)
            .chain_update(&self.nonce)
            .verify_slice(&self.hmac)
            .map_err(|_| {
                EncryptedStorageError::IntegrityError(
                    "HMAC verification failed - data may be tampered".to_string(),
                )
            })?;

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| EncryptedStorageError::CryptoError(format!("Key init failed: {}", e)))?;
        let nonce = Nonce::from_slice(&self.nonce);

        cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|e| EncryptedStorageError::CryptoError(format!("Decryption failed: {}", e)))
            .map(|pt| pt.to_vec())
    }
}

/// Encrypted IndexedDB storage manager
pub struct EncryptedStorageManager {
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    db_name: String,
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    store_name: String,
    key: [u8; 32],
}

impl EncryptedStorageManager {
    /// Create new encrypted storage manager
    ///
    /// # Security Note
    /// The key must be derived from a user password or secure key material.
    /// Do NOT hardcode keys in production.
    pub fn new(db_name: &str, store_name: &str, key: [u8; 32]) -> Self {
        Self {
            db_name: db_name.to_string(),
            store_name: store_name.to_string(),
            key,
        }
    }

    /// Derive encryption key from password using PBKDF2
    #[cfg(target_arch = "wasm32")]
    pub async fn derive_key_from_password(
        password: &str,
        salt: &[u8],
    ) -> Result<[u8; 32], EncryptedStorageError> {
        use pbkdf2::pbkdf2_hmac;

        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
        Ok(key)
    }

    /// Save encrypted item to IndexedDB
    #[cfg(target_arch = "wasm32")]
    pub async fn save<T: Serialize>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), EncryptedStorageError> {
        self.save_without_index(key, value).await?;
        self.add_index_key(key).await
    }

    #[cfg(target_arch = "wasm32")]
    async fn save_without_index<T: Serialize>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), EncryptedStorageError> {
        let plaintext = serde_json::to_vec(value)
            .map_err(|e| EncryptedStorageError::SerializeError(e.to_string()))?;

        let envelope = EncryptedEnvelope::encrypt(&plaintext, &self.key)?;

        let js_value = serde_wasm_bindgen::to_value(&envelope).map_err(|e| {
            EncryptedStorageError::BrowserError(format!("JS conversion failed: {}", e))
        })?;

        self.set_indexeddb(key, js_value).await
    }

    /// Load and decrypt item from IndexedDB
    #[cfg(target_arch = "wasm32")]
    pub async fn load<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<T, EncryptedStorageError> {
        let js_value = self
            .get_indexeddb(key)
            .await?
            .ok_or_else(|| EncryptedStorageError::NotFound(key.to_string()))?;

        let envelope: EncryptedEnvelope =
            serde_wasm_bindgen::from_value(js_value).map_err(|e| {
                EncryptedStorageError::SerializeError(format!("JS conversion failed: {}", e))
            })?;

        let plaintext = envelope.decrypt(&self.key)?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| EncryptedStorageError::SerializeError(e.to_string()))
    }

    /// Delete item from IndexedDB
    #[cfg(target_arch = "wasm32")]
    pub async fn delete(&self, key: &str) -> Result<(), EncryptedStorageError> {
        self.delete_indexeddb(key).await?;
        self.remove_index_key(key).await
    }

    /// Check if key exists
    #[cfg(target_arch = "wasm32")]
    pub async fn contains(&self, key: &str) -> bool {
        self.get_indexeddb(key).await.ok().flatten().is_some()
    }

    /// List encrypted item keys without scanning plaintext localStorage.
    #[cfg(target_arch = "wasm32")]
    pub async fn list_keys(&self) -> Result<Vec<String>, EncryptedStorageError> {
        match self.load::<Vec<String>>(INDEX_KEY).await {
            Ok(keys) => Ok(keys.into_iter().filter(|key| key != INDEX_KEY).collect()),
            Err(EncryptedStorageError::NotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Load all indexed values. A stale index entry is a storage-integrity error.
    #[cfg(target_arch = "wasm32")]
    pub async fn load_all<T: for<'de> Deserialize<'de>>(
        &self,
    ) -> Result<Vec<T>, EncryptedStorageError> {
        let keys = self.list_keys().await?;
        let mut values = Vec::with_capacity(keys.len());

        for key in keys {
            values.push(self.load::<T>(&key).await.map_err(|e| {
                EncryptedStorageError::IntegrityError(format!(
                    "Encrypted index references unreadable key '{}': {}",
                    key, e
                ))
            })?);
        }

        Ok(values)
    }

    /// Move legacy localStorage entries into encrypted IndexedDB and remove the plaintext copy.
    #[cfg(target_arch = "wasm32")]
    pub async fn migrate_local_storage_prefix<T: Serialize + for<'de> Deserialize<'de>>(
        &self,
        prefix: &str,
    ) -> Result<usize, EncryptedStorageError> {
        let window = web_sys::window()
            .ok_or_else(|| EncryptedStorageError::BrowserError("No window".to_string()))?;
        let storage = window
            .local_storage()
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?
            .ok_or_else(|| {
                EncryptedStorageError::BrowserError("localStorage not available".to_string())
            })?;

        let mut keys = Vec::new();
        for i in 0..storage.length().unwrap_or(0) {
            if let Some(full_key) = storage.key(i).ok().flatten() {
                if full_key.starts_with(prefix) {
                    keys.push(full_key);
                }
            }
        }

        let mut migrated = 0usize;
        for full_key in keys {
            let Some(raw) = storage
                .get_item(&full_key)
                .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?
            else {
                continue;
            };
            let value = serde_json::from_str::<T>(&raw)
                .map_err(|e| EncryptedStorageError::SerializeError(e.to_string()))?;
            let encrypted_key = full_key.strip_prefix(prefix).unwrap_or(&full_key);

            self.save(encrypted_key, &value).await?;
            storage
                .remove_item(&full_key)
                .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;
            migrated += 1;
        }

        Ok(migrated)
    }

    #[cfg(target_arch = "wasm32")]
    async fn add_index_key(&self, key: &str) -> Result<(), EncryptedStorageError> {
        if key == INDEX_KEY {
            return Ok(());
        }

        let mut keys = self.list_keys().await?;
        if !keys.iter().any(|existing| existing == key) {
            keys.push(key.to_string());
            keys.sort();
            self.save_without_index(INDEX_KEY, &keys).await?;
        }

        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    async fn remove_index_key(&self, key: &str) -> Result<(), EncryptedStorageError> {
        if key == INDEX_KEY {
            return Ok(());
        }

        let mut keys = self.list_keys().await?;
        let before = keys.len();
        keys.retain(|existing| existing != key);
        if keys.len() != before {
            self.save_without_index(INDEX_KEY, &keys).await?;
        }

        Ok(())
    }

    /// IndexedDB set operation via web-sys
    #[cfg(target_arch = "wasm32")]
    async fn set_indexeddb(
        &self,
        key: &str,
        value: wasm_bindgen::JsValue,
    ) -> Result<(), EncryptedStorageError> {
        use web_sys::IdbTransactionMode;

        let db = self.open_database().await?;

        // Start transaction
        let transaction = db
            .transaction_with_str_and_mode(&self.store_name, IdbTransactionMode::Readwrite)
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        let store = transaction
            .object_store(&self.store_name)
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        // Put value
        let put_request = store
            .put_with_key(&value, &wasm_bindgen::JsValue::from_str(key))
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        Self::await_idb_request(put_request).await?;

        Ok(())
    }

    /// IndexedDB get operation via web-sys
    #[cfg(target_arch = "wasm32")]
    async fn get_indexeddb(
        &self,
        key: &str,
    ) -> Result<Option<wasm_bindgen::JsValue>, EncryptedStorageError> {
        use web_sys::IdbTransactionMode;

        let db = self.open_database().await?;

        let transaction = db
            .transaction_with_str_and_mode(&self.store_name, IdbTransactionMode::Readonly)
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        let store = transaction
            .object_store(&self.store_name)
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        let get_request = store
            .get(&wasm_bindgen::JsValue::from_str(key))
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        let result = Self::await_idb_request(get_request).await?;

        if result.is_null() || result.is_undefined() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// IndexedDB delete operation via web-sys
    #[cfg(target_arch = "wasm32")]
    async fn delete_indexeddb(&self, key: &str) -> Result<(), EncryptedStorageError> {
        use web_sys::IdbTransactionMode;

        let db = self.open_database().await?;

        let transaction = db
            .transaction_with_str_and_mode(&self.store_name, IdbTransactionMode::Readwrite)
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        let store = transaction
            .object_store(&self.store_name)
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        let delete_request = store
            .delete(&wasm_bindgen::JsValue::from_str(key))
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        Self::await_idb_request(delete_request).await?;

        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    async fn open_database(&self) -> Result<web_sys::IdbDatabase, EncryptedStorageError> {
        use wasm_bindgen::JsCast;
        use wasm_bindgen::closure::Closure;

        let window = web_sys::window()
            .ok_or_else(|| EncryptedStorageError::BrowserError("No window".to_string()))?;
        let indexed_db = window
            .indexed_db()
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?
            .ok_or_else(|| {
                EncryptedStorageError::BrowserError("IndexedDB not available".to_string())
            })?;

        let open_request = indexed_db
            .open_with_u32(&self.db_name, 1)
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))?;

        let store_name = self.store_name.clone();
        let on_upgrade =
            Closure::<dyn FnMut(_)>::new(move |event: web_sys::IdbVersionChangeEvent| {
                let Some(target) = event.target() else {
                    return;
                };
                let Ok(request) = target.dyn_into::<web_sys::IdbOpenDbRequest>() else {
                    return;
                };
                let Ok(db) = request
                    .result()
                    .and_then(|value| value.dyn_into::<web_sys::IdbDatabase>())
                else {
                    return;
                };
                if !db.object_store_names().contains(&store_name) {
                    let _ = db.create_object_store(&store_name);
                }
            });
        open_request.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
        on_upgrade.forget();

        Self::await_idb_request(open_request.into())
            .await?
            .dyn_into()
            .map_err(|_| EncryptedStorageError::BrowserError("Invalid DB".to_string()))
    }

    #[cfg(target_arch = "wasm32")]
    async fn await_idb_request(
        request: web_sys::IdbRequest,
    ) -> Result<wasm_bindgen::JsValue, EncryptedStorageError> {
        use js_sys::{Function, Promise};
        use wasm_bindgen::JsCast;
        use wasm_bindgen::JsValue;
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen_futures::JsFuture;

        let promise = Promise::new(&mut |resolve: Function, reject: Function| {
            let success_request = request.clone();
            let on_success = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
                let value = success_request.result().unwrap_or(JsValue::UNDEFINED);
                let _ = resolve.call1(&JsValue::NULL, &value);
            });

            let error_request = request.clone();
            let on_error = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
                let _ = error_request;
                let _ = reject.call1(
                    &JsValue::NULL,
                    &JsValue::from_str("IndexedDB request failed"),
                );
            });

            request.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
            request.set_onerror(Some(on_error.as_ref().unchecked_ref()));
            on_success.forget();
            on_error.forget();
        });

        JsFuture::from(promise)
            .await
            .map_err(|e| EncryptedStorageError::BrowserError(format!("{:?}", e)))
    }
}

impl Drop for EncryptedStorageManager {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Factory for seal nullifier encrypted storage
pub fn seal_nullifier_storage(key: [u8; 32]) -> EncryptedStorageManager {
    EncryptedStorageManager::new("csv-seal-nullifiers", "nullifiers", key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let plaintext = b"test seal nullifier data";

        let envelope = EncryptedEnvelope::encrypt(plaintext, &key).unwrap();
        let decrypted = envelope.decrypt(&key).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_envelope_nonce_is_aes_gcm_size() {
        let key = [0x42u8; 32];
        let envelope = EncryptedEnvelope::encrypt(b"nonce size regression", &key).unwrap();

        assert_eq!(envelope.nonce.len(), 12);
    }

    #[test]
    fn test_integrity_failure() {
        let key = [0x42u8; 32];
        let plaintext = b"test data";

        let mut envelope = EncryptedEnvelope::encrypt(plaintext, &key).unwrap();
        // Tamper with ciphertext
        envelope.ciphertext[0] ^= 0xFF;

        let result = envelope.decrypt(&key);
        assert!(matches!(
            result,
            Err(EncryptedStorageError::IntegrityError(_))
        ));
    }

    /// Regression test: Verify encryption produces different ciphertext for same plaintext
    /// This ensures the nonce is properly randomized each time.
    #[test]
    fn test_encryption_produces_different_ciphertext() {
        let key = [0x42u8; 32];
        let plaintext = b"test seal nullifier data";

        let envelope1 = EncryptedEnvelope::encrypt(plaintext, &key).unwrap();
        let envelope2 = EncryptedEnvelope::encrypt(plaintext, &key).unwrap();

        // Ciphertexts should differ due to random nonce
        assert_ne!(
            envelope1.ciphertext, envelope2.ciphertext,
            "Encryption should produce different ciphertext for same plaintext (nonce randomization)"
        );

        // But both should decrypt to the same plaintext
        assert_eq!(plaintext.to_vec(), envelope1.decrypt(&key).unwrap());
        assert_eq!(plaintext.to_vec(), envelope2.decrypt(&key).unwrap());
    }

    /// Regression test: Verify HMAC integrity check catches tampering
    #[test]
    fn test_hmac_catches_nonce_tampering() {
        let key = [0x42u8; 32];
        let plaintext = b"test data";

        let mut envelope = EncryptedEnvelope::encrypt(plaintext, &key).unwrap();
        // Tamper with nonce
        envelope.nonce[0] ^= 0xFF;

        let result = envelope.decrypt(&key);
        assert!(matches!(
            result,
            Err(EncryptedStorageError::IntegrityError(_))
        ));
    }

    /// Regression test: Verify key derivation produces consistent keys
    #[cfg(target_arch = "wasm32")]
    #[tokio::test]
    async fn test_key_derivation_consistency() {
        let password = "test-password";
        let salt = b"test-salt";

        let key1 = EncryptedStorageManager::derive_key_from_password(password, salt)
            .await
            .unwrap();
        let key2 = EncryptedStorageManager::derive_key_from_password(password, salt)
            .await
            .unwrap();

        assert_eq!(
            key1, key2,
            "Key derivation should be deterministic for same password/salt"
        );
    }
}
