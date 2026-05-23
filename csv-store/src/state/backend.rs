//! Storage backend trait and implementations.
//!
//! Provides pluggable storage backends for different environments:
//! - FileStorage: Desktop CLI (JSON files)
//! - (Browser storage is in browser_storage.rs)

use super::storage::StateStorage;
use thiserror::Error;

/// Storage backend error types.
#[derive(Debug, Error)]
pub enum StorageError {
    /// IO error.
    #[error("IO error: {0}")]
    IoError(String),
    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializeError(String),
    /// Item not found.
    #[error("Not found: {0}")]
    NotFound(String),
    /// Version mismatch during migration.
    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },
}

/// Trait for storage backends (file-based, localStorage, SQLite, etc.)
pub trait StorageBackend {
    /// Load state from storage.
    fn load(&self) -> Result<StateStorage, StorageError>;

    /// Save state to storage.
    fn save(&self, storage: &StateStorage) -> Result<(), StorageError>;

    /// Check if storage exists.
    fn exists(&self) -> bool;
}

/// File-based storage backend (for CLI/desktop).
#[cfg(all(not(target_arch = "wasm32"), feature = "file-storage"))]
pub struct FileStorage {
    /// Path to the storage file.
    pub path: String,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "file-storage"))]
impl FileStorage {
    /// Create new file storage at the given path.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    /// Default storage path (~/.csv/state.json).
    pub fn default_path() -> String {
        if let Some(home) = dirs::home_dir() {
            home.join(".csv/state.json").to_string_lossy().to_string()
        } else {
            std::env::temp_dir()
                .join("csv-state.json")
                .to_string_lossy()
                .to_string()
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "file-storage"))]
impl StorageBackend for FileStorage {
    fn load(&self) -> Result<StateStorage, StorageError> {
        let path = std::path::Path::new(&self.path);
        if !path.exists() {
            return Ok(StateStorage::new().with_defaults());
        }

        let content = std::fs::read_to_string(&self.path)
            .map_err(|e| StorageError::IoError(e.to_string()))?;

        let storage: StateStorage = serde_json::from_str(&content)
            .map_err(|e| StorageError::SerializeError(e.to_string()))?;

        Ok(storage)
    }

    fn save(&self, storage: &StateStorage) -> Result<(), StorageError> {
        let path = std::path::Path::new(&self.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StorageError::IoError(e.to_string()))?;
        }

        let content = serde_json::to_string_pretty(storage)
            .map_err(|e| StorageError::SerializeError(e.to_string()))?;

        std::fs::write(&self.path, content).map_err(|e| StorageError::IoError(e.to_string()))?;

        Ok(())
    }

    fn exists(&self) -> bool {
        std::path::Path::new(&self.path).exists()
    }
}
