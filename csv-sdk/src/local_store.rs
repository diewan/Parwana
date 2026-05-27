//! Client-local Sanad storage used by the lightweight SDK client.
#![allow(missing_docs)]

use csv_hash::sanad::SanadId;
use serde::{Deserialize, Serialize};

/// A persisted Sanad record owned by the SDK client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanadRecord {
    pub sanad_id: SanadId,
    pub chain: String,
    pub owner: Vec<u8>,
    pub sanad_data: Vec<u8>,
    pub consumed: bool,
    pub recorded_at: u64,
    pub consumed_at: Option<u64>,
}

/// Failure returned by client-local storage operations.
#[derive(Debug)]
pub enum StoreError {
    DuplicateRecord(String),
    NotFound(String),
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateRecord(message) => write!(f, "Duplicate record: {}", message),
            Self::NotFound(message) => write!(f, "Not found: {}", message),
        }
    }
}

/// Minimal in-memory Sanad store for SDK sessions.
pub struct InMemorySealStore {
    sanads: Vec<SanadRecord>,
}

impl InMemorySealStore {
    pub fn new() -> Self {
        Self { sanads: Vec::new() }
    }

    pub fn save_sanad(&mut self, record: &SanadRecord) -> Result<(), StoreError> {
        if self.has_sanad(&record.sanad_id)? {
            return Err(StoreError::DuplicateRecord(format!(
                "Sanad with ID {:?} already exists",
                record.sanad_id
            )));
        }
        self.sanads.push(record.clone());
        Ok(())
    }

    pub fn get_sanad(&self, sanad_id: &SanadId) -> Result<Option<SanadRecord>, StoreError> {
        Ok(self
            .sanads
            .iter()
            .find(|record| record.sanad_id.0.as_bytes() == sanad_id.0.as_bytes())
            .cloned())
    }

    pub fn list_sanads_by_chain(&self, chain: &str) -> Result<Vec<SanadRecord>, StoreError> {
        Ok(self
            .sanads
            .iter()
            .filter(|record| record.chain == chain)
            .cloned()
            .collect())
    }

    pub fn consume_sanad(
        &mut self,
        sanad_id: &SanadId,
        consumed_at: u64,
    ) -> Result<(), StoreError> {
        let record = self
            .sanads
            .iter_mut()
            .find(|record| record.sanad_id.0.as_bytes() == sanad_id.0.as_bytes())
            .ok_or_else(|| StoreError::NotFound(format!("Sanad {:?} not found", sanad_id)))?;
        if record.consumed {
            return Err(StoreError::DuplicateRecord(format!(
                "Sanad {:?} already consumed",
                sanad_id
            )));
        }
        record.consumed = true;
        record.consumed_at = Some(consumed_at);
        Ok(())
    }

    pub fn list_active_sanads(&self) -> Result<Vec<SanadRecord>, StoreError> {
        Ok(self
            .sanads
            .iter()
            .filter(|record| !record.consumed)
            .cloned()
            .collect())
    }

    pub fn has_sanad(&self, sanad_id: &SanadId) -> Result<bool, StoreError> {
        Ok(self
            .sanads
            .iter()
            .any(|record| record.sanad_id.0.as_bytes() == sanad_id.0.as_bytes()))
    }
}

impl Default for InMemorySealStore {
    fn default() -> Self {
        Self::new()
    }
}
