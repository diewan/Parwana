//! Agent-friendly SDK error metadata.
#![allow(missing_docs)]

use serde::Serialize;
use std::collections::HashMap;

/// Machine-actionable remediation for an SDK error.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FixAction {
    FundFromFaucet {
        url: String,
        amount: String,
    },
    Retry {
        parameter_changes: HashMap<String, String>,
    },
    CheckState {
        url: String,
        what: String,
    },
    WaitForConfirmations {
        confirmations: u32,
        estimated_seconds: u64,
    },
}

/// Structured error presentation for SDK callers.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorSuggestion {
    pub message: String,
    pub fix: Option<FixAction>,
    pub docs_url: String,
    pub error_code: String,
}

/// An error that can describe a suggested remediation.
pub trait HasErrorSuggestion {
    fn error_code(&self) -> &'static str;
    fn description(&self) -> String;
    fn suggested_fix(&self) -> String;
    fn docs_url(&self) -> String;
    fn fix_action(&self) -> Option<FixAction>;

    fn to_suggestion(&self) -> ErrorSuggestion {
        ErrorSuggestion {
            error_code: self.error_code().to_string(),
            message: self.description(),
            docs_url: self.docs_url(),
            fix: self.fix_action(),
        }
    }
}

/// Stable SDK error codes.
pub mod error_codes {
    pub const CSV_CHAIN_NOT_SUPPORTED: &str = "CSV_001";
    pub const CSV_CHAIN_NOT_ENABLED: &str = "CSV_002";
    pub const CSV_INSUFFICIENT_FUNDS: &str = "CSV_003";
    pub const CSV_INVALID_SANAD_ID: &str = "CSV_004";
    pub const CSV_SANAD_NOT_FOUND: &str = "CSV_005";
    pub const CSV_TRANSFER_NOT_FOUND: &str = "CSV_006";
    pub const CSV_SANAD_ALREADY_CONSUMED: &str = "CSV_007";
    pub const CSV_TRANSFER_FAILED: &str = "CSV_008";
    pub const CSV_INVALID_COMMITMENT: &str = "CSV_009";
    pub const CSV_PROOF_VERIFICATION_FAILED: &str = "CSV_010";
    pub const CSV_WALLET_ERROR: &str = "CSV_011";
    pub const CSV_NETWORK_ERROR: &str = "CSV_012";
    pub const CSV_SERIALIZATION_ERROR: &str = "CSV_013";
    pub const CSV_CONFIG_ERROR: &str = "CSV_014";
    pub const CSV_STORE_ERROR: &str = "CSV_015";
    pub const CSV_BUILDER_ERROR: &str = "CSV_016";
    pub const CSV_DEPLOYMENT_ERROR: &str = "CSV_017";
    pub const CSV_EVENT_STREAM_ERROR: &str = "CSV_018";
    pub const CSV_ADAPTER_ERROR: &str = "CSV_019";
    pub const CSV_GENERIC: &str = "CSV_099";

    pub fn docs_url(error_code: &str) -> String {
        format!("https://docs.csv.dev/errors/{}", error_code)
    }
}
