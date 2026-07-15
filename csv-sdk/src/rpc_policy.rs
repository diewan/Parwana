//! Typed RPC endpoint selection and trust policy.
//!
//! This module contains configuration data and deterministic selection only. It
//! never reads process environment variables, `.env` files, browser storage, or
//! the filesystem. Applications may obtain a policy from those sources, but
//! must pass the resulting value explicitly.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Transport spoken by an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcTransport {
    /// JSON-RPC carried over HTTP(S).
    JsonRpcHttp,
    /// JSON-RPC or chain subscription protocol carried over WebSocket.
    WebSocket,
    /// A chain-specific HTTP REST API.
    Rest,
    /// A chain-specific gRPC API.
    Grpc,
}

/// Operation an endpoint is allowed to serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcCapability {
    /// Non-authoritative wallet/UI reads.
    Read,
    /// Transaction submission. Confirmation must use independent evidence.
    Broadcast,
    /// Subscription delivery.
    Subscribe,
    /// Address history or UTXO discovery.
    AddressIndex,
    /// Evidence used by protocol verification or finality decisions.
    Verify,
}

/// Where an endpoint definition came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcEndpointSource {
    /// Shipped in the reviewed application/chain registry.
    BuiltIn,
    /// Explicitly supplied by the user or deployment operator.
    User,
}

/// Which source groups may be selected and in what order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcSelectionMode {
    /// Use only reviewed endpoints shipped with the application.
    #[default]
    BuiltInOnly,
    /// Use only endpoints explicitly supplied by the user/operator.
    UserOnly,
    /// Prefer user endpoints and then use built-ins. This must be explicit.
    UserThenBuiltIn,
}

/// Trust requirement for a class of RPC operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum RpcTrustRequirement {
    /// One endpoint is sufficient for non-authoritative data.
    Single,
    /// Independent providers must reach the configured agreement threshold.
    Quorum {
        /// Minimum number of independent providers queried.
        min_providers: u8,
        /// Minimum agreeing responses.
        min_agreement: u8,
    },
}

/// Reference to a credential held by an application-owned secret store.
///
/// The referenced secret is deliberately not part of serializable RPC policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcCredentialRef {
    /// Opaque keyring/vault identifier resolved by the host application.
    pub id: String,
}

/// One endpoint with explicit transport, provider, and capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcEndpoint {
    /// Stable local identifier used in health and audit records.
    pub id: String,
    /// Endpoint URL. Secrets should be represented by `credential`, not here.
    pub url: String,
    /// Protocol/transport spoken by this URL.
    pub transport: RpcTransport,
    /// Operations allowed on this endpoint.
    pub capabilities: Vec<RpcCapability>,
    /// Configuration source.
    pub source: RpcEndpointSource,
    /// Independent provider/operator identity used for quorum accounting.
    pub provider: String,
    /// Lower values are attempted first within a source group.
    #[serde(default)]
    pub priority: u16,
    /// Optional reference to credentials held outside this configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<RpcCredentialRef>,
}

impl RpcEndpoint {
    /// Validate transport, URL, identity, and capability metadata.
    pub fn validate(&self) -> Result<(), RpcPolicyError> {
        if self.id.trim().is_empty() {
            return Err(RpcPolicyError::InvalidEndpoint(
                "endpoint id cannot be empty".to_string(),
            ));
        }
        if self.provider.trim().is_empty() {
            return Err(RpcPolicyError::InvalidEndpoint(format!(
                "endpoint {} has no provider identity",
                self.id
            )));
        }
        if self.capabilities.is_empty() {
            return Err(RpcPolicyError::InvalidEndpoint(format!(
                "endpoint {} has no capabilities",
                self.id
            )));
        }
        if self
            .credential
            .as_ref()
            .is_some_and(|credential| credential.id.trim().is_empty())
        {
            return Err(RpcPolicyError::InvalidEndpoint(format!(
                "endpoint {} has an empty credential reference",
                self.id
            )));
        }

        let is_loopback = self.url.starts_with("http://127.0.0.1")
            || self.url.starts_with("http://localhost")
            || self.url.starts_with("ws://127.0.0.1")
            || self.url.starts_with("ws://localhost");
        let scheme_ok = match self.transport {
            RpcTransport::JsonRpcHttp | RpcTransport::Rest | RpcTransport::Grpc => {
                self.url.starts_with("https://") || (is_loopback && self.url.starts_with("http://"))
            }
            RpcTransport::WebSocket => {
                self.url.starts_with("wss://") || (is_loopback && self.url.starts_with("ws://"))
            }
        };
        if !scheme_ok {
            return Err(RpcPolicyError::InvalidEndpoint(format!(
                "endpoint {} URL scheme does not match {:?} or is not TLS",
                self.id, self.transport
            )));
        }
        if self.url.contains('@') {
            return Err(RpcPolicyError::InvalidEndpoint(format!(
                "endpoint {} embeds URL user-info; use a credential reference",
                self.id
            )));
        }
        Ok(())
    }
}

/// Complete endpoint policy for one chain and one exact network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainRpcPolicy {
    /// Canonical chain name, such as `ethereum` or `solana`.
    pub chain: String,
    /// Exact network name, such as `sepolia`, `devnet`, or `signet`.
    pub network: String,
    /// Source selection and fallback behavior.
    #[serde(default)]
    pub selection: RpcSelectionMode,
    /// Ordered endpoint candidates.
    pub endpoints: Vec<RpcEndpoint>,
}

impl ChainRpcPolicy {
    /// Validate the policy without performing network I/O.
    pub fn validate(&self) -> Result<(), RpcPolicyError> {
        if self.chain.trim().is_empty() || self.network.trim().is_empty() {
            return Err(RpcPolicyError::MissingNetworkIdentity);
        }
        let mut ids = HashSet::new();
        for endpoint in &self.endpoints {
            endpoint.validate()?;
            if !ids.insert(endpoint.id.as_str()) {
                return Err(RpcPolicyError::DuplicateEndpoint(endpoint.id.clone()));
            }
        }
        if self.selection == RpcSelectionMode::UserOnly
            && !self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.source == RpcEndpointSource::User)
        {
            return Err(RpcPolicyError::NoCandidate {
                capability: RpcCapability::Read,
                selection: self.selection,
            });
        }
        Ok(())
    }

    /// Return deterministic candidates for a capability.
    ///
    /// Fallback never changes source groups implicitly. The returned order is
    /// the complete order the caller is allowed to attempt.
    pub fn candidates(
        &self,
        capability: RpcCapability,
    ) -> Result<Vec<&RpcEndpoint>, RpcPolicyError> {
        self.validate()?;
        let source_rank = |source: RpcEndpointSource| match (self.selection, source) {
            (RpcSelectionMode::BuiltInOnly, RpcEndpointSource::BuiltIn) => Some(0),
            (RpcSelectionMode::UserOnly, RpcEndpointSource::User) => Some(0),
            (RpcSelectionMode::UserThenBuiltIn, RpcEndpointSource::User) => Some(0),
            (RpcSelectionMode::UserThenBuiltIn, RpcEndpointSource::BuiltIn) => Some(1),
            _ => None,
        };
        let mut candidates: Vec<_> = self
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.capabilities.contains(&capability))
            .filter_map(|endpoint| source_rank(endpoint.source).map(|rank| (rank, endpoint)))
            .collect();
        candidates.sort_by_key(|(rank, endpoint)| (*rank, endpoint.priority, &endpoint.id));
        let candidates: Vec<_> = candidates
            .into_iter()
            .map(|(_, endpoint)| endpoint)
            .collect();
        if candidates.is_empty() {
            return Err(RpcPolicyError::NoCandidate {
                capability,
                selection: self.selection,
            });
        }
        Ok(candidates)
    }

    /// Ensure the selected candidates can satisfy a trust requirement.
    pub fn enforce_trust(
        &self,
        capability: RpcCapability,
        requirement: RpcTrustRequirement,
    ) -> Result<Vec<&RpcEndpoint>, RpcPolicyError> {
        let candidates = self.candidates(capability)?;
        if let RpcTrustRequirement::Quorum {
            min_providers,
            min_agreement,
        } = requirement
        {
            if min_providers == 0 || min_agreement == 0 || min_agreement > min_providers {
                return Err(RpcPolicyError::InvalidQuorum);
            }
            let independent = candidates
                .iter()
                .map(|endpoint| endpoint.provider.as_str())
                .collect::<HashSet<_>>()
                .len();
            if independent < usize::from(min_providers) {
                return Err(RpcPolicyError::InsufficientIndependentProviders {
                    required: min_providers,
                    available: independent,
                });
            }
        }
        Ok(candidates)
    }

    /// Install a user endpoint and switch to strict user-only selection.
    ///
    /// Built-in endpoints remain recorded so a later, explicit
    /// [`RpcSelectionMode::UserThenBuiltIn`] choice can re-enable them.
    pub fn use_user_endpoint(&mut self, endpoint: RpcEndpoint) -> Result<(), RpcPolicyError> {
        if endpoint.source != RpcEndpointSource::User {
            return Err(RpcPolicyError::InvalidEndpoint(
                "injected endpoint source must be user".to_string(),
            ));
        }
        endpoint.validate()?;
        self.endpoints.retain(|current| current.id != endpoint.id);
        self.endpoints.push(endpoint);
        self.selection = RpcSelectionMode::UserOnly;
        self.validate()
    }
}

/// RPC policy validation or resolution error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcPolicyError {
    /// Chain or exact network identity is missing.
    #[error("RPC policy requires an explicit chain and network")]
    MissingNetworkIdentity,
    /// Endpoint metadata is malformed or unsafe.
    #[error("invalid RPC endpoint: {0}")]
    InvalidEndpoint(String),
    /// Endpoint identifiers must be unique.
    #[error("duplicate RPC endpoint id: {0}")]
    DuplicateEndpoint(String),
    /// No endpoint satisfies the explicit source/capability policy.
    #[error("no RPC candidate for {capability:?} under {selection:?}")]
    NoCandidate {
        /// Requested operation.
        capability: RpcCapability,
        /// Active selection mode.
        selection: RpcSelectionMode,
    },
    /// Quorum parameters are contradictory.
    #[error("invalid RPC quorum parameters")]
    InvalidQuorum,
    /// Selected endpoints cannot meet the required independent-provider count.
    #[error(
        "RPC quorum requires {required} independent providers but only {available} are configured"
    )]
    InsufficientIndependentProviders {
        /// Required independent provider count.
        required: u8,
        /// Available independent provider count.
        available: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(id: &str, source: RpcEndpointSource, provider: &str, priority: u16) -> RpcEndpoint {
        RpcEndpoint {
            id: id.to_string(),
            url: format!("https://{id}.example.test"),
            transport: RpcTransport::JsonRpcHttp,
            capabilities: vec![RpcCapability::Read, RpcCapability::Verify],
            source,
            provider: provider.to_string(),
            priority,
            credential: None,
        }
    }

    fn policy() -> ChainRpcPolicy {
        ChainRpcPolicy {
            chain: "ethereum".to_string(),
            network: "sepolia".to_string(),
            selection: RpcSelectionMode::BuiltInOnly,
            endpoints: vec![
                endpoint("builtin", RpcEndpointSource::BuiltIn, "builtin-provider", 0),
                endpoint("user", RpcEndpointSource::User, "user-provider", 0),
            ],
        }
    }

    #[test]
    fn user_injection_is_strict_by_default() {
        let mut policy = policy();
        policy
            .use_user_endpoint(endpoint(
                "private",
                RpcEndpointSource::User,
                "self-hosted",
                1,
            ))
            .expect("valid fixture");
        let candidates = policy.candidates(RpcCapability::Read).expect("candidate");
        assert!(
            candidates
                .iter()
                .all(|endpoint| endpoint.source == RpcEndpointSource::User)
        );
        assert_eq!(policy.selection, RpcSelectionMode::UserOnly);
    }

    #[test]
    fn built_in_fallback_requires_explicit_mode() {
        let mut policy = policy();
        policy.selection = RpcSelectionMode::UserOnly;
        let strict = policy
            .candidates(RpcCapability::Read)
            .expect("user candidate");
        assert_eq!(strict.len(), 1);
        assert_eq!(strict[0].id, "user");

        policy.selection = RpcSelectionMode::UserThenBuiltIn;
        let fallback = policy
            .candidates(RpcCapability::Read)
            .expect("fallback candidates");
        assert_eq!(fallback[0].id, "user");
        assert_eq!(fallback[1].id, "builtin");
    }

    #[test]
    fn remote_plaintext_and_transport_mismatch_are_rejected() {
        let mut invalid = endpoint("bad", RpcEndpointSource::User, "self-hosted", 0);
        invalid.url = "http://remote.example.test".to_string();
        assert!(matches!(
            invalid.validate(),
            Err(RpcPolicyError::InvalidEndpoint(_))
        ));

        invalid.url = "wss://remote.example.test".to_string();
        assert!(matches!(
            invalid.validate(),
            Err(RpcPolicyError::InvalidEndpoint(_))
        ));
    }

    #[test]
    fn verification_quorum_counts_independent_providers() {
        let mut policy = policy();
        policy.selection = RpcSelectionMode::UserOnly;
        policy.endpoints = vec![
            endpoint("one-a", RpcEndpointSource::User, "one", 0),
            endpoint("one-b", RpcEndpointSource::User, "one", 1),
            endpoint("two", RpcEndpointSource::User, "two", 2),
        ];
        assert_eq!(
            policy.enforce_trust(
                RpcCapability::Verify,
                RpcTrustRequirement::Quorum {
                    min_providers: 3,
                    min_agreement: 2,
                },
            ),
            Err(RpcPolicyError::InsufficientIndependentProviders {
                required: 3,
                available: 2,
            })
        );
    }
}
