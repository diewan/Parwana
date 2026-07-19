//! Network and deployment identity probes for RPC endpoints (RFC-0013 / RPC-003).
//!
//! Changing `network` in configuration does not prove that an endpoint belongs
//! to that network: an endpoint claiming "Sepolia" may serve mainnet. Before an
//! endpoint enters the usable set, it must be probed to confirm both:
//!
//! - **Network identity** — the RPC-reported chain id (and genesis hash where
//!   available) matches the endpoint's declared `chain`/`network`.
//! - **Deployment identity** — the expected contract/program/package (from the
//!   deployment manifest) is present.
//!
//! A mismatch removes the endpoint with a **distinct** typed error and never
//! serves a request. Network mismatch and deployment mismatch are different
//! errors. Probes carry timestamps for UI display (WAL-010), re-run on a
//! validation timer / reconnect, and are rate-limited. A probe I/O failure
//! marks the endpoint *degraded* — it does not crash the client, and it does
//! not let the endpoint through.
//!
//! Built-in (reviewed) endpoints are probed exactly like user endpoints — there
//! is no bypass.
//!
//! I/O is behind the [`IdentityProbe`] trait so the same logic runs on native
//! and WASM builds; only the transport differs.

use std::collections::HashMap;

use csv_protocol::deployment_manifest::{DeploymentManifest, ethereum_chain_id_from};

use crate::rpc_policy::{RpcCapability, RpcEndpoint, RpcTransport};

/// Identity a probe observed from a live endpoint. `None` means the endpoint did
/// not report that field; a required-but-absent field fails closed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedIdentity {
    /// Chain id the endpoint reported (e.g. EVM chain id, Solana genesis hash).
    pub chain_id: Option<String>,
    /// Genesis / network hash the endpoint reported, where the chain exposes one.
    pub genesis_hash: Option<String>,
    /// Whether the expected deployment (contract/program/package) is present.
    pub deployment_present: Option<bool>,
}

/// Identity an endpoint is required to match, derived from the chain policy and
/// the signed deployment manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    /// Declared canonical chain, e.g. `ethereum`.
    pub chain: String,
    /// Declared exact network, e.g. `sepolia`.
    pub network: String,
    /// Expected chain id, when the chain has a stable numeric/string id.
    pub chain_id: Option<String>,
    /// Expected genesis/network hash, when available.
    pub genesis_hash: Option<String>,
    /// Whether a deployment (contract/program/package) must be present.
    pub requires_deployment: bool,
}

impl ExpectedIdentity {
    /// Derive the required identity for a chain and exact network from the
    /// (already signature-verified) deployment manifest.
    ///
    /// Network identity is bound where the manifest carries it: Ethereum
    /// supplies a numeric `chain_id`. Deployment identity is required for a
    /// chain whose on-chain contract/program/package is recorded in the
    /// manifest; Bitcoin is UTXO-native and carries no deployment, so only its
    /// declared network is bound. The caller must have verified the manifest
    /// signature (RPC-006) before calling this — this reads only already-trusted
    /// data and performs no I/O.
    pub fn from_manifest(chain: &str, network: &str, manifest: &DeploymentManifest) -> Self {
        let deployments = &manifest.deployments;
        let (chain_id, requires_deployment) = match chain {
            "ethereum" => (
                ethereum_chain_id_from(manifest).map(|id| id.to_string()),
                deployments.ethereum.as_ref().is_some_and(|ethereum| {
                    ethereum.contracts.iter().any(|contract| {
                        contract.name == "CSVSeal" && !contract.address.trim().is_empty()
                    })
                }),
            ),
            "solana" => (
                None,
                deployments.solana.as_ref().is_some_and(|solana| {
                    solana
                        .program_id
                        .as_ref()
                        .or(solana.package_id.as_ref())
                        .is_some_and(|id| !id.trim().is_empty())
                }),
            ),
            "sui" => (
                None,
                deployments.sui.as_ref().is_some_and(|sui| {
                    sui.package_id
                        .as_ref()
                        .is_some_and(|id| !id.trim().is_empty())
                }),
            ),
            "aptos" => (
                None,
                deployments
                    .aptos
                    .as_ref()
                    .is_some_and(|aptos| !aptos.module_address.trim().is_empty()),
            ),
            // Bitcoin (UTXO-native) and any unrecognized chain: bind the declared
            // network only. No manifest deployment or numeric id to require.
            _ => (None, false),
        };
        ExpectedIdentity {
            chain: chain.to_string(),
            network: network.to_string(),
            chain_id,
            genesis_hash: None,
            requires_deployment,
        }
    }
}

/// Distinct reasons an endpoint fails identity validation. Network identity and
/// deployment identity are intentionally different variants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityMismatch {
    /// The reported chain id does not match the expected network.
    #[error("network mismatch: expected chain id {expected:?}, endpoint reported {observed:?}")]
    NetworkMismatch {
        /// Expected chain id.
        expected: String,
        /// Observed chain id.
        observed: String,
    },
    /// The reported genesis/network hash does not match.
    #[error("genesis mismatch: expected {expected}, endpoint reported {observed}")]
    GenesisMismatch {
        /// Expected genesis hash.
        expected: String,
        /// Observed genesis hash.
        observed: String,
    },
    /// The expected deployment is absent — distinct from a network mismatch.
    #[error("deployment identity mismatch: expected contract/program not present on endpoint")]
    DeploymentMismatch,
    /// A required identity field could not be observed; fail closed.
    #[error("endpoint did not report required identity field: {0}")]
    Unobservable(&'static str),
}

/// A transport error while probing. Distinct from a genuine mismatch: it marks
/// the endpoint degraded (retryable) rather than proven wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("identity probe transport error: {0}")]
pub struct ProbeError(pub String);

/// Pure identity evaluation. No I/O — the observed identity is supplied.
///
/// Fails closed: an expected field that the endpoint did not report is a
/// rejection, not a pass.
pub fn evaluate_identity(
    expected: &ExpectedIdentity,
    observed: &ObservedIdentity,
) -> Result<(), IdentityMismatch> {
    if let Some(expected_id) = &expected.chain_id {
        match &observed.chain_id {
            Some(observed_id) if observed_id == expected_id => {}
            Some(observed_id) => {
                return Err(IdentityMismatch::NetworkMismatch {
                    expected: expected_id.clone(),
                    observed: observed_id.clone(),
                });
            }
            None => return Err(IdentityMismatch::Unobservable("chain_id")),
        }
    }
    if let Some(expected_genesis) = &expected.genesis_hash {
        match &observed.genesis_hash {
            Some(observed_genesis) if observed_genesis == expected_genesis => {}
            Some(observed_genesis) => {
                return Err(IdentityMismatch::GenesisMismatch {
                    expected: expected_genesis.clone(),
                    observed: observed_genesis.clone(),
                });
            }
            None => return Err(IdentityMismatch::Unobservable("genesis_hash")),
        }
    }
    if expected.requires_deployment {
        match observed.deployment_present {
            Some(true) => {}
            Some(false) => return Err(IdentityMismatch::DeploymentMismatch),
            None => return Err(IdentityMismatch::Unobservable("deployment_present")),
        }
    }
    Ok(())
}

/// Result of a single probe, carrying a timestamp for UI display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// Endpoint the probe targeted.
    pub endpoint_id: String,
    /// Unix seconds when the probe completed.
    pub validated_at_unix: u64,
    /// Validation status.
    pub status: ProbeStatus,
}

/// Terminal state of a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeStatus {
    /// Identity confirmed; the endpoint may serve requests.
    Valid,
    /// Identity is wrong; the endpoint is removed and must not serve requests.
    Rejected(IdentityMismatch),
    /// Transport failure; the endpoint is temporarily unusable (retryable).
    Degraded(ProbeError),
}

impl ProbeStatus {
    /// Only a confirmed-valid endpoint may serve requests.
    pub fn is_usable(&self) -> bool {
        matches!(self, ProbeStatus::Valid)
    }
}

/// Observes endpoint identity over the network. Mockable; WASM-compatible.
#[allow(async_fn_in_trait)]
pub trait IdentityProbe {
    /// Query the endpoint's reported chain/network/deployment identity.
    async fn observe(&self, endpoint: &RpcEndpoint) -> Result<ObservedIdentity, ProbeError>;
}

/// Tracks probe outcomes per endpoint and gates the usable set.
///
/// Endpoints are keyed by id. Every endpoint — built-in or user — must have a
/// [`ProbeStatus::Valid`] record before it is usable; there is no bypass.
#[derive(Debug, Clone)]
pub struct EndpointValidator {
    outcomes: HashMap<String, ProbeOutcome>,
    revalidate_after_secs: u64,
    min_probe_interval_secs: u64,
}

impl EndpointValidator {
    /// Create a validator. `revalidate_after_secs` is how long a `Valid` record
    /// is trusted before a re-probe; `min_probe_interval_secs` rate-limits
    /// probing of any one endpoint.
    pub fn new(revalidate_after_secs: u64, min_probe_interval_secs: u64) -> Self {
        Self {
            outcomes: HashMap::new(),
            revalidate_after_secs,
            min_probe_interval_secs,
        }
    }

    /// Last recorded probe outcome for an endpoint, for UI display.
    pub fn outcome(&self, endpoint_id: &str) -> Option<&ProbeOutcome> {
        self.outcomes.get(endpoint_id)
    }

    /// Whether an endpoint should be (re)probed at `now`.
    pub fn needs_probe(&self, endpoint_id: &str, now: u64) -> bool {
        match self.outcomes.get(endpoint_id) {
            None => true,
            Some(outcome) => {
                let age = now.saturating_sub(outcome.validated_at_unix);
                // Rate-limit: never probe more often than min interval.
                if age < self.min_probe_interval_secs {
                    return false;
                }
                match &outcome.status {
                    // A still-fresh Valid record does not need re-probing.
                    ProbeStatus::Valid => age >= self.revalidate_after_secs,
                    // Rejected/Degraded endpoints are re-probed once the rate
                    // limit allows (a degraded transport may recover; a rejected
                    // identity may have been a reconfigured endpoint).
                    _ => true,
                }
            }
        }
    }

    /// Probe every endpoint that is due and record the outcome. Built-in and
    /// user endpoints are treated identically. A transport error is recorded as
    /// `Degraded` and does not abort the sweep.
    pub async fn validate_all<P: IdentityProbe>(
        &mut self,
        endpoints: &[RpcEndpoint],
        expected: &ExpectedIdentity,
        prober: &P,
        now: u64,
    ) {
        for endpoint in endpoints {
            if !self.needs_probe(&endpoint.id, now) {
                continue;
            }
            let status = match prober.observe(endpoint).await {
                Ok(observed) => match evaluate_identity(expected, &observed) {
                    Ok(()) => ProbeStatus::Valid,
                    Err(mismatch) => ProbeStatus::Rejected(mismatch),
                },
                Err(err) => ProbeStatus::Degraded(err),
            };
            self.outcomes.insert(
                endpoint.id.clone(),
                ProbeOutcome {
                    endpoint_id: endpoint.id.clone(),
                    validated_at_unix: now,
                    status,
                },
            );
        }
    }

    /// Filter policy candidates to only identity-validated endpoints for a
    /// capability. An endpoint with no `Valid` record — including a never-probed
    /// or degraded one — is excluded (fail closed).
    pub fn usable<'a>(
        &self,
        candidates: &[&'a RpcEndpoint],
        _capability: RpcCapability,
    ) -> Vec<&'a RpcEndpoint> {
        candidates
            .iter()
            .filter(|endpoint| {
                self.outcomes
                    .get(&endpoint.id)
                    .is_some_and(|outcome| outcome.status.is_usable())
            })
            .copied()
            .collect()
    }
}

/// Transport the identity prober uses to talk to an endpoint.
///
/// The host supplies a native (e.g. `reqwest`) or WASM (`fetch`) implementation;
/// the prober logic that builds requests and interprets responses lives here and
/// is transport-agnostic, so it is identical on both targets and unit-testable
/// with a fake. An implementation returns the JSON-RPC `result` value, or a
/// [`ProbeError`] for any transport/HTTP/JSON envelope failure (which the
/// validator records as *degraded*, never as a pass).
#[allow(async_fn_in_trait)]
pub trait IdentityTransport {
    /// Perform a JSON-RPC call against `url` and return the `result` value.
    async fn json_rpc(
        &self,
        url: &str,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProbeError>;
}

/// Live identity probe for EVM JSON-RPC endpoints (RFC-0013 / RPC-003).
///
/// Confirms the endpoint's reported numeric chain id via `eth_chainId` and, when
/// a deployment address is configured, that the expected seal contract has code
/// on-chain via `eth_getCode`. A malformed or absent response leaves the
/// corresponding [`ObservedIdentity`] field `None`, which [`evaluate_identity`]
/// treats as unobservable and rejects (fail closed). Transport failures surface
/// as [`ProbeError`] so the endpoint is marked degraded, not passed.
///
/// The probe is scoped to one chain's endpoints, matching
/// [`EndpointValidator::validate_all`], which is invoked per chain/expected.
pub struct EvmIdentityProbe<T: IdentityTransport> {
    transport: T,
    deployment_address: Option<String>,
}

impl<T: IdentityTransport> EvmIdentityProbe<T> {
    /// Build an EVM identity probe. `deployment_address` is the expected seal
    /// contract whose on-chain code proves deployment identity; `None` checks
    /// network identity only.
    pub fn new(transport: T, deployment_address: Option<String>) -> Self {
        Self {
            transport,
            deployment_address,
        }
    }
}

impl<T: IdentityTransport> IdentityProbe for EvmIdentityProbe<T> {
    async fn observe(&self, endpoint: &RpcEndpoint) -> Result<ObservedIdentity, ProbeError> {
        if endpoint.transport != RpcTransport::JsonRpcHttp {
            return Err(ProbeError(format!(
                "EVM identity probe requires a json_rpc_http endpoint, got {:?}",
                endpoint.transport
            )));
        }
        let chain_id_result = self
            .transport
            .json_rpc(
                &endpoint.url,
                "eth_chainId",
                serde_json::Value::Array(vec![]),
            )
            .await?;
        // eth_chainId returns a 0x-prefixed hex quantity; normalize to decimal so
        // it compares against the manifest's numeric chain id. A malformed value
        // is left unobservable (rejected), never coerced to a pass.
        let chain_id = chain_id_result
            .as_str()
            .and_then(|hex| u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok())
            .map(|id| id.to_string());

        let deployment_present = match &self.deployment_address {
            Some(address) => {
                let code = self
                    .transport
                    .json_rpc(
                        &endpoint.url,
                        "eth_getCode",
                        serde_json::Value::Array(vec![
                            serde_json::Value::String(address.clone()),
                            serde_json::Value::String("latest".to_string()),
                        ]),
                    )
                    .await?;
                Some(
                    code.as_str()
                        .map(|code| code != "0x" && !code.is_empty())
                        .unwrap_or(false),
                )
            }
            None => None,
        };

        Ok(ObservedIdentity {
            chain_id,
            genesis_hash: None,
            deployment_present,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_policy::{RpcEndpointSource, RpcTransport};

    fn endpoint(id: &str, source: RpcEndpointSource, caps: &[RpcCapability]) -> RpcEndpoint {
        RpcEndpoint {
            id: id.to_string(),
            url: format!("https://{id}.example.test"),
            transport: RpcTransport::JsonRpcHttp,
            capabilities: caps.to_vec(),
            source,
            provider: format!("{id}-provider"),
            priority: 0,
            credential: None,
        }
    }

    fn expected() -> ExpectedIdentity {
        ExpectedIdentity {
            chain: "ethereum".into(),
            network: "sepolia".into(),
            chain_id: Some("11155111".into()),
            genesis_hash: None,
            requires_deployment: true,
        }
    }

    /// Mock prober keyed by endpoint id.
    struct MockProbe(HashMap<String, Result<ObservedIdentity, ProbeError>>);

    impl IdentityProbe for MockProbe {
        async fn observe(&self, endpoint: &RpcEndpoint) -> Result<ObservedIdentity, ProbeError> {
            self.0
                .get(&endpoint.id)
                .cloned()
                .unwrap_or_else(|| Err(ProbeError("no mock".into())))
        }
    }

    #[test]
    fn wrong_chain_id_is_network_mismatch() {
        let observed = ObservedIdentity {
            chain_id: Some("1".into()), // mainnet, not sepolia
            genesis_hash: None,
            deployment_present: Some(true),
        };
        assert!(matches!(
            evaluate_identity(&expected(), &observed),
            Err(IdentityMismatch::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn missing_deployment_is_distinct_from_network_mismatch() {
        let observed = ObservedIdentity {
            chain_id: Some("11155111".into()),
            genesis_hash: None,
            deployment_present: Some(false),
        };
        assert_eq!(
            evaluate_identity(&expected(), &observed),
            Err(IdentityMismatch::DeploymentMismatch)
        );
    }

    #[test]
    fn unobservable_required_field_fails_closed() {
        let observed = ObservedIdentity {
            chain_id: None,
            genesis_hash: None,
            deployment_present: Some(true),
        };
        assert_eq!(
            evaluate_identity(&expected(), &observed),
            Err(IdentityMismatch::Unobservable("chain_id"))
        );
    }

    #[test]
    fn matching_identity_passes() {
        let observed = ObservedIdentity {
            chain_id: Some("11155111".into()),
            genesis_hash: None,
            deployment_present: Some(true),
        };
        assert_eq!(evaluate_identity(&expected(), &observed), Ok(()));
    }

    #[tokio::test]
    async fn builtin_endpoint_with_wrong_chain_id_never_serves() {
        // A reviewed BUILT-IN endpoint that lies about its chain must still be
        // removed — no bypass for built-ins.
        let builtin = endpoint(
            "builtin",
            RpcEndpointSource::BuiltIn,
            &[RpcCapability::Read],
        );
        let mut mock = HashMap::new();
        mock.insert(
            "builtin".to_string(),
            Ok(ObservedIdentity {
                chain_id: Some("1".into()),
                genesis_hash: None,
                deployment_present: Some(true),
            }),
        );
        let prober = MockProbe(mock);
        let mut validator = EndpointValidator::new(3600, 0);
        validator
            .validate_all(std::slice::from_ref(&builtin), &expected(), &prober, 1000)
            .await;

        assert!(matches!(
            validator.outcome("builtin").unwrap().status,
            ProbeStatus::Rejected(IdentityMismatch::NetworkMismatch { .. })
        ));
        let candidates = vec![&builtin];
        assert!(
            validator
                .usable(&candidates, RpcCapability::Read)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn every_capability_class_is_probed_and_gated() {
        // request, subscription, and address-index endpoints must all be probed.
        let request = endpoint("req", RpcEndpointSource::User, &[RpcCapability::Read]);
        let subscribe = endpoint("sub", RpcEndpointSource::User, &[RpcCapability::Subscribe]);
        let index = endpoint(
            "idx",
            RpcEndpointSource::User,
            &[RpcCapability::AddressIndex],
        );

        let mut mock = HashMap::new();
        let good = ObservedIdentity {
            chain_id: Some("11155111".into()),
            genesis_hash: None,
            deployment_present: Some(true),
        };
        // request + address-index are honest; subscription lies about its network.
        mock.insert("req".into(), Ok(good.clone()));
        mock.insert("idx".into(), Ok(good.clone()));
        mock.insert(
            "sub".into(),
            Ok(ObservedIdentity {
                chain_id: Some("1".into()),
                ..good.clone()
            }),
        );
        let prober = MockProbe(mock);
        let mut validator = EndpointValidator::new(3600, 0);
        let all = [request.clone(), subscribe.clone(), index.clone()];
        validator
            .validate_all(&all, &expected(), &prober, 1000)
            .await;

        // All three were probed (each has a timestamped record).
        for id in ["req", "sub", "idx"] {
            assert_eq!(validator.outcome(id).unwrap().validated_at_unix, 1000);
        }
        // The lying subscription endpoint is not usable.
        assert!(validator.outcome("req").unwrap().status.is_usable());
        assert!(validator.outcome("idx").unwrap().status.is_usable());
        assert!(!validator.outcome("sub").unwrap().status.is_usable());
        let sub_candidates = vec![&subscribe];
        assert!(
            validator
                .usable(&sub_candidates, RpcCapability::Subscribe)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn transport_error_is_degraded_not_fatal_and_not_usable() {
        let ep = endpoint("flaky", RpcEndpointSource::User, &[RpcCapability::Read]);
        let mut mock = HashMap::new();
        mock.insert("flaky".into(), Err(ProbeError("timeout".into())));
        let prober = MockProbe(mock);
        let mut validator = EndpointValidator::new(3600, 0);
        validator
            .validate_all(std::slice::from_ref(&ep), &expected(), &prober, 500)
            .await;
        assert!(matches!(
            validator.outcome("flaky").unwrap().status,
            ProbeStatus::Degraded(_)
        ));
        assert!(validator.usable(&[&ep], RpcCapability::Read).is_empty());
    }

    #[test]
    fn rate_limit_and_revalidation_timer() {
        let mut validator = EndpointValidator::new(100, 10);
        validator.outcomes.insert(
            "e".into(),
            ProbeOutcome {
                endpoint_id: "e".into(),
                validated_at_unix: 1000,
                status: ProbeStatus::Valid,
            },
        );
        // within min interval: no probe
        assert!(!validator.needs_probe("e", 1005));
        // past min interval but within revalidation window: still no probe
        assert!(!validator.needs_probe("e", 1050));
        // past revalidation window: probe
        assert!(validator.needs_probe("e", 1101));
        // never-probed endpoint always needs a probe
        assert!(validator.needs_probe("unseen", 1101));
    }

    fn manifest(json: &str) -> DeploymentManifest {
        serde_json::from_str(json).expect("valid synthetic manifest")
    }

    #[test]
    fn expected_identity_from_manifest_binds_ethereum_chain_id_and_deployment() {
        let m = manifest(
            r#"{"deployments":{
                "ethereum":{"network":"sepolia","chain_id":11155111,
                    "contracts":[{"name":"CSVSeal","address":"0xabc","deployment_tx":"0x1"}]},
                "solana":null,"sui":null,"aptos":null}}"#,
        );
        let expected = ExpectedIdentity::from_manifest("ethereum", "sepolia", &m);
        assert_eq!(expected.chain_id.as_deref(), Some("11155111"));
        assert!(expected.requires_deployment);
        assert!(expected.genesis_hash.is_none());
    }

    #[test]
    fn expected_identity_from_manifest_bitcoin_is_network_only() {
        let m =
            manifest(r#"{"deployments":{"ethereum":null,"solana":null,"sui":null,"aptos":null}}"#);
        let expected = ExpectedIdentity::from_manifest("bitcoin", "signet", &m);
        assert_eq!(expected.chain_id, None);
        assert!(!expected.requires_deployment);
    }

    /// Fake JSON-RPC transport returning canned `eth_chainId` / `eth_getCode`
    /// responses, so the EVM probe is exercised with no network.
    struct FakeEvmTransport {
        chain_id_hex: &'static str,
        code: &'static str,
        fail: bool,
    }

    impl IdentityTransport for FakeEvmTransport {
        async fn json_rpc(
            &self,
            _url: &str,
            method: &str,
            _params: serde_json::Value,
        ) -> Result<serde_json::Value, ProbeError> {
            if self.fail {
                return Err(ProbeError("connection reset".into()));
            }
            match method {
                "eth_chainId" => Ok(serde_json::Value::String(self.chain_id_hex.into())),
                "eth_getCode" => Ok(serde_json::Value::String(self.code.into())),
                other => Err(ProbeError(format!("unexpected method {other}"))),
            }
        }
    }

    fn evm_endpoint() -> RpcEndpoint {
        endpoint("eth", RpcEndpointSource::BuiltIn, &[RpcCapability::Read])
    }

    #[tokio::test]
    async fn evm_probe_observes_chain_id_and_deployment() {
        // 0xaa36a7 == 11155111 (Sepolia); non-empty code == deployment present.
        let probe = EvmIdentityProbe::new(
            FakeEvmTransport {
                chain_id_hex: "0xaa36a7",
                code: "0x60016002",
                fail: false,
            },
            Some("0xabc".into()),
        );
        let observed = probe.observe(&evm_endpoint()).await.expect("observation");
        assert_eq!(observed.chain_id.as_deref(), Some("11155111"));
        assert_eq!(observed.deployment_present, Some(true));
        assert_eq!(evaluate_identity(&expected(), &observed), Ok(()));
    }

    #[tokio::test]
    async fn evm_probe_reports_wrong_network_and_absent_deployment() {
        // Endpoint on mainnet (0x1) => network mismatch against Sepolia expected.
        let probe = EvmIdentityProbe::new(
            FakeEvmTransport {
                chain_id_hex: "0x1",
                code: "0x",
                fail: false,
            },
            Some("0xabc".into()),
        );
        let observed = probe.observe(&evm_endpoint()).await.expect("observation");
        assert_eq!(observed.chain_id.as_deref(), Some("1"));
        assert_eq!(observed.deployment_present, Some(false));
        assert!(matches!(
            evaluate_identity(&expected(), &observed),
            Err(IdentityMismatch::NetworkMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn evm_probe_transport_failure_surfaces_as_probe_error() {
        let probe = EvmIdentityProbe::new(
            FakeEvmTransport {
                chain_id_hex: "0xaa36a7",
                code: "0x60",
                fail: true,
            },
            None,
        );
        // A transport failure is a ProbeError, which the validator degrades — it
        // is never silently treated as a valid identity.
        assert!(probe.observe(&evm_endpoint()).await.is_err());
    }

    #[tokio::test]
    async fn evm_probe_end_to_end_gates_the_validator() {
        let m = manifest(
            r#"{"deployments":{
                "ethereum":{"network":"sepolia","chain_id":11155111,
                    "contracts":[{"name":"CSVSeal","address":"0xabc","deployment_tx":"0x1"}]},
                "solana":null,"sui":null,"aptos":null}}"#,
        );
        let expected = ExpectedIdentity::from_manifest("ethereum", "sepolia", &m);
        let ep = endpoint(
            "eth-req",
            RpcEndpointSource::BuiltIn,
            &[RpcCapability::Read],
        );

        // Honest endpoint: probed valid, becomes usable.
        let probe = EvmIdentityProbe::new(
            FakeEvmTransport {
                chain_id_hex: "0xaa36a7",
                code: "0x60016002",
                fail: false,
            },
            Some("0xabc".into()),
        );
        let mut validator = EndpointValidator::new(3600, 0);
        validator
            .validate_all(std::slice::from_ref(&ep), &expected, &probe, 1)
            .await;
        assert!(validator.outcome("eth-req").unwrap().status.is_usable());

        // Impostor endpoint (mainnet): probed rejected, never usable.
        let impostor = EvmIdentityProbe::new(
            FakeEvmTransport {
                chain_id_hex: "0x1",
                code: "0x60016002",
                fail: false,
            },
            Some("0xabc".into()),
        );
        let mut validator = EndpointValidator::new(3600, 0);
        validator
            .validate_all(std::slice::from_ref(&ep), &expected, &impostor, 1)
            .await;
        assert!(!validator.outcome("eth-req").unwrap().status.is_usable());
        assert!(validator.usable(&[&ep], RpcCapability::Read).is_empty());
    }
}
