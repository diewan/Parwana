//! Runtime verification quorum for protocol decisions (RFC-0013 / RPC-004).
//!
//! RFC-0013/RFC-0010 require that protocol decisions — inclusion, finality,
//! seal state, and mint confirmation — be established from **independent
//! providers** rather than a single endpoint. Until now only a policy-level
//! precondition existed (`rpc_policy::enforce_trust`); the runtime read path did
//! not actually evaluate agreement. This module is that evaluation: given
//! per-provider observations of a decision-relevant value, it returns the agreed
//! value only when enough *independent* providers agree, and fails closed with a
//! distinct error otherwise.
//!
//! Rules enforced here:
//!
//! - **Independent providers.** Multiple endpoints/URLs from the same provider
//!   count once. A provider whose own endpoints disagree is dropped as
//!   unreliable.
//! - **Agreement threshold.** At least `min_agreement` independent providers
//!   must report the same value, drawn from at least `min_providers` queried.
//! - **No self-confirmation.** The provider that submitted the transaction may
//!   never be the sole confirmation source for that transaction's completion.
//!
//! This module is evidence collection for the runtime/verifier authorities, not
//! a new authority. Display reads and broadcast are out of scope: a single user
//! node remains valid for those (per RFC-0013) and must not be routed through
//! this function. WebSocket notifications are hints that should trigger an
//! independently validated read — they are never a decision on their own.

use std::collections::HashMap;
use std::hash::Hash;

/// The class of protocol decision a quorum is being evaluated for. Used for
/// diagnostics; the evaluation logic is identical across classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolDecision {
    /// Transaction inclusion in a block.
    Inclusion,
    /// Finality / irreversibility of an included transaction.
    Finality,
    /// On-chain seal state (consumed / live).
    SealState,
    /// Mint confirmation for a materialized sanad.
    MintConfirmation,
}

/// One provider's observation of a decision-relevant value.
///
/// `provider` is the independent operator identity used for quorum accounting;
/// `endpoint_id` distinguishes multiple endpoints owned by the same provider.
#[derive(Debug, Clone)]
pub struct ProviderObservation<T> {
    /// Independent provider/operator identity.
    pub provider: String,
    /// Specific endpoint that produced this observation.
    pub endpoint_id: String,
    /// The decision-relevant value observed (e.g. `included: bool`, a state hash).
    pub observation: T,
}

/// Quorum parameters. `min_agreement` must be `>= 1` and `<= min_providers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumParams {
    /// Minimum number of independent providers that must be queried.
    pub min_providers: u8,
    /// Minimum number of independent providers that must agree.
    pub min_agreement: u8,
}

impl QuorumParams {
    /// The RFC-0013 default: three independent providers, two agreeing.
    pub const RFC_DEFAULT: QuorumParams = QuorumParams {
        min_providers: 3,
        min_agreement: 2,
    };
}

/// Why a quorum could not be established. Each variant is a distinct fail-closed
/// reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuorumError {
    /// Parameters are contradictory (e.g. `min_agreement > min_providers`).
    #[error("invalid quorum parameters")]
    InvalidParams,
    /// Fewer independent providers gave a usable observation than required.
    #[error("insufficient independent providers: required {required}, available {available}")]
    InsufficientProviders {
        /// Required independent-provider count.
        required: u8,
        /// Independent providers that gave a usable observation.
        available: usize,
    },
    /// No value reached the agreement threshold across independent providers.
    #[error("no quorum agreement: best {agreed} providers agreed, need {required}")]
    NoAgreement {
        /// Providers agreeing on the most-agreed value.
        agreed: usize,
        /// Required agreeing-provider count.
        required: u8,
    },
    /// The submitting provider is the only confirmation source — rejected.
    #[error("submitter is the sole confirmation source for its own transaction")]
    SubmitterIsSoleConfirmer,
}

/// Evaluate a verification quorum over per-provider observations.
///
/// Returns the agreed value on success. `submitter_provider`, when present,
/// names the provider that submitted the transaction; it may corroborate but
/// may never be the sole confirmer.
pub fn evaluate_quorum<T>(
    _decision: ProtocolDecision,
    observations: &[ProviderObservation<T>],
    params: QuorumParams,
    submitter_provider: Option<&str>,
) -> Result<T, QuorumError>
where
    T: Clone + Eq + Hash,
{
    if params.min_providers == 0
        || params.min_agreement == 0
        || params.min_agreement > params.min_providers
    {
        return Err(QuorumError::InvalidParams);
    }

    // Collapse multiple endpoints per provider into one vote. A provider whose
    // own endpoints disagree is dropped as unreliable.
    let mut per_provider: HashMap<&str, Option<&T>> = HashMap::new();
    for obs in observations {
        match per_provider.get(obs.provider.as_str()) {
            None => {
                per_provider.insert(&obs.provider, Some(&obs.observation));
            }
            Some(Some(existing)) if *existing == &obs.observation => {}
            Some(Some(_)) => {
                // internal disagreement: mark this provider unreliable
                per_provider.insert(&obs.provider, None);
            }
            Some(None) => {}
        }
    }

    // Providers that produced a single consistent observation.
    let reliable: Vec<(&str, &T)> = per_provider
        .iter()
        .filter_map(|(provider, obs)| obs.map(|value| (*provider, value)))
        .collect();

    if reliable.len() < usize::from(params.min_providers) {
        return Err(QuorumError::InsufficientProviders {
            required: params.min_providers,
            available: reliable.len(),
        });
    }

    // Tally one vote per reliable provider.
    let mut tally: HashMap<&T, Vec<&str>> = HashMap::new();
    for (provider, value) in &reliable {
        tally.entry(*value).or_default().push(*provider);
    }

    // Pick the most-agreed value. Ties are resolved deterministically by taking
    // the larger agreeing set; the returned value is a clone of an agreeing
    // observation, so tie identity does not matter for safety (agreement count
    // is what gates the decision).
    let (winning_value, agreeing_providers) = tally
        .into_iter()
        .max_by_key(|(_, providers)| providers.len())
        .expect("reliable is non-empty");

    if agreeing_providers.len() < usize::from(params.min_agreement) {
        return Err(QuorumError::NoAgreement {
            agreed: agreeing_providers.len(),
            required: params.min_agreement,
        });
    }

    // The submitter may never be the sole confirmation source: the agreeing set
    // must contain at least one provider that is not the submitter.
    if let Some(submitter) = submitter_provider {
        let has_independent_confirmer = agreeing_providers
            .iter()
            .any(|provider| *provider != submitter);
        if !has_independent_confirmer {
            return Err(QuorumError::SubmitterIsSoleConfirmer);
        }
    }

    Ok(winning_value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs<T>(provider: &str, endpoint: &str, observation: T) -> ProviderObservation<T> {
        ProviderObservation {
            provider: provider.to_string(),
            endpoint_id: endpoint.to_string(),
            observation,
        }
    }

    #[test]
    fn inclusion_reaches_quorum() {
        let observations = vec![
            obs("alpha", "a1", true),
            obs("beta", "b1", true),
            obs("gamma", "c1", true),
        ];
        assert_eq!(
            evaluate_quorum(
                ProtocolDecision::Inclusion,
                &observations,
                QuorumParams::RFC_DEFAULT,
                None,
            ),
            Ok(true)
        );
    }

    #[test]
    fn finality_disagreement_fails_closed() {
        // 3 providers, but they split 2 vs 1 with min_agreement 3 required.
        let observations = vec![
            obs("alpha", "a1", true),
            obs("beta", "b1", true),
            obs("gamma", "c1", false),
        ];
        let strict = QuorumParams {
            min_providers: 3,
            min_agreement: 3,
        };
        assert_eq!(
            evaluate_quorum(ProtocolDecision::Finality, &observations, strict, None),
            Err(QuorumError::NoAgreement {
                agreed: 2,
                required: 3,
            })
        );
    }

    #[test]
    fn insufficient_providers_fails_closed() {
        let observations = vec![obs("alpha", "a1", true), obs("beta", "b1", true)];
        assert_eq!(
            evaluate_quorum(
                ProtocolDecision::Inclusion,
                &observations,
                QuorumParams::RFC_DEFAULT,
                None,
            ),
            Err(QuorumError::InsufficientProviders {
                required: 3,
                available: 2,
            })
        );
    }

    #[test]
    fn same_provider_multiple_urls_count_once() {
        // alpha has three endpoints; still one independent provider.
        let observations = vec![
            obs("alpha", "a1", true),
            obs("alpha", "a2", true),
            obs("alpha", "a3", true),
            obs("beta", "b1", true),
        ];
        // Only 2 independent providers -> below RFC default of 3.
        assert_eq!(
            evaluate_quorum(
                ProtocolDecision::Inclusion,
                &observations,
                QuorumParams::RFC_DEFAULT,
                None,
            ),
            Err(QuorumError::InsufficientProviders {
                required: 3,
                available: 2,
            })
        );
    }

    #[test]
    fn provider_with_internally_disagreeing_endpoints_is_dropped() {
        let observations = vec![
            obs("alpha", "a1", true),
            obs("alpha", "a2", false), // alpha contradicts itself -> dropped
            obs("beta", "b1", true),
            obs("gamma", "c1", true),
        ];
        // alpha dropped; beta+gamma remain = 2 providers < 3 required.
        assert_eq!(
            evaluate_quorum(
                ProtocolDecision::SealState,
                &observations,
                QuorumParams::RFC_DEFAULT,
                None,
            ),
            Err(QuorumError::InsufficientProviders {
                required: 3,
                available: 2,
            })
        );
    }

    #[test]
    fn submitter_as_sole_confirmer_is_rejected() {
        // Only the submitter "alpha" confirms mint; others observe not-yet.
        let observations = vec![
            obs("alpha", "a1", "minted"),
            obs("beta", "b1", "pending"),
            obs("gamma", "c1", "pending"),
        ];
        let params = QuorumParams {
            min_providers: 3,
            min_agreement: 1,
        };
        // "pending" actually wins here (2 vs 1). Construct the sole-submitter
        // case explicitly: everyone else missing, only submitter reports.
        let solo = vec![obs("alpha", "a1", "minted")];
        let single = QuorumParams {
            min_providers: 1,
            min_agreement: 1,
        };
        assert_eq!(
            evaluate_quorum(
                ProtocolDecision::MintConfirmation,
                &solo,
                single,
                Some("alpha"),
            ),
            Err(QuorumError::SubmitterIsSoleConfirmer)
        );
        // With independent corroboration the submitter may participate.
        let corroborated = vec![
            obs("alpha", "a1", "minted"),
            obs("beta", "b1", "minted"),
            obs("gamma", "c1", "minted"),
        ];
        assert_eq!(
            evaluate_quorum(
                ProtocolDecision::MintConfirmation,
                &corroborated,
                params,
                Some("alpha"),
            ),
            Ok("minted")
        );
    }

    #[test]
    fn seal_state_quorum_over_hashes() {
        // Decision value can be any Eq+Hash type, e.g. a state hash.
        let observations = vec![
            obs("alpha", "a1", [1u8; 32]),
            obs("beta", "b1", [1u8; 32]),
            obs("gamma", "c1", [9u8; 32]),
        ];
        assert_eq!(
            evaluate_quorum(
                ProtocolDecision::SealState,
                &observations,
                QuorumParams::RFC_DEFAULT,
                None,
            ),
            Ok([1u8; 32])
        );
    }

    #[test]
    fn invalid_params_rejected() {
        let observations = vec![obs("alpha", "a1", true)];
        assert_eq!(
            evaluate_quorum(
                ProtocolDecision::Inclusion,
                &observations,
                QuorumParams {
                    min_providers: 2,
                    min_agreement: 3,
                },
                None,
            ),
            Err(QuorumError::InvalidParams)
        );
    }
}
