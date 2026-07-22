//! Joins registered profile descriptors with their open codecs.
//!
//! A [`ProfileRegistry`] is the run-time table that lets a generic [`crate::ActionIntent`]
//! be built, decoded, and independently re-verified without the accountability core
//! knowing any concrete profile. It is the behavioural counterpart to the published
//! [`ProfileDescriptor`] set in the contract manifest (Master Plan §35, §36).

use alloc::{collections::BTreeMap, vec::Vec};

use crate::intent::{DbMigrationCodec, GitHubDeploymentCodec, IntentError};
use crate::profile::{BoxedProfileCodec, ProfileCodec, ProfileDescriptor, ProfileId};

/// A run-time table of registered profiles.
///
/// Each entry pairs a [`ProfileDescriptor`] (published data) with a
/// [`BoxedProfileCodec`] (open behaviour). Lookups are by stable [`ProfileId`].
#[derive(Default)]
pub struct ProfileRegistry {
    entries: BTreeMap<ProfileId, BoxedProfileCodec>,
}

impl ProfileRegistry {
    /// Constructs an empty registry.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Registers a profile codec.
    ///
    /// The codec's descriptor is validated (complete, disjoint-by-class evidence sources)
    /// before insertion, and a duplicate profile id is rejected so registration is
    /// deterministic and order-independent.
    pub fn register(&mut self, codec: BoxedProfileCodec) -> Result<(), IntentError> {
        let profile_id = codec.descriptor().profile_id.clone();
        codec.descriptor().validate()?;
        if self.entries.contains_key(&profile_id) {
            return Err(IntentError::DuplicateProfile);
        }
        self.entries.insert(profile_id, codec);
        Ok(())
    }

    /// Returns the registered codec for `profile_id`, if any.
    pub fn codec(&self, profile_id: &ProfileId) -> Option<&(dyn ProfileCodec + Send + Sync)> {
        self.entries.get(profile_id).map(|codec| codec.as_ref())
    }

    /// Returns the published descriptor for `profile_id`, if any.
    pub fn descriptor(&self, profile_id: &ProfileId) -> Option<&ProfileDescriptor> {
        self.entries.get(profile_id).map(|codec| codec.descriptor())
    }

    /// Returns every registered descriptor, in stable id order.
    pub fn descriptors(&self) -> Vec<&ProfileDescriptor> {
        self.entries
            .values()
            .map(|codec| codec.descriptor())
            .collect()
    }

    /// Decodes and validates `profile_bytes` against the registered profile.
    ///
    /// Returns the profile's stable target bytes on success. Fails closed if the profile
    /// is not registered or the bytes are not its exact canonical encoding.
    pub fn decode_profile(
        &self,
        profile_id: &ProfileId,
        profile_bytes: &[u8],
    ) -> Result<Vec<u8>, IntentError> {
        let codec = self
            .codec(profile_id)
            .ok_or(IntentError::UnregisteredProfile)?;
        codec.validate_canonical_bytes(profile_bytes)
    }
}

/// Returns a registry preloaded with the built-in profiles.
///
/// Registers the GitHub deployment profile and the database-migration profile
/// (PROFILE-02). New profiles are added by registering their codec, not by
/// editing the core, which is the whole point of the open registry.
pub fn default_registry() -> ProfileRegistry {
    let mut registry = ProfileRegistry::new();
    registry
        .register(alloc::boxed::Box::new(GitHubDeploymentCodec::default()))
        .expect("built-in github deployment profile registers cleanly");
    registry
        .register(alloc::boxed::Box::new(DbMigrationCodec::default()))
        .expect("built-in db-migration profile registers cleanly");
    registry
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec;

    use super::*;
    use crate::profile::{
        EvidenceSourceClass, EvidenceSourceDecl, EvidenceSourceId, QuarantineReleaseRule,
    };

    /// A minimal non-GitHub profile proving the registry boundary is open.
    struct ToyCodec {
        descriptor: ProfileDescriptor,
    }

    impl ToyCodec {
        fn new() -> Self {
            let descriptor = ProfileDescriptor {
                profile_id: ProfileId::new("org.example.toy.intent.v1").unwrap(),
                action_type: String::from("example.toy"),
                parameters_media_type: String::from("application/vnd.example.toy.v1"),
                parameters_domain_tag: b"example-toy-parameters-v1".to_vec(),
                evidence_sources: vec![
                    EvidenceSourceDecl::new(
                        EvidenceSourceId::new("evidence.executor.attempt-record").unwrap(),
                        EvidenceSourceClass::Executor,
                    ),
                    EvidenceSourceDecl::new(
                        EvidenceSourceId::new("evidence.example.receipt").unwrap(),
                        EvidenceSourceClass::ProviderCorroborating,
                    ),
                ],
                quarantine_release: QuarantineReleaseRule::NeverReleasable,
                max_context_commitments: 4,
                max_identity_bytes: 64,
            };
            Self { descriptor }
        }
    }

    impl ProfileCodec for ToyCodec {
        fn descriptor(&self) -> &ProfileDescriptor {
            &self.descriptor
        }

        fn validate_canonical_bytes(&self, profile_bytes: &[u8]) -> Result<Vec<u8>, IntentError> {
            // A toy profile is exactly eight bytes interpreted as a big-endian target id.
            if profile_bytes.len() != 8 {
                return Err(IntentError::MalformedProfileBytes);
            }
            Ok(profile_bytes.to_vec())
        }
    }

    #[test]
    fn default_registry_round_trips_the_github_profile() {
        let registry = default_registry();
        let github = crate::intent::github_deployment_descriptor();
        assert!(registry.descriptor(&github.profile_id).is_some());
    }

    #[test]
    fn an_unrelated_profile_registers_without_core_edits() {
        let mut registry = default_registry();
        registry.register(Box::new(ToyCodec::new())).unwrap();
        let toy_id = ProfileId::new("org.example.toy.intent.v1").unwrap();
        assert_eq!(
            registry.decode_profile(&toy_id, &[1, 2, 3, 4, 5, 6, 7, 8]),
            Ok(vec![1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(
            registry.decode_profile(&toy_id, &[0, 0]),
            Err(IntentError::MalformedProfileBytes)
        );
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let mut registry = ProfileRegistry::new();
        registry.register(Box::new(ToyCodec::new())).unwrap();
        assert_eq!(
            registry.register(Box::new(ToyCodec::new())),
            Err(IntentError::DuplicateProfile)
        );
    }

    #[test]
    fn unregistered_profile_fails_closed() {
        let registry = ProfileRegistry::new();
        let toy_id = ProfileId::new("org.example.toy.intent.v1").unwrap();
        assert_eq!(
            registry.decode_profile(&toy_id, &[1, 2, 3, 4, 5, 6, 7, 8]),
            Err(IntentError::UnregisteredProfile)
        );
    }
}
