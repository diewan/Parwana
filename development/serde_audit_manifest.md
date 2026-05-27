# Serde Audit Manifest — Workstream A-1

> Generated: 2025-01-27
> Total types with Serialize/Deserialize: 196
> Target: All must migrate to csv-wire *Wire types

## Summary by Crate

| Crate | Count | Priority |
|-------|-------|----------|
| csv-protocol | 127 | High |
| csv-proof | 38 | High |
| csv-hash | 21 | High |
| csv-verifier | 4 | Medium |
| csv-codec | 0 | N/A |

## csv-hash (21 types)

### canonical.rs
- CanonicalProof (line 279)

### chain_id.rs
- ChainId (line 15)

### commitment.rs
- Commitment (line 53)

### dag.rs
- DagNode (line 12)
- MerkleProof (line 60)

### hash_registry.rs
- HashAlgorithm (line 15)
- HashOutput (line 325)
- HashContext (line 350)
- HashDomain (line 368)
- HashPurpose (line 386)
- HashVersion (line 404)
- HashSecurityLevel (line 422)
- HashCompliance (line 440)

### nullifier.rs
- Nullifier (line 61)

### registry.rs
- HashEntry (line 104)
- HashRegistryConfig (line 131)
- HashRegistryState (line 22)
- HashRegistryEntry (line 77)

### sanad.rs
- SanadId (line 10)

### seal.rs
- SealPoint (line 179)
- SealOutput (line 29)

## csv-proof (38 types)

### certification.rs
- Certification (line 19)
- CertificationClaim (line 6)

### chain_config.rs
- ChainCapability (line 17)
- ChainConfig (line 28)
- ChainParams (line 6)

### commitments_ext.rs
- ExtendedCommitment (line 161)
- CommitmentExtension (line 20)
- CommitmentBundle (line 224)
- CommitmentProof (line 245)
- CommitmentWitness (line 93)

### cross_chain.rs
- CrossChainProof (line 22)
- ChainAnchor (line 29)
- AnchorProof (line 40)
- CrossChainBundle (line 7)

### events.rs
- ProofEvent (line 7)

### proof_dags.rs
- ProofDag (line 103)
- DagEdge (line 16)
- DagPath (line 37)
- DagCheckpoint (line 50)

### proof.rs
- Proof (line 107, field-level)
- ProofHeader (line 174)
- ProofMetadata (line 35)
- ProofBody (line 61, field-level)

### proof_types.rs
- ProofBundle (line 141)
- ProofElement (line 178)
- ProofWitness (line 27)
- ProofStatement (line 298)
- ProofCredential (line 394)
- ProofAttestation (line 424)
- ProofEndorsement (line 453)
- ProofCertificate (line 479)
- ProofSignature (line 505)
- ProofTimestamp (line 538)
- ProofVersion (line 566)
- ProofHash (line 591)

### provenance.rs
- Provenance (line 6)

### signature.rs
- ProofSignature (line 17)
- SignatureScheme (line 6)

## csv-protocol (127 types)

### backend.rs
- ChainOpError (line 102)
- ChainOpResult (line 123)
- ChainQuery (line 139)
- ChainSigner (line 154)
- ChainBroadcaster (line 169)
- ChainDeployer (line 182)
- ChainProofProvider (line 205)
- ChainSanadOps (line 222)
- TransactionStatus (line 28)
- DeploymentStatus (line 79)

### canonical_proof.rs
- CanonicalProof (line 15)

### chain_config.rs
- ChainConfig (line 6)

### cross_chain.rs
- CrossChainTransfer (line 124)
- TransferParams (line 149)
- TransferReceipt (line 179)
- TransferState (line 19)
- LockParams (line 226)
- MintParams (line 282)
- ProofParams (line 298)
- FinalityParams (line 318)
- RecoveryParams (line 336)
- ConfirmationParams (line 352)
- BroadcastParams (line 372)
- ValidationParams (line 383)
- ExecutionParams (line 398)
- MonitoringParams (line 415)
- CancellationParams (line 430)
- CompletionParams (line 445)

### deterministic_recovery.rs
- RecoveryStrategy (line 127)
- RecoveryCheckpoint (line 146)
- RecoveryState (line 169)
- RecoveryContext (line 178)
- RecoveryResult (line 259)
- RecoveryConfig (line 28)
- RecoveryEvent (line 46, field-level)

### envelope.rs
- Envelope (line 13)
- EnvelopeHeader (line 20)
- EnvelopeBody (line 30)
- EnvelopeSignature (line 77)

### events.rs
- TransferEvent (line 1002)
- PhaseEvent (line 1014)
- ChainEvent (line 104)
- SystemEvent (line 79)
- NetworkEvent (line 808)
- StorageEvent (line 848)
- ValidationEvent (line 912)
- VerificationEvent (line 926)
- RecoveryEvent (line 940)
- MonitoringEvent (line 956)
- HealthEvent (line 972)
- MetricsEvent (line 988)

### failure_domains.rs
- FailureDomain (line 100)
- DomainConfig (line 128)
- DomainState (line 241)
- DomainId (line 25)
- DomainStatus (line 58)
- DomainHealth (line 83)

### finality/abstraction.rs
- FinalityAbstraction (line 16)
- FinalityContext (line 78)
- FinalityResult (line 95)

### finality/capabilities.rs
- FinalityCapability (line 11)
- FinalityQuery (line 136)
- FinalityOperation (line 187)
- FinalityConfig (line 26)
- FinalityParams (line 41)
- FinalityResult (line 501)
- FinalityStatus (line 514)
- FinalityError (line 550)
- FinalityEvent (line 58)
- FinalityState (line 73)
- FinalityHealth (line 87)
- FinalityMetrics (line 99)

### finality/chain_specific.rs
- BitcoinFinality (line 14)
- EthereumFinality (line 33)

### finality/mod.rs
- FinalityMode (line 32)
- FinalityConfig (line 351)
- FinalityResult (line 453)
- FinalityStatus (line 528)
- FinalityContext (line 75)
- FinalityEvent (line 845)
- FinalityError (line 862)
- FinalityState (line 878)
- FinalityHealth (line 947)

### finality/state.rs
- FinalityState (line 19)
- FinalityContext (line 6)

### genesis.rs
- GenesisConfig (line 16)

### invariants.rs
- InvariantViolation (line 257)

### lease.rs
- LeaseId (line 35)
- LeaseState (line 57)

### proof_types.rs
- ProofBundle (line 146)
- ProofElement (line 183)
- ProofWitness (line 303)
- ProofStatement (line 32)
- ProofCredential (line 399)
- ProofAttestation (line 429)
- ProofEndorsement (line 458)
- ProofCertificate (line 484)
- ProofSignature (line 510)
- ProofTimestamp (line 543)
- ProofVersion (line 571)
- ProofHash (line 596)
- ProofMetadata (line 618)
- ProofField (line 644, field-level)
- ProofResult (line 678)

### replay/registry.rs
- ReplayRegistry (line 105)
- ReplayEntry (line 293)
- ReplayCheckpoint (line 364)
- ReplayId (line 44)
- ReplayConfig (line 521)

### sanad.rs
- SanadId (line 104)
- Sanad (line 13)
- SanadState (line 24)
- SanadConfig (line 70)

### signature.rs
- Signature (line 27)

### state.rs
- StateEntry (line 101)
- StateValue (line 135)
- StateKey (line 159)
- StateVersion (line 18)
- StateConfig (line 56)

### transfer_state/mod.rs
- TransferPhase (line 103)

### verification.rs
- VerificationLevel (line 9)

### verified.rs
- Verified (line 15)
- VerifiedBundle (line 29)
- VerifiedState (line 42)
- VerifiedResult (line 55)
- VerifiedError (line 64)
- VerifiedConfig (line 98)

### version.rs
- Version (line 154)
- VersionRange (line 318)
- VersionConstraint (line 369)
- VersionPolicy (line 475)
- VersionCompatibility (line 50)
- VersionInfo (line 541)

## csv-verifier (4 types)

### verifier.rs
- VerificationResult (line 242)
- VerificationConfig (line 340)
- VerificationParams (line 54)
- VerificationContext (line 93)

## csv-codec

No Serialize/Deserialize derives found (already clean or uses csv-wire)

## Migration Priority

### Priority 1 (Core protocol types - must migrate first)
- csv-protocol::proof_types::ProofBundle
- csv-protocol::seal::SealPoint (in csv-hash)
- csv-protocol::transfer_state types
- csv-hash primitives (Hash, SanadId, Commitment)

### Priority 2 (Cross-chain and finality types)
- csv-protocol::cross_chain types
- csv-protocol::finality types
- csv-proof::cross_chain types

### Priority 3 (Events, configuration, infrastructure)
- Event types
- Configuration types
- Backend/adapter types

### Priority 4 (Verification and observability)
- csv-verifier types
- Metrics/health types

## Notes

- Some types appear in multiple crates (e.g., ProofBundle in both csv-protocol and csv-proof)
- Field-level derives exist (e.g., ProofBody field in proof.rs)
- csv-codec appears to already be clean or uses csv-wire
- Total migration effort: ~196 types across 4 crates
