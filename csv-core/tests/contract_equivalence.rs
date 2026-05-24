#![cfg(any())]
//! Contract equivalence tests per Phase 7
//!
//! These tests verify that contracts across different chains emit
//! equivalent canonical events and follow the ABI constitution.

use csv_core::abi_constitution::*;
use csv_core::canonical_events::*;
use csv_hash::Hash;

/// Test that canonical events have consistent structure across chains.
#[test]
fn test_canonical_event_consistency() {
    // SealCreated event should have same structure across all chains
    let seal_created_ethereum = CanonicalEvent::SealCreated(SealCreatedEvent {
        seal_id: Hash::zero(),
        owner: vec![1, 2, 3, 4],
        commitment: Hash::zero(),
    });

    let seal_created_solana = CanonicalEvent::SealCreated(SealCreatedEvent {
        seal_id: Hash::zero(),
        owner: vec![5, 6, 7, 8],
        commitment: Hash::zero(),
    });

    // Event names should be identical
    assert_eq!(
        seal_created_ethereum.event_name(),
        seal_created_solana.event_name()
    );

    // Signature hashes should be identical (same event type)
    assert_eq!(
        seal_created_ethereum.signature_hash(),
        seal_created_solana.signature_hash()
    );
}

/// Test that required functions have consistent signatures.
#[test]
fn test_required_function_signatures() {
    let functions = vec![
        RequiredFunction::CreateSeal,
        RequiredFunction::ConsumeSeal,
        RequiredFunction::LockSeal,
        RequiredFunction::MintSeal,
        RequiredFunction::RefundSeal,
        RequiredFunction::RegisterNullifier,
        RequiredFunction::UpdateProofRoot,
    ];

    for func in &functions {
        // Each function should have a valid signature
        let signature = func.signature();
        assert!(!signature.is_empty());

        // Each function should have a valid selector
        let selector = func.selector();
        assert_ne!(selector, [0u8; 4]);
    }
}

/// Test that ABI constitution compliance check works.
#[test]
fn test_abi_compliance_check() {
    let constitution = AbiConstitution::new();

    // Create a compliant contract ABI
    let compliant_abi = ContractAbi {
        name: "CSVMint".to_string(),
        functions: vec![FunctionAbi {
            name: RequiredFunction::CreateSeal.signature().to_string(),
            inputs: vec![ParameterAbi {
                name: "commitment".to_string(),
                param_type: "bytes32".to_string(),
                indexed: false,
            }],
            outputs: vec![ParameterAbi {
                name: "sealId".to_string(),
                param_type: "bytes32".to_string(),
                indexed: false,
            }],
            payable: false,
        }],
        events: vec![EventAbi {
            name: "SealCreated".to_string(),
            indexed: vec![
                ParameterAbi {
                    name: "sealId".to_string(),
                    param_type: "bytes32".to_string(),
                    indexed: true,
                },
                ParameterAbi {
                    name: "owner".to_string(),
                    param_type: "address".to_string(),
                    indexed: true,
                },
            ],
            non_indexed: vec![ParameterAbi {
                name: "commitment".to_string(),
                param_type: "bytes32".to_string(),
                indexed: false,
            }],
        }],
        errors: vec![],
    };

    let result = constitution.check_compliance(&compliant_abi);
    // Should have missing functions since we only added one
    assert!(!result.missing_functions.is_empty());
}

/// Test that error codes are consistent across chains.
#[test]
fn test_error_code_consistency() {
    let errors = vec![
        ErrorCode::SealNotFound,
        ErrorCode::SealAlreadyConsumed,
        ErrorCode::SealAlreadyLocked,
        ErrorCode::InvalidCommitment,
        ErrorCode::InvalidProof,
        ErrorCode::NullifierAlreadyRegistered,
        ErrorCode::InvalidProofRoot,
        ErrorCode::Unauthorized,
        ErrorCode::InvalidChainId,
        ErrorCode::RefundNotAvailable,
    ];

    for error in &errors {
        // Each error should have a valid code
        let code = error.as_u8();
        assert!(code > 0);

        // Each error should have a valid name
        let name = error.name();
        assert!(!name.is_empty());
    }
}

/// Test that state machine invariants are enforced.
#[test]
fn test_state_machine_invariants() {
    let invariants = StateMachineInvariants::new();

    // Valid transitions should be allowed
    assert!(invariants.check_transition(SealState::Created, SealState::Consumed));
    assert!(invariants.check_transition(SealState::Created, SealState::Locked));
    assert!(invariants.check_transition(SealState::Locked, SealState::Minted));
    assert!(invariants.check_transition(SealState::Locked, SealState::Refunded));

    // Invalid transitions should be rejected
    assert!(!invariants.check_transition(SealState::Consumed, SealState::Created));
    assert!(!invariants.check_transition(SealState::Minted, SealState::Locked));
}

/// Test that event encoders produce consistent encodings.
#[test]
fn test_event_encoder_consistency() {
    let event = CanonicalEvent::SealCreated(SealCreatedEvent {
        seal_id: Hash::zero(),
        owner: vec![1, 2, 3, 4],
        commitment: Hash::zero(),
    });

    let eth_encoder = EthereumEventEncoder;
    let sol_encoder = SolanaEventEncoder;
    let sui_encoder = SuiEventEncoder;
    let aptos_encoder = AptosEventEncoder;

    // All encoders should be able to encode the event
    let eth_encoded = eth_encoder.encode(&event);
    let sol_encoded = sol_encoder.encode(&event);
    let sui_encoded = sui_encoder.encode(&event);
    let aptos_encoded = aptos_encoder.encode(&event);

    assert!(eth_encoded.is_ok());
    assert!(sol_encoded.is_ok());
    assert!(sui_encoded.is_ok());
    assert!(aptos_encoded.is_ok());

    // Encodings may differ by chain, but should all be non-empty
    assert!(!eth_encoded.unwrap().is_empty());
    assert!(!sol_encoded.unwrap().is_empty());
    assert!(!sui_encoded.unwrap().is_empty());
    assert!(!aptos_encoded.unwrap().is_empty());
}

/// Test that deployment manifests are reproducible.
#[test]
fn test_deployment_manifest_reproducibility() {
    let manifest1 = DeploymentManifest::new(
        "CSVMint".to_string(),
        "1.0.0".to_string(),
        "ethereum".to_string(),
        &[1, 2, 3, 4],
        vec![],
        vec![5, 6, 7, 8],
    );

    let manifest2 = DeploymentManifest::new(
        "CSVMint".to_string(),
        "1.0.0".to_string(),
        "ethereum".to_string(),
        &[1, 2, 3, 4],
        vec![],
        vec![5, 6, 7, 8],
    );

    // Identical manifests should have identical checksums
    assert_eq!(manifest1.checksum(), manifest2.checksum());
}

/// Test that deployment registry tracks deployments correctly.
#[test]
fn test_deployment_registry() {
    let mut registry = DeploymentRegistry::new();
    let manifest = DeploymentManifest::new(
        "CSVMint".to_string(),
        "1.0.0".to_string(),
        "ethereum".to_string(),
        &[1, 2, 3, 4],
        vec![],
        vec![5, 6, 7, 8],
    );

    let mut finalized = manifest.clone();
    finalized.finalize(vec![9, 10, 11, 12], Hash::zero(), 100);

    registry.register(finalized).unwrap();
    assert!(registry.verify_deployment(&[9, 10, 11, 12]));
}

/// Test that CREATE2 address calculation is deterministic.
#[test]
fn test_create2_deterministic() {
    let deployer = Create2Deployer::new(vec![1; 20], Hash::zero());
    let bytecode = vec![2; 100];

    let address1 = deployer.calculate_address(&bytecode).unwrap();
    let address2 = deployer.calculate_address(&bytecode).unwrap();

    // Same inputs should produce same address
    assert_eq!(address1, address2);
}

/// Test that canonical events can be serialized and deserialized.
#[test]
fn test_canonical_event_serialization() {
    let event = CanonicalEvent::SealCreated(SealCreatedEvent {
        seal_id: Hash::zero(),
        owner: vec![1, 2, 3, 4],
        commitment: Hash::zero(),
    });

    // Serialize to canonical CBOR
    let cbor = csv_codec::to_canonical_cbor(&event).unwrap();
    assert!(!cbor.is_empty());

    // Deserialize from canonical CBOR
    let restored: CanonicalEvent = csv_codec::from_canonical_cbor(&cbor).unwrap();
    assert_eq!(event.event_name(), restored.event_name());
}

/// Test that deployment manifests can be serialized and deserialized.
#[test]
fn test_deployment_manifest_serialization() {
    let manifest = DeploymentManifest::new(
        "CSVMint".to_string(),
        "1.0.0".to_string(),
        "ethereum".to_string(),
        &[1, 2, 3, 4],
        vec![],
        vec![5, 6, 7, 8],
    );

    // Serialize to canonical CBOR
    let cbor = manifest.to_canonical_cbor().unwrap();
    assert!(!cbor.is_empty());

    // Deserialize from canonical CBOR
    let restored = DeploymentManifest::from_canonical_cbor(&cbor).unwrap();
    assert_eq!(manifest.contract_name, restored.contract_name);
    assert_eq!(manifest.checksum(), restored.checksum());
}

/// Test that contract bytecode verification works.
#[test]
fn test_contract_bytecode_verification() {
    let bytecode = vec![1, 2, 3, 4, 5];
    let contract_bytecode = ContractBytecode::new(bytecode.clone(), "solc-0.8.20".to_string());

    assert!(contract_bytecode.verify());
    assert_eq!(contract_bytecode.checksum, Hash::sha256(&bytecode));
}
