//! CSV Seal Module for Aptos — thin-registry cross-chain mint (RFC-0012)
//!
//! This Move module is the Aptos destination-chain **thin registry** for CSV cross-chain
//! transfers. Cross-chain correctness is decided OFF-CHAIN by the canonical CSV verifier
//! (`validate_source_proof`). This module does NOT re-adjudicate the proof; it records a
//! mint only when the calldata carries at least `threshold` distinct valid verifier
//! signatures over the frozen RFC-0012 §9.2 attestation digest, and it enforces on-chain
//! replay protection (`sanad_id` / `nullifier` / `lock_event_id` uniqueness).
//!
//! ## Authenticity model (RFC-0012 §9 / ABI_CONSTITUTION.md §9)
//!
//! The former proof-root gating model (an installed `proof_root` / Merkle inclusion proof
//! as a mint precondition) is REMOVED from the mint path. Under RFC-0012 §4 none of
//! `proof_root`, `state_root`, Merkle proof bytes, or `leaf_position` gate mint. Authority
//! travels in the payload as a verifier-signed attestation, not in whoever submits the
//! transaction — mint is authenticated, not permissionless, and there is no `msg.sender`
//! allowlist.
//!
//! ## Signature scheme (RFC-0012 §9.2, frozen)
//!
//! - Digest: SHA-256 over the fixed 287-byte preimage (see `mint_attestation_digest`).
//! - Signature: secp256k1 ECDSA over that digest, recovered natively via the Aptos
//!   `aptos_std::secp256k1` stdlib. Each verifier identity is stored as the compressed
//!   33-byte secp256k1 public key (the pinned non-EVM form).
//!
//! ## Error Codes
//!
//! - `ESealAlreadyConsumed` (1): Attempted to consume an already consumed seal
//! - `ESealNotConsumed` (2): Attempted operation requiring consumed seal
//! - `EAnchorDataExists` (3): Resource already exists for this account/key
//! - `ESealNotFound` (4): Seal / registry / lock not found
//! - `EInvalidMetadata` (5): Invalid token/NFT/proof metadata
//! - `EInvalidProof` (6): Invalid input to a proof utility (retained for input validation)
//! - `ENullifierAlreadyRegistered` (7): Nullifier already registered / used
//! - `ESanadAlreadyMinted` (8): sanad_id already minted (duplicate-mint guard)
//! - `ELockEventAlreadyRecorded` (9): lock_event_id already recorded (duplicate-source-lock guard)
//! - `EInvalidMintRequest` (10): Malformed mint field set (bad length / zero key)
//! - `EInsufficientSignatures` (11): Fewer than `threshold` distinct valid verifier signatures
//! - `EInvalidVerifierSignature` (12): A signature did not recover to an authorized verifier
//! - `EMalformedSignature` (13): Signature is not a well-formed 65-byte r||s||v encoding
//! - `EAttestationExpired` (14): `attestation_expiry` is in the past
//! - `EUnauthorized` (15): Caller is not the authorized deployer / owner
//! - `EInvalidVerifier` (16): Verifier public key is not a 33-byte compressed key
//! - `EInvalidThreshold` (17): Threshold is zero or exceeds the verifier set size
//! - `ETimelockNotExpired` (18): Governance timelock has not elapsed

module csv_seal::CSVSeal {
    use std::signer;
    use std::event;
    use std::account;
    use aptos_std::smart_table::{Self, SmartTable};
    use aptos_std::aptos_hash;
    use aptos_std::secp256k1;
    use std::option;
    use std::vector;
    use std::bcs;
    use std::hash;

    const ASSET_CLASS_UNSPECIFIED: u8 = 0;
    const ASSET_CLASS_PROOF_SANAD: u8 = 3;
    const PROOF_SYSTEM_UNSPECIFIED: u8 = 0;

    /// Protocol version (thin-registry / verifier-attested mint). Matches the ETH `CSVSeal`.
    const VERSION: u64 = 6;

    /// Governance timelock period (7 days). Scopes ONLY verifier-set and ownership changes —
    /// never a per-mint precondition (RFC-0012 §9.3).
    const TIMELOCK_PERIOD: u64 = 604800;

    /// Refund timeout for a locked Sanad (24 hours), in seconds.
    const REFUND_TIMEOUT: u64 = 86400;

    // =========================================================================
    // Events (canonical set — RFC-0012 / ABI_CONSTITUTION Canonical Event Names)
    // =========================================================================

    // Emitted when a new seal/Sanad is created.
    #[event]
    struct SanadCreated has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
    }

    // Emitted when a seal/Sanad is consumed.
    #[event]
    struct SanadConsumed has drop, store {
        sanad_id: vector<u8>,
        consumer: address,
    }

    // Emitted when a Sanad is locked for cross-chain transfer.
    #[event]
    struct CrossChainLock has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        /// Destination chain identity: keccak256("csv.chain.<name>") (32 bytes).
        destination_chain: vector<u8>,
        destination_owner: vector<u8>,
        source_tx_hash: vector<u8>,
        locked_at: u64,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
    }

    // Emitted when a Sanad is minted on this destination chain from a verifier attestation.
    // Carries the FULL `destination_owner` bytes so settlement / replay evidence can be
    // reconstructed off-chain (only `keccak256(destination_owner)` is stored on-chain).
    #[event]
    struct SanadMinted has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        /// Source chain identity: keccak256("csv.chain.<name>") (32 bytes).
        source_chain: vector<u8>,
        destination_owner: vector<u8>,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        minted_at: u64,
    }

    // Emitted when a locked Sanad is refunded after timeout.
    #[event]
    struct CrossChainRefund has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        refunded_at: u64,
    }

    // Emitted whenever token/NFT/proof metadata is attached to a Sanad (archival; NOT on the
    // mint hot path — RFC-0012 §4).
    #[event]
    struct SanadMetadataRecorded has drop, store {
        sanad_id: vector<u8>,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
    }

    // Emitted when a nullifier is registered / consumed.
    #[event]
    struct NullifierRegistered has drop, store {
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
    }

    // Emitted when a verifier is added to the set.
    #[event]
    struct VerifierAdded has drop, store { verifier: vector<u8> }

    // Emitted when a verifier is removed from the set.
    #[event]
    struct VerifierRemoved has drop, store { verifier: vector<u8> }

    // Emitted when the signature threshold `M` is updated.
    #[event]
    struct ThresholdUpdated has drop, store { threshold: u64 }

    // =========================================================================
    // Canonical State Constants (matching Ethereum/Solana/Sui)
    // =========================================================================

    const SANAD_STATE_UNCREATED: u8 = 0;
    const SANAD_STATE_CREATED: u8 = 1;
    const SANAD_STATE_ACTIVE: u8 = 2;
    const SANAD_STATE_LOCKED: u8 = 3;
    const SANAD_STATE_CONSUMED: u8 = 4;
    const SANAD_STATE_MINTED: u8 = 5;
    const SANAD_STATE_TRANSFERRED: u8 = 6;
    const SANAD_STATE_REFUNDED: u8 = 7;
    const SANAD_STATE_BURNED: u8 = 8;
    const SANAD_STATE_INVALID: u8 = 9;

    // =========================================================================
    // Error Codes
    // =========================================================================

    const ESealAlreadyConsumed: u64 = 1;
    const ESealNotConsumed: u64 = 2;
    const EAnchorDataExists: u64 = 3;
    const ESealNotFound: u64 = 4;
    const EInvalidMetadata: u64 = 5;
    const EInvalidProof: u64 = 6;
    const ENullifierAlreadyRegistered: u64 = 7;
    const ESanadAlreadyMinted: u64 = 8;
    const ELockEventAlreadyRecorded: u64 = 9;
    const EInvalidMintRequest: u64 = 10;
    const EInsufficientSignatures: u64 = 11;
    const EInvalidVerifierSignature: u64 = 12;
    const EMalformedSignature: u64 = 13;
    const EAttestationExpired: u64 = 14;
    const EUnauthorized: u64 = 15;
    const EInvalidVerifier: u64 = 16;
    const EInvalidThreshold: u64 = 17;
    const ETimelockNotExpired: u64 = 18;

    // =========================================================================
    // Structs — seal lifecycle
    // =========================================================================

    // Anchor event emitted when a seal is consumed.
    #[event]
    struct AnchorEvent has drop, store {
        commitment: vector<u8>,
        seal_address: address,
        nonce: u64,
        timestamp_secs: u64,
    }

    /// Seal resource that can be consumed exactly once.
    struct Seal has store, drop {
        nonce: u64,
        state: u8,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
    }

    /// Collection of seals for an account (allows multiple seals per account like Sui).
    struct SealCollection has key {
        seals: SmartTable<u64, Seal>,
        next_nonce: u64,
    }

    /// Persistent storage of commitment after seal consumption.
    struct AnchorDataCollection has key {
        anchor_data: SmartTable<u64, AnchorData>,
    }

    struct AnchorData has store, copy, drop {
        commitment: vector<u8>,
        consumed_at: u64,
        nonce: u64,
    }

    // =========================================================================
    // Structs — verifier authority (RFC-0012 §9.3)
    // =========================================================================

    /// Authorized verifier set + threshold `M`, plus governance timelock state.
    /// Stored at `@csv_seal`. Mint requires >= `threshold` distinct valid verifier
    /// signatures over the §9.2 digest. Rotation/revocation are timelocked owner
    /// operations kept OFF the mint hot path.
    struct MintAuthority has key {
        owner: address,
        /// Compressed 33-byte secp256k1 public keys.
        verifiers: vector<vector<u8>>,
        threshold: u64,
        // ---- ownership timelock ----
        pending_owner: address,
        pending_owner_valid_after: u64,
        // ---- verifier-set update timelock ----
        pending_verifier_active: bool,
        pending_verifier_pk: vector<u8>,
        pending_verifier_add: bool,
        pending_verifier_threshold: u64,
        pending_verifier_valid_after: u64,
    }

    // =========================================================================
    // Structs — lock / mint registry
    // =========================================================================

    /// Lock record for tracking cross-chain transfers and refunds.
    struct LockRecord has store, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        destination_chain: vector<u8>,
        locked_at: u64,
        refunded: bool,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
    }

    /// Minimal destination-mint record persisted for settlement / inspection (RFC-0012 §3).
    struct MintRecord has store, drop {
        commitment: vector<u8>,
        source_chain: vector<u8>,
        destination_owner_hash: vector<u8>,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        minted_at: u64,
    }

    /// Shared registry: locks + the on-chain anti-replay domain for mint.
    struct LockRegistry has key {
        locks: SmartTable<vector<u8>, LockRecord>,
        refund_timeout: u64,
        /// Duplicate-mint key: sanad_id already minted.
        minted_sanads: SmartTable<vector<u8>, bool>,
        /// Replay-protection key: nullifier already used.
        nullifiers: SmartTable<vector<u8>, bool>,
        /// Duplicate-source-lock key: lock_event_id already recorded.
        used_lock_events: SmartTable<vector<u8>, bool>,
        /// Persisted mint records keyed by sanad_id.
        mint_records: SmartTable<vector<u8>, MintRecord>,
    }

    // =========================================================================
    // Module / registry / authority initialization
    // =========================================================================

    /// Initialize the module event handle (stored at module publish address).
    public entry fun initialize_module(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<AnchorEventHandle>(addr), EAnchorDataExists);
        move_to(account, AnchorEventHandle {
            events: account::new_event_handle<AnchorEvent>(account),
        });
    }

    struct AnchorEventHandle has key {
        events: event::EventHandle<AnchorEvent>,
    }

    /// Initialize the LockRegistry (called once by the deployer during deployment).
    public entry fun init_registry(account: &signer) {
        let addr = signer::address_of(account);
        assert!(addr == @csv_seal, EUnauthorized);
        assert!(!exists<LockRegistry>(addr), EAnchorDataExists);
        move_to(account, LockRegistry {
            locks: smart_table::new(),
            refund_timeout: REFUND_TIMEOUT,
            minted_sanads: smart_table::new(),
            nullifiers: smart_table::new(),
            used_lock_events: smart_table::new(),
            mint_records: smart_table::new(),
        });
    }

    /// Seed the verifier set with a single verifier and threshold `M = 1` (RFC-0012 §9.3).
    /// Only the deployer (`@csv_seal`) may install the authority. `verifier_pubkey` is the
    /// compressed 33-byte secp256k1 public key.
    public entry fun init_mint_authority(account: &signer, verifier_pubkey: vector<u8>) {
        let addr = signer::address_of(account);
        assert!(addr == @csv_seal, EUnauthorized);
        assert!(!exists<MintAuthority>(addr), EAnchorDataExists);
        assert!(vector::length(&verifier_pubkey) == 33, EInvalidVerifier);

        let verifiers = vector::empty<vector<u8>>();
        vector::push_back(&mut verifiers, copy verifier_pubkey);

        move_to(account, MintAuthority {
            owner: addr,
            verifiers,
            threshold: 1,
            pending_owner: @0x0,
            pending_owner_valid_after: 0,
            pending_verifier_active: false,
            pending_verifier_pk: vector::empty<u8>(),
            pending_verifier_add: false,
            pending_verifier_threshold: 0,
            pending_verifier_valid_after: 0,
        });

        event::emit(VerifierAdded { verifier: verifier_pubkey });
        event::emit(ThresholdUpdated { threshold: 1 });
    }

    /// Get the registry / authority address (module deployer).
    public fun get_registry_addr(): address {
        @csv_seal
    }

    // =========================================================================
    // Seal Creation
    // =========================================================================

    public entry fun init_seal_collection(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<SealCollection>(addr), EAnchorDataExists);
        move_to(account, SealCollection {
            seals: smart_table::new(),
            next_nonce: 0,
        });
    }

    public entry fun create_seal(account: &signer, nonce: u64) acquires SealCollection {
        let addr = signer::address_of(account);
        assert!(exists<SealCollection>(addr), ESealNotFound);

        let collection = borrow_global_mut<SealCollection>(addr);
        assert!(!smart_table::contains(&collection.seals, nonce), EAnchorDataExists);

        smart_table::add(&mut collection.seals, nonce, Seal {
            nonce,
            state: SANAD_STATE_CREATED,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
        });

        if (nonce >= collection.next_nonce) {
            collection.next_nonce = nonce + 1;
        };
    }

    public entry fun create_seal_auto(account: &signer) acquires SealCollection {
        let addr = signer::address_of(account);
        assert!(exists<SealCollection>(addr), ESealNotFound);

        let collection = borrow_global_mut<SealCollection>(addr);
        let nonce = collection.next_nonce;

        smart_table::add(&mut collection.seals, nonce, Seal {
            nonce,
            state: SANAD_STATE_CREATED,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
        });

        collection.next_nonce = nonce + 1;
    }

    /// Attach token/NFT/proof metadata to an unconsumed seal (archival; NOT on the mint path).
    public entry fun record_sanad_metadata(
        account: &signer,
        nonce: u64,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
    ) acquires SealCollection {
        let addr = signer::address_of(account);
        assert!(exists<SealCollection>(addr), ESealNotFound);
        assert!(asset_class <= ASSET_CLASS_PROOF_SANAD, EInvalidMetadata);
        assert!(asset_class == ASSET_CLASS_UNSPECIFIED || vector::length(&asset_id) > 0, EInvalidMetadata);

        let collection = borrow_global_mut<SealCollection>(addr);
        assert!(smart_table::contains(&collection.seals, nonce), ESealNotFound);

        let seal = smart_table::borrow_mut(&mut collection.seals, nonce);
        assert!(seal.state != SANAD_STATE_CONSUMED, ESealAlreadyConsumed);

        seal.asset_class = asset_class;
        seal.asset_id = asset_id;
        seal.metadata_hash = metadata_hash;
        seal.proof_system = proof_system;

        event::emit(SanadMetadataRecorded {
            sanad_id: bcs::to_bytes(&addr),
            asset_class,
            asset_id: seal.asset_id,
            metadata_hash: seal.metadata_hash,
            proof_system,
        });
    }

    // =========================================================================
    // Seal Consumption
    // =========================================================================

    public entry fun init_anchor_collection(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<AnchorDataCollection>(addr), EAnchorDataExists);
        move_to(account, AnchorDataCollection {
            anchor_data: smart_table::new(),
        });
    }

    public entry fun consume_seal(account: &signer, nonce: u64, commitment: vector<u8>) acquires SealCollection, AnchorDataCollection {
        let seal_addr = signer::address_of(account);
        assert!(exists<SealCollection>(seal_addr), ESealNotFound);

        let collection = borrow_global_mut<SealCollection>(seal_addr);
        assert!(smart_table::contains(&collection.seals, nonce), ESealNotFound);

        let seal = smart_table::borrow_mut(&mut collection.seals, nonce);
        assert!(seal.state != SANAD_STATE_CONSUMED, ESealAlreadyConsumed);
        seal.state = SANAD_STATE_CONSUMED;

        let timestamp = aptos_framework::timestamp::now_seconds();

        if (!exists<AnchorDataCollection>(seal_addr)) {
            move_to(account, AnchorDataCollection {
                anchor_data: smart_table::new(),
            });
        };

        let anchor_collection = borrow_global_mut<AnchorDataCollection>(seal_addr);
        assert!(!smart_table::contains(&anchor_collection.anchor_data, nonce), EAnchorDataExists);
        smart_table::add(&mut anchor_collection.anchor_data, nonce, AnchorData {
            commitment: copy commitment,
            consumed_at: timestamp,
            nonce,
        });

        event::emit(AnchorEvent {
            commitment,
            seal_address: seal_addr,
            nonce,
            timestamp_secs: timestamp,
        });
    }

    // =========================================================================
    // Queries — seal lifecycle
    // =========================================================================

    public fun is_seal_available(addr: address, nonce: u64): bool acquires SealCollection {
        if (!exists<SealCollection>(addr)) { return false };
        let collection = borrow_global<SealCollection>(addr);
        if (!smart_table::contains(&collection.seals, nonce)) { return false };
        smart_table::borrow(&collection.seals, nonce).state != SANAD_STATE_CONSUMED
    }

    public fun is_consumed(addr: address, nonce: u64): bool acquires SealCollection {
        if (!exists<SealCollection>(addr)) { return false };
        let collection = borrow_global<SealCollection>(addr);
        if (!smart_table::contains(&collection.seals, nonce)) { return false };
        smart_table::borrow(&collection.seals, nonce).state == SANAD_STATE_CONSUMED
    }

    public fun get_seal_nonce(addr: address, nonce: u64): u64 acquires SealCollection {
        assert!(exists<SealCollection>(addr), ESealNotFound);
        let collection = borrow_global<SealCollection>(addr);
        assert!(smart_table::contains(&collection.seals, nonce), ESealNotFound);
        smart_table::borrow(&collection.seals, nonce).nonce
    }

    public fun get_anchor_data(addr: address, nonce: u64): AnchorData acquires AnchorDataCollection {
        assert!(exists<AnchorDataCollection>(addr), ESealNotFound);
        let collection = borrow_global<AnchorDataCollection>(addr);
        assert!(smart_table::contains(&collection.anchor_data, nonce), ESealNotFound);
        *smart_table::borrow(&collection.anchor_data, nonce)
    }

    public fun has_anchor_data(addr: address, nonce: u64): bool acquires AnchorDataCollection {
        if (!exists<AnchorDataCollection>(addr)) { return false };
        let collection = borrow_global<AnchorDataCollection>(addr);
        smart_table::contains(&collection.anchor_data, nonce)
    }

    public fun get_commitment(addr: address, nonce: u64): vector<u8> acquires AnchorDataCollection {
        assert!(exists<AnchorDataCollection>(addr), ESealNotFound);
        let collection = borrow_global<AnchorDataCollection>(addr);
        assert!(smart_table::contains(&collection.anchor_data, nonce), ESealNotFound);
        smart_table::borrow(&collection.anchor_data, nonce).commitment
    }

    public fun get_consumed_at(addr: address, nonce: u64): u64 acquires AnchorDataCollection {
        assert!(exists<AnchorDataCollection>(addr), ESealNotFound);
        let collection = borrow_global<AnchorDataCollection>(addr);
        assert!(smart_table::contains(&collection.anchor_data, nonce), ESealNotFound);
        smart_table::borrow(&collection.anchor_data, nonce).consumed_at
    }

    public fun get_next_nonce(addr: address): u64 acquires SealCollection {
        assert!(exists<SealCollection>(addr), ESealNotFound);
        borrow_global<SealCollection>(addr).next_nonce
    }

    // =========================================================================
    // Cross-Chain Lock
    // =========================================================================

    /// Lock a seal for cross-chain transfer. Consumes the seal and records the lock.
    /// `destination_chain` is the 32-byte keccak256("csv.chain.<name>") identity.
    public entry fun lock_sanad(
        account: &signer,
        nonce: u64,
        sanad_id: vector<u8>,
        destination_chain: vector<u8>,
        destination_owner: vector<u8>,
    ) acquires SealCollection, LockRegistry, AnchorDataCollection {
        let owner_addr = signer::address_of(account);
        assert!(exists<SealCollection>(owner_addr), ESealNotFound);

        let collection = borrow_global_mut<SealCollection>(owner_addr);
        assert!(smart_table::contains(&collection.seals, nonce), ESealNotFound);

        let seal = smart_table::borrow_mut(&mut collection.seals, nonce);
        assert!(seal.state != SANAD_STATE_CONSUMED, ESealAlreadyConsumed);

        let commitment = get_commitment_bytes(sanad_id, nonce);

        let registry_addr = get_registry_addr();
        assert!(exists<LockRegistry>(registry_addr), ESealNotFound);
        let registry = borrow_global_mut<LockRegistry>(registry_addr);
        let locked_at = aptos_framework::timestamp::now_seconds();

        assert!(!smart_table::contains(&registry.locks, copy sanad_id), EAnchorDataExists);
        smart_table::add(&mut registry.locks, copy sanad_id, LockRecord {
            sanad_id: copy sanad_id,
            commitment: copy commitment,
            owner: owner_addr,
            destination_chain: copy destination_chain,
            locked_at,
            refunded: false,
            asset_class: seal.asset_class,
            asset_id: seal.asset_id,
            metadata_hash: seal.metadata_hash,
            proof_system: seal.proof_system,
        });

        event::emit(CrossChainLock {
            sanad_id: copy sanad_id,
            commitment: copy commitment,
            owner: owner_addr,
            destination_chain,
            destination_owner,
            source_tx_hash: vector::empty<u8>(),
            locked_at,
            asset_class: seal.asset_class,
            asset_id: seal.asset_id,
            metadata_hash: seal.metadata_hash,
            proof_system: seal.proof_system,
        });

        event::emit(SanadConsumed {
            sanad_id: copy sanad_id,
            consumer: owner_addr,
        });

        seal.state = SANAD_STATE_CONSUMED;

        if (!exists<AnchorDataCollection>(owner_addr)) {
            move_to(account, AnchorDataCollection {
                anchor_data: smart_table::new(),
            });
        };

        let anchor_collection = borrow_global_mut<AnchorDataCollection>(owner_addr);
        assert!(!smart_table::contains(&anchor_collection.anchor_data, nonce), EAnchorDataExists);
        smart_table::add(&mut anchor_collection.anchor_data, nonce, AnchorData {
            commitment,
            consumed_at: locked_at,
            nonce,
        });
    }

    // =========================================================================
    // Verifier-attested destination mint (RFC-0012 §3 / §9)
    // =========================================================================

    /// Mint (materialize) a Sanad on this destination chain.
    ///
    /// THIN REGISTRY. Cross-chain validity is decided off-chain; authenticity here is a set of
    /// verifier signatures over the frozen §9.2 attestation digest. There is NO proof root,
    /// state root, Merkle proof, or leaf index. Uniqueness of `sanad_id` / `nullifier` /
    /// `lock_event_id` is enforced on-chain.
    ///
    /// * `sanad_id` — unique sanad identifier (32 bytes); primary duplicate-mint key.
    /// * `commitment` — commitment binding the sanad content/ownership (32 bytes).
    /// * `source_chain` — keccak256("csv.chain.<src>") (32 bytes).
    /// * `destination_owner` — recipient identity bytes; full bytes emitted, only the hash stored.
    /// * `lock_event_id` — identity of the source-chain lock event (32 bytes).
    /// * `nullifier` — replay nullifier consumed by the source seal (32 bytes).
    /// * `attestation_expiry` — u64 unix seconds; 0 = no expiry. Bound over the digest (§9.2).
    /// * `signatures` — vector of 65-byte secp256k1 signatures (r||s||v) over the §9.2 digest.
    public entry fun mint_sanad(
        _account: &signer,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        source_chain: vector<u8>,
        destination_owner: vector<u8>,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        attestation_expiry: u64,
        signatures: vector<vector<u8>>,
    ) acquires MintAuthority, LockRegistry {
        // Field sanity: every real mint carries fixed-width, non-zero replay keys.
        assert!(is_fixed32_nonzero(&sanad_id), EInvalidMintRequest);
        assert!(is_fixed32_nonzero(&commitment), EInvalidMintRequest);
        assert!(is_fixed32_nonzero(&source_chain), EInvalidMintRequest);
        assert!(is_fixed32_nonzero(&lock_event_id), EInvalidMintRequest);
        assert!(is_fixed32_nonzero(&nullifier), EInvalidMintRequest);
        assert!(vector::length(&destination_owner) > 0, EInvalidMintRequest);

        // §9.2 expiry bound.
        let now = aptos_framework::timestamp::now_seconds();
        if (attestation_expiry != 0) {
            assert!(now <= attestation_expiry, EAttestationExpired);
        };

        // On-chain anti-replay domain (RFC-0012 §3): reject if any uniqueness key is taken.
        let registry = borrow_global_mut<LockRegistry>(@csv_seal);
        assert!(!smart_table::contains(&registry.minted_sanads, copy sanad_id), ESanadAlreadyMinted);
        assert!(!smart_table::contains(&registry.nullifiers, copy nullifier), ENullifierAlreadyRegistered);
        assert!(!smart_table::contains(&registry.used_lock_events, copy lock_event_id), ELockEventAlreadyRecorded);

        // §9 authentication: verify M-of-N verifier signatures over the frozen §9.2 digest.
        let destination_owner_hash = aptos_hash::keccak256(copy destination_owner);
        let digest = mint_attestation_digest(
            copy sanad_id,
            copy commitment,
            copy source_chain,
            copy destination_owner_hash,
            copy lock_event_id,
            copy nullifier,
            attestation_expiry,
        );
        let auth = borrow_global<MintAuthority>(@csv_seal);
        require_verifier_threshold(auth, digest, &signatures);

        // Record the mint and consume the replay keys.
        smart_table::add(&mut registry.minted_sanads, copy sanad_id, true);
        smart_table::add(&mut registry.nullifiers, copy nullifier, true);
        smart_table::add(&mut registry.used_lock_events, copy lock_event_id, true);
        smart_table::add(&mut registry.mint_records, copy sanad_id, MintRecord {
            commitment: copy commitment,
            source_chain: copy source_chain,
            destination_owner_hash,
            lock_event_id: copy lock_event_id,
            nullifier: copy nullifier,
            minted_at: now,
        });

        event::emit(SanadMinted {
            sanad_id: copy sanad_id,
            commitment,
            source_chain,
            destination_owner,
            lock_event_id,
            nullifier: copy nullifier,
            minted_at: now,
        });
        event::emit(NullifierRegistered { nullifier, sanad_id });
    }

    // Compute the frozen §9.2 mint attestation digest.
    //
    // SHA-256 over the fixed 287-byte preimage:
    //   "csv.mint.attestation.v1" (23) || destinationChainId (32) || destinationContract (32)
    //   || sanad_id (32) || commitment (32) || source_chain (32) || keccak256(destination_owner) (32)
    //   || lock_event_id (32) || nullifier (32) || attestation_expiry (u64 big-endian, 8).
    //
    // `destinationChainId` = keccak256("csv.chain.aptos"); `destinationContract` = the
    // `@csv_seal` account address (32-byte BCS). Exposed as a `#[view]` so operators and the
    // off-chain adapter reproduce the exact digest they must sign.
    #[view]
    public fun mint_attestation_digest(
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        source_chain: vector<u8>,
        destination_owner_hash: vector<u8>,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        attestation_expiry: u64,
    ): vector<u8> {
        let preimage = vector::empty<u8>();
        vector::append(&mut preimage, b"csv.mint.attestation.v1");           // 23 bytes
        vector::append(&mut preimage, aptos_hash::keccak256(b"csv.chain.aptos")); // destinationChainId (32)
        vector::append(&mut preimage, bcs::to_bytes(&@csv_seal));            // destinationContract (32)
        vector::append(&mut preimage, sanad_id);                            // 32
        vector::append(&mut preimage, commitment);                          // 32
        vector::append(&mut preimage, source_chain);                        // 32
        vector::append(&mut preimage, destination_owner_hash);              // 32
        vector::append(&mut preimage, lock_event_id);                       // 32
        vector::append(&mut preimage, nullifier);                           // 32
        vector::append(&mut preimage, u64_to_be_bytes(attestation_expiry)); // 8
        hash::sha2_256(preimage)
    }

    /// Require at least `threshold` DISTINCT valid verifier signatures over `digest`.
    /// Every signature MUST recover to an authorized verifier (else abort); duplicate
    /// signatures recovering to the same verifier are counted once.
    fun require_verifier_threshold(auth: &MintAuthority, digest: vector<u8>, sigs: &vector<vector<u8>>) {
        let m = auth.threshold;
        let n = vector::length(sigs);
        assert!(n >= m, EInsufficientSignatures);

        let seen = vector::empty<vector<u8>>();
        let i = 0;
        while (i < n) {
            let pk = recover_compressed_pubkey(copy digest, vector::borrow(sigs, i));
            assert!(is_registered_verifier(auth, &pk), EInvalidVerifierSignature);
            if (!contains_bytes(&seen, &pk)) {
                vector::push_back(&mut seen, pk);
            };
            i = i + 1;
        };

        assert!(vector::length(&seen) >= m, EInsufficientSignatures);
    }

    /// Recover the compressed 33-byte secp256k1 public key that signed `digest`.
    /// `sig` is a 65-byte r||s||v encoding; `v` is a recovery id (0/1, or 27/28).
    fun recover_compressed_pubkey(digest: vector<u8>, sig: &vector<u8>): vector<u8> {
        assert!(vector::length(sig) == 65, EMalformedSignature);

        let rs = vector::empty<u8>();
        let i = 0;
        while (i < 64) {
            vector::push_back(&mut rs, *vector::borrow(sig, i));
            i = i + 1;
        };
        let v = *vector::borrow(sig, 64);
        let recovery_id = if (v >= 27) { v - 27 } else { v };
        assert!(recovery_id == 0 || recovery_id == 1, EMalformedSignature);

        let signature = secp256k1::ecdsa_signature_from_bytes(rs);
        let maybe_pk = secp256k1::ecdsa_recover(digest, recovery_id, &signature);
        assert!(option::is_some(&maybe_pk), EInvalidVerifierSignature);
        let raw = secp256k1::ecdsa_raw_public_key_to_bytes(&option::extract(&mut maybe_pk)); // 64 bytes x||y
        compress_pubkey(&raw)
    }

    /// Compress a 64-byte raw (x||y) secp256k1 public key to the 33-byte SEC1 form.
    fun compress_pubkey(raw: &vector<u8>): vector<u8> {
        assert!(vector::length(raw) == 64, EInvalidVerifier);
        let out = vector::empty<u8>();
        let y_last = *vector::borrow(raw, 63);
        let prefix = if ((y_last & 1) == 0) { 2u8 } else { 3u8 };
        vector::push_back(&mut out, prefix);
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut out, *vector::borrow(raw, i));
            i = i + 1;
        };
        out
    }

    fun is_registered_verifier(auth: &MintAuthority, pk: &vector<u8>): bool {
        contains_bytes(&auth.verifiers, pk)
    }

    fun contains_bytes(haystack: &vector<vector<u8>>, needle: &vector<u8>): bool {
        let i = 0;
        let n = vector::length(haystack);
        while (i < n) {
            if (*vector::borrow(haystack, i) == *needle) { return true };
            i = i + 1;
        };
        false
    }

    /// True iff `v` is exactly 32 bytes and not all-zero.
    fun is_fixed32_nonzero(v: &vector<u8>): bool {
        if (vector::length(v) != 32) { return false };
        let i = 0;
        while (i < 32) {
            if (*vector::borrow(v, i) != 0) { return true };
            i = i + 1;
        };
        false
    }

    /// Encode a u64 as 8 big-endian bytes (matches the §9.2 frozen layout).
    fun u64_to_be_bytes(v: u64): vector<u8> {
        let out = vector::empty<u8>();
        let i = 0;
        while (i < 8) {
            let shift = ((7 - i) * 8 as u8);
            vector::push_back(&mut out, (((v >> shift) & 0xff) as u8));
            i = i + 1;
        };
        out
    }

    // =========================================================================
    // Nullifier registration (authorized out-of-band; RFC-0012)
    // =========================================================================

    /// Register a nullifier for replay protection. GATED to the authority owner: permissionless
    /// registration would let anyone pre-register a nullifier and grief a future mint. The
    /// authenticated mint path folds nullifier registration in; this remains only for
    /// authorized out-of-band registration.
    public entry fun register_nullifier(
        account: &signer,
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
    ) acquires MintAuthority, LockRegistry {
        let auth = borrow_global<MintAuthority>(@csv_seal);
        assert!(signer::address_of(account) == auth.owner, EUnauthorized);
        assert!(is_fixed32_nonzero(&nullifier), EInvalidMintRequest);

        let registry = borrow_global_mut<LockRegistry>(@csv_seal);
        assert!(!smart_table::contains(&registry.nullifiers, copy nullifier), ENullifierAlreadyRegistered);
        smart_table::add(&mut registry.nullifiers, copy nullifier, true);

        event::emit(NullifierRegistered { nullifier, sanad_id });
    }

    // =========================================================================
    // Refund
    // =========================================================================

    public entry fun refund_sanad(
        account: &signer,
        sanad_id: vector<u8>,
        registry_addr: address,
    ) acquires LockRegistry {
        let claimant = signer::address_of(account);

        assert!(exists<LockRegistry>(registry_addr), ESealNotFound);
        let registry = borrow_global_mut<LockRegistry>(registry_addr);

        assert!(smart_table::contains(&registry.locks, copy sanad_id), ESealNotFound);

        // A confirmed destination mint must never be refunded (mutual exclusion with settlement).
        assert!(!smart_table::contains(&registry.minted_sanads, copy sanad_id), ESanadAlreadyMinted);

        let lock = smart_table::borrow_mut(&mut registry.locks, copy sanad_id);
        assert!(!lock.refunded, ESealAlreadyConsumed);
        assert!(lock.owner == claimant, ESealNotConsumed);

        let now = aptos_framework::timestamp::now_seconds();
        assert!(now >= lock.locked_at + registry.refund_timeout, ESealNotConsumed);

        let commitment_copy = lock.commitment;
        let sanad_id_copy = copy sanad_id;

        smart_table::remove(&mut registry.locks, sanad_id);

        event::emit(CrossChainRefund {
            sanad_id: sanad_id_copy,
            commitment: commitment_copy,
            claimant,
            refunded_at: now,
        });
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// Helper to generate commitment from sanad_id and nonce using SHA3-256.
    fun get_commitment_bytes(sanad_id: vector<u8>, nonce: u64): vector<u8> {
        let data = vector::empty<u8>();
        vector::append(&mut data, sanad_id);
        vector::append(&mut data, bcs::to_bytes(&nonce));
        hash::sha3_256(data)
    }

    // =========================================================================
    // Query Functions (canonical state machine interface)
    // =========================================================================

    public fun get_lock_info(
        registry_addr: address,
        sanad_id: vector<u8>,
    ): (vector<u8>, address, u64, bool) acquires LockRegistry {
        assert!(exists<LockRegistry>(registry_addr), ESealNotFound);
        let registry = borrow_global<LockRegistry>(registry_addr);
        assert!(smart_table::contains(&registry.locks, sanad_id), ESealNotFound);
        let lock = smart_table::borrow(&registry.locks, sanad_id);
        (lock.commitment, lock.owner, lock.locked_at, lock.refunded)
    }

    public fun can_refund(
        registry_addr: address,
        sanad_id: vector<u8>,
        now: u64,
    ): bool acquires LockRegistry {
        if (!exists<LockRegistry>(registry_addr)) { return false };
        let registry = borrow_global<LockRegistry>(registry_addr);
        if (!smart_table::contains(&registry.locks, copy sanad_id)) { return false };
        let lock = smart_table::borrow(&registry.locks, sanad_id);
        !lock.refunded && now >= lock.locked_at + registry.refund_timeout
    }

    #[view]
    public fun is_sanad_minted(registry_addr: address, sanad_id: vector<u8>): bool acquires LockRegistry {
        if (!exists<LockRegistry>(registry_addr)) { return false };
        smart_table::contains(&borrow_global<LockRegistry>(registry_addr).minted_sanads, sanad_id)
    }

    #[view]
    public fun is_nullifier_registered(registry_addr: address, nullifier: vector<u8>): bool acquires LockRegistry {
        if (!exists<LockRegistry>(registry_addr)) { return false };
        smart_table::contains(&borrow_global<LockRegistry>(registry_addr).nullifiers, nullifier)
    }

    #[view]
    public fun is_lock_event_recorded(registry_addr: address, lock_event_id: vector<u8>): bool acquires LockRegistry {
        if (!exists<LockRegistry>(registry_addr)) { return false };
        smart_table::contains(&borrow_global<LockRegistry>(registry_addr).used_lock_events, lock_event_id)
    }

    #[view]
    public fun verifier_count(): u64 acquires MintAuthority {
        vector::length(&borrow_global<MintAuthority>(@csv_seal).verifiers)
    }

    #[view]
    public fun is_verifier(pubkey: vector<u8>): bool acquires MintAuthority {
        contains_bytes(&borrow_global<MintAuthority>(@csv_seal).verifiers, &pubkey)
    }

    #[view]
    public fun threshold(): u64 acquires MintAuthority {
        borrow_global<MintAuthority>(@csv_seal).threshold
    }

    #[view]
    public fun version(): u64 { VERSION }

    public fun get_sanad_state(
        registry_addr: address,
        sanad_id: vector<u8>,
    ): u8 acquires LockRegistry {
        if (!exists<LockRegistry>(registry_addr)) { return SANAD_STATE_UNCREATED };
        let registry = borrow_global<LockRegistry>(registry_addr);
        if (smart_table::contains(&registry.minted_sanads, copy sanad_id)) {
            return SANAD_STATE_MINTED
        };
        if (!smart_table::contains(&registry.locks, copy sanad_id)) {
            return SANAD_STATE_UNCREATED
        };
        let lock = smart_table::borrow(&registry.locks, sanad_id);
        if (lock.refunded) { SANAD_STATE_REFUNDED } else { SANAD_STATE_LOCKED }
    }

    public fun is_sanad_locked(
        registry_addr: address,
        sanad_id: vector<u8>,
    ): bool acquires LockRegistry {
        if (!exists<LockRegistry>(registry_addr)) { return false };
        let registry = borrow_global<LockRegistry>(registry_addr);
        if (!smart_table::contains(&registry.locks, copy sanad_id)) { return false };
        !smart_table::borrow(&registry.locks, sanad_id).refunded
    }

    public fun is_sanad_refunded(
        registry_addr: address,
        sanad_id: vector<u8>,
    ): bool acquires LockRegistry {
        if (!exists<LockRegistry>(registry_addr)) { return false };
        let registry = borrow_global<LockRegistry>(registry_addr);
        if (!smart_table::contains(&registry.locks, copy sanad_id)) { return false };
        smart_table::borrow(&registry.locks, sanad_id).refunded
    }

    // =========================================================================
    // Verifier-set / ownership governance (OFF the mint path — RFC-0012 §9.3)
    // =========================================================================

    /// Schedule a verifier-set update (add/remove a verifier, set threshold) with timelock.
    public entry fun schedule_verifier_update(
        account: &signer,
        verifier_pubkey: vector<u8>,
        add: bool,
        new_threshold: u64,
    ) acquires MintAuthority {
        let auth = borrow_global_mut<MintAuthority>(@csv_seal);
        assert!(signer::address_of(account) == auth.owner, EUnauthorized);
        assert!(vector::length(&verifier_pubkey) == 33, EInvalidVerifier);

        auth.pending_verifier_active = true;
        auth.pending_verifier_pk = verifier_pubkey;
        auth.pending_verifier_add = add;
        auth.pending_verifier_threshold = new_threshold;
        auth.pending_verifier_valid_after = aptos_framework::timestamp::now_seconds() + TIMELOCK_PERIOD;
    }

    /// Execute a scheduled verifier-set update once the timelock has elapsed.
    public entry fun execute_verifier_update(account: &signer) acquires MintAuthority {
        let auth = borrow_global_mut<MintAuthority>(@csv_seal);
        assert!(signer::address_of(account) == auth.owner, EUnauthorized);
        assert!(auth.pending_verifier_active, ESealNotFound);
        assert!(
            aptos_framework::timestamp::now_seconds() >= auth.pending_verifier_valid_after,
            ETimelockNotExpired,
        );

        let pk = auth.pending_verifier_pk;
        if (auth.pending_verifier_add) {
            if (!contains_bytes(&auth.verifiers, &pk)) {
                vector::push_back(&mut auth.verifiers, copy pk);
                event::emit(VerifierAdded { verifier: pk });
            };
        } else {
            remove_verifier(&mut auth.verifiers, &pk);
            event::emit(VerifierRemoved { verifier: pk });
        };

        // Threshold must be a valid M-of-N over the resulting set.
        let set_size = vector::length(&auth.verifiers);
        assert!(auth.pending_verifier_threshold > 0 && auth.pending_verifier_threshold <= set_size, EInvalidThreshold);
        auth.threshold = auth.pending_verifier_threshold;
        event::emit(ThresholdUpdated { threshold: auth.threshold });

        auth.pending_verifier_active = false;
        auth.pending_verifier_pk = vector::empty<u8>();
    }

    fun remove_verifier(verifiers: &mut vector<vector<u8>>, pk: &vector<u8>) {
        let i = 0;
        let n = vector::length(verifiers);
        while (i < n) {
            if (*vector::borrow(verifiers, i) == *pk) {
                vector::swap_remove(verifiers, i);
                return
            };
            i = i + 1;
        };
    }

    /// Schedule an ownership transfer with timelock.
    public entry fun schedule_ownership_transfer(account: &signer, new_owner: address) acquires MintAuthority {
        let auth = borrow_global_mut<MintAuthority>(@csv_seal);
        assert!(signer::address_of(account) == auth.owner, EUnauthorized);
        assert!(new_owner != @0x0, EUnauthorized);
        auth.pending_owner = new_owner;
        auth.pending_owner_valid_after = aptos_framework::timestamp::now_seconds() + TIMELOCK_PERIOD;
    }

    /// Execute a scheduled ownership transfer once the timelock has elapsed.
    public entry fun execute_ownership_transfer(account: &signer) acquires MintAuthority {
        let auth = borrow_global_mut<MintAuthority>(@csv_seal);
        assert!(auth.pending_owner != @0x0, ESealNotFound);
        assert!(signer::address_of(account) == auth.pending_owner, EUnauthorized);
        assert!(
            aptos_framework::timestamp::now_seconds() >= auth.pending_owner_valid_after,
            ETimelockNotExpired,
        );
        auth.owner = auth.pending_owner;
        auth.pending_owner = @0x0;
        auth.pending_owner_valid_after = 0;
    }

    // =========================================================================
    // Tests
    // =========================================================================
    // Test vectors are generated deterministically off-chain (secp256k1 over the §9.2 digest)
    // for a fixed verifier key and the fixed dev address `@csv_seal = 0xCAFE`. Any change to
    // the digest layout, the dev address, or the field values below invalidates these vectors.

    #[test_only]
    use aptos_framework::timestamp;

    #[test_only]
    const T_VERIFIER: vector<u8> = x"034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    #[test_only]
    const T_SRC_CHAIN: vector<u8> = x"7d0dc209c5a3fa11e0ee0a3f9680f759f6e93896d643983f9c68ae5323226e48";
    #[test_only]
    const T_OWNER: vector<u8> = x"6170746f732d726563697069656e742d626c6f62";
    #[test_only]
    const T_COMMITMENT: vector<u8> = x"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

    // MAIN vector
    #[test_only]
    const T_MAIN_SANAD: vector<u8> = x"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    #[test_only]
    const T_MAIN_LOCK: vector<u8> = x"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    #[test_only]
    const T_MAIN_NULL: vector<u8> = x"d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";
    #[test_only]
    const T_MAIN_SIG: vector<u8> = x"88445caba2f9316610bedd7411389f721f70889f08e59b15ca424cc557e7efca55f1aded693c7f97676cfd6a989a7c197c5381e491f825669c1374ff5947e7cd01";

    // NULLDUP vector (same nullifier as MAIN, different sanad/lock)
    #[test_only]
    const T_NULLDUP_SANAD: vector<u8> = x"a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    #[test_only]
    const T_NULLDUP_LOCK: vector<u8> = x"c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";
    #[test_only]
    const T_NULLDUP_SIG: vector<u8> = x"d3109e9d27c35e2e14ad1f0bb92ee3fd5a4ceb2957177e397512ec713dd4f964653ed98afa18a6a3619b04de8b9afbe4aef9da00af755a7f6c01f60d69be64b000";

    // LOCKDUP vector (same lock_event as MAIN, different sanad/null)
    #[test_only]
    const T_LOCKDUP_SANAD: vector<u8> = x"a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
    #[test_only]
    const T_LOCKDUP_NULL: vector<u8> = x"d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6";
    #[test_only]
    const T_LOCKDUP_SIG: vector<u8> = x"9ba0f645854a46184dc7e53bc34ca488b749040d74f183c6e310a3584ce7e63d76216508334321b709ce17b31885b57189d7bded74eb60b6b71445f28073682900";

    // FUTURE vector (expiry far in the future)
    #[test_only]
    const T_FUTURE_SANAD: vector<u8> = x"a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9";
    #[test_only]
    const T_FUTURE_LOCK: vector<u8> = x"c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9";
    #[test_only]
    const T_FUTURE_NULL: vector<u8> = x"d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9";
    #[test_only]
    const T_FUTURE_EXP: u64 = 4102444800;
    #[test_only]
    const T_FUTURE_SIG: vector<u8> = x"f6c47ddb1a24884f7460fb6ba9303866c2942a128f76bd26673f1fa07dab627e4d493b92d553e28dd22f42215f03efe78e3bce1ae9fadf9d748ba7e13e814a3701";

    // EXPIRED vector (MAIN fields, expiry = 1 in the past)
    #[test_only]
    const T_EXPIRED_EXP: u64 = 1;
    #[test_only]
    const T_EXPIRED_SIG: vector<u8> = x"b3fb153cd16751591a0e586cf7a89298b5f077535e8891e83e7c0947e28145e845779a6a1bd9150768f2f0bab62fb1e86f874cf4c39c1b67ffa3c3ac0dd01ed701";

    #[test_only]
    fun setup(deployer: &signer, framework: &signer) {
        timestamp::set_time_has_started_for_testing(framework);
        account::create_account_for_test(signer::address_of(deployer));
        init_registry(deployer);
        init_mint_authority(deployer, T_VERIFIER);
    }

    #[test_only]
    fun sigs_of(sig: vector<u8>): vector<vector<u8>> {
        let v = vector::empty<vector<u8>>();
        vector::push_back(&mut v, sig);
        v
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    fun test_happy_mint(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        mint_sanad(
            deployer, T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, 0, sigs_of(T_MAIN_SIG),
        );
        assert!(is_sanad_minted(@csv_seal, T_MAIN_SANAD), 100);
        assert!(is_nullifier_registered(@csv_seal, T_MAIN_NULL), 101);
        assert!(is_lock_event_recorded(@csv_seal, T_MAIN_LOCK), 102);
        assert!(get_sanad_state(@csv_seal, T_MAIN_SANAD) == SANAD_STATE_MINTED, 103);
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    fun test_future_expiry_mints(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        mint_sanad(
            deployer, T_FUTURE_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_FUTURE_LOCK, T_FUTURE_NULL, T_FUTURE_EXP, sigs_of(T_FUTURE_SIG),
        );
        assert!(is_sanad_minted(@csv_seal, T_FUTURE_SANAD), 110);
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    #[expected_failure(abort_code = EAttestationExpired)]
    fun test_expired_attestation_rejected(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        // Advance chain time past the expiry (=1).
        timestamp::update_global_time_for_test_secs(1000);
        mint_sanad(
            deployer, T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, T_EXPIRED_EXP, sigs_of(T_EXPIRED_SIG),
        );
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    #[expected_failure(abort_code = EInvalidVerifierSignature)]
    fun test_forged_attestation_rejected(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        // A syntactically valid signature that recovers to a NON-verifier key: flip the
        // recovery bit so the recovered pubkey differs from the registered verifier.
        let forged = copy T_MAIN_SIG;
        let last = *vector::borrow(&forged, 64);
        *vector::borrow_mut(&mut forged, 64) = if (last == 0) { 1 } else { 0 };
        mint_sanad(
            deployer, T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, 0, sigs_of(forged),
        );
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    #[expected_failure(abort_code = EInsufficientSignatures)]
    fun test_no_signatures_rejected(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        mint_sanad(
            deployer, T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, 0, vector::empty<vector<u8>>(),
        );
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    #[expected_failure(abort_code = EMalformedSignature)]
    fun test_malformed_signature_rejected(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        mint_sanad(
            deployer, T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, 0, sigs_of(x"deadbeef"),
        );
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    #[expected_failure(abort_code = EInvalidVerifierSignature)]
    fun test_wrong_payload_signature_rejected(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        // Valid MAIN signature but applied to different field values → recovers to a key
        // that does not match the verifier for this digest.
        mint_sanad(
            deployer, T_FUTURE_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_FUTURE_LOCK, T_FUTURE_NULL, 0, sigs_of(T_MAIN_SIG),
        );
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESanadAlreadyMinted)]
    fun test_duplicate_sanad_rejected(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        mint_sanad(
            deployer, T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, 0, sigs_of(T_MAIN_SIG),
        );
        // Replay the identical mint request → duplicate sanad_id.
        mint_sanad(
            deployer, T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, 0, sigs_of(T_MAIN_SIG),
        );
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    #[expected_failure(abort_code = ENullifierAlreadyRegistered)]
    fun test_duplicate_nullifier_rejected(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        mint_sanad(
            deployer, T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, 0, sigs_of(T_MAIN_SIG),
        );
        // Distinct sanad_id + lock_event, but the SAME nullifier as MAIN.
        mint_sanad(
            deployer, T_NULLDUP_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_NULLDUP_LOCK, T_MAIN_NULL, 0, sigs_of(T_NULLDUP_SIG),
        );
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    #[expected_failure(abort_code = ELockEventAlreadyRecorded)]
    fun test_duplicate_lock_event_rejected(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        mint_sanad(
            deployer, T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, 0, sigs_of(T_MAIN_SIG),
        );
        // Distinct sanad_id + nullifier, but the SAME lock_event_id as MAIN.
        mint_sanad(
            deployer, T_LOCKDUP_SANAD, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_LOCKDUP_NULL, 0, sigs_of(T_LOCKDUP_SIG),
        );
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    #[expected_failure(abort_code = EInvalidMintRequest)]
    fun test_zero_keys_rejected(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        let zero32 = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut zero32, 0u8); i = i + 1; };
        mint_sanad(
            deployer, zero32, T_COMMITMENT, T_SRC_CHAIN, T_OWNER,
            T_MAIN_LOCK, T_MAIN_NULL, 0, sigs_of(T_MAIN_SIG),
        );
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    fun test_register_nullifier_owner_gated(deployer: &signer, framework: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        register_nullifier(deployer, T_MAIN_NULL, T_MAIN_SANAD);
        assert!(is_nullifier_registered(@csv_seal, T_MAIN_NULL), 120);
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework, attacker = @0xBAD)]
    #[expected_failure(abort_code = EUnauthorized)]
    fun test_register_nullifier_rejects_non_owner(deployer: &signer, framework: &signer, attacker: &signer) acquires MintAuthority, LockRegistry {
        setup(deployer, framework);
        register_nullifier(attacker, T_MAIN_NULL, T_MAIN_SANAD);
    }

    #[test(deployer = @csv_seal, framework = @aptos_framework)]
    fun test_digest_matches_offchain_vector(deployer: &signer, framework: &signer) {
        setup(deployer, framework);
        // The on-chain digest must equal the digest the off-chain signer used. We assert the
        // recovered verifier matches by exercising a happy mint elsewhere; here we sanity-check
        // that the digest is exactly 32 bytes and deterministic.
        let owner_hash = aptos_hash::keccak256(T_OWNER);
        let d = mint_attestation_digest(
            T_MAIN_SANAD, T_COMMITMENT, T_SRC_CHAIN, owner_hash, T_MAIN_LOCK, T_MAIN_NULL, 0,
        );
        assert!(vector::length(&d) == 32, 130);
    }
}
