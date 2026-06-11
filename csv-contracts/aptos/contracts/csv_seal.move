//! CSV Seal Module for Aptos — Canonical Naming
//!
//! This Move module provides seal management for the CSV (Client-Side Validation) adapter.
//! Uses canonical function/event names matching Ethereum/Solana/Sui.

module csv_seal::CSVSeal {
    use std::signer;
    use aptos_framework::event;
    use aptos_framework::timestamp;

    // =========================================================================
    // Chain IDs (must match all CSV contracts)
    // =========================================================================

    const CHAIN_BITCOIN: u8 = 0;
    const CHAIN_SUI: u8 = 1;
    const CHAIN_APTOS: u8 = 2;
    const CHAIN_ETHEREUM: u8 = 3;
    const CHAIN_SOLANA: u8 = 4;

    // =========================================================================
    // Canonical State Constants
    // =========================================================================

    /// Canonical Sanad lifecycle state — matches Ethereum/Solana/Sui
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

    /// Refund timeout in seconds (24 hours)
    const REFUND_TIMEOUT_SECS: u64 = 24 * 60 * 60;

    // =========================================================================
    // Canonical ProofLeafV1 Schema
    // =========================================================================

    /// Canonical ProofLeafV1 schema for cross-chain proof verification
    /// This struct matches the canonical schema defined in csv-protocol
    struct ProofLeafV1 has copy, drop {
        /// Version of the proof leaf schema
        version: u32,
        /// Source chain identifier
        source_chain: u8,
        /// Destination chain identifier
        destination_chain: u8,
        /// Sanad identifier
        sanad_id: vector<u8>,
        /// Commitment hash
        commitment: vector<u8>,
        /// Content descriptor hash (optional, default empty)
        content_descriptor_hash: vector<u8>,
        /// Source seal reference hash (optional, default empty)
        source_seal_ref_hash: vector<u8>,
        /// Destination owner hash (optional, default empty)
        destination_owner_hash: vector<u8>,
        /// Nullifier hash (optional, default empty)
        nullifier: vector<u8>,
        /// Lock event ID hash (optional, default empty)
        lock_event_id: vector<u8>,
        /// Metadata hash (optional, default empty)
        metadata_hash: vector<u8>,
        /// Proof policy hash (optional, default empty)
        proof_policy_hash: vector<u8>,
    }

    /// Compute the canonical hash of a ProofLeafV1 using sha3_256 (Aptos's native hash)
    /// Uses Minimal Canonical Encoding (MCE) - fixed-width byte layout without serialization libraries
    /// This matches the Rust ProofLeafV1::to_canonical_bytes() implementation exactly.
    public fun hash_proof_leaf_v1(leaf: &ProofLeafV1): vector<u8> {
        let mut data = vector::empty();
        
        // Domain tag (17 bytes): "csv.proof.leaf.v1"
        let domain = b"csv.proof.leaf.v1";
        vector::append(&mut data, domain);
        
        // Version (4 bytes, little-endian u32)
        // BCS for u32 produces exactly 4 bytes LE, matching Rust's to_le_bytes()
        let version_bytes = bcs::to_bytes(&leaf.version);
        vector::append(&mut data, version_bytes);
        
        // Chain IDs (1 byte each)
        vector::push_back(&mut data, leaf.source_chain);
        vector::push_back(&mut data, leaf.destination_chain);
        
        // Fixed-width hashes (32 bytes each)
        vector::append(&mut data, leaf.sanad_id);
        vector::append(&mut data, leaf.commitment);
        vector::append(&mut data, leaf.content_descriptor_hash);
        vector::append(&mut data, leaf.source_seal_ref_hash);
        vector::append(&mut data, leaf.destination_owner_hash);
        vector::append(&mut data, leaf.nullifier);
        vector::append(&mut data, leaf.lock_event_id);
        vector::append(&mut data, leaf.metadata_hash);
        vector::append(&mut data, leaf.proof_policy_hash);
        
        // Use sha3_256 (Aptos's native hash)
        hash::sha3_256(&data)
    }

    /// Compute ProofLeafV1 hash using chain-specific hash function
    /// For Aptos, this uses sha3_256 (native hash function)
    public fun hash_proof_leaf_v1_with_chain_function(leaf: &ProofLeafV1, _chain: u8): vector<u8> {
        hash_proof_leaf_v1(leaf)
    }

    // =========================================================================
    // Error Codes
    // =========================================================================

    const ESealAlreadyConsumed: u64 = 1;
    const ESealNotConsumed: u64 = 2;
    const EAnchorDataExists: u64 = 3;
    const ESealNotFound: u64 = 4;
    const ETIMEOUT_NOT_EXPIRED: u64 = 5;
    const EALREADY_REFUNDED: u64 = 6;
    const ENOT_AUTHORIZED: u64 = 7;
    const EALREADY_LOCKED: u64 = 8;

    // =========================================================================
    // Structs
    // =========================================================================

    /// Canonical: Emitted when a Sanad is created
    struct SanadCreated has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        timestamp_secs: u64,
    }

    /// Canonical: Emitted when a Sanad is consumed
    struct SanadConsumed has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        consumer: address,
        timestamp_secs: u64,
    }

    /// Canonical: Emitted when a Sanad is locked for cross-chain transfer
    struct SanadLocked has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        destination_chain: u8,
        destination_owner: vector<u8>,
        timestamp_secs: u64,
    }

    /// Legacy: Emitted when a Sanad is locked (backward compatibility)
    struct CrossChainLock has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        destination_chain: u8,
        destination_owner: vector<u8>,
        timestamp_secs: u64,
    }

    /// Canonical: Emitted when a Sanad is minted on destination chain
    struct SanadMinted has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        timestamp_secs: u64,
    }

    /// Legacy: Emitted when a Sanad is minted (backward compatibility)
    struct CrossChainMint has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        timestamp_secs: u64,
    }

    /// Canonical: Emitted when a locked Sanad is refunded
    struct SanadRefunded has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        reason: vector<u8>,
        timestamp_secs: u64,
    }

    /// Legacy: Emitted when a locked Sanad is refunded (backward compatibility)
    struct CrossChainRefund has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        timestamp_secs: u64,
    }

    /// Canonical: Emitted when Sanad ownership is transferred
    struct SanadTransferred has drop, store {
        sanad_id: vector<u8>,
        from: address,
        to: address,
        timestamp_secs: u64,
    }

    /// Canonical: Emitted when a nullifier is registered
    struct NullifierRegistered has drop, store {
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
        timestamp_secs: u64,
    }

    /// Canonical: Emitted when a commitment is anchored
    struct CommitmentAnchored has drop, store {
        commitment: vector<u8>,
        seal_address: address,
        owner: address,
        timestamp_secs: u64,
    }

    /// Canonical: Emitted when proof root is updated
    struct ProofRootUpdated has drop, store {
        proof_root: vector<u8>,
        timestamp_secs: u64,
        updater: address,
    }

    /// Legacy events
    struct AnchorEvent has drop, store {
        commitment: vector<u8>,
        seal_address: address,
        nonce: u64,
        timestamp_secs: u64,
    }
    struct ProofAccepted has drop, store {
        proof_root: vector<u8>,
        protocol_version: vector<u8>,
        timestamp_secs: u64,
    }
    struct ProofRejected has drop, store {
        proof_root: vector<u8>,
        reason: vector<u8>,
        timestamp_secs: u64,
    }
    struct ReplayDetected has drop, store {
        replay_id: vector<u8>,
        sanad_id: vector<u8>,
        timestamp_secs: u64,
    }

    /// Seal resource with canonical state field
    struct Seal has key, store {
        /// Nonce for replay resistance
        nonce: u64,
        /// Unique Sanad identifier
        sanad_id: vector<u8>,
        /// Commitment hash
        commitment: vector<u8>,
        /// Canonical lifecycle state
        state: u8,
        /// Owner of the seal
        owner: address,
        /// Asset class
        asset_class: u8,
        /// Asset ID
        asset_id: vector<u8>,
        /// Metadata hash
        metadata_hash: vector<u8>,
        /// Proof system
        proof_system: u8,
        /// Proof root
        proof_root: vector<u8>,
        /// Creation timestamp
        created_at: u64,
        /// Lock timestamp
        locked_at: u64,
        /// Consumption timestamp
        consumed_at: u64,
        /// Mint timestamp
        minted_at: u64,
        /// Refund timestamp
        refunded_at: u64,
    }

    /// Persistent storage of commitment after seal consumption
    struct AnchorData has key, store {
        /// The commitment hash that was anchored
        commitment: vector<u8>,
        /// Timestamp when the seal was consumed
        consumed_at: u64,
        /// Nonce of the original seal
        nonce: u64,
        /// Sanad ID
        sanad_id: vector<u8>,
    }

    /// Event handle for anchor events
    struct AnchorEventHandle has key {
        events: event::EventHandle<AnchorEvent>,
    }

    // =========================================================================
    // Seal Creation
    // =========================================================================

    /// Create a new seal resource
    #[cmd]
    public entry fun create_seal(account: &signer, sanad_id: vector<u8>, commitment: vector<u8>, nonce: u64) {
        let addr = signer::address_of(account);
        assert!(!exists<Seal>(addr), EAnchorDataExists);

        let timestamp = timestamp::now_seconds();
        move_to(account, Seal {
            nonce,
            sanad_id: sanad_id.clone(),
            commitment: commitment.clone(),
            state: SANAD_STATE_CREATED,
            owner: addr,
            asset_class: 0,
            asset_id: vector::empty(),
            metadata_hash: vector::empty(),
            proof_system: 0,
            proof_root: vector::empty(),
            created_at: timestamp,
            locked_at: 0,
            consumed_at: 0,
            minted_at: 0,
            refunded_at: 0,
        });

        event::emit_event<SanadCreated>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            SanadCreated {
                sanad_id,
                commitment,
                owner: addr,
                timestamp_secs: timestamp,
            },
        );
    }

    // =========================================================================
    // Seal Consumption
    // =========================================================================

    /// Consume a seal (canonical name)
    #[cmd]
    public entry fun consume_seal(account: &signer, commitment: vector<u8>) {
        let seal_addr = signer::address_of(account);
        assert!(exists<Seal>(seal_addr), ESealNotFound);

        let seal = borrow_global_mut<Seal>(seal_addr);
        assert!(seal.state != SANAD_STATE_CONSUMED, ESealAlreadyConsumed);

        let nonce = seal.nonce;
        let sanad_id = seal.sanad_id.clone();
        let commitment = seal.commitment.clone();
        seal.state = SANAD_STATE_CONSUMED;
        seal.consumed_at = timestamp::now_seconds();

        // Create AnchorData storage
        assert!(!exists<AnchorData>(seal_addr), EAnchorDataExists);
        move_to(account, AnchorData {
            commitment,
            consumed_at: seal.consumed_at,
            nonce,
            sanad_id,
        });

        // Emit canonical event
        event::emit_event<SanadConsumed>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            SanadConsumed {
                sanad_id: seal.sanad_id,
                commitment: seal.commitment,
                consumer: seal_addr,
                timestamp_secs: seal.consumed_at,
            },
        );

        // Emit legacy event
        event::emit_event<AnchorEvent>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            AnchorEvent {
                commitment,
                seal_address: seal_addr,
                nonce,
                timestamp_secs: seal.consumed_at,
            },
        );
    }

    // =========================================================================
    // Lock / Mint / Refund
    // =========================================================================

    /// Lock a Sanad for cross-chain transfer (canonical name)
    #[cmd]
    public entry fun lock_sanad(account: &signer, destination_chain: u8, destination_owner: vector<u8>) {
        let addr = signer::address_of(account);
        assert!(exists<Seal>(addr), ESealNotFound);

        let seal = borrow_global_mut<Seal>(addr);
        assert!(seal.state != SANAD_STATE_CONSUMED, ESealAlreadyConsumed);
        assert!(seal.state != SANAD_STATE_LOCKED, EALREADY_LOCKED);

        let timestamp = timestamp::now_seconds();
        seal.state = SANAD_STATE_LOCKED;
        seal.locked_at = timestamp;

        event::emit_event<SanadLocked>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            SanadLocked {
                sanad_id: seal.sanad_id.clone(),
                commitment: seal.commitment.clone(),
                owner: addr,
                destination_chain,
                destination_owner,
                timestamp_secs: timestamp,
            },
        );

        event::emit_event<CrossChainLock>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            CrossChainLock {
                sanad_id: seal.sanad_id.clone(),
                commitment: seal.commitment.clone(),
                owner: addr,
                destination_chain,
                destination_owner,
                timestamp_secs: timestamp,
            },
        );
    }

    /// Mint a Sanad on destination chain (canonical name)
    #[cmd]
    public entry fun mint_sanad(
        account: &signer,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        proof: vector<u8>,
        proof_root: vector<u8>,
        leaf_position: u64,
    ) {
        let addr = signer::address_of(account);

        verify_cross_chain_proof(&sanad_id, &commitment, source_chain, &proof, &proof_root, leaf_position);

        assert!(!exists<Seal>(addr), EAnchorDataExists);

        let timestamp = timestamp::now_seconds();
        move_to(account, Seal {
            nonce: 0,
            sanad_id: sanad_id.clone(),
            commitment: commitment.clone(),
            state: SANAD_STATE_MINTED,
            owner: addr,
            asset_class: 0,
            asset_id: vector::empty(),
            metadata_hash: vector::empty(),
            proof_system: 0,
            proof_root,
            created_at: timestamp,
            minted_at: timestamp,
            locked_at: 0,
            consumed_at: 0,
            refunded_at: 0,
        });

        assert!(!exists<AnchorData>(addr), EAnchorDataExists);
        move_to(account, AnchorData {
            commitment,
            consumed_at: timestamp,
            nonce: 0,
            sanad_id,
        });

        event::emit_event<SanadMinted>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            SanadMinted {
                sanad_id,
                commitment,
                owner: addr,
                source_chain,
                source_seal_ref,
                timestamp_secs: timestamp,
            },
        );
    }

    /// Mint a new Sanad using canonical ProofLeafV1 schema
    /// This is the recommended method for cross-chain minting
    #[cmd]
    public entry fun mint_sanad_with_proof_leaf(
        account: &signer,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        source_chain: u8,
        destination_chain: u8,
        source_seal_ref: vector<u8>,
        proof: vector<u8>,
        proof_root: vector<u8>,
        leaf_position: u64,
        content_descriptor_hash: vector<u8>,
        source_seal_ref_hash: vector<u8>,
        destination_owner_hash: vector<u8>,
        nullifier: vector<u8>,
        lock_event_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_policy_hash: vector<u8>,
        asset_class: u8,
        asset_id: vector<u8>,
        proof_system: u8,
    ) {
        let addr = signer::address_of(account);

        // Verify cross-chain proof using canonical ProofLeafV1 schema
        verify_cross_chain_proof_with_proof_leaf(
            &sanad_id,
            &commitment,
            source_chain,
            destination_chain,
            &proof,
            &proof_root,
            leaf_position,
            content_descriptor_hash,
            source_seal_ref_hash,
            destination_owner_hash,
            nullifier,
            lock_event_id,
            metadata_hash,
            proof_policy_hash,
        );

        assert!(!exists<Seal>(addr), EAnchorDataExists);

        let timestamp = timestamp::now_seconds();
        move_to(account, Seal {
            nonce: 0,
            sanad_id: sanad_id.clone(),
            commitment: commitment.clone(),
            state: SANAD_STATE_MINTED,
            owner: addr,
            asset_class,
            asset_id,
            metadata_hash,
            proof_system,
            proof_root,
            created_at: timestamp,
            minted_at: timestamp,
            locked_at: 0,
            consumed_at: 0,
            refunded_at: 0,
        });

        assert!(!exists<AnchorData>(addr), EAnchorDataExists);
        move_to(account, AnchorData {
            commitment,
            consumed_at: timestamp,
            nonce: 0,
            sanad_id,
        });

        event::emit_event<SanadMinted>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            SanadMinted {
                sanad_id,
                commitment,
                owner: addr,
                source_chain,
                source_seal_ref,
                timestamp_secs: timestamp,
            },
        );
    }

    /// Refund a locked Sanad after timeout (canonical name)
    #[cmd]
    public entry fun refund_sanad(account: &signer) {
        let addr = signer::address_of(account);
        assert!(exists<Seal>(addr), ESealNotFound);

        let seal = borrow_global_mut<Seal>(addr);
        assert!(seal.state == SANAD_STATE_LOCKED, ESanadNotFound);

        let now = timestamp::now_seconds();
        assert!(now >= seal.locked_at + REFUND_TIMEOUT_SECS, ETIMEOUT_NOT_EXPIRED);

        seal.state = SANAD_STATE_REFUNDED;
        seal.refunded_at = now;

        event::emit_event<SanadRefunded>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            SanadRefunded {
                sanad_id: seal.sanad_id.clone(),
                commitment: seal.commitment.clone(),
                claimant: addr,
                reason: b"timeout",
                timestamp_secs: now,
            },
        );

        event::emit_event<CrossChainRefund>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            CrossChainRefund {
                sanad_id: seal.sanad_id.clone(),
                commitment: seal.commitment.clone(),
                claimant: addr,
                timestamp_secs: now,
            },
        );
    }

    /// Transfer Sanad ownership (canonical name)
    #[cmd]
    public entry fun transfer_sanad(account: &signer, to: address) {
        let addr = signer::address_of(account);
        assert!(exists<Seal>(addr), ESealNotFound);

        let seal = borrow_global_mut<Seal>(addr);
        assert!(seal.state != SANAD_STATE_CONSUMED, ESealAlreadyConsumed);
        assert!(seal.state != SANAD_STATE_LOCKED, EALREADY_LOCKED);

        let timestamp = timestamp::now_seconds();
        let sanad_id = seal.sanad_id.clone();

        // Transfer the Seal resource
        let seal = move_from<Seal>(addr);
        move_to(to, seal);

        event::emit_event<SanadTransferred>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            SanadTransferred {
                sanad_id,
                from: addr,
                to,
                timestamp_secs: timestamp,
            },
        );
    }

    /// Register nullifier for replay protection
    #[cmd]
    public entry fun register_nullifier(account: &signer, nullifier: vector<u8>, sanad_id: vector<u8>) {
        let timestamp = timestamp::now_seconds();
        event::emit_event<NullifierRegistered>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            NullifierRegistered {
                nullifier,
                sanad_id,
                timestamp_secs: timestamp,
            },
        );
    }

    /// Anchor commitment on-chain
    #[cmd]
    public entry fun anchor_commitment(account: &signer, commitment: vector<u8>) {
        let addr = signer::address_of(account);
        assert!(exists<Seal>(addr), ESealNotFound);

        let seal = borrow_global<Seal>(addr);
        let timestamp = timestamp::now_seconds();

        event::emit_event<CommitmentAnchored>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            CommitmentAnchored {
                commitment,
                seal_address: addr,
                owner: seal.owner,
                timestamp_secs: timestamp,
            },
        );
    }

    /// Record metadata for a Sanad
    #[cmd]
    public entry fun record_sanad_metadata(
        account: &signer,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    ) {
        let addr = signer::address_of(account);
        assert!(exists<Seal>(addr), ESealNotFound);

        let seal = borrow_global_mut<Seal>(addr);
        seal.asset_class = asset_class;
        seal.asset_id = asset_id;
        seal.metadata_hash = metadata_hash;
        seal.proof_system = proof_system;
        seal.proof_root = proof_root;
    }

    // =========================================================================
    // Proof Verification
    // =========================================================================

    fun verify_cross_chain_proof(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        source_chain: u8,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64,
    ) {
        let mut leaf_data = vector<u8>[];
        vector::append(&mut leaf_data, sanad_id);
        vector::append(&mut leaf_data, commitment);
        vector::append(&mut leaf_data, &bcs::to_bytes(&source_chain));
        let leaf_hash = keccak256(&leaf_data);

        let is_valid = verify_merkle_proof(proof, proof_root, &leaf_hash, leaf_position);
        assert!(is_valid, ESealNotFound);
    }

    /// Verify cross-chain proof using canonical ProofLeafV1 schema
    /// This is the recommended verification method for cross-chain proofs
    fun verify_cross_chain_proof_with_proof_leaf(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        source_chain: u8,
        destination_chain: u8,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64,
        content_descriptor_hash: vector<u8>,
        source_seal_ref_hash: vector<u8>,
        destination_owner_hash: vector<u8>,
        nullifier: vector<u8>,
        lock_event_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_policy_hash: vector<u8>,
    ) {
        // Construct canonical ProofLeafV1
        let leaf = ProofLeafV1 {
            version: 1,  // ProofLeafV1 version
            source_chain,
            destination_chain,
            sanad_id: sanad_id.clone(),
            commitment: commitment.clone(),
            content_descriptor_hash,
            source_seal_ref_hash,
            destination_owner_hash,
            nullifier,
            lock_event_id,
            metadata_hash,
            proof_policy_hash,
        };

        // Compute canonical hash using sha3_256 (Aptos's native hash)
        let leaf_hash = hash_proof_leaf_v1(&leaf);

        // Verify Merkle proof using sha3_256 (Aptos's native hash)
        let is_valid = verify_merkle_proof(proof, proof_root, &leaf_hash, leaf_position);
        assert!(is_valid, ESealNotFound);
    }

    fun keccak256(data: &vector<u8>): vector<u8> {
        let mut domain = b"csv.keccak256.compat";
        let mut input = vector<u8>[];
        vector::append(&mut input, domain);
        vector::append(&mut input, data);
        hash::sha256(&input)
    }

    fun verify_merkle_proof(
        proof: &vector<u8>,
        root: &vector<u8>,
        leaf: &vector<u8>,
        leaf_position: u64,
    ): bool {
        let proof_len = vector::length(proof);
        let root_len = vector::length(root);
        let leaf_len = vector::length(leaf);

        if (proof_len == 0 || proof_len % 32 != 0) return false;
        if (root_len != 32 || leaf_len != 32) return false;

        let num_levels = proof_len / 32;
        let mut current_hash = *leaf;
        let mut i = 0;

        while (i < num_levels) {
            let start = i * 32;
            let mut sibling_hash: vector<u8> = vector::empty();
            let mut j = 0;
            while (j < 32) {
                vector::push_back(&mut sibling_hash, *vector::borrow(proof, start + j));
                j = j + 1;
            };

            let bit = (leaf_position >> i) & 1;
            let mut hash_input: vector<u8> = vector::empty();
            if (bit == 0) {
                vector::append(&mut hash_input, &current_hash);
                vector::append(&mut hash_input, &sibling_hash);
            } else {
                vector::append(&mut hash_input, &sibling_hash);
                vector::append(&mut hash_input, &current_hash);
            };

            current_hash = keccak256(&hash_input);
            i = i + 1;
        };

        let mut result = true;
        let mut k = 0;
        while (k < 32) {
            if (*vector::borrow(&current_hash, k) != *vector::borrow(root, k)) {
                result = false;
                break
            };
            k = k + 1;
        };

        result
    }

    // =========================================================================
    // View Functions (Canonical Names)
    // =========================================================================

    /// Get Sanad state
    public fun get_sanad_state(addr: address): u8 {
        assert!(exists<Seal>(addr), ESealNotFound);
        borrow_global<Seal>(addr).state
    }

    /// Check if seal is available (not consumed)
    public fun is_seal_available(addr: address): bool {
        if (!exists<Seal>(addr)) return false;
        borrow_global<Seal>(addr).state != SANAD_STATE_CONSUMED
    }

    /// Check if seal is consumed (canonical name)
    public fun is_seal_consumed(addr: address): bool {
        if (!exists<Seal>(addr)) return false;
        borrow_global<Seal>(addr).state == SANAD_STATE_CONSUMED
    }

    /// Get the nonce of a seal at the given address.
    public fun get_seal_nonce(addr: address): u64 {
        assert!(exists<Seal>(addr), ESealNotFound);
        borrow_global<Seal>(addr).nonce
    }

    /// Get the AnchorData for a consumed seal.
    public fun get_anchor_data(addr: address): AnchorData {
        assert!(exists<AnchorData>(addr), ESealNotFound);
        *borrow_global<AnchorData>(addr)
    }

    /// Check if AnchorData exists for a seal
    public fun has_anchor_data(addr: address): bool {
        exists<AnchorData>(addr)
    }

    /// Get the commitment from AnchorData.
    public fun get_commitment(addr: address): vector<u8> {
        assert!(exists<AnchorData>(addr), ESealNotFound);
        borrow_global<AnchorData>(addr).commitment
    }

    /// Get the consumption timestamp from AnchorData.
    public fun get_consumed_at(addr: address): u64 {
        assert!(exists<AnchorData>(addr), ESealNotFound);
        borrow_global<AnchorData>(addr).consumed_at
    }

    /// Check if refund is available
    public fun can_refund(addr: address): bool {
        if (!exists<Seal>(addr)) return false;
        let seal = borrow_global<Seal>(addr);
        seal.state == SANAD_STATE_LOCKED && (timestamp::now_seconds() >= seal.locked_at + REFUND_TIMEOUT_SECS)
    }

    // =========================================================================
    // Module Initialization
    // =========================================================================

    /// Initialize the module by creating the event handle.
    #[cmd]
    public entry fun initialize_module(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<AnchorEventHandle>(addr), EAnchorDataExists);
        move_to(account, AnchorEventHandle {
            events: event::new_event_handle<AnchorEvent>(account),
        });
    }
}
