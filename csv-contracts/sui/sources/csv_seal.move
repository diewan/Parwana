module csv_seal::csv_seal {
    use sui::bcs;
    use sui::event;
    use sui::transfer;

    /// Chain IDs for cross-chain transfers (must match other CSV contracts)
    #[allow(unused_const)]
    const CHAIN_BITCOIN: u8 = 0;
    #[allow(unused_const)]
    const CHAIN_SUI: u8 = 1;
    #[allow(unused_const)]
    const CHAIN_APTOS: u8 = 2;
    #[allow(unused_const)]
    const CHAIN_ETHEREUM: u8 = 3;
    #[allow(unused_const)]
    const CHAIN_SOLANA: u8 = 4;

    /// Asset class constants
    #[allow(unused_const)]
    const ASSET_CLASS_UNSPECIFIED: u8 = 0;
    #[allow(unused_const)]
    const ASSET_CLASS_FUNGIBLE_TOKEN: u8 = 1;
    #[allow(unused_const)]
    const ASSET_CLASS_NON_FUNGIBLE_TOKEN: u8 = 2;
    #[allow(unused_const)]
    const ASSET_CLASS_PROOF_SANAD: u8 = 3;

    /// Proof system constants
    const PROOF_SYSTEM_UNSPECIFIED: u8 = 0;

    /// Error codes
    const ESEAL_ALREADY_CONSUMED: u64 = 0;
    const EINVALID_PROOF: u64 = 1;
    const EALREADY_LOCKED: u64 = 2;
    #[allow(unused_const)]
    const EALREADY_MINTED: u64 = 3;
    const ETIMEOUT_NOT_EXPIRED: u64 = 4;
    const EALREADY_REFUNDED: u64 = 5;
    const ENOT_AUTHORIZED: u64 = 6;
    const ESANAD_NOT_FOUND: u64 = 7;

    /// Canonical Sanad lifecycle state — matches Ethereum/Solana/Aptos
    /// 0=Uncreated, 1=Created, 2=Active, 3=Locked, 4=Consumed, 5=Minted, 6=Transferred, 7=Refunded, 8=Burned, 9=Invalid
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

    /// Canonical Seal lifecycle state
    /// 0=Created, 1=Consumed, 2=Locked, 3=Minted, 4=Refunded
    const SEAL_STATE_CREATED: u8 = 0;
    const SEAL_STATE_CONSUMED: u8 = 1;
    const SEAL_STATE_LOCKED: u8 = 2;
    const SEAL_STATE_MINTED: u8 = 3;
    const SEAL_STATE_REFUNDED: u8 = 4;

    /// Refund timeout in milliseconds (24 hours)
    const REFUND_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

    /// Canonical ProofLeafV1 schema for cross-chain proof verification
    /// This struct matches the canonical schema defined in csv-protocol
    public struct ProofLeafV1 has copy, drop {
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

    /// Compute the canonical hash of a ProofLeafV1 using blake2b256 (Sui's native hash)
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
        
        // Use blake2b256 (Sui's native hash)
        sui::hash::blake2b256(&data)
    }

    /// Compute ProofLeafV1 hash using chain-specific hash function
    /// For Sui, this uses blake2b256 (native hash function)
    public fun hash_proof_leaf_v1_with_chain_function(leaf: &ProofLeafV1, _chain: u8): vector<u8> {
        hash_proof_leaf_v1(leaf)
    }

    /// A seal object that can be consumed exactly once.
    public struct Seal has key, store {
        id: object::UID,
        /// Unique Sanad identifier (preserved across chains)
        sanad_id: vector<u8>,
        /// Commitment hash (preserved across chains)
        commitment: vector<u8>,
        /// State root (off-chain state commitment)
        state_root: vector<u8>,
        /// Nonce for replay resistance
        nonce: u64,
        /// Canonical lifecycle state (replaces consumed/locked booleans)
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
        /// Creation timestamp (Unix epoch milliseconds)
        created_at: u64,
        /// Lock timestamp (Unix epoch milliseconds)
        locked_at: u64,
        /// Consumption timestamp (Unix epoch milliseconds)
        consumed_at: u64,
        /// Mint timestamp (Unix epoch milliseconds)
        minted_at: u64,
        /// Refund timestamp (Unix epoch milliseconds)
        refunded_at: u64,
    }

    /// Lock record for refund support
    public struct LockRecord has key, store {
        id: object::UID,
        /// Sanad identifier
        sanad_id: vector<u8>,
        /// Commitment hash
        commitment: vector<u8>,
        /// Original owner
        owner: address,
        /// Destination chain ID
        destination_chain: u8,
        /// Destination owner (hashed)
        destination_owner: vector<u8>,
        /// Lock timestamp (Unix epoch milliseconds)
        locked_at: u64,
        /// Whether this lock has been refunded
        refunded: bool,
    }

    /// Minted Sanad record for replay protection
    public struct MintedSanad has key, store {
        id: object::UID,
        /// Sanad identifier that was minted
        sanad_id: vector<u8>,
        /// When it was minted (Unix epoch milliseconds)
        minted_at: u64,
    }

    /// Canonical: Emitted when a Sanad is created
    public struct SanadCreated has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        timestamp_ms: u64,
    }

    /// Canonical: Emitted when a Sanad is consumed
    public struct SanadConsumed has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        consumer: address,
        timestamp_ms: u64,
    }

    /// Canonical: Emitted when a Sanad is locked for cross-chain transfer
    public struct SanadLocked has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        destination_chain: u8,
        destination_owner: vector<u8>,
        timestamp_ms: u64,
    }

    /// Legacy: Emitted when a Sanad is locked for cross-chain transfer (backward compatibility)
    public struct CrossChainLock has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        destination_chain: u8,
        destination_owner: vector<u8>,
        timestamp_ms: u64,
    }

    /// Canonical: Emitted when a Sanad is minted on destination chain
    public struct SanadMinted has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        timestamp_ms: u64,
    }

    /// Legacy: Emitted when a Sanad is minted from cross-chain transfer (backward compatibility)
    public struct CrossChainMint has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        timestamp_ms: u64,
    }

    /// Canonical: Emitted when a locked Sanad is refunded
    public struct SanadRefunded has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        reason: vector<u8>,
        timestamp_ms: u64,
    }

    /// Legacy: Emitted when a locked Sanad is refunded (backward compatibility)
    public struct CrossChainRefund has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        timestamp_ms: u64,
    }

    /// Canonical: Emitted when Sanad ownership is transferred
    public struct SanadTransferred has copy, drop {
        sanad_id: vector<u8>,
        from: address,
        to: address,
        timestamp_ms: u64,
    }

    /// Canonical: Emitted when a nullifier is registered
    public struct NullifierRegistered has copy, drop {
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
        timestamp_ms: u64,
    }

    /// Canonical: Emitted when a commitment is anchored
    public struct CommitmentAnchored has copy, drop {
        commitment: vector<u8>,
        seal_id: sui::object::ID,
        owner: address,
        timestamp_ms: u64,
    }

    /// Canonical: Emitted when proof root is updated
    public struct ProofRootUpdated has copy, drop {
        proof_root: vector<u8>,
        timestamp_ms: u64,
        updater: address,
    }

    /// Canonical: Emitted when replay is detected
    public struct ReplayDetected has copy, drop {
        replay_id: vector<u8>,
        sanad_id: vector<u8>,
        timestamp_ms: u64,
    }

    /// Legacy events (backward compatibility)
    public struct AnchorEvent has copy, drop {
        commitment: vector<u8>,
        seal_id: sui::object::ID,
        timestamp_ms: u64,
    }
    public struct ProofAccepted has copy, drop {
        proof_root: vector<u8>,
        protocol_version: vector<u8>,
        timestamp_ms: u64,
    }
    public struct ProofRejected has copy, drop {
        proof_root: vector<u8>,
        reason: vector<u8>,
        timestamp_ms: u64,
    }

    /// Create a new seal with the given parameters.
    public fun create_seal(
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        nonce: u64,
        owner: address,
        ctx: &mut tx_context::TxContext,
    ): Seal {
        let timestamp_ms = tx_context::epoch(ctx) * 1000;
        Seal {
            id: object::new(ctx),
            sanad_id,
            commitment,
            state_root,
            nonce,
            state: SANAD_STATE_CREATED,
            owner,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty(),
            metadata_hash: vector::empty(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root: vector::empty(),
            created_at: timestamp_ms,
            locked_at: 0,
            consumed_at: 0,
            minted_at: 0,
            refunded_at: 0,
        }
    }

    /// Consume a seal (canonical name)
    public fun consume_seal(
        seal: &mut Seal,
        commitment: vector<u8>,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(seal.state != SANAD_STATE_CONSUMED, ESEAL_ALREADY_CONSUMED);
        seal.state = SANAD_STATE_CONSUMED;
        seal.consumed_at = tx_context::epoch(ctx) * 1000;

        let timestamp_ms = tx_context::epoch(ctx) * 1000;
        let sender = tx_context::sender(ctx);

        event::emit(SanadConsumed {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            consumer: sender,
            timestamp_ms,
        });

        event::emit(AnchorEvent {
            commitment,
            seal_id: object::uid_to_inner(&seal.id),
            timestamp_ms,
        });
    }

    /// Lock a Sanad for cross-chain transfer (canonical name)
    public fun lock_sanad(
        seal: &mut Seal,
        destination_chain: u8,
        destination_owner: vector<u8>,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(seal.state != SANAD_STATE_CONSUMED, ESEAL_ALREADY_CONSUMED);
        assert!(seal.state != SANAD_STATE_LOCKED, EALREADY_LOCKED);

        let timestamp_ms = tx_context::epoch(ctx) * 1000;

        seal.state = SANAD_STATE_LOCKED;
        seal.locked_at = timestamp_ms;

        event::emit(SanadLocked {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            owner: seal.owner,
            destination_chain,
            destination_owner,
            timestamp_ms,
        });

        event::emit(CrossChainLock {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            owner: seal.owner,
            destination_chain,
            destination_owner,
            timestamp_ms,
        });
    }

    /// Mint a new Sanad on destination chain (canonical name)
    public fun mint_sanad(
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        proof: vector<u8>,
        proof_root: vector<u8>,
        leaf_position: u64,
        owner: address,
        ctx: &mut tx_context::TxContext,
    ): Seal {
        if (source_chain == CHAIN_BITCOIN) {
            verify_bitcoin_proof(&sanad_id, &commitment, &proof, &proof_root, leaf_position);
        } else {
            verify_cross_chain_proof(&sanad_id, &commitment, source_chain, &proof, &proof_root, leaf_position);
        };

        let timestamp_ms = tx_context::epoch(ctx) * 1000;

        event::emit(SanadMinted {
            sanad_id,
            commitment,
            owner,
            source_chain,
            source_seal_ref,
            timestamp_ms,
        });

        event::emit(CrossChainMint {
            sanad_id,
            commitment,
            owner,
            source_chain,
            source_seal_ref,
            timestamp_ms,
        });

        Seal {
            id: object::new(ctx),
            sanad_id,
            commitment,
            state_root,
            nonce: 0,
            state: SANAD_STATE_MINTED,
            owner,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty(),
            metadata_hash: vector::empty(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root,
            created_at: timestamp_ms,
            minted_at: timestamp_ms,
            locked_at: 0,
            consumed_at: 0,
            refunded_at: 0,
        }
    }

    /// Mint a new Sanad using canonical ProofLeafV1 schema
    /// This is the recommended method for cross-chain minting
    public fun mint_sanad_with_proof_leaf(
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
        owner: address,
        ctx: &mut tx_context::TxContext,
    ): Seal {
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

        let timestamp_ms = tx_context::epoch(ctx) * 1000;

        event::emit(SanadMinted {
            sanad_id,
            commitment,
            owner,
            source_chain,
            source_seal_ref,
            timestamp_ms,
        });

        event::emit(CrossChainMint {
            sanad_id,
            commitment,
            owner,
            source_chain,
            source_seal_ref,
            timestamp_ms,
        });

        Seal {
            id: object::new(ctx),
            sanad_id,
            commitment,
            state_root,
            nonce: 0,
            state: SANAD_STATE_MINTED,
            owner,
            asset_class,
            asset_id,
            metadata_hash,
            proof_system,
            proof_root,
            created_at: timestamp_ms,
            minted_at: timestamp_ms,
            locked_at: 0,
            consumed_at: 0,
            refunded_at: 0,
        }
    }

    /// Refund a locked Sanad after timeout (canonical name)
    public fun refund_sanad(
        seal: &mut Seal,
        _destination_owner_hash: vector<u8>,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(seal.state == SANAD_STATE_LOCKED, ESANAD_NOT_FOUND);
        let now = tx_context::epoch(ctx) * 1000;
        assert!(now >= seal.locked_at + REFUND_TIMEOUT_MS, ETIMEOUT_NOT_EXPIRED);
        assert!(seal.owner == tx_context::sender(ctx), ENOT_AUTHORIZED);

        seal.state = SANAD_STATE_REFUNDED;
        seal.refunded_at = now;

        let timestamp_ms = now;
        let claimant = tx_context::sender(ctx);

        event::emit(SanadRefunded {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            claimant,
            reason: bcs::to_bytes(&b"timeout"),
            timestamp_ms,
        });

        event::emit(CrossChainRefund {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            claimant,
            timestamp_ms,
        });
    }

    /// Transfer Sanad ownership (canonical name, replaces transfer_seal)
    public fun transfer_sanad(seal: Seal, to: address, _ctx: &mut tx_context::TxContext) {
        assert!(seal.state != SANAD_STATE_CONSUMED, ESEAL_ALREADY_CONSUMED);
        assert!(seal.state != SANAD_STATE_LOCKED, EALREADY_LOCKED);
        transfer::public_transfer(seal, to);
    }

    /// Register nullifier for replay protection
    public fun register_nullifier(
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
        ctx: &mut tx_context::TxContext,
    ) {
        let timestamp_ms = tx_context::epoch(ctx) * 1000;
        event::emit(NullifierRegistered {
            nullifier,
            sanad_id,
            timestamp_ms,
        });
    }

    /// Anchor commitment on-chain
    public fun anchor_commitment(
        commitment: vector<u8>,
        seal: &Seal,
        ctx: &mut tx_context::TxContext,
    ) {
        let timestamp_ms = tx_context::epoch(ctx) * 1000;
        let seal_id = object::uid_to_inner(&seal.id);
        event::emit(CommitmentAnchored {
            commitment,
            seal_id,
            owner: seal.owner,
            timestamp_ms,
        });
    }

    /// Record metadata for a Sanad
    public fun record_sanad_metadata(
        seal: &mut Seal,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    ) {
        seal.asset_class = asset_class;
        seal.asset_id = asset_id;
        seal.metadata_hash = metadata_hash;
        seal.proof_system = proof_system;
        seal.proof_root = proof_root;
    }

    /// Verify cross-chain Merkle proof (non-Bitcoin chains)
    fun verify_cross_chain_proof(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        source_chain: u8,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64,
    ) {
        let mut leaf_data = vector::empty();
        vector::append(&mut leaf_data, *sanad_id);
        vector::append(&mut leaf_data, *commitment);
        let chain_bytes = bcs::to_bytes(&source_chain);
        vector::append(&mut leaf_data, chain_bytes);

        let leaf_hash = if (source_chain == CHAIN_SUI) {
            sui::hash::blake2b256(&leaf_data)
        } else if (source_chain == CHAIN_ETHEREUM || source_chain == CHAIN_SOLANA) {
            sui::hash::keccak256(&leaf_data)
        } else if (source_chain == CHAIN_APTOS) {
            std::hash::sha3_256(leaf_data)
        } else {
            abort EINVALID_PROOF
        };

        let is_valid = verify_merkle_proof_with_hash(proof, proof_root, &leaf_hash, leaf_position, source_chain);
        assert!(is_valid, EINVALID_PROOF);
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
            sanad_id: *sanad_id,
            commitment: *commitment,
            content_descriptor_hash,
            source_seal_ref_hash,
            destination_owner_hash,
            nullifier,
            lock_event_id,
            metadata_hash,
            proof_policy_hash,
        };

        // Compute canonical hash using blake2b256 (Sui's native hash)
        let leaf_hash = hash_proof_leaf_v1(&leaf);

        // Verify Merkle proof using blake2b256 (Sui's native hash)
        let is_valid = verify_merkle_proof_with_hash(proof, proof_root, &leaf_hash, leaf_position, CHAIN_SUI);
        assert!(is_valid, EINVALID_PROOF);
    }

    /// Verify cross-chain Merkle proof for Bitcoin
    fun verify_bitcoin_proof(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64,
    ) {
        let mut leaf_data = vector::empty();
        vector::append(&mut leaf_data, *sanad_id);
        vector::append(&mut leaf_data, *commitment);

        let leaf_hash = double_sha256(&leaf_data);
        let is_valid = verify_merkle_proof(proof, proof_root, &leaf_hash, leaf_position);
        assert!(is_valid, EINVALID_PROOF);
    }

    fun double_sha256(data: &vector<u8>): vector<u8> {
        let first = std::hash::sha2_256(*data);
        std::hash::sha2_256(first)
    }

    fun verify_merkle_proof(
        proof: &vector<u8>,
        root: &vector<u8>,
        leaf: &vector<u8>,
        leaf_position: u64,
    ): bool {
        verify_merkle_proof_with_hash(proof, root, leaf, leaf_position, 0)
    }

    fun verify_merkle_proof_with_hash(
        proof: &vector<u8>,
        root: &vector<u8>,
        leaf: &vector<u8>,
        leaf_position: u64,
        source_chain: u8,
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
            let mut sibling_hash = vector::empty();
            let mut j = 0;
            while (j < 32) {
                vector::push_back(&mut sibling_hash, *vector::borrow(proof, start + j));
                j = j + 1;
            };

            let bit = ((leaf_position >> (i as u8)) & 1) as u8;
            let mut hash_input = vector::empty();

            if (bit == 0) {
                vector::append(&mut hash_input, current_hash);
                vector::append(&mut hash_input, sibling_hash);
            } else {
                vector::append(&mut hash_input, sibling_hash);
                vector::append(&mut hash_input, current_hash);
            };

            current_hash = if (source_chain == CHAIN_SUI) {
                sui::hash::blake2b256(&hash_input)
            } else if (source_chain == CHAIN_ETHEREUM || source_chain == CHAIN_SOLANA) {
                sui::hash::keccak256(&hash_input)
            } else if (source_chain == CHAIN_APTOS) {
                std::hash::sha3_256(hash_input)
            } else {
                sui::hash::blake2b256(&hash_input)
            };
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

    // ==================== View Functions (Canonical Names) ====================

    /// Get Sanad state
    public fun state(seal: &Seal): u8 {
        seal.state
    }

    /// Get Sanad ID
    public fun sanad_id(seal: &Seal): vector<u8> {
        seal.sanad_id
    }

    /// Check if seal is available (not consumed)
    public fun is_seal_available(seal: &Seal): bool {
        seal.state != SANAD_STATE_CONSUMED
    }

    /// Check if seal is consumed (canonical name)
    public fun is_seal_consumed(seal: &Seal): bool {
        seal.state == SANAD_STATE_CONSUMED
    }

    /// Get the nonce of a seal.
    public fun nonce(seal: &Seal): u64 {
        seal.nonce
    }

    /// Get the object ID of a seal.
    public fun id(seal: &Seal): sui::object::ID {
        object::uid_to_inner(&seal.id)
    }

    /// Get the owner of a seal.
    public fun owner(seal: &Seal): address {
        seal.owner
    }
}
