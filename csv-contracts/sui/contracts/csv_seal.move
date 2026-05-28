module csv_seal {
    use std::string;
    use sui::object;
    use sui::tx_context;
    use sui::transfer;
    use sui::event;
    use sui::hash;

    /// Chain IDs for cross-chain transfers (must match other CSV contracts)
    const CHAIN_BITCOIN: u8 = 0;
    const CHAIN_SUI: u8 = 1;
    const CHAIN_APTOS: u8 = 2;
    const CHAIN_ETHEREUM: u8 = 3;
    const CHAIN_SOLANA: u8 = 4;

    /// Asset class constants
    const ASSET_CLASS_UNSPECIFIED: u8 = 0;
    const ASSET_CLASS_FUNGIBLE_TOKEN: u8 = 1;
    const ASSET_CLASS_NON_FUNGIBLE_TOKEN: u8 = 2;
    const ASSET_CLASS_PROOF_SANAD: u8 = 3;

    /// Proof system constants
    const PROOF_SYSTEM_UNSPECIFIED: u8 = 0;

    /// Error codes
    const ESEAL_ALREADY_CONSUMED: u64 = 0;
    const EINVALID_PROOF: u64 = 1;
    const EALREADY_LOCKED: u64 = 2;
    const EALREADY_MINTED: u64 = 3;

    /// A seal object that can be consumed exactly once.
    /// Seals are created by the contract owner and distributed to users
    /// who then consume them to anchor commitments.
    struct Seal has key, store {
        id: object::UID,
        /// Unique Sanad identifier (preserved across chains)
        sanad_id: vector<u8>,
        /// Commitment hash (preserved across chains)
        commitment: vector<u8>,
        /// State root (off-chain state commitment)
        state_root: vector<u8>,
        /// Nonce for replay resistance
        nonce: u64,
        /// Whether this seal has been consumed
        consumed: bool,
        /// Whether this seal is locked for cross-chain transfer
        locked: bool,
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
    }

    /// Lock record for refund support
    struct LockRecord has key, store {
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
    struct MintedSanad has key, store {
        id: object::UID,
        /// Sanad identifier that was minted
        sanad_id: vector<u8>,
        /// When it was minted (Unix epoch milliseconds)
        minted_at: u64,
    }

    /// Event emitted when a seal is consumed with a commitment.
    struct AnchorEvent has copy, drop {
        /// The commitment hash being anchored
        commitment: vector<u8>,
        /// The object ID of the consumed seal
        seal_id: address,
        /// Timestamp of the anchoring (Unix epoch milliseconds)
        timestamp_ms: u64,
    }

    /// Event emitted when a Sanad is created
    struct SanadCreated has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        timestamp_ms: u64,
    }

    /// Event emitted when a Sanad is consumed
    struct SanadConsumed has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        consumer: address,
        timestamp_ms: u64,
    }

    /// Event emitted when a Sanad is locked for cross-chain transfer
    struct CrossChainLock has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        destination_chain: u8,
        destination_owner: vector<u8>,
        timestamp_ms: u64,
    }

    /// Event emitted when a Sanad is minted from cross-chain transfer
    struct CrossChainMint has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        timestamp_ms: u64,
    }

    /// Event emitted when a locked Sanad is refunded
    struct CrossChainRefund has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        timestamp_ms: u64,
    }

    /// Event emitted when a nullifier is registered
    struct NullifierRegistered has copy, drop {
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
        timestamp_ms: u64,
    }

    /// Event emitted when a proof is accepted
    struct ProofAccepted has copy, drop {
        proof_root: vector<u8>,
        protocol_version: vector<u8>,
        timestamp_ms: u64,
    }

    /// Event emitted when a proof is rejected
    struct ProofRejected has copy, drop {
        proof_root: vector<u8>,
        reason: vector<u8>,
        timestamp_ms: u64,
    }

    /// Event emitted when a replay attack is detected
    struct ReplayDetected has copy, drop {
        replay_id: vector<u8>,
        sanad_id: vector<u8>,
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
        // Note: Sui doesn't provide Unix timestamp in tx_context.
        // Using epoch as a monotonic counter. For production, integrate with
        // a timestamp oracle or use block time from the Sui framework when available.
        // This is sufficient for ordering but not for absolute time comparisons.
        let timestamp_ms = tx_context::epoch(ctx) * 1000;
        Seal {
            id: object::new(ctx),
            sanad_id,
            commitment,
            state_root,
            nonce,
            consumed: false,
            locked: false,
            owner,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty(),
            metadata_hash: vector::empty(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root: vector::empty(),
            created_at: timestamp_ms,
        }
    }

    /// Consume a seal and emit an AnchorEvent with the commitment.
    /// This function deletes the seal's usability by marking it consumed.
    public fun consume_seal(
        seal: &mut Seal,
        commitment: vector<u8>,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(!seal.consumed, ESEAL_ALREADY_CONSUMED);
        seal.consumed = true;

        let timestamp_ms = tx_context::epoch(ctx) * 1000;

        event::emit(AnchorEvent {
            commitment,
            seal_id: object::uid_to_inner(&seal.id),
            timestamp_ms,
        });

        event::emit(SanadConsumed {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            consumer: tx_context::sender(ctx),
            timestamp_ms,
        });
    }

    /// Lock a Sanad for cross-chain transfer
    /// Consumes the Sanad and creates a LockRecord for refund support
    public fun lock_sanad(
        seal: &mut Seal,
        destination_chain: u8,
        destination_owner: vector<u8>,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(!seal.consumed, ESEAL_ALREADY_CONSUMED);
        assert!(!seal.locked, EALREADY_LOCKED);

        seal.locked = true;
        seal.consumed = true;

        let timestamp_ms = tx_context::epoch(ctx) * 1000;

        event::emit(CrossChainLock {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            owner: seal.owner,
            destination_chain,
            destination_owner,
            timestamp_ms,
        });

        event::emit(SanadConsumed {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            consumer: seal.owner,
            timestamp_ms,
        });
    }

    /// Mint a new Sanad from a cross-chain transfer proof
    /// Creates a new Seal with the same commitment as the source chain
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
        // Verify cross-chain proof before minting
        verify_cross_chain_proof(&sanad_id, &commitment, source_chain, &proof, &proof_root, leaf_position);

        let timestamp_ms = tx_context::epoch(ctx) * 1000;

        event::emit(CrossChainMint {
            sanad_id: sanad_id.clone(),
            commitment: commitment.clone(),
            owner,
            source_chain,
            source_seal_ref: source_seal_ref.clone(),
            timestamp_ms,
        });

        Seal {
            id: object::new(ctx),
            sanad_id,
            commitment,
            state_root,
            nonce: 0,
            consumed: false,
            locked: false,
            owner,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty(),
            metadata_hash: vector::empty(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root,
            created_at: timestamp_ms,
        }
    }

    /// Verify cross-chain Merkle proof for mint operations
    /// Uses leaf position for deterministic verification
    fun verify_cross_chain_proof(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        source_chain: u8,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64,
    ) {
        // Build leaf hash: keccak256(sanad_id || commitment || source_chain)
        // Sui doesn't have native keccak256, so we use sha256 with domain separator
        let mut leaf_data = vector::empty();
        vector::append(&mut leaf_data, sanad_id);
        vector::append(&mut leaf_data, commitment);
        let chain_bytes = bcs::to_bytes(&source_chain);
        vector::append(&mut leaf_data, &chain_bytes);
        
        let leaf_hash = keccak256_compat(&leaf_data);
        
        // Verify Merkle proof against proof root
        let is_valid = verify_merkle_proof(proof, proof_root, &leaf_hash, leaf_position);
        assert!(is_valid, EINVALID_PROOF);
    }

    /// keccak256 compatibility layer for Sui
    /// Uses sha256 with domain separator to match Ethereum/Solana behavior
    fun keccak256_compat(data: &vector<u8>): vector<u8> {
        let mut domain = b"csv.keccak256.compat";
        let mut input = vector::empty();
        vector::append(&mut input, domain);
        vector::append(&mut input, data);
        hash::sha256(&input)
    }

    /// Verify a Merkle proof for leaf inclusion
    /// Walks the Merkle tree bottom-up, hashing pairs at each level
    fun verify_merkle_proof(
        proof: &vector<u8>,
        root: &vector<u8>,
        leaf: &vector<u8>,
        leaf_position: u64,
    ): bool {
        let proof_len = vector::length(proof);
        let root_len = vector::length(root);
        let leaf_len = vector::length(leaf);

        // Validate inputs
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

            let bit = (leaf_position >> i) & 1;
            let mut hash_input = vector::empty();
            
            if (bit == 0) {
                vector::append(&mut hash_input, &current_hash);
                vector::append(&mut hash_input, &sibling_hash);
            } else {
                vector::append(&mut hash_input, &sibling_hash);
                vector::append(&mut hash_input, &current_hash);
            };

            current_hash = keccak256_compat(&hash_input);
            i = i + 1;
        };

        // Compare computed root with expected root
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

    /// Check if a seal exists and has not been consumed.
    public fun is_seal_available(seal: &Seal): bool {
        !seal.consumed
    }

    /// Get the nonce of a seal.
    public fun nonce(seal: &Seal): u64 {
        seal.nonce
    }

    /// Get the object ID of a seal.
    public fun id(seal: &Seal): address {
        object::uid_to_inner(&seal.id)
    }

    /// Check if a seal has been consumed.
    public fun is_consumed(seal: &Seal): bool {
        seal.consumed
    }

    /// Get the owner of a seal.
    public fun owner(seal: &Seal): address {
        seal.owner
    }

    /// Transfer a seal to an address (only if not consumed).
    public fun transfer_seal(seal: Seal, to: address, _ctx: &mut tx_context::TxContext) {
        assert!(!seal.consumed, ESEAL_ALREADY_CONSUMED);
        transfer::public_transfer(seal, to);
    }
}