/// CSV Seal — Cross-Chain Sanad Transfer on Sui
///
/// This module implements:
/// - `create_seal()` — Create a new Sanad anchored to a Sui object
/// - `consume_seal()` — Consume a Sanad (single-use enforcement via object deletion)
/// - `lock_sanad()` — Lock a Sanad for cross-chain transfer (consumes seal, emits event)
/// - `mint_sanad()` — Mint a new Sanad from a cross-chain transfer proof
/// - `refund_sanad()` — Recover a Sanad after lock timeout (settlement strategy)

module csv_seal::csv_seal {
    use sui::object::{Self, UID, ID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::table;
    use sui::event;
    use std::vector;

    const ASSET_CLASS_UNSPECIFIED: u8 = 0;
    const ASSET_CLASS_PROOF_SANAD: u8 = 3;
    const PROOF_SYSTEM_UNSPECIFIED: u8 = 0;
    const E_INVALID_METADATA: u64 = 1006;

    /// A Sanad anchored to Sui as an object.
    /// The object's existence = the Sanad's validity.
    /// Deleting the object = consuming the Sanad (single-use enforced).
    struct SanadObject has key, store {
        id: UID,
        /// Unique Sanad identifier (preserved across chains)
        sanad_id: vector<u8>,
        /// Commitment hash (preserved across chains)
        commitment: vector<u8>,
        /// Owner address
        owner: address,
        /// Nullifier (for L3 chains that use nullifiers)
        nullifier: vector<u8>,
        /// State root (off-chain state commitment)
        state_root: vector<u8>,
        /// Asset class: 0 unspecified, 1 fungible token, 2 NFT, 3 proof sanad
        asset_class: u8,
        /// Chain-native token/NFT/proof family id
        asset_id: vector<u8>,
        /// Hash of canonical metadata
        metadata_hash: vector<u8>,
        /// Proof system identifier
        proof_system: u8,
        /// Proof root or verification-key commitment
        proof_root: vector<u8>,
    }

    /// Lock record for refund tracking
    struct LockRecord has store {
        /// Sanad identifier
        sanad_id: vector<u8>,
        /// Commitment hash
        commitment: vector<u8>,
        /// Original owner
        owner: address,
        /// Destination chain ID
        destination_chain: u8,
        /// Asset/proof metadata copied from the locked Sanad
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
        /// Lock timestamp (Unix epoch seconds)
        locked_at: u64,
        /// Whether this lock has been refunded
        refunded: bool,
    }

    /// Shared object tracking lock records for settlement
    struct LockRegistry has key {
        id: UID,
        /// Map from sanad_id to LockRecord
        locks: table::Table<vector<u8>, LockRecord>,
        /// Refund timeout in seconds (24 hours)
        refund_timeout: u64,
    }

    // Event structs (copy + drop)
    struct SanadCreated has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        object_id: ID,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    }

    struct SanadConsumed has copy, drop {
        sanad_id: vector<u8>,
        consumer: address,
    }

    struct CrossChainLock has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        destination_chain: u8,
        destination_owner: vector<u8>,
        source_tx_hash: vector<u8>,
        locked_at: u64,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    }

    struct CrossChainMint has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    }

    struct CrossChainRefund has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        refunded_at: u64,
    }

    struct SanadMetadataRecorded has copy, drop {
        sanad_id: vector<u8>,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    }

    struct NullifierRegistered has copy, drop {
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
    }

    /// Create a new LockRegistry (called once during deployment)
    public fun create_registry(ctx: &mut TxContext) {
        let registry = LockRegistry {
            id: object::new(ctx),
            locks: table::new(ctx),
            refund_timeout: 86400, // 24 hours
        };
        transfer::share_object(registry);
    }

    /// Create a new Sanad on Sui
    public fun create_seal(
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        ctx: &mut TxContext
    ) {
        let sanad = SanadObject {
            id: object::new(ctx),
            sanad_id,
            commitment,
            owner: tx_context::sender(ctx),
            nullifier: vector::empty<u8>(),
            state_root,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root: vector::empty<u8>(),
        };

        event::emit(SanadCreated {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner: sanad.owner,
            object_id: object::uid_to_inner(&sanad.id),
            asset_class: sanad.asset_class,
            asset_id: sanad.asset_id,
            metadata_hash: sanad.metadata_hash,
            proof_system: sanad.proof_system,
            proof_root: sanad.proof_root,
        });

        transfer::public_transfer(sanad, tx_context::sender(ctx));
    }

    /// Record token/NFT/proof metadata for an unconsumed Sanad.
    public fun record_sanad_metadata(
        sanad: &mut SanadObject,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    ) {
        assert!(asset_class <= ASSET_CLASS_PROOF_SANAD, E_INVALID_METADATA);
        assert!(asset_class == ASSET_CLASS_UNSPECIFIED || vector::length(&asset_id) > 0, E_INVALID_METADATA);
        assert!(proof_system == PROOF_SYSTEM_UNSPECIFIED || vector::length(&proof_root) > 0, E_INVALID_METADATA);

        sanad.asset_class = asset_class;
        sanad.asset_id = asset_id;
        sanad.metadata_hash = metadata_hash;
        sanad.proof_system = proof_system;
        sanad.proof_root = proof_root;

        event::emit(SanadMetadataRecorded {
            sanad_id: sanad.sanad_id,
            asset_class,
            asset_id: sanad.asset_id,
            metadata_hash: sanad.metadata_hash,
            proof_system,
            proof_root: sanad.proof_root,
        });
    }

    /// Consume a Sanad (single-use enforcement via object deletion)
    public fun consume_seal(
        sanad: SanadObject,
        ctx: &mut TxContext
    ) {
        event::emit(SanadConsumed {
            sanad_id: sanad.sanad_id,
            consumer: tx_context::sender(ctx),
        });

        let SanadObject {
            id,
            sanad_id: _,
            commitment: _,
            owner: _,
            nullifier: _,
            state_root: _,
            asset_class: _,
            asset_id: _,
            metadata_hash: _,
            proof_system: _,
            proof_root: _,
        } = sanad;
        object::delete(id);
    }

    /// Lock a Sanad for cross-chain transfer.
    /// This consumes the Sanad (deletes the object) and emits a CrossChainLock event.
    /// The lock is recorded in the registry for refund support.
    public fun lock_sanad(
        sanad: SanadObject,
        destination_chain: u8,
        destination_owner: vector<u8>,
        registry: &mut LockRegistry,
        ctx: &mut TxContext
    ) {
        let locked_at = tx_context::epoch_timestamp_ms(ctx) / 1000;

        // Record the lock in the registry
        let lock = LockRecord {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner: sanad.owner,
            destination_chain,
            asset_class: sanad.asset_class,
            asset_id: sanad.asset_id,
            metadata_hash: sanad.metadata_hash,
            proof_system: sanad.proof_system,
            proof_root: sanad.proof_root,
            locked_at,
            refunded: false,
        };

        table::add(&mut registry.locks, sanad.sanad_id, lock);

        event::emit(CrossChainLock {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner: sanad.owner,
            destination_chain,
            destination_owner,
            source_tx_hash: *tx_context::digest(ctx),
            locked_at,
            asset_class: sanad.asset_class,
            asset_id: sanad.asset_id,
            metadata_hash: sanad.metadata_hash,
            proof_system: sanad.proof_system,
            proof_root: sanad.proof_root,
        });

        // Consume the Sanad (object deletion = single-use enforcement)
        let SanadObject {
            id,
            sanad_id: _,
            commitment: _,
            owner: _,
            nullifier: _,
            state_root: _,
            asset_class: _,
            asset_id: _,
            metadata_hash: _,
            proof_system: _,
            proof_root: _,
        } = sanad;
        object::delete(id);
    }

    /// Mint a new Sanad from a cross-chain transfer proof.
    /// This creates a new SanadObject with the same commitment as the source chain's Sanad.
    /// 
    /// # Arguments
    /// * `sanad_id` - Unique Sanad identifier from source chain
    /// * `commitment` - Commitment hash preserved across chains
    /// * `state_root` - Off-chain state root
    /// * `source_chain` - Source chain ID
    /// * `source_seal_ref` - Reference to source chain seal
    /// * `proof` - Cross-chain Merkle proof bytes
    /// * `proof_root` - Trusted proof root for verification
    /// * `leaf_position` - Position of leaf in Merkle tree for deterministic verification
    public fun mint_sanad(
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        proof: vector<u8>,
        proof_root: vector<u8>,
        leaf_position: u64,
        ctx: &mut TxContext
    ) {
        // Verify cross-chain proof before minting
        verify_cross_chain_proof(&sanad_id, &commitment, source_chain, &proof, &proof_root, leaf_position);

        let sanad = SanadObject {
            id: object::new(ctx),
            sanad_id,
            commitment,
            owner: tx_context::sender(ctx),
            nullifier: vector::empty<u8>(),
            state_root,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root,
        };

        event::emit(CrossChainMint {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner: sanad.owner,
            source_chain,
            source_seal_ref,
            asset_class: sanad.asset_class,
            asset_id: sanad.asset_id,
            metadata_hash: sanad.metadata_hash,
            proof_system: sanad.proof_system,
            proof_root: sanad.proof_root,
        });

        transfer::public_transfer(sanad, tx_context::sender(ctx));
    }

    /// Verify cross-chain Merkle proof for mint operations
    /// Uses leaf position for deterministic verification
    fun verify_cross_chain_proof(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        source_chain: u8,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64
    ) {
        use sui::hash;
        
        // Validate inputs
        assert!(proof_root.len() == 32, E_INVALID_METADATA);
        assert!(proof.len() % 32 == 0, E_INVALID_METADATA);
        
        // Build leaf hash: hash(sanad_id || commitment || source_chain)
        let mut hasher = hash::sha2_256();
        hash::update(&mut hasher, sanad_id);
        hash::update(&mut hasher, commitment);
        hash::update(&mut hasher, &source_chain.to_le_bytes());
        let leaf = hash::finish(hasher);
        
        // Verify Merkle proof using leaf position
        let current = leaf;
        let num_levels = proof.len() / 32;
        let mut i = 0;
        
        while (i < num_levels) {
            let start = i * 32;
            let end = start + 32;
            let sibling = vector::slice(proof, start, end);
            
            // Use leaf_position bit to determine ordering
            let bit = (leaf_position >> i) & 1;
            if (bit == 0) {
                // Current is left child
                let mut pair_hasher = hash::sha2_256();
                hash::update(&mut pair_hasher, &current);
                hash::update(&mut pair_hasher, &sibling);
                current = hash::finish(pair_hasher);
            } else {
                // Current is right child
                let mut pair_hasher = hash::sha2_256();
                hash::update(&mut pair_hasher, &sibling);
                hash::update(&mut pair_hasher, &current);
                current = hash::finish(pair_hasher);
            };
            i = i + 1;
        }
        
        // Verify computed root matches expected root
        assert!(current == *proof_root, E_INVALID_METADATA);
    }

    /// Refund a Sanad after the lock timeout has elapsed.
    /// This re-creates the SanadObject if:
    /// 1. The lock was recorded in the registry
    /// 2. The REFUND_TIMEOUT has elapsed
    /// 3. The Sanad has not already been refunded
    public fun refund_sanad(
        sanad_id: vector<u8>,
        state_root: vector<u8>,
        registry: &mut LockRegistry,
        ctx: &mut TxContext
    ) {
        assert!(
            table::contains(&registry.locks, sanad_id),
            1003 // Lock not found in registry
        );

        let lock = table::borrow_mut(&mut registry.locks, sanad_id);
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;

        // Verify timeout has elapsed
        assert!(
            now >= lock.locked_at + registry.refund_timeout,
            1004 // Refund timeout not yet expired
        );

        // Verify not already refunded
        assert!(!lock.refunded, 1005); // Already refunded

        // Copy lock data before removing
        let lock_sanad_id = lock.sanad_id;
        let lock_commitment = lock.commitment;
        let lock_asset_class = lock.asset_class;
        let lock_asset_id = lock.asset_id;
        let lock_metadata_hash = lock.metadata_hash;
        let lock_proof_system = lock.proof_system;
        let lock_proof_root = lock.proof_root;

        // Remove lock record from registry to prevent storage bloat
        table::remove(&mut registry.locks, sanad_id);

        // Re-create the SanadObject
        let sanad = SanadObject {
            id: object::new(ctx),
            sanad_id: lock_sanad_id,
            commitment: lock_commitment,
            owner: tx_context::sender(ctx),
            nullifier: vector::empty<u8>(),
            state_root,
            asset_class: lock_asset_class,
            asset_id: lock_asset_id,
            metadata_hash: lock_metadata_hash,
            proof_system: lock_proof_system,
            proof_root: lock_proof_root,
        };

        event::emit(CrossChainRefund {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            claimant: tx_context::sender(ctx),
            refunded_at: now,
        });

        transfer::public_transfer(sanad, tx_context::sender(ctx));
    }

    /// Register a nullifier for a Sanad (prevents double-spend on L3 chains).
    /// Reverts if the Sanad's nullifier field is already non-empty.
    public fun register_nullifier(
        sanad: &mut SanadObject,
        nullifier: vector<u8>,
        _ctx: &mut TxContext
    ) {
        assert!(vector::is_empty(&sanad.nullifier), 1007); // Nullifier already set
        sanad.nullifier = nullifier;

        event::emit(NullifierRegistered {
            nullifier,
            sanad_id: sanad.sanad_id,
        });
    }

    /// Transfer ownership of a Sanad
    public fun transfer_sanad(
        sanad: SanadObject,
        new_owner: address,
        _ctx: &mut TxContext
    ) {
        transfer::public_transfer(sanad, new_owner);
    }

    /// Get lock info (for off-chain refund verification)
    public fun get_lock_info(
        registry: &LockRegistry,
        sanad_id: vector<u8>,
    ): (vector<u8>, u64, bool) {
        let lock = table::borrow(&registry.locks, sanad_id);
        (lock.commitment, lock.locked_at, lock.refunded)
    }

    /// Check if refund is available for a Sanad
    public fun can_refund(
        registry: &LockRegistry,
        sanad_id: vector<u8>,
        now: u64,
    ): bool {
        if (!table::contains(&registry.locks, sanad_id)) {
            return false
        };
        let lock = table::borrow(&registry.locks, sanad_id);
        !lock.refunded && now >= lock.locked_at + registry.refund_timeout
    }
}
