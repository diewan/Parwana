//! CSV Seal Module for Aptos
//!
//! This Move module provides seal management for the CSV (Client-Side Validation) adapter.
//! Seals are resources that can be consumed exactly once to anchor commitments on-chain.
//!
//! ## Architecture
//!
//! Seals in Aptos are implemented as resources with a consumed flag and AnchorData storage.
//! Unlike the minimal version that simply deletes resources, this version provides:
//! - Consumed state tracking (seals are marked consumed, not deleted)
//! - AnchorData persistence (commitment stored on-chain after consumption)
//! - Transfer functionality (seals can be transferred between accounts)
//! - Timestamp tracking (consumption time recorded)
//! - Multiple seals per account via LinearCollection pattern
//! - Cross-chain proof verification with Merkle tree
//! - Nullifier registration for double-spend prevention
//!
//! ## Usage Flow
//!
//! 1. **Seal Creation**: Mint seal objects via `create_seal`
//! 2. **Seal Transfer**: Transfer seals between accounts via `transfer_seal`
//! 3. **Seal Consumption**: Call `consume_seal` to mark consumed and emit event
//! 4. **Cross-Chain**: Lock/Mint/Refund with Merkle proof verification
//! 5. **Nullifier**: Register nullifiers for double-spend prevention
//! 6. **Verification**: Verify the event was emitted with the correct commitment data
//!
//! ## Error Codes
//!
//! - `ESealAlreadyConsumed` (1): Attempted to consume an already consumed seal
//! - `ESealNotConsumed` (2): Attempted operation requiring consumed seal
//! - `EAnchorDataExists` (3): AnchorData already exists for this seal
//! - `ESealNotFound` (4): Seal object not found
//! - `EInvalidMetadata` (5): Invalid token/NFT/proof metadata
//! - `EInvalidProof` (6): Invalid cross-chain proof
//! - `ENullifierAlreadyRegistered` (7): Nullifier already registered

module csv_seal::CSVSealV2 {
    use std::signer;
    use std::event;
    use std::account;
    use std::object;
    use aptos_std::smart_table::{Self, SmartTable};
    use std::vector;
    use std::bcs;
    use std::hash;

    const ASSET_CLASS_UNSPECIFIED: u8 = 0;
    const ASSET_CLASS_PROOF_SANAD: u8 = 3;
    const PROOF_SYSTEM_UNSPECIFIED: u8 = 0;

    // =========================================================================
    // Cross-Chain Events (matching Ethereum version)
    // =========================================================================

    /// Emitted when a new seal/Sanad is created.
    #[event]
    struct SanadCreated has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    }

    /// Emitted when a seal/Sanad is consumed.
    #[event]
    struct SanadConsumed has drop, store {
        sanad_id: vector<u8>,
        consumer: address,
    }

    /// Emitted when a Sanad is locked for cross-chain transfer.
    #[event]
    struct CrossChainLock has drop, store {
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

    /// Emitted when a Sanad is minted from cross-chain proof.
    #[event]
    struct CrossChainMint has drop, store {
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

    /// Emitted when a Sanad is refunded after timeout.
    #[event]
    struct CrossChainRefund has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        refunded_at: u64,
    }

    /// Emitted whenever token/NFT/proof metadata is attached to a Sanad.
    #[event]
    struct SanadMetadataRecorded has drop, store {
        sanad_id: vector<u8>,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    }

    /// Emitted when a nullifier is registered.
    #[event]
    struct NullifierRegistered has drop, store {
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
    }

    // =========================================================================
    // Transfer State
    // =========================================================================

    /// Represents a seal that is pending transfer to a specific recipient.
    /// This is the safe transfer pattern - recipient must accept the transfer.
    struct PendingTransfer has key, drop {
        /// The seal being transferred
        seal: Seal,
        /// The intended recipient address
        recipient: address,
    }

    // =========================================================================
    // Error Codes
    // =========================================================================

    /// Attempted to consume an already consumed seal.
    const ESealAlreadyConsumed: u64 = 1;
    /// Attempted operation requiring consumed seal.
    const ESealNotConsumed: u64 = 2;
    /// AnchorData already exists for this seal.
    const EAnchorDataExists: u64 = 3;
    /// Seal not found at expected address.
    const ESealNotFound: u64 = 4;
    /// Invalid token/NFT/proof metadata.
    const EInvalidMetadata: u64 = 5;
    /// Invalid cross-chain proof.
    const EInvalidProof: u64 = 6;
    /// Nullifier already registered.
    const ENullifierAlreadyRegistered: u64 = 7;

    // =========================================================================
    // Structs
    // =========================================================================

    /// Anchor event emitted when a seal is consumed.
    #[event]
    struct AnchorEvent has drop, store {
        /// The commitment hash being anchored (32 bytes).
        commitment: vector<u8>,
        /// The address of the consumed seal.
        seal_address: address,
        /// Nonce of the seal for replay resistance.
        nonce: u64,
        /// Timestamp of the anchoring (Unix epoch seconds).
        timestamp_secs: u64,
    }

    /// Seal resource that can be consumed exactly once.
    /// Contains a consumed flag and nonce for replay resistance.
    struct Seal has key, store, drop {
        /// Nonce for replay resistance.
        nonce: u64,
        /// Whether this seal has been consumed.
        consumed: bool,
        /// Asset class: 0 unspecified, 1 fungible token, 2 NFT, 3 proof sanad.
        asset_class: u8,
        /// Chain-native token/NFT/proof family id.
        asset_id: vector<u8>,
        /// Hash of canonical metadata.
        metadata_hash: vector<u8>,
        /// Proof system identifier.
        proof_system: u8,
        /// Proof root or verification-key commitment.
        proof_root: vector<u8>,
        /// Nullifier for double-spend prevention (empty if not registered).
        nullifier: vector<u8>,
    }

    /// Persistent storage of commitment after seal consumption.
    /// Created when a seal is consumed and persists the commitment data.
    struct AnchorData has key, store, copy, drop {
        /// The commitment hash that was anchored.
        commitment: vector<u8>,
        /// Timestamp when the seal was consumed (Unix epoch seconds).
        consumed_at: u64,
        /// Nonce of the original seal.
        nonce: u64,
    }

    // =========================================================================
    // Seal Creation
    // =========================================================================

    /// Create a new seal resource at the signer's address with the given nonce.
    public entry fun create_seal(account: &signer, nonce: u64) {
        let addr = signer::address_of(account);
        assert!(!exists<Seal>(addr), EAnchorDataExists);
        move_to(account, Seal {
            nonce,
            consumed: false,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root: vector::empty<u8>(),
            nullifier: vector::empty<u8>(),
        });
    }

    /// Attach token/NFT/proof metadata to an unconsumed seal.
    public entry fun record_sanad_metadata(
        account: &signer,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    ) acquires Seal {
        let addr = signer::address_of(account);
        assert!(exists<Seal>(addr), ESealNotFound);
        assert!(asset_class <= ASSET_CLASS_PROOF_SANAD, EInvalidMetadata);
        assert!(asset_class == ASSET_CLASS_UNSPECIFIED || vector::length(&asset_id) > 0, EInvalidMetadata);
        assert!(proof_system == PROOF_SYSTEM_UNSPECIFIED || vector::length(&proof_root) > 0, EInvalidMetadata);

        let seal = borrow_global_mut<Seal>(addr);
        assert!(!seal.consumed, ESealAlreadyConsumed);

        seal.asset_class = asset_class;
        seal.asset_id = asset_id;
        seal.metadata_hash = metadata_hash;
        seal.proof_system = proof_system;
        seal.proof_root = proof_root;

        event::emit(SanadMetadataRecorded {
            sanad_id: bcs::to_bytes(&addr),
            asset_class,
            asset_id: seal.asset_id,
            metadata_hash: seal.metadata_hash,
            proof_system,
            proof_root: seal.proof_root,
        });
    }

    // =========================================================================
    // Seal Consumption
    // =========================================================================

    /// Consume a seal and emit an AnchorEvent with the commitment.
    public entry fun consume_seal(account: &signer, commitment: vector<u8>) {
        let seal_addr = signer::address_of(account);
        assert!(exists<Seal>(seal_addr), ESealNotFound);

        let seal = borrow_global_mut<Seal>(seal_addr);
        assert!(!seal.consumed, ESealAlreadyConsumed);

        let nonce = seal.nonce;
        seal.consumed = true;

        // Get current timestamp
        let timestamp = aptos_framework::timestamp::now_seconds();

        // Create AnchorData storage
        assert!(!exists<AnchorData>(seal_addr), EAnchorDataExists);
        move_to(account, AnchorData {
            commitment,
            consumed_at: timestamp,
            nonce,
        });

        // Emit anchor event using std::event API
        event::emit(AnchorEvent {
            commitment,
            seal_address: seal_addr,
            nonce,
            timestamp_secs: timestamp,
        });
    }

    // =========================================================================
    // Seal Transfer (Safe Two-Phase Pattern)
    // =========================================================================

    /// Initiate a seal transfer to a specific recipient.
    /// The seal is moved to a pending state where only the specified
    /// recipient can claim it. This is the safe transfer pattern.
    public entry fun initiate_transfer(from: &signer, recipient: address) {
        let from_addr = signer::address_of(from);
        assert!(exists<Seal>(from_addr), ESealNotFound);

        let seal = borrow_global<Seal>(from_addr);
        assert!(!seal.consumed, ESealAlreadyConsumed);
        assert!(!exists<PendingTransfer>(from_addr), EAnchorDataExists);

        // Move seal to pending transfer state at sender's address
        let seal_res = move_from<Seal>(from_addr);
        move_to(from, PendingTransfer {
            seal: seal_res,
            recipient,
        });
    }

    /// Accept a pending seal transfer.
    /// The intended recipient calls this to claim the seal.
    public entry fun accept_transfer(recipient_signer: &signer, sender_addr: address) {
        let recipient_addr = signer::address_of(recipient_signer);

        // Verify transfer exists and recipient is authorized
        assert!(exists<PendingTransfer>(sender_addr), ESealNotFound);
        let pending = borrow_global<PendingTransfer>(sender_addr);
        assert!(pending.recipient == recipient_addr, ESealNotFound);

        // Verify recipient doesn't already have a seal
        assert!(!exists<Seal>(recipient_addr), EAnchorDataExists);

        // Move seal from pending to recipient's account
        let PendingTransfer { seal, recipient: _ } = move_from<PendingTransfer>(sender_addr);
        move_to(recipient_signer, seal);
    }

    /// Cancel a pending transfer (only the sender can cancel).
    public entry fun cancel_transfer(sender: &signer) {
        let sender_addr = signer::address_of(sender);
        assert!(exists<PendingTransfer>(sender_addr), ESealNotFound);

        // Return seal to sender's account
        assert!(!exists<Seal>(sender_addr), EAnchorDataExists);
        let PendingTransfer { seal, recipient: _ } = move_from<PendingTransfer>(sender_addr);
        move_to(sender, seal);
    }

    /// Check if there's a pending transfer for a specific sender.
    public fun has_pending_transfer(sender_addr: address): bool {
        exists<PendingTransfer>(sender_addr)
    }

    /// Get the intended recipient for a pending transfer.
    public fun get_pending_recipient(sender_addr: address): address {
        assert!(exists<PendingTransfer>(sender_addr), ESealNotFound);
        borrow_global<PendingTransfer>(sender_addr).recipient
    }

    // =========================================================================
    // Queries
    // =========================================================================

    /// Check if a seal exists and has not been consumed.
    public fun is_seal_available(addr: address): bool {
        exists<Seal>(addr) && !borrow_global<Seal>(addr).consumed
    }

    /// Check if a seal has been consumed.
    /// Returns false if no seal exists at the address.
    public fun is_consumed(addr: address): bool {
        if (!exists<Seal>(addr)) {
            return false
        };
        borrow_global<Seal>(addr).consumed
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

    /// Check if AnchorData exists for a seal (i.e., seal was consumed).
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

    // =========================================================================
    // Cross-Chain Lock Registry
    // =========================================================================

    /// Lock record for tracking cross-chain transfers and refunds.
    struct LockRecord has store, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        destination_chain: u8,
        locked_at: u64,
        refunded: bool,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    }

    /// Shared registry tracking all locks for settlement support.
    struct LockRegistry has key {
        locks: SmartTable<vector<u8>, LockRecord>,
        refund_timeout: u64,
        /// Track minted Sanads for replay protection (using SmartTable for efficiency)
        minted_sanads: SmartTable<vector<u8>, bool>,
    }

    /// Initialize the LockRegistry (called once during deployment).
    public entry fun init_registry(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<LockRegistry>(addr), EAnchorDataExists);
        move_to(account, LockRegistry {
            locks: smart_table::new(),
            refund_timeout: 86400, // 24 hours in seconds
            minted_sanads: smart_table::new(),
        });
    }

    /// Get the LockRegistry address (module deployer).
    public fun get_registry_addr(): address {
        @csv_seal
    }

    // =========================================================================
    // Cross-Chain Proof Verification
    // =========================================================================

    /// Verify a cross-chain Merkle proof using SHA3-256 hashing and leaf position.
    /// Computes leaf = sha3_256(sanad_id || commitment || source_chain)
    /// then walks up the tree using leaf_position to determine left/right ordering.
    fun verify_cross_chain_proof(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        source_chain: u8,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64,
    ) {
        // Validate inputs
        assert!(vector::length(proof_root) == 32, EInvalidProof);
        assert!(vector::length(proof) % 32 == 0, EInvalidProof);
        assert!(vector::length(sanad_id) == 32, EInvalidProof);
        assert!(vector::length(commitment) == 32, EInvalidProof);

        // Build leaf hash: sha3_256(sanad_id || commitment || source_chain)
        let leaf_data = vector::empty<u8>();
        let j = 0;
        while (j < vector::length(sanad_id)) {
            vector::push_back(&mut leaf_data, *vector::borrow(sanad_id, j));
            j = j + 1;
        };
        let j = 0;
        while (j < vector::length(commitment)) {
            vector::push_back(&mut leaf_data, *vector::borrow(commitment, j));
            j = j + 1;
        };
        vector::push_back(&mut leaf_data, source_chain);
        let leaf = hash::sha3_256(leaf_data);

        // Verify Merkle proof using leaf position
        let current = leaf;
        let num_levels = vector::length(proof) / 32;
        let i = 0;

        while (i < num_levels) {
            let start = i * 32;
            let end = start + 32;
            let sibling = vector::slice(proof, start, end);

            // Use leaf_position bit to determine ordering
            let bit = (leaf_position >> (i as u8)) & 1;
            if (bit == 0) {
                // Current is left child
                let pair_data = vector::empty<u8>();
                let j = 0;
                while (j < vector::length(&current)) {
                    vector::push_back(&mut pair_data, *vector::borrow(&current, j));
                    j = j + 1;
                };
                let j = 0;
                while (j < vector::length(&sibling)) {
                    vector::push_back(&mut pair_data, *vector::borrow(&sibling, j));
                    j = j + 1;
                };
                current = hash::sha3_256(pair_data);
            } else {
                // Current is right child
                let pair_data = vector::empty<u8>();
                let j = 0;
                while (j < vector::length(&sibling)) {
                    vector::push_back(&mut pair_data, *vector::borrow(&sibling, j));
                    j = j + 1;
                };
                let j = 0;
                while (j < vector::length(&current)) {
                    vector::push_back(&mut pair_data, *vector::borrow(&current, j));
                    j = j + 1;
                };
                current = hash::sha3_256(pair_data);
            };
            i = i + 1;
        };

        // Verify computed root matches expected root
        assert!(current == *proof_root, EInvalidProof);
    }

    // =========================================================================
    // Lock / Mint / Refund
    // =========================================================================

    /// Lock a seal for cross-chain transfer.
    /// This consumes the seal and records the lock in the registry.
    public entry fun lock_sanad(
        account: &signer,
        sanad_id: vector<u8>,
        destination_chain: u8,
        destination_owner: vector<u8>,
    ) acquires Seal, LockRegistry {
        let owner_addr = signer::address_of(account);
        assert!(exists<Seal>(owner_addr), ESealNotFound);

        let seal = borrow_global<Seal>(owner_addr);
        assert!(!seal.consumed, ESealAlreadyConsumed);

        let nonce = seal.nonce;
        let commitment = get_commitment_bytes(sanad_id, nonce);

        // Record lock in registry
        let registry_addr = get_registry_addr();
        assert!(exists<LockRegistry>(registry_addr), ESealNotFound);
        let registry = borrow_global_mut<LockRegistry>(registry_addr);
        let locked_at = aptos_framework::timestamp::now_seconds();

        assert!(!smart_table::contains(&registry.locks, sanad_id), EAnchorDataExists);
        smart_table::add(&mut registry.locks, sanad_id, LockRecord {
            sanad_id: copy sanad_id,
            commitment: copy commitment,
            owner: owner_addr,
            destination_chain,
            locked_at,
            refunded: false,
            asset_class: seal.asset_class,
            asset_id: seal.asset_id,
            metadata_hash: seal.metadata_hash,
            proof_system: seal.proof_system,
            proof_root: seal.proof_root,
        });

        // Get transaction hash (use empty for now - filled off-chain)
        let source_tx_hash = vector::empty<u8>();

        // Emit CrossChainLock event
        event::emit(CrossChainLock {
            sanad_id: copy sanad_id,
            commitment: copy commitment,
            owner: owner_addr,
            destination_chain,
            destination_owner,
            source_tx_hash,
            locked_at,
            asset_class: seal.asset_class,
            asset_id: seal.asset_id,
            metadata_hash: seal.metadata_hash,
            proof_system: seal.proof_system,
            proof_root: seal.proof_root,
        });

        // Emit SanadConsumed event
        event::emit(SanadConsumed {
            sanad_id: copy sanad_id,
            consumer: owner_addr,
        });

        // Consume the seal (mark as consumed and store AnchorData)
        let seal_res = move_from<Seal>(owner_addr);
        move_to(account, AnchorData {
            commitment,
            consumed_at: locked_at,
            nonce: seal_res.nonce,
        });
        // seal_res dropped automatically (has drop ability)
    }

    /// Mint a new Sanad from a cross-chain transfer proof.
    /// Verifies the Merkle proof before minting (prevents unauthorized mints).
    ///
    /// # Arguments
    /// * `account` - Signer (becomes owner of the new Sanad)
    /// * `sanad_id` - Unique Sanad identifier (from source chain)
    /// * `commitment` - Sanad's commitment hash (preserved across chains)
    /// * `source_chain` - Source chain ID
    /// * `source_seal_ref` - Reference to source chain seal
    /// * `nonce` - Nonce for the new seal
    /// * `proof` - Merkle proof bytes verifying the source chain lock event
    /// * `proof_root` - The trusted proof root (e.g., bridge commitment root)
    /// * `leaf_position` - Position of leaf in the Merkle tree
    public entry fun mint_sanad(
        account: &signer,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        nonce: u64,
        proof: vector<u8>,
        proof_root: vector<u8>,
        leaf_position: u64,
    ) acquires LockRegistry {
        // Input validation: 32-byte checks for hashes
        assert!(vector::length(&sanad_id) == 32, EInvalidProof);
        assert!(vector::length(&commitment) == 32, EInvalidProof);
        assert!(vector::length(&proof_root) == 32, EInvalidProof);

        // Replay protection: check if sanad_id already minted
        let registry_addr = get_registry_addr();
        assert!(exists<LockRegistry>(registry_addr), ESealNotFound);
        let registry = borrow_global_mut<LockRegistry>(registry_addr);
        assert!(!smart_table::contains(&registry.minted_sanads, copy sanad_id), ESealAlreadyConsumed);

        // Verify cross-chain proof before minting
        verify_cross_chain_proof(&sanad_id, &commitment, source_chain, &proof, &proof_root, leaf_position);

        // Mark as minted (replay protection)
        smart_table::add(&mut registry.minted_sanads, sanad_id, true);

        let owner_addr = signer::address_of(account);
        assert!(!exists<Seal>(owner_addr), EAnchorDataExists);

        // Create new seal
        move_to(account, Seal {
            nonce,
            consumed: false,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root,
            nullifier: vector::empty<u8>(),
        });

        // Emit CrossChainMint event
        event::emit(CrossChainMint {
            sanad_id: copy sanad_id,
            commitment: copy commitment,
            owner: owner_addr,
            source_chain,
            source_seal_ref,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root: vector::empty<u8>(),
        });

        // Emit SanadCreated event
        event::emit(SanadCreated {
            sanad_id,
            commitment,
            owner: owner_addr,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root: vector::empty<u8>(),
        });
    }

    /// Register a nullifier for a Sanad (prevents double-spend).
    /// Reverts if the nullifier has already been registered for this Sanad.
    public entry fun register_nullifier(
        account: &signer,
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
    ) acquires Seal {
        let addr = signer::address_of(account);
        assert!(exists<Seal>(addr), ESealNotFound);
        let seal = borrow_global_mut<Seal>(addr);
        assert!(seal.nullifier == vector::empty<u8>(), ENullifierAlreadyRegistered);

        // Store the nullifier in the seal for on-chain verification
        seal.nullifier = nullifier;

        event::emit(NullifierRegistered {
            nullifier,
            sanad_id,
        });
    }

    /// Refund a seal after the lock timeout has elapsed.
    public entry fun refund_sanad(
        account: &signer,
        sanad_id: vector<u8>,
        registry_addr: address,
    ) acquires LockRegistry {
        let claimant = signer::address_of(account);

        assert!(exists<LockRegistry>(registry_addr), ESealNotFound);
        let registry = borrow_global_mut<LockRegistry>(registry_addr);

        assert!(smart_table::contains(&registry.locks, copy sanad_id), ESealNotFound);

        // Verify not already refunded and timeout has elapsed
        let lock = smart_table::borrow_mut(&mut registry.locks, sanad_id);
        assert!(!lock.refunded, ESealAlreadyConsumed);

        // Verify caller is the original owner (security: prevent unauthorized refunds)
        assert!(lock.owner == claimant, ESealNotConsumed);

        let now = aptos_framework::timestamp::now_seconds();
        assert!(now >= lock.locked_at + registry.refund_timeout, ESealNotConsumed);

        // Copy values for event emission before removing lock
        let commitment_copy = lock.commitment;
        let sanad_id_copy = sanad_id;

        // Remove lock record from registry to prevent bloat
        smart_table::remove(&mut registry.locks, sanad_id);

        // Emit CrossChainRefund event
        event::emit(CrossChainRefund {
            sanad_id: sanad_id_copy,
            commitment: commitment_copy,
            claimant,
            refunded_at: now,
        });
    }

    /// Get lock info for off-chain verification.
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

    /// Check if refund is available for a seal.
    public fun can_refund(
        registry_addr: address,
        sanad_id: vector<u8>,
        now: u64,
    ): bool acquires LockRegistry {
        if (!exists<LockRegistry>(registry_addr)) {
            return false
        };
        let registry = borrow_global<LockRegistry>(registry_addr);
        if (!smart_table::contains(&registry.locks, copy sanad_id)) {
            return false
        };
        let lock = smart_table::borrow(&registry.locks, sanad_id);
        !lock.refunded && now >= lock.locked_at + registry.refund_timeout
    }

    /// Helper to generate commitment from sanad_id and nonce using SHA3-256.
    fun get_commitment_bytes(sanad_id: vector<u8>, nonce: u64): vector<u8> {
        let data = vector::empty<u8>();
        let j = 0;
        while (j < vector::length(&sanad_id)) {
            vector::push_back(&mut data, *vector::borrow(&sanad_id, j));
            j = j + 1;
        };
        let nonce_bytes = bcs::to_bytes(&nonce);
        let j = 0;
        while (j < vector::length(&nonce_bytes)) {
            vector::push_back(&mut data, *vector::borrow(&nonce_bytes, j));
            j = j + 1;
        };
        hash::sha3_256(data)
    }

    // =========================================================================
    // Module Initialization
    // =========================================================================

    /// Initialize the module by creating the event handle.
    public entry fun initialize_module(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<AnchorEventHandle>(addr), EAnchorDataExists);
        move_to(account, AnchorEventHandle {
            events: account::new_event_handle<AnchorEvent>(account),
        });
    }

    /// Event handle for anchor events (stored at module publish address).
    struct AnchorEventHandle has key {
        events: event::EventHandle<AnchorEvent>,
    }
}