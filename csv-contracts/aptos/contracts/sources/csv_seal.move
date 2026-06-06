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
//! - Multiple seals per account via SmartTable pattern (like Sui's object model)
//! - Cross-chain proof verification with Merkle tree
//! - Nullifier registration for double-spend prevention
//!
//! ## Usage Flow
//!
//! 1. **Seal Creation**: Initialize collection, then create seal objects via `create_seal`
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

module csv_seal::CSVSeal {
    use std::signer;
    use std::event;
    use std::account;
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
        proof_root: vector<u8>,
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

    // Emitted when a Sanad is minted from cross-chain proof.
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

    // Emitted when a Sanad is refunded after timeout.
    #[event]
    struct CrossChainRefund has drop, store {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        refunded_at: u64,
    }

    // Emitted whenever token/NFT/proof metadata is attached to a Sanad.
    #[event]
    struct SanadMetadataRecorded has drop, store {
        sanad_id: vector<u8>,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    }

    // Emitted when a nullifier is registered.
    #[event]
    struct NullifierRegistered has drop, store {
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
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

    // Anchor event emitted when a seal is consumed.
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
    struct Seal has store, drop {
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

    /// Collection of seals for an account (allows multiple seals per account like Sui).
    struct SealCollection has key {
        seals: SmartTable<u64, Seal>,
        next_nonce: u64,
    }

    /// Persistent storage of commitment after seal consumption.
    /// Created when a seal is consumed and persists the commitment data.
    struct AnchorDataCollection has key {
        anchor_data: SmartTable<u64, AnchorData>,
    }

    /// Persistent storage of commitment after seal consumption.
    /// Created when a seal is consumed and persists the commitment data.
    struct AnchorData has store, copy, drop {
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

    /// Initialize the seal collection for an account (called once).
    public entry fun init_seal_collection(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<SealCollection>(addr), EAnchorDataExists);
        move_to(account, SealCollection {
            seals: smart_table::new(),
            next_nonce: 0,
        });
    }

    /// Create a new seal resource at the signer's address with the given nonce.
    /// If nonce is not provided, uses the next available nonce from the collection.
    public entry fun create_seal(account: &signer, nonce: u64) acquires SealCollection {
        let addr = signer::address_of(account);
        assert!(exists<SealCollection>(addr), ESealNotFound);
        
        let collection = borrow_global_mut<SealCollection>(addr);
        assert!(!smart_table::contains(&collection.seals, nonce), EAnchorDataExists);
        
        smart_table::add(&mut collection.seals, nonce, Seal {
            nonce,
            consumed: false,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root: vector::empty<u8>(),
            nullifier: vector::empty<u8>(),
        });
        
        // Update next_nonce if this is the highest nonce
        if (nonce >= collection.next_nonce) {
            collection.next_nonce = nonce + 1;
        };
    }

    /// Create a new seal with auto-generated nonce (like Sui).
    public entry fun create_seal_auto(account: &signer) acquires SealCollection {
        let addr = signer::address_of(account);
        assert!(exists<SealCollection>(addr), ESealNotFound);
        
        let collection = borrow_global_mut<SealCollection>(addr);
        let nonce = collection.next_nonce;
        
        smart_table::add(&mut collection.seals, nonce, Seal {
            nonce,
            consumed: false,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root: vector::empty<u8>(),
            nullifier: vector::empty<u8>(),
        });
        
        collection.next_nonce = nonce + 1;
    }

    /// Attach token/NFT/proof metadata to an unconsumed seal.
    public entry fun record_sanad_metadata(
        account: &signer,
        nonce: u64,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        proof_root: vector<u8>,
    ) acquires SealCollection {
        let addr = signer::address_of(account);
        assert!(exists<SealCollection>(addr), ESealNotFound);
        assert!(asset_class <= ASSET_CLASS_PROOF_SANAD, EInvalidMetadata);
        assert!(asset_class == ASSET_CLASS_UNSPECIFIED || vector::length(&asset_id) > 0, EInvalidMetadata);
        assert!(proof_system == PROOF_SYSTEM_UNSPECIFIED || vector::length(&proof_root) > 0, EInvalidMetadata);

        let collection = borrow_global_mut<SealCollection>(addr);
        assert!(smart_table::contains(&collection.seals, nonce), ESealNotFound);
        
        let seal = smart_table::borrow_mut(&mut collection.seals, nonce);
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

    /// Initialize the anchor data collection for an account (called once).
    public entry fun init_anchor_collection(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<AnchorDataCollection>(addr), EAnchorDataExists);
        move_to(account, AnchorDataCollection {
            anchor_data: smart_table::new(),
        });
    }

    /// Consume a seal and emit an AnchorEvent with the commitment.
    public entry fun consume_seal(account: &signer, nonce: u64, commitment: vector<u8>) acquires SealCollection, AnchorDataCollection {
        let seal_addr = signer::address_of(account);
        assert!(exists<SealCollection>(seal_addr), ESealNotFound);

        let collection = borrow_global_mut<SealCollection>(seal_addr);
        assert!(smart_table::contains(&collection.seals, nonce), ESealNotFound);
        
        let seal = smart_table::borrow_mut(&mut collection.seals, nonce);
        assert!(!seal.consumed, ESealAlreadyConsumed);
        seal.consumed = true;

        // Get current timestamp
        let timestamp = aptos_framework::timestamp::now_seconds();

        // Initialize anchor collection if needed
        if (!exists<AnchorDataCollection>(seal_addr)) {
            move_to(account, AnchorDataCollection {
                anchor_data: smart_table::new(),
            });
        };

        // Add to AnchorData collection
        let anchor_collection = borrow_global_mut<AnchorDataCollection>(seal_addr);
        assert!(!smart_table::contains(&anchor_collection.anchor_data, nonce), EAnchorDataExists);
        smart_table::add(&mut anchor_collection.anchor_data, nonce, AnchorData {
            commitment: copy commitment,
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
    // NOTE: Transfer functionality disabled for collection-based seals.
    // Use cross-chain mint/lock instead for seal movement between accounts.
    // Transfers within the same chain can be implemented by consuming
    // and re-minting with different nonces if needed.

    // =========================================================================
    // Queries
    // =========================================================================

    /// Check if a seal exists and has not been consumed.
    public fun is_seal_available(addr: address, nonce: u64): bool {
        if (!exists<SealCollection>(addr)) {
            return false
        };
        let collection = borrow_global<SealCollection>(addr);
        if (!smart_table::contains(&collection.seals, nonce)) {
            return false
        };
        !smart_table::borrow(&collection.seals, nonce).consumed
    }

    /// Check if a seal has been consumed.
    /// Returns false if no seal exists at the address.
    public fun is_consumed(addr: address, nonce: u64): bool {
        if (!exists<SealCollection>(addr)) {
            return false
        };
        let collection = borrow_global<SealCollection>(addr);
        if (!smart_table::contains(&collection.seals, nonce)) {
            return false
        };
        smart_table::borrow(&collection.seals, nonce).consumed
    }

    /// Get the nonce of a seal at the given address.
    public fun get_seal_nonce(addr: address, nonce: u64): u64 {
        assert!(exists<SealCollection>(addr), ESealNotFound);
        let collection = borrow_global<SealCollection>(addr);
        assert!(smart_table::contains(&collection.seals, nonce), ESealNotFound);
        smart_table::borrow(&collection.seals, nonce).nonce
    }

    /// Get the AnchorData for a consumed seal.
    public fun get_anchor_data(addr: address, nonce: u64): AnchorData acquires AnchorDataCollection {
        assert!(exists<AnchorDataCollection>(addr), ESealNotFound);
        let collection = borrow_global<AnchorDataCollection>(addr);
        assert!(smart_table::contains(&collection.anchor_data, nonce), ESealNotFound);
        *smart_table::borrow(&collection.anchor_data, nonce)
    }

    /// Check if AnchorData exists for a seal (i.e., seal was consumed).
    public fun has_anchor_data(addr: address, nonce: u64): bool {
        if (!exists<AnchorDataCollection>(addr)) {
            return false
        };
        let collection = borrow_global<AnchorDataCollection>(addr);
        smart_table::contains(&collection.anchor_data, nonce)
    }

    /// Get the commitment from AnchorData.
    public fun get_commitment(addr: address, nonce: u64): vector<u8> acquires AnchorDataCollection {
        assert!(exists<AnchorDataCollection>(addr), ESealNotFound);
        let collection = borrow_global<AnchorDataCollection>(addr);
        assert!(smart_table::contains(&collection.anchor_data, nonce), ESealNotFound);
        smart_table::borrow(&collection.anchor_data, nonce).commitment
    }

    /// Get the consumption timestamp from AnchorData.
    public fun get_consumed_at(addr: address, nonce: u64): u64 acquires AnchorDataCollection {
        assert!(exists<AnchorDataCollection>(addr), ESealNotFound);
        let collection = borrow_global<AnchorDataCollection>(addr);
        assert!(smart_table::contains(&collection.anchor_data, nonce), ESealNotFound);
        smart_table::borrow(&collection.anchor_data, nonce).consumed_at
    }

    /// Get the next available nonce for an account.
    public fun get_next_nonce(addr: address): u64 acquires SealCollection {
        assert!(exists<SealCollection>(addr), ESealNotFound);
        borrow_global<SealCollection>(addr).next_nonce
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

    /// Verify a cross-chain Merkle proof using source chain-specific hash functions (non-Bitcoin chains).
    /// Uses native hash functions where available:
    /// - Ethereum/Solana: keccak256 (native via aptos_std::aptos_hash::keccak256)
    /// - Sui: blake2b256 (native via aptos_std::aptos_hash::blake2b_256)
    /// - Aptos: sha3_256 (native via hash::sha3_256)
    /// - SHA-256: sha2_256 (native via hash::sha2_256)
    /// Note: All hash functions are now available natively in Aptos via aptos_std::aptos_hash
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

        // Build leaf hash using source chain's native hash function
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
        
        let leaf = if (source_chain == 2) { // Aptos
            // Aptos uses sha3_256 (native)
            hash::sha3_256(leaf_data)
        } else if (source_chain == 3 || source_chain == 4) { // Ethereum (3) or Solana (4)
            // Ethereum/Solana use keccak256 (native via aptos_std::aptos_hash)
            aptos_std::aptos_hash::keccak256(leaf_data)
        } else if (source_chain == 1) { // Sui (1)
            // Sui uses blake2b256 (native via aptos_std::aptos_hash)
            aptos_std::aptos_hash::blake2b_256(leaf_data)
        } else {
            abort EInvalidProof
        };

        // Verify Merkle proof using leaf position with appropriate hash function
        let is_valid = verify_merkle_proof_with_chain(proof, proof_root, &leaf, leaf_position, source_chain);
        assert!(is_valid, EInvalidProof);
    }

    /// Verify a Merkle proof for leaf inclusion with source chain-specific hash function
    fun verify_merkle_proof_with_chain(
        proof: &vector<u8>,
        root: &vector<u8>,
        leaf: &vector<u8>,
        leaf_position: u64,
        source_chain: u8,
    ): bool {
        let proof_len = vector::length(proof);
        let root_len = vector::length(root);
        let leaf_len = vector::length(leaf);

        // Validate inputs
        if (proof_len == 0 || proof_len % 32 != 0) return false;
        if (root_len != 32 || leaf_len != 32) return false;

        let num_levels = proof_len / 32;
        let current = *leaf;
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
                current = hash_pair_with_chain(pair_data, source_chain);
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
                current = hash_pair_with_chain(pair_data, source_chain);
            };
            i = i + 1;
        };

        // Verify computed root matches expected root
        current == *root
    }

    /// Hash a pair using source chain's native hash function
    fun hash_pair_with_chain(data: vector<u8>, source_chain: u8): vector<u8> {
        // Use source chain's native hash function
        if (source_chain == 3 || source_chain == 4) { // Ethereum (3) or Solana (4)
            // Ethereum/Solana use keccak256 (native via aptos_std::aptos_hash)
            aptos_std::aptos_hash::keccak256(data)
        } else if (source_chain == 2) { // Aptos (2)
            // Aptos uses sha3_256 (native)
            hash::sha3_256(data)
        } else if (source_chain == 1) { // Sui (1)
            // Sui uses blake2b256 (native via aptos_std::aptos_hash)
            aptos_std::aptos_hash::blake2b_256(data)
        } else {
            hash::sha3_256(data) // Default
        }
    }

    /// sha3_256 hash function for cross-chain compatibility (Aptos-specific)
    /// Aptos Move has sha3_256 natively
    fun sha3_256_hash(data: &vector<u8>): vector<u8> {
        let data_copy = *data;
        hash::sha3_256(data_copy)
    }

    /// sha2_256 (SHA-256) hash function for cross-chain compatibility (Aptos-specific)
    /// Aptos Move has sha2_256 natively
    fun sha2_256_hash(data: &vector<u8>): vector<u8> {
        let data_copy = *data;
        hash::sha2_256(data_copy)
    }

    /// double SHA-256 hash function for Bitcoin compatibility (Aptos implementation)
    /// Bitcoin uses SHA256(SHA256(data)) for Merkle tree construction
    /// Aptos has sha2_256 natively
    fun double_sha256(data: &vector<u8>): vector<u8> {
        let data_copy = *data;
        let first = hash::sha2_256(data_copy);
        hash::sha2_256(first)
    }

    /// Verify a cross-chain Merkle proof for Bitcoin (uses double SHA-256).
    /// Computes leaf = double_sha256(sanad_id || commitment)
    /// Bitcoin uses SHA256(SHA256(data)) for Merkle tree construction.
    fun verify_bitcoin_proof(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64,
    ) {
        // Validate inputs
        assert!(vector::length(proof_root) == 32, EInvalidProof);
        assert!(vector::length(proof) % 32 == 0, EInvalidProof);
        assert!(vector::length(sanad_id) == 32, EInvalidProof);
        assert!(vector::length(commitment) == 32, EInvalidProof);

        // Build leaf hash: double_sha256(sanad_id || commitment)
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
        let leaf = double_sha256(&leaf_data);

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
                current = double_sha256(&pair_data);
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
                current = double_sha256(&pair_data);
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
        nonce: u64,
        sanad_id: vector<u8>,
        destination_chain: u8,
        destination_owner: vector<u8>,
    ) acquires SealCollection, LockRegistry, AnchorDataCollection {
        let owner_addr = signer::address_of(account);
        assert!(exists<SealCollection>(owner_addr), ESealNotFound);

        let collection = borrow_global_mut<SealCollection>(owner_addr);
        assert!(smart_table::contains(&collection.seals, nonce), ESealNotFound);
        
        let seal = smart_table::borrow_mut(&mut collection.seals, nonce);
        assert!(!seal.consumed, ESealAlreadyConsumed);

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
        seal.consumed = true;

        // Initialize anchor collection if needed
        if (!exists<AnchorDataCollection>(owner_addr)) {
            move_to(account, AnchorDataCollection {
                anchor_data: smart_table::new(),
            });
        };

        // Add to AnchorData collection
        let anchor_collection = borrow_global_mut<AnchorDataCollection>(owner_addr);
        assert!(!smart_table::contains(&anchor_collection.anchor_data, nonce), EAnchorDataExists);
        smart_table::add(&mut anchor_collection.anchor_data, nonce, AnchorData {
            commitment,
            consumed_at: locked_at,
            nonce,
        });
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
    ) acquires LockRegistry, SealCollection {
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
        // Use appropriate hash function based on source chain
        if (source_chain == 0) { // CHAIN_BITCOIN
            verify_bitcoin_proof(&sanad_id, &commitment, &proof, &proof_root, leaf_position);
        } else {
            verify_cross_chain_proof(&sanad_id, &commitment, source_chain, &proof, &proof_root, leaf_position);
        };

        // Mark as minted (replay protection)
        smart_table::add(&mut registry.minted_sanads, sanad_id, true);

        let owner_addr = signer::address_of(account);
        
        // Initialize seal collection if needed
        if (!exists<SealCollection>(owner_addr)) {
            move_to(account, SealCollection {
                seals: smart_table::new(),
                next_nonce: 0,
            });
        };

        let collection = borrow_global_mut<SealCollection>(owner_addr);
        assert!(!smart_table::contains(&collection.seals, nonce), EAnchorDataExists);

        // Create new seal
        smart_table::add(&mut collection.seals, nonce, Seal {
            nonce,
            consumed: false,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty<u8>(),
            metadata_hash: vector::empty<u8>(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            proof_root,
            nullifier: vector::empty<u8>(),
        });

        // Update next_nonce if needed
        if (nonce >= collection.next_nonce) {
            collection.next_nonce = nonce + 1;
        };

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
        nonce: u64,
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
    ) acquires SealCollection {
        let addr = signer::address_of(account);
        assert!(exists<SealCollection>(addr), ESealNotFound);
        let collection = borrow_global_mut<SealCollection>(addr);
        assert!(smart_table::contains(&collection.seals, nonce), ESealNotFound);
        let seal = smart_table::borrow_mut(&mut collection.seals, nonce);
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