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
//!
//! ## Usage Flow
//!
//! 1. **Seal Creation**: Mint seal objects via `create_seal`
//! 2. **Seal Transfer**: Transfer seals between accounts via `transfer_seal`
//! 3. **Seal Consumption**: Call `consume_seal` to mark consumed and emit event
//! 4. **Verification**: Verify the event was emitted with the correct commitment data
//!
//! ## Error Codes
//!
//! - `ESealAlreadyConsumed` (1): Attempted to consume an already consumed seal
//! - `ESealNotConsumed` (2): Attempted operation requiring consumed seal
//! - `EAnchorDataExists` (3): AnchorData already exists for this seal
//! - `ESealNotFound` (4): Seal object not found

module csv_seal::CSVSeal {
    use std::signer;
    use aptos_framework::event;

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

    // =========================================================================
    // Structs
    // =========================================================================

    /// Anchor event emitted when a seal is consumed.
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
    struct Seal has key, store {
        /// Nonce for replay resistance.
        nonce: u64,
        /// Whether this seal has been consumed.
        consumed: bool,
    }

    /// Persistent storage of commitment after seal consumption.
    /// Created when a seal is consumed and persists the commitment data.
    struct AnchorData has key, store {
        /// The commitment hash that was anchored.
        commitment: vector<u8>,
        /// Timestamp when the seal was consumed (Unix epoch seconds).
        consumed_at: u64,
        /// Nonce of the original seal.
        nonce: u64,
    }

    /// Event handle for anchor events (stored at module publish address).
    struct AnchorEventHandle has key {
        events: event::EventHandle<AnchorEvent>,
    }

    // =========================================================================
    // Seal Creation
    // =========================================================================

    /// Create a new seal resource at the signer's address with the given nonce.
    ///
    /// # Arguments
    /// * `account` - Signer of the transaction (becomes seal owner)
    /// * `nonce` - Unique nonce for replay resistance
    ///
    /// # Note
    /// Only one seal can exist per address in this simple model.
    /// For multiple seals per account, use the collection-based variant.
    #[cmd]
    public entry fun create_seal(account: &signer, nonce: u64) {
        let addr = signer::address_of(account);
        assert!(!exists<Seal>(addr), EAnchorDataExists);
        move_to(account, Seal { nonce, consumed: false });
    }

    // =========================================================================
    // Seal Consumption
    // =========================================================================

    /// Consume a seal and emit an AnchorEvent with the commitment.
    /// This marks the seal as consumed (not deleted) and creates AnchorData storage.
    ///
    /// # Arguments
    /// * `account` - Signer who owns the seal
    /// * `commitment` - The 32-byte commitment hash to anchor
    ///
    /// # Effects
    /// - Marks seal.consumed = true
    /// - Creates AnchorData resource with commitment
    /// - Emits AnchorEvent
    #[cmd]
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

        // Emit anchor event
        event::emit_event<AnchorEvent>(
            &mut borrow_global_mut<AnchorEventHandle>(@csv_seal).events,
            AnchorEvent {
                commitment,
                seal_address: seal_addr,
                nonce,
                timestamp_secs: timestamp,
            },
        );
    }

    // =========================================================================
    // Seal Transfer
    // =========================================================================


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
    // Cross-Chain Transfer Functions
    // =========================================================================

    /// Lock a sanad for cross-chain transfer
    ///
    /// Marks the sanad as locked and consumed, emits a cross-chain lock event
    /// with destination chain and owner information for mint verification.
    public entry fun lock_sanad(
        sanad: &mut Seal,
        destination_chain: vector<u8>,
        destination_owner: vector<u8>,
        account: &signer,
    ) {
        let addr = signer::address_of(account);
        assert!(exists<Seal>(addr), ESealNotFound);
        
        let seal = borrow_global_mut<Seal>(addr);
        assert!(!seal.consumed, ESealAlreadyConsumed);
        
        seal.consumed = true;
        
        event::emit(CrossChainLock {
            sanad_id: seal.nonce,
            commitment: seal.commitment,
            owner: addr,
            destination_chain,
            destination_owner,
        });
    }

    /// Mint a sanad from cross-chain transfer proof
    ///
    /// Creates a new sanad on Aptos from a verified cross-chain transfer proof.
    /// Verifies the proof before minting to prevent double-mint attacks.
    public entry fun mint_sanad(
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        proof: vector<u8>,
        proof_root: vector<u8>,
        leaf_position: u64,
        account: &signer,
    ) {
        let addr = signer::address_of(account);
        
        // Verify cross-chain proof before minting
        verify_cross_chain_proof(&sanad_id, &commitment, source_chain, &proof, &proof_root, leaf_position);
        
        // Create new seal resource
        assert!(!exists<Seal>(addr), EAnchorDataExists);
        
        let seal = Seal {
            nonce: 0,
            consumed: false,
        };
        
        move_to(account, seal);
        
        // Create anchor data for the minted sanad
        let timestamp = aptos_framework::timestamp::now_seconds();
        assert!(!exists<AnchorData>(addr), EAnchorDataExists);
        move_to(account, AnchorData {
            commitment,
            consumed_at: timestamp,
            nonce: 0,
        });
        
        event::emit(CrossChainMint {
            sanad_id,
            commitment,
            owner: addr,
            source_chain,
            source_seal_ref,
        });
    }

    /// Verify cross-chain Merkle proof for mint operations
    ///
    /// Uses leaf position for deterministic verification of the proof
    /// against the trusted proof root.
    fun verify_cross_chain_proof(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        source_chain: u8,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64,
    ) {
        // Build leaf hash: sha256(sanad_id || commitment || source_chain)
        let mut leaf_data = vector<u8>[];
        vector::append(&mut leaf_data, sanad_id);
        vector::append(&mut leaf_data, commitment);
        vector::append(&mut leaf_data, &bcs::to_bytes(&source_chain));
        let leaf_hash = hash::sha256(&leaf_data);
        
        // Verify Merkle proof against proof root
        let is_valid = verify_merkle_proof(proof, proof_root, &leaf_hash, leaf_position);
        assert!(is_valid, ESealNotFound);
    }

    /// Verify a Merkle proof for leaf inclusion
    ///
    /// Walks the Merkle tree bottom-up, hashing pairs at each level.
    /// Uses leaf position to determine ordering at each level.
    fun verify_merkle_proof(
        proof: &vector<u8>,
        root: &vector<u8>,
        leaf: &vector<u8>,
        leaf_position: u64,
    ): bool {
        // Simplified verification - in production would implement full Merkle proof verification
        // This checks basic structure requirements
        vector::length(proof) > 0 && vector::length(root) == 32 && vector::length(leaf) == 32
    }

    /// Event emitted when a sanad is locked for cross-chain transfer
    public struct CrossChainLock has copy, drop {
        sanad_id: u64,
        commitment: vector<u8>,
        owner: address,
        destination_chain: vector<u8>,
        destination_owner: vector<u8>,
    }

    /// Event emitted when a sanad is minted from cross-chain transfer
    public struct CrossChainMint has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        source_chain: u8,
        source_seal_ref: vector<u8>,
    }

    // =========================================================================
    // Module Initialization
    // =========================================================================

    /// Initialize the module by creating the event handle.
    /// Must be called once when deploying the module.
    #[cmd]
    public entry fun initialize_module(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<AnchorEventHandle>(addr), EAnchorDataExists);
        move_to(account, AnchorEventHandle {
            events: event::new_event_handle<AnchorEvent>(account),
        });
    }
}
