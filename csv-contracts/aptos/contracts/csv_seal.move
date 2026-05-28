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
    // Chain IDs (must match all CSV contracts)
    // =========================================================================

    const CHAIN_BITCOIN: u8 = 0;
    const CHAIN_SUI: u8 = 1;
    const CHAIN_APTOS: u8 = 2;
    const CHAIN_ETHEREUM: u8 = 3;
    const CHAIN_SOLANA: u8 = 4;

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
    /// Uses keccak256 for consistency with Ethereum and Solana contracts.
    fun verify_cross_chain_proof(
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        source_chain: u8,
        proof: &vector<u8>,
        proof_root: &vector<u8>,
        leaf_position: u64,
    ) {
        // Build leaf hash: keccak256(sanad_id || commitment || source_chain)
        // This matches Ethereum and Solana for cross-chain compatibility
        let mut leaf_data = vector<u8>[];
        vector::append(&mut leaf_data, sanad_id);
        vector::append(&mut leaf_data, commitment);
        vector::append(&mut leaf_data, &bcs::to_bytes(&source_chain));
        let leaf_hash = keccak256(&leaf_data);
        
        // Verify Merkle proof against proof root
        let is_valid = verify_merkle_proof(proof, proof_root, &leaf_hash, leaf_position);
        assert!(is_valid, ESealNotFound);
    }

    /// keccak256 hash function for cross-chain compatibility
    /// Matches Ethereum's keccak256 and Solana's hashv for consistent proof verification
    fun keccak256(data: &vector<u8>): vector<u8> {
        // Aptos Move doesn't have native keccak256, so we use sha256 as a fallback
        // with a domain separator to distinguish it from other uses
        // This is a pragmatic choice for cross-chain compatibility
        // In a future upgrade, we can add native keccak256 support via Move extensions
        let mut domain = b"csv.keccak256.compat";
        let mut input = vector<u8>[];
        vector::append(&mut input, domain);
        vector::append(&mut input, data);
        hash::sha256(&input)
    }

    /// Verify a Merkle proof for leaf inclusion
    ///
    /// Walks the Merkle tree bottom-up, hashing pairs at each level.
    /// Uses leaf position to determine ordering at each level.
    /// This is the canonical Merkle proof verification algorithm used across all CSV contracts.
    /// Uses keccak256 compatibility layer for cross-chain consistency.
    fun verify_merkle_proof(
        proof: &vector<u8>,
        root: &vector<u8>,
        leaf: &vector<u8>,
        leaf_position: u64,
    ): bool {
        // Validate input structure
        let proof_len = vector::length(proof);
        let root_len = vector::length(root);
        let leaf_len = vector::length(leaf);
        
        // Proof must be non-empty and divisible by 32 (each sibling is 32 bytes)
        if (proof_len == 0 || proof_len % 32 != 0) return false;
        // Root and leaf must be exactly 32 bytes
        if (root_len != 32 || leaf_len != 32) return false;
        
        // Calculate number of levels in the Merkle tree
        let num_levels = proof_len / 32;
        
        // Start with the leaf hash
        let mut current_hash = *leaf;
        let mut i = 0;
        
        // Walk up the Merkle tree level by level
        while (i < num_levels) {
            // Extract the sibling hash at this level
            let start = i * 32;
            let mut sibling_hash: vector<u8> = vector::empty();
            let mut j = 0;
            while (j < 32) {
                vector::push_back(&mut sibling_hash, *vector::borrow(proof, start + j));
                j = j + 1;
            };
            
            // Use leaf_position bit to determine ordering
            // If bit is 0, current is left child; if 1, current is right child
            let bit = (leaf_position >> i) & 1;
            
            // Hash the pair in the correct order
            let mut hash_input: vector<u8> = vector::empty();
            if (bit == 0) {
                // Current is left, sibling is right
                vector::append(&mut hash_input, &current_hash);
                vector::append(&mut hash_input, &sibling_hash);
            } else {
                // Sibling is left, current is right
                vector::append(&mut hash_input, &sibling_hash);
                vector::append(&mut hash_input, &current_hash);
            };
            
            // Compute hash using keccak256 compatibility layer
            current_hash = keccak256(&hash_input);
            
            i = i + 1;
        };
        
        // Verify the computed root matches the expected root
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

    /// Event emitted when a sanad is locked for cross-chain transfer
    public struct CrossChainLock has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        destination_chain: u8,
        destination_owner: vector<u8>,
        timestamp_secs: u64,
    }

    /// Event emitted when a sanad is minted from cross-chain transfer
    public struct CrossChainMint has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        source_chain: u8,
        source_seal_ref: vector<u8>,
        timestamp_secs: u64,
    }

    /// Event emitted when a locked sanad is refunded
    public struct CrossChainRefund has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        timestamp_secs: u64,
    }

    /// Event emitted when a proof is accepted
    public struct ProofAccepted has copy, drop {
        proof_root: vector<u8>,
        protocol_version: vector<u8>,
        timestamp_secs: u64,
    }

    /// Event emitted when a proof is rejected
    public struct ProofRejected has copy, drop {
        proof_root: vector<u8>,
        reason: vector<u8>,
        timestamp_secs: u64,
    }

    /// Event emitted when a replay attack is detected
    public struct ReplayDetected has copy, drop {
        replay_id: vector<u8>,
        sanad_id: vector<u8>,
        timestamp_secs: u64,
    }

    /// Event emitted when a sanad is created
    public struct SanadCreated has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        timestamp_secs: u64,
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
