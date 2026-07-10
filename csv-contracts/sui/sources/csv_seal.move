/// CSVSeal — Cross-Chain Sanad materialization on Sui (thin registry).
///
/// Authenticity model (RFC-0012 §9 / ABI_CONSTITUTION.md §9): destination mint is a
/// THIN REGISTRY. Cross-chain correctness is decided OFF-CHAIN by the CSV verifier; this
/// package does NOT re-adjudicate the proof. It records a mint only when the call carries at
/// least `threshold` distinct valid verifier signatures over the frozen §9.2 attestation
/// digest, and it enforces on-chain replay protection (`sanadId` / `nullifier` /
/// `lockEventId` uniqueness) via `Registry` tables.
///
/// The former Merkle-proof / proof-root gating model is REMOVED from the mint path (RFC-0012
/// §4): no proof root, state root, Merkle proof bytes, or leaf position gates `mint_sanad`.
///
/// Sui has the strongest native single-use model: the minted `Seal` is an owned object (the
/// object *is* the seal). Uniqueness that a single owned object cannot express — global
/// non-replay across independently submitted mints — is enforced by the shared `Registry`.
module csv_seal::csv_seal {
    use sui::address;
    use sui::clock::{Self, Clock};
    use sui::ecdsa_k1;
    use sui::event;
    use sui::hash;
    use sui::table::{Self, Table};
    use sui::transfer;
    use std::hash as std_hash;

    // ==================== Constants ====================

    /// Asset / proof-system defaults (metadata is NOT on the mint hot path — RFC-0012 §4).
    const ASSET_CLASS_UNSPECIFIED: u8 = 0;
    const PROOF_SYSTEM_UNSPECIFIED: u8 = 0;

    /// Canonical Sanad lifecycle state — matches Ethereum/Solana/Aptos.
    /// 0=Uncreated, 1=Created, 2=Active, 3=Locked, 4=Consumed, 5=Minted, 6=Transferred, 7=Refunded, 8=Burned, 9=Invalid
    const SANAD_STATE_CREATED: u8 = 1;
    const SANAD_STATE_LOCKED: u8 = 3;
    const SANAD_STATE_CONSUMED: u8 = 4;
    const SANAD_STATE_MINTED: u8 = 5;
    const SANAD_STATE_REFUNDED: u8 = 7;

    /// Refund timeout in milliseconds (24 hours).
    const REFUND_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

    /// `secp256k1_ecrecover` / `secp256k1_verify` hash selector: 0 = keccak256, 1 = sha256.
    /// The §9.2 digest is SHA-256, so the verifier signs `sha256(preimage)` and we recover with
    /// this flag (the native primitive hashes the raw preimage internally).
    const SHA256_FLAG: u8 = 1;

    /// Fixed width of the opaque 32-byte hash fields in the mint ABI / digest.
    const FIELD_LEN: u64 = 32;
    /// Compressed secp256k1 public key length (RFC-0012 §9.2 non-EVM verifier identity form).
    const PUBKEY_LEN: u64 = 33;
    /// Recoverable secp256k1 signature length (r || s || v).
    const SIGNATURE_LEN: u64 = 65;

    /// Domain tag for the §9.2 mint attestation digest (23 bytes, ASCII, no NUL).
    const MINT_ATTESTATION_DOMAIN: vector<u8> = b"csv.mint.attestation.v1";
    /// Chain-ABI identity for Sui (RFC-0012 §6): keccak256("csv.chain.sui").
    const CHAIN_SUI_TAG: vector<u8> = b"csv.chain.sui";

    /// BIP-340-style tag for the lock-event identity, matching the off-chain
    /// `csv_tagged_hash("csv.mint.lock-event.v1", ..)` (tag prefix `urn:lnp-bp:csv:`).
    const LOCK_EVENT_TAG: vector<u8> = b"urn:lnp-bp:csv:csv.mint.lock-event.v1";

    /// A Sui lock has no transaction output index: the lock is the whole transaction,
    /// identified by its digest. The runtime records `lock_output_index = 0` for every
    /// non-Bitcoin source, and the lock-event preimage is `tx_digest || u32_le(index)`,
    /// so the on-chain derivation appends four zero bytes.
    const LOCK_OUTPUT_INDEX_LE: vector<u8> = x"00000000";

    // ==================== Errors ====================

    const EALREADY_MINTED: u64 = 1;
    const ENULLIFIER_ALREADY_USED: u64 = 2;
    const ELOCK_EVENT_ALREADY_RECORDED: u64 = 3;
    const EINSUFFICIENT_SIGNATURES: u64 = 4;
    const EINVALID_VERIFIER_SIGNATURE: u64 = 5;
    const EMALFORMED_SIGNATURE: u64 = 6;
    const EATTESTATION_EXPIRED: u64 = 7;
    const EINVALID_THRESHOLD: u64 = 8;
    const EINVALID_MINT_REQUEST: u64 = 9;
    const EINVALID_PUBKEY: u64 = 10;
    const ENOT_CONFIGURED: u64 = 11;
    const EINVALID_FIELD_LENGTH: u64 = 12;
    const EVERIFIER_EXISTS: u64 = 13;
    const EVERIFIER_NOT_FOUND: u64 = 14;
    // lifecycle
    const ESEAL_ALREADY_CONSUMED: u64 = 20;
    const EALREADY_LOCKED: u64 = 21;
    const ETIMEOUT_NOT_EXPIRED: u64 = 22;
    const ENOT_AUTHORIZED: u64 = 23;
    const ESANAD_NOT_FOUND: u64 = 24;

    // ==================== Objects / State ====================

    /// Package-level authority capability. Holding it authorizes verifier-set rotation and
    /// threshold changes (RFC-0012 §9.3). Rotation is OFF the mint path: `mint_sanad` never
    /// consults an `AdminCap`, only the recorded verifier set and threshold.
    public struct AdminCap has key, store {
        id: object::UID,
    }

    /// Shared thin-registry state. Holds the authorized verifier set + threshold and the
    /// on-chain anti-replay domain (minted sanads / nullifiers / lock events).
    public struct Registry has key {
        id: object::UID,
        /// Authorized verifier identities: 33-byte compressed secp256k1 public keys.
        verifiers: vector<vector<u8>>,
        /// Signature threshold `M`: mint requires >= `M` distinct valid verifier signatures.
        threshold: u64,
        /// sanadId -> true. Primary duplicate-mint key.
        minted_sanads: Table<vector<u8>, bool>,
        /// nullifier -> true. Replay key.
        nullifiers: Table<vector<u8>, bool>,
        /// lockEventId -> true. Duplicate-source-lock key.
        used_lock_events: Table<vector<u8>, bool>,
        /// sanadId -> minimal mint record (auditability / settlement — RFC-0012 §3).
        mint_records: Table<vector<u8>, MintRecord>,
    }

    /// Minimal destination-mint record (RFC-0012 §3). Stores `keccak256(destinationOwner)`;
    /// the full bytes travel in the `SanadMinted` event.
    public struct MintRecord has store, drop {
        commitment: vector<u8>,
        source_chain: vector<u8>,
        destination_owner_hash: vector<u8>,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        minted_at: u64,
    }

    /// The materialized sanad: an owned object that IS the seal (Sui linear single-use).
    public struct Seal has key, store {
        id: object::UID,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        /// Canonical lifecycle state.
        state: u8,
        owner: address,
        /// Chain-ABI identity of the source chain (empty for a locally created seal).
        source_chain: vector<u8>,
        /// Source lock event id (empty unless minted from a cross-chain lock).
        lock_event_id: vector<u8>,
        /// Replay nullifier (empty unless consumed / minted).
        nullifier: vector<u8>,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
        created_at: u64,
        locked_at: u64,
        consumed_at: u64,
        minted_at: u64,
        refunded_at: u64,
    }

    // ==================== Events (canonical — ABI_CONSTITUTION §Canonical Event Names) ====================

    public struct SanadCreated has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        timestamp_ms: u64,
    }

    public struct SanadConsumed has copy, drop {
        sanad_id: vector<u8>,
        nullifier: vector<u8>,
        consumer: address,
        timestamp_ms: u64,
    }

    /// Emitted when a Sanad is locked for cross-chain transfer.
    public struct CrossChainLock has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        source_chain: vector<u8>,
        destination_chain: vector<u8>,
        lock_event_id: vector<u8>,
        owner: address,
        timestamp_ms: u64,
    }

    /// Emitted when a Sanad is materialized on this destination chain (RFC-0012 §3).
    /// Carries the FULL `destination_owner` bytes; the registry stores only its hash.
    public struct SanadMinted has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        source_chain: vector<u8>,
        destination_owner: vector<u8>,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        timestamp_ms: u64,
    }

    public struct SanadRefunded has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        claimant: address,
        reason: vector<u8>,
        timestamp_ms: u64,
    }

    public struct SanadTransferred has copy, drop {
        sanad_id: vector<u8>,
        from: address,
        to: address,
        timestamp_ms: u64,
    }

    public struct NullifierRegistered has copy, drop {
        nullifier: vector<u8>,
        sanad_id: vector<u8>,
        source_chain: vector<u8>,
        timestamp_ms: u64,
    }

    public struct CommitmentAnchored has copy, drop {
        commitment: vector<u8>,
        seal_id: object::ID,
        owner: address,
        timestamp_ms: u64,
    }

    public struct VerifierAdded has copy, drop { verifier: vector<u8> }
    public struct VerifierRemoved has copy, drop { verifier: vector<u8> }
    public struct ThresholdUpdated has copy, drop { threshold: u64 }

    // ==================== Initialization ====================

    /// Module initializer: create the shared `Registry` (empty verifier set, threshold 0 —
    /// mint is FAIL-CLOSED until an `AdminCap` holder configures it) and hand the `AdminCap`
    /// to the publisher.
    fun init(ctx: &mut tx_context::TxContext) {
        let registry = Registry {
            id: object::new(ctx),
            verifiers: vector::empty(),
            threshold: 0,
            minted_sanads: table::new(ctx),
            nullifiers: table::new(ctx),
            used_lock_events: table::new(ctx),
            mint_records: table::new(ctx),
        };
        transfer::share_object(registry);
        transfer::public_transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    // ==================== Verifier-set governance (AdminCap-gated, OFF the mint path) ====================

    /// Add an authorized verifier (33-byte compressed secp256k1 public key).
    public entry fun add_verifier(_admin: &AdminCap, registry: &mut Registry, pubkey: vector<u8>) {
        assert!(vector::length(&pubkey) == PUBKEY_LEN, EINVALID_PUBKEY);
        assert!(!contains_bytes(&registry.verifiers, &pubkey), EVERIFIER_EXISTS);
        vector::push_back(&mut registry.verifiers, pubkey);
        event::emit(VerifierAdded { verifier: pubkey });
    }

    /// Remove an authorized verifier. Aborts if the remaining set would be smaller than the
    /// current threshold — the admin must lower the threshold first, never brick the set.
    public entry fun remove_verifier(_admin: &AdminCap, registry: &mut Registry, pubkey: vector<u8>) {
        let (found, idx) = index_of_bytes(&registry.verifiers, &pubkey);
        assert!(found, EVERIFIER_NOT_FOUND);
        vector::swap_remove(&mut registry.verifiers, idx);
        assert!(registry.threshold <= vector::length(&registry.verifiers), EINVALID_THRESHOLD);
        event::emit(VerifierRemoved { verifier: pubkey });
    }

    /// Set the signature threshold `M`. Must be 1..=|verifiers| (a valid M-of-N).
    public entry fun set_threshold(_admin: &AdminCap, registry: &mut Registry, new_threshold: u64) {
        assert!(new_threshold >= 1, EINVALID_THRESHOLD);
        assert!(new_threshold <= vector::length(&registry.verifiers), EINVALID_THRESHOLD);
        registry.threshold = new_threshold;
        event::emit(ThresholdUpdated { threshold: new_threshold });
    }

    // ==================== Verifier-attested destination mint (RFC-0012 §3 / §9) ====================

    /// Materialize a Sanad on this destination chain.
    ///
    /// THIN REGISTRY. Cross-chain validity is decided off-chain; authenticity here is a set of
    /// verifier signatures over the frozen §9.2 attestation digest. There is NO proof root,
    /// state root, Merkle proof, or leaf index. Uniqueness of `sanad_id` / `nullifier` /
    /// `lock_event_id` is enforced on-chain via the `Registry` tables. On success the minted
    /// `Seal` is transferred to `destination_owner`.
    ///
    /// * `source_chain` — chain-ABI identity keccak256("csv.chain.<src>") of the lock chain.
    /// * `destination_owner` — Sui recipient; its 32-byte address is the chain-native
    ///   `destinationOwner` bytes. `keccak256(address_bytes)` binds the digest; the full bytes
    ///   are emitted in `SanadMinted`.
    /// * `attestation_expiry` — u64 unix seconds; 0 = no expiry. Bound over the digest (§9.2).
    /// * `verifier_signatures` — 65-byte (r||s||v) secp256k1 signatures over the §9.2 digest.
    public entry fun mint_sanad(
        registry: &mut Registry,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        source_chain: vector<u8>,
        destination_owner: address,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        attestation_expiry: u64,
        verifier_signatures: vector<vector<u8>>,
        clock: &Clock,
        ctx: &mut tx_context::TxContext,
    ) {
        // Field width + sanity: every real mint carries fixed-width, non-zero replay keys.
        assert_field_len(&sanad_id);
        assert_field_len(&commitment);
        assert_field_len(&source_chain);
        assert_field_len(&lock_event_id);
        assert_field_len(&nullifier);
        assert!(
            !is_zero(&sanad_id)
                && !is_zero(&commitment)
                && !is_zero(&source_chain)
                && !is_zero(&lock_event_id)
                && !is_zero(&nullifier),
            EINVALID_MINT_REQUEST,
        );

        // §9.2 expiry bound (attestation_expiry is unix seconds; Clock is unix ms).
        if (attestation_expiry != 0) {
            let now_secs = clock::timestamp_ms(clock) / 1000;
            assert!(now_secs <= attestation_expiry, EATTESTATION_EXPIRED);
        };

        // On-chain anti-replay domain (RFC-0012 §3): reject if any uniqueness key is taken.
        assert!(!table::contains(&registry.minted_sanads, sanad_id), EALREADY_MINTED);
        assert!(!table::contains(&registry.nullifiers, nullifier), ENULLIFIER_ALREADY_USED);
        assert!(!table::contains(&registry.used_lock_events, lock_event_id), ELOCK_EVENT_ALREADY_RECORDED);

        let destination_owner_bytes = address::to_bytes(destination_owner);
        let destination_owner_hash = hash::keccak256(&destination_owner_bytes);

        // §9 authentication: verify M-of-N verifier signatures over the frozen §9.2 preimage.
        let preimage = build_mint_preimage(
            registry,
            &sanad_id,
            &commitment,
            &source_chain,
            &destination_owner_hash,
            &lock_event_id,
            &nullifier,
            attestation_expiry,
        );
        require_verifier_threshold(registry, &preimage, &verifier_signatures);

        // Consume the replay keys and record the mint.
        let now_ms = clock::timestamp_ms(clock);
        table::add(&mut registry.minted_sanads, sanad_id, true);
        table::add(&mut registry.nullifiers, nullifier, true);
        table::add(&mut registry.used_lock_events, lock_event_id, true);
        table::add(&mut registry.mint_records, sanad_id, MintRecord {
            commitment,
            source_chain,
            destination_owner_hash,
            lock_event_id,
            nullifier,
            minted_at: now_ms,
        });

        event::emit(SanadMinted {
            sanad_id,
            commitment,
            source_chain,
            destination_owner: destination_owner_bytes,
            lock_event_id,
            nullifier,
            timestamp_ms: now_ms,
        });
        event::emit(NullifierRegistered {
            nullifier,
            sanad_id,
            source_chain,
            timestamp_ms: now_ms,
        });

        let seal = Seal {
            id: object::new(ctx),
            sanad_id,
            commitment,
            state: SANAD_STATE_MINTED,
            owner: destination_owner,
            source_chain,
            lock_event_id,
            nullifier,
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty(),
            metadata_hash: vector::empty(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            created_at: now_ms,
            locked_at: 0,
            consumed_at: 0,
            minted_at: now_ms,
            refunded_at: 0,
        };
        transfer::public_transfer(seal, destination_owner);
    }

    /// Require at least `threshold` DISTINCT valid verifier signatures over `preimage`.
    ///
    /// Every signature MUST recover (via secp256k1 ecrecover over `sha256(preimage)`) to a
    /// public key in the verifier set; an out-of-set recovery aborts. Distinctness is by
    /// recovered public key, so signature malleability cannot inflate the count. Fail-closed:
    /// an unconfigured registry (threshold 0) rejects every mint.
    fun require_verifier_threshold(
        registry: &Registry,
        preimage: &vector<u8>,
        sigs: &vector<vector<u8>>,
    ) {
        let m = registry.threshold;
        assert!(m > 0, ENOT_CONFIGURED);

        let n = vector::length(sigs);
        assert!(n >= m, EINSUFFICIENT_SIGNATURES);

        let mut seen = vector::empty<vector<u8>>();
        let mut i = 0;
        while (i < n) {
            let sig = vector::borrow(sigs, i);
            assert!(vector::length(sig) == SIGNATURE_LEN, EMALFORMED_SIGNATURE);

            // Aborts (native) on a cryptographically unrecoverable signature.
            let recovered = ecdsa_k1::secp256k1_ecrecover(sig, preimage, SHA256_FLAG);
            assert!(contains_bytes(&registry.verifiers, &recovered), EINVALID_VERIFIER_SIGNATURE);

            if (!contains_bytes(&seen, &recovered)) {
                vector::push_back(&mut seen, recovered);
            };
            i = i + 1;
        };

        assert!(vector::length(&seen) >= m, EINSUFFICIENT_SIGNATURES);
    }

    /// Build the frozen §9.2 mint-attestation preimage (287 bytes):
    ///   "csv.mint.attestation.v1" (23) || destinationChainId (32) || destinationContract (32)
    ///   || sanadId (32) || commitment (32) || sourceChain (32) || keccak256(destinationOwner) (32)
    ///   || lockEventId (32) || nullifier (32) || attestationExpiry (u64 big-endian, 8).
    ///
    /// `destinationChainId` = keccak256("csv.chain.sui"); `destinationContract` = this
    /// `Registry` object's 32-byte id (the mint-authority identity on Sui — RFC-0012 §9.2
    /// non-EVM canonical form). The verifier signs `sha256(preimage)`.
    fun build_mint_preimage(
        registry: &Registry,
        sanad_id: &vector<u8>,
        commitment: &vector<u8>,
        source_chain: &vector<u8>,
        destination_owner_hash: &vector<u8>,
        lock_event_id: &vector<u8>,
        nullifier: &vector<u8>,
        attestation_expiry: u64,
    ): vector<u8> {
        assert_field_len(destination_owner_hash);

        let chain_sui_tag = CHAIN_SUI_TAG;
        let mut pre = vector::empty<u8>();
        vector::append(&mut pre, MINT_ATTESTATION_DOMAIN);
        vector::append(&mut pre, hash::keccak256(&chain_sui_tag));
        vector::append(&mut pre, address::to_bytes(object::uid_to_address(&registry.id)));
        vector::append(&mut pre, *sanad_id);
        vector::append(&mut pre, *commitment);
        vector::append(&mut pre, *source_chain);
        vector::append(&mut pre, *destination_owner_hash);
        vector::append(&mut pre, *lock_event_id);
        vector::append(&mut pre, *nullifier);
        vector::append(&mut pre, u64_to_be_bytes(attestation_expiry));
        pre
    }

    /// Reproduce the frozen §9.2 mint-attestation preimage off-chain (operators / verifier).
    public fun mint_attestation_preimage(
        registry: &Registry,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        source_chain: vector<u8>,
        destination_owner_hash: vector<u8>,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        attestation_expiry: u64,
    ): vector<u8> {
        build_mint_preimage(
            registry,
            &sanad_id,
            &commitment,
            &source_chain,
            &destination_owner_hash,
            &lock_event_id,
            &nullifier,
            attestation_expiry,
        )
    }

    /// The §9.2 attestation digest = sha256(preimage). Exposed so operators and the off-chain
    /// verifier can reproduce the exact value they must sign.
    public fun mint_attestation_digest(
        registry: &Registry,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        source_chain: vector<u8>,
        destination_owner_hash: vector<u8>,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        attestation_expiry: u64,
    ): vector<u8> {
        std_hash::sha2_256(build_mint_preimage(
            registry,
            &sanad_id,
            &commitment,
            &source_chain,
            &destination_owner_hash,
            &lock_event_id,
            &nullifier,
            attestation_expiry,
        ))
    }

    // ==================== Source-side lifecycle (owned-object linear semantics) ====================

    /// Create a new (source-side) seal.
    public fun create_seal(
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        ctx: &mut tx_context::TxContext,
    ): Seal {
        let timestamp_ms = tx_context::epoch_timestamp_ms(ctx);
        let seal = Seal {
            id: object::new(ctx),
            sanad_id,
            commitment,
            state: SANAD_STATE_CREATED,
            owner,
            source_chain: vector::empty(),
            lock_event_id: vector::empty(),
            nullifier: vector::empty(),
            asset_class: ASSET_CLASS_UNSPECIFIED,
            asset_id: vector::empty(),
            metadata_hash: vector::empty(),
            proof_system: PROOF_SYSTEM_UNSPECIFIED,
            created_at: timestamp_ms,
            locked_at: 0,
            consumed_at: 0,
            minted_at: 0,
            refunded_at: 0,
        };
        event::emit(SanadCreated {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            owner,
            timestamp_ms,
        });
        seal
    }

    // ==================== Read-only views (SUI-SANAD-STATE-001) ====================
    //
    // Off-chain readers can decode a `Seal` object's BCS contents directly, but
    // these accessors give on-chain callers and typed clients a stable,
    // schema-independent way to read the canonical sanad state without assuming
    // the struct's field layout.

    /// Canonical lifecycle fields of a Sanad seal, in the order used by the
    /// off-chain `CanonicalSanadState`:
    /// `(state, owner, commitment, nullifier, created_at, locked_at,
    ///   consumed_at, minted_at, refunded_at)`.
    /// A zero timestamp means "not set"; an empty nullifier means "not registered".
    public fun sanad_state(
        seal: &Seal,
    ): (u8, address, vector<u8>, vector<u8>, u64, u64, u64, u64, u64) {
        (
            seal.state,
            seal.owner,
            seal.commitment,
            seal.nullifier,
            seal.created_at,
            seal.locked_at,
            seal.consumed_at,
            seal.minted_at,
            seal.refunded_at,
        )
    }

    /// Replay nullifier (empty unless consumed / minted).
    public fun nullifier(seal: &Seal): vector<u8> {
        seal.nullifier
    }

    /// Lock timestamp (0 if never locked).
    public fun locked_at(seal: &Seal): u64 {
        seal.locked_at
    }

    /// Mint timestamp (0 if never minted).
    public fun minted_at(seal: &Seal): u64 {
        seal.minted_at
    }

    /// Refund timestamp (0 if never refunded).
    public fun refunded_at(seal: &Seal): u64 {
        seal.refunded_at
    }

    /// Consume a seal, binding its replay nullifier.
    public fun consume_seal(
        seal: &mut Seal,
        nullifier: vector<u8>,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(seal.state != SANAD_STATE_CONSUMED, ESEAL_ALREADY_CONSUMED);
        let timestamp_ms = tx_context::epoch_timestamp_ms(ctx);
        seal.state = SANAD_STATE_CONSUMED;
        seal.consumed_at = timestamp_ms;
        seal.nullifier = nullifier;

        event::emit(SanadConsumed {
            sanad_id: seal.sanad_id,
            nullifier,
            consumer: tx_context::sender(ctx),
            timestamp_ms,
        });
    }

    /// Lock a Sanad for cross-chain transfer, emitting the canonical `CrossChainLock`.
    ///
    /// `lock_event_id` is NOT a caller argument: it is the identity of *this* lock
    /// transaction (`tagged_hash(tx_digest || u32_le(0))`), so no caller could supply it
    /// before the transaction exists. Deriving it here makes the emitted `CrossChainLock`
    /// carry exactly the `lockEventId` the destination registry will later record as the
    /// duplicate-source-lock key.
    ///
    /// `locked_at` comes from the shared `Clock`, the same time source as `mint_sanad`,
    /// because `refund_sanad` gates on it.
    public fun lock_sanad(
        seal: &mut Seal,
        source_chain: vector<u8>,
        destination_chain: vector<u8>,
        clock: &Clock,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(seal.state != SANAD_STATE_CONSUMED, ESEAL_ALREADY_CONSUMED);
        assert!(seal.state != SANAD_STATE_LOCKED, EALREADY_LOCKED);

        // A `&mut Seal` on an owned object can only be supplied by its owner, so the
        // sender IS the current owner. Re-anchoring the field here keeps `seal.owner`
        // (and therefore `refund_sanad`'s authorization check) correct even if the object
        // reached this holder through a raw `public_transfer` rather than `transfer_sanad`.
        seal.owner = tx_context::sender(ctx);

        let timestamp_ms = clock::timestamp_ms(clock);
        let lock_event_id = derive_lock_event_id(ctx);
        seal.state = SANAD_STATE_LOCKED;
        seal.locked_at = timestamp_ms;
        seal.source_chain = source_chain;
        seal.lock_event_id = lock_event_id;

        event::emit(CrossChainLock {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            source_chain,
            destination_chain,
            lock_event_id,
            owner: seal.owner,
            timestamp_ms,
        });
    }

    /// Refund a locked Sanad after the refund timeout elapses.
    ///
    /// Both `now` and `seal.locked_at` are `Clock` milliseconds, so the comparison against
    /// `REFUND_TIMEOUT_MS` measures real elapsed time.
    public fun refund_sanad(seal: &mut Seal, clock: &Clock, ctx: &mut tx_context::TxContext) {
        assert!(seal.state == SANAD_STATE_LOCKED, ESANAD_NOT_FOUND);
        let now = clock::timestamp_ms(clock);
        assert!(now >= seal.locked_at + REFUND_TIMEOUT_MS, ETIMEOUT_NOT_EXPIRED);
        assert!(seal.owner == tx_context::sender(ctx), ENOT_AUTHORIZED);

        seal.state = SANAD_STATE_REFUNDED;
        seal.refunded_at = now;

        event::emit(SanadRefunded {
            sanad_id: seal.sanad_id,
            commitment: seal.commitment,
            claimant: tx_context::sender(ctx),
            reason: b"timeout",
            timestamp_ms: now,
        });
    }

    /// Transfer Sanad ownership (same chain).
    ///
    /// `seal.owner` moves with the object: leaving it behind would make `refund_sanad`
    /// authorize the previous owner and make `CrossChainLock.owner` name the wrong party.
    public fun transfer_sanad(seal: Seal, to: address, ctx: &mut tx_context::TxContext) {
        assert!(seal.state != SANAD_STATE_CONSUMED, ESEAL_ALREADY_CONSUMED);
        assert!(seal.state != SANAD_STATE_LOCKED, EALREADY_LOCKED);
        let mut seal = seal;
        let from = seal.owner;
        seal.owner = to;
        event::emit(SanadTransferred {
            sanad_id: seal.sanad_id,
            from,
            to,
            timestamp_ms: tx_context::epoch_timestamp_ms(ctx),
        });
        transfer::public_transfer(seal, to);
    }

    /// Anchor a commitment on-chain (auditability).
    public fun anchor_commitment(
        commitment: vector<u8>,
        seal: &Seal,
        ctx: &mut tx_context::TxContext,
    ) {
        event::emit(CommitmentAnchored {
            commitment,
            seal_id: object::uid_to_inner(&seal.id),
            owner: seal.owner,
            timestamp_ms: tx_context::epoch_timestamp_ms(ctx),
        });
    }

    /// Record archival metadata for a Sanad (NOT on the mint hot path — RFC-0012 §4).
    public fun record_sanad_metadata(
        seal: &mut Seal,
        asset_class: u8,
        asset_id: vector<u8>,
        metadata_hash: vector<u8>,
        proof_system: u8,
    ) {
        seal.asset_class = asset_class;
        seal.asset_id = asset_id;
        seal.metadata_hash = metadata_hash;
        seal.proof_system = proof_system;
    }

    // ==================== Lock-event identity ====================

    /// The lock-event identity for an arbitrary source transaction digest.
    ///
    /// `tagged_hash(tag, data) = sha256(sha256(tag) || sha256(tag) || data)` over
    /// `data = tx_digest || u32_le(output_index)`, reproducing the off-chain
    /// `csv_tagged_hash("csv.mint.lock-event.v1", ..)` byte for byte. Exposed so operators
    /// and the verifier can recompute the `lockEventId` an emitted `CrossChainLock` carries.
    public fun lock_event_id_for_digest(tx_digest: vector<u8>): vector<u8> {
        let tag_hash = std_hash::sha2_256(LOCK_EVENT_TAG);
        let mut pre = vector::empty<u8>();
        vector::append(&mut pre, tag_hash);
        vector::append(&mut pre, tag_hash);
        vector::append(&mut pre, tx_digest);
        vector::append(&mut pre, LOCK_OUTPUT_INDEX_LE);
        std_hash::sha2_256(pre)
    }

    /// The lock-event identity of the transaction currently executing.
    fun derive_lock_event_id(ctx: &tx_context::TxContext): vector<u8> {
        lock_event_id_for_digest(*tx_context::digest(ctx))
    }

    // ==================== Internal helpers ====================

    fun assert_field_len(v: &vector<u8>) {
        assert!(vector::length(v) == FIELD_LEN, EINVALID_FIELD_LENGTH);
    }

    fun is_zero(v: &vector<u8>): bool {
        let mut i = 0;
        let len = vector::length(v);
        while (i < len) {
            if (*vector::borrow(v, i) != 0) return false;
            i = i + 1;
        };
        true
    }

    fun contains_bytes(haystack: &vector<vector<u8>>, needle: &vector<u8>): bool {
        let (found, _) = index_of_bytes(haystack, needle);
        found
    }

    fun index_of_bytes(haystack: &vector<vector<u8>>, needle: &vector<u8>): (bool, u64) {
        let mut i = 0;
        let len = vector::length(haystack);
        while (i < len) {
            if (vector::borrow(haystack, i) == needle) return (true, i);
            i = i + 1;
        };
        (false, 0)
    }

    /// Big-endian 8-byte encoding of a u64 (matches EVM `abi.encodePacked(uint64)`).
    fun u64_to_be_bytes(v: u64): vector<u8> {
        let mut out = vector::empty<u8>();
        let mut i = 0u64;
        while (i < 8) {
            let shift = ((7 - i) * 8) as u8;
            vector::push_back(&mut out, ((v >> shift) & 0xff) as u8);
            i = i + 1;
        };
        out
    }

    // ==================== Views ====================

    public fun threshold(registry: &Registry): u64 { registry.threshold }

    public fun verifier_count(registry: &Registry): u64 { vector::length(&registry.verifiers) }

    public fun is_verifier(registry: &Registry, pubkey: &vector<u8>): bool {
        contains_bytes(&registry.verifiers, pubkey)
    }

    public fun is_sanad_minted(registry: &Registry, sanad_id: vector<u8>): bool {
        table::contains(&registry.minted_sanads, sanad_id)
    }

    public fun is_nullifier_used(registry: &Registry, nullifier: vector<u8>): bool {
        table::contains(&registry.nullifiers, nullifier)
    }

    public fun is_lock_event_recorded(registry: &Registry, lock_event_id: vector<u8>): bool {
        table::contains(&registry.used_lock_events, lock_event_id)
    }

    public fun state(seal: &Seal): u8 { seal.state }

    public fun sanad_id(seal: &Seal): vector<u8> { seal.sanad_id }

    public fun commitment(seal: &Seal): vector<u8> { seal.commitment }

    public fun owner(seal: &Seal): address { seal.owner }

    /// The `lockEventId` written by `lock_sanad` (empty until locked).
    public fun seal_lock_event_id(seal: &Seal): vector<u8> { seal.lock_event_id }

    /// The source chain identity written by `lock_sanad` (empty until locked).
    public fun seal_source_chain(seal: &Seal): vector<u8> { seal.source_chain }

    public fun created_at(seal: &Seal): u64 { seal.created_at }

    public fun consumed_at(seal: &Seal): u64 { seal.consumed_at }

    public fun id(seal: &Seal): object::ID { object::uid_to_inner(&seal.id) }

    public fun is_seal_available(seal: &Seal): bool { seal.state != SANAD_STATE_CONSUMED }

    public fun is_seal_consumed(seal: &Seal): bool { seal.state == SANAD_STATE_CONSUMED }

    // ==================== Test-only ====================

    #[test_only]
    public fun init_for_testing(ctx: &mut tx_context::TxContext) {
        init(ctx);
    }
}
