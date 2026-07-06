//! CSV Seal — Cross-Chain Sanad Transfer on Solana (RFC-0012 thin registry)
//!
//! This Anchor program implements the uniform thin-registry model:
//! - `create_seal()`  — Create a Sanad anchored to a Solana PDA
//! - `consume_seal()` — Consume a Sanad (single-use enforcement)
//! - `lock_sanad()`   — Lock a Sanad for cross-chain transfer (records a LockAccount)
//! - `mint_sanad()`   — Materialize a Sanad from a **verifier-signed §9.2 attestation**
//! - `settle_lock()`  — Release a source lock on a **verifier-signed §10 receipt**
//! - `refund_sanad()` — Recover a lock after timeout (mutually exclusive with settle)
//!
//! Authenticity model (RFC-0012 §9 / ABI_CONSTITUTION §9): destination mint is a
//! THIN REGISTRY. Cross-chain correctness is decided OFF-CHAIN by the CSV verifier;
//! this program does not re-adjudicate the proof. It records a mint only when the
//! instruction carries at least `threshold` DISTINCT valid verifier signatures over
//! the frozen §9.2 attestation digest, and it enforces on-chain replay protection
//! via the uniqueness of the minted-sanad, nullifier, and lock-event PDAs.
//!
//! The former proof-root / Merkle-leaf mint model (`proof_root`, `ProofLeafV1`,
//! `verify_*_proof`) is REMOVED. No installed root, state root, Merkle proof, or
//! leaf index gates the mint hot path.
//!
//! Solana has the weakest native single-use guarantee (accounts are closable and
//! reopenable), so the nullifier registry carries more of the burden. The three
//! replay tombstones (`MintRecord`, `NullifierRecord`, `LockEventRecord`) and the
//! `SettlementRecord` are created with `init` and are NEVER closed by any
//! instruction — their permanent existence is what defeats close+reopen replay.

use anchor_lang::prelude::*;
use solana_program::secp256k1_recover::secp256k1_recover;

pub mod constants;
pub mod errors;
pub mod events;
pub mod instructions;
pub mod state;

#[cfg(test)]
mod tests;

pub use constants::*;
pub use errors::*;
pub use events::*;
#[allow(unused_imports)]
pub use instructions::*;
pub use state::*;

declare_id!("9ekKQYpaLkTrycYmRNRDHohYZwXycHAyfLNirUDRnRVh");

// ==================== Attestation / signature primitives (RFC-0012 §9/§10) ====================

/// Compute `keccak256("csv.chain.solana")` — the bytes32 `destinationChainId` bound
/// into the §9.2 mint attestation digest (RFC-0012 §6).
pub fn solana_chain_id() -> [u8; 32] {
    solana_program::keccak::hashv(&[CHAIN_NAME_SOLANA]).to_bytes()
}

/// Compute the frozen §9.2 mint attestation digest (SHA-256 over the 287-byte preimage).
///
/// `destinationChainId` = `keccak256("csv.chain.solana")`; `destinationContract` =
/// this program's id (its native 32-byte identity). These bind the attestation to
/// this chain and this deployment, closing the cross-chain / redeploy replay gap.
pub fn mint_attestation_digest(
    sanad_id: &[u8; 32],
    commitment: &[u8; 32],
    source_chain: &[u8; 32],
    destination_owner_hash: &[u8; 32],
    lock_event_id: &[u8; 32],
    nullifier: &[u8; 32],
    attestation_expiry: u64,
) -> [u8; 32] {
    let destination_chain_id = solana_chain_id();
    let destination_contract = crate::ID.to_bytes();

    // 23 + 8*32 + 8 = 287 bytes.
    let mut preimage = Vec::with_capacity(287);
    preimage.extend_from_slice(MINT_ATTESTATION_DOMAIN); // 23
    preimage.extend_from_slice(&destination_chain_id); // 32
    preimage.extend_from_slice(&destination_contract); // 32
    preimage.extend_from_slice(sanad_id); // 32
    preimage.extend_from_slice(commitment); // 32
    preimage.extend_from_slice(source_chain); // 32
    preimage.extend_from_slice(destination_owner_hash); // 32
    preimage.extend_from_slice(lock_event_id); // 32
    preimage.extend_from_slice(nullifier); // 32
    preimage.extend_from_slice(&attestation_expiry.to_be_bytes()); // 8

    solana_program::hash::hash(&preimage).to_bytes()
}

/// Compute the frozen §10 settlement-receipt digest (SHA-256 over the 257-byte preimage).
///
/// `sourceChainId` = `keccak256("csv.chain.solana")` (this escrow lives on Solana);
/// `sourceEscrowContract` = this program's id. `operatorPayoutAddress` uses the native
/// 32-byte account value directly (ABI §10 non-EVM canonical form).
pub fn settlement_receipt_digest(
    sanad_id: &[u8; 32],
    lock_event_id: &[u8; 32],
    destination_chain_id: &[u8; 32],
    destination_mint_tx_ref: &[u8; 32],
    operator_payout: &[u8; 32],
    receipt_expiry: u64,
) -> [u8; 32] {
    let source_chain_id = solana_chain_id();
    let source_escrow_contract = crate::ID.to_bytes();

    // 25 + 7*32 + 8 = 257 bytes.
    let mut preimage = Vec::with_capacity(257);
    preimage.extend_from_slice(SETTLEMENT_RECEIPT_DOMAIN); // 25
    preimage.extend_from_slice(&source_chain_id); // 32
    preimage.extend_from_slice(&source_escrow_contract); // 32
    preimage.extend_from_slice(sanad_id); // 32
    preimage.extend_from_slice(lock_event_id); // 32
    preimage.extend_from_slice(destination_chain_id); // 32
    preimage.extend_from_slice(destination_mint_tx_ref); // 32
    preimage.extend_from_slice(operator_payout); // 32
    preimage.extend_from_slice(&receipt_expiry.to_be_bytes()); // 8

    solana_program::hash::hash(&preimage).to_bytes()
}

/// Whether `s` (big-endian) exceeds n/2 (secp256k1 low-s malleability guard).
fn is_high_s(s: &[u8]) -> bool {
    for i in 0..32 {
        if s[i] > SECP256K1_HALF_ORDER_BE[i] {
            return true;
        }
        if s[i] < SECP256K1_HALF_ORDER_BE[i] {
            return false;
        }
    }
    false // equal to n/2 is permitted
}

/// Recover the compressed 33-byte secp256k1 public key that signed `digest`.
///
/// `sig` MUST be the 65-byte `r || s || v` encoding. `v` is accepted as a recovery
/// id in `{0,1}` or the EVM form `{27,28}`. High-s encodings are rejected so a single
/// signature cannot be re-encoded into a second valid one.
fn recover_compressed_verifier(digest: &[u8; 32], sig: &[u8]) -> Result<[u8; 33]> {
    require!(sig.len() == 65, CsvError::MalformedSignature);

    let s = &sig[32..64];
    require!(!is_high_s(s), CsvError::MalformedSignature);

    let v = sig[64];
    let recovery_id: u8 = if v >= 27 { v - 27 } else { v };
    require!(recovery_id <= 1, CsvError::MalformedSignature);

    let recovered = secp256k1_recover(digest, recovery_id, &sig[0..64])
        .map_err(|_| error!(CsvError::InvalidVerifierSignature))?;
    let uncompressed = recovered.to_bytes(); // [u8; 64] = X || Y

    let mut compressed = [0u8; 33];
    compressed[0] = 0x02 | (uncompressed[63] & 0x01);
    compressed[1..33].copy_from_slice(&uncompressed[0..32]);
    Ok(compressed)
}

/// Require at least `threshold` DISTINCT valid verifier signatures over `digest`.
///
/// Every signature MUST recover to a verifier in the set (an unauthorized signer
/// reverts); duplicate signatures from the same verifier are counted once. This is
/// the sole mint/settlement authorization primitive — there is no `msg.sender`
/// allowlist and no proof root.
fn require_verifier_threshold(
    registry: &VerifierRegistry,
    digest: &[u8; 32],
    sigs: &[Vec<u8>],
) -> Result<()> {
    let m = registry.threshold as usize;
    require!(sigs.len() >= m, CsvError::InsufficientSignatures);

    let mut seen: Vec<[u8; 33]> = Vec::with_capacity(sigs.len());
    for sig in sigs {
        let recovered = recover_compressed_verifier(digest, sig)?;
        require!(
            registry.verifiers.iter().any(|v| v == &recovered),
            CsvError::InvalidVerifierSignature
        );
        if !seen.iter().any(|v| v == &recovered) {
            seen.push(recovered);
        }
    }

    require!(seen.len() >= m, CsvError::InsufficientSignatures);
    Ok(())
}

#[program]
pub mod csv_seal {
    use super::*;

    const ASSET_CLASS_UNSPECIFIED: u8 = 0;
    const ASSET_CLASS_PROOF_SANAD: u8 = 3;
    const PROOF_SYSTEM_UNSPECIFIED: u8 = 0;

    /// Initialize the LockRegistry (called once during deployment)
    pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.authority = ctx.accounts.authority.key();
        registry.refund_timeout = REFUND_TIMEOUT;
        registry.lock_count = 0;
        registry.bump = ctx.bumps.registry;

        emit!(RegistryInitialized {
            authority: registry.authority,
            refund_timeout: registry.refund_timeout,
        });

        Ok(())
    }

    // ==================== Verifier set governance (RFC-0012 §9.3 — OFF the mint path) ====================

    /// Initialize the verifier registry with the authorized set and threshold `M`.
    ///
    /// Verifier identities are the compressed 33-byte secp256k1 public keys (the
    /// non-EVM canonical form). `M = 1` is permitted; because signatures are carried
    /// as a vector at mint time, growing to M-of-N needs no ABI change.
    pub fn initialize_verifier_registry(
        ctx: Context<InitializeVerifierRegistry>,
        verifiers: Vec<[u8; 33]>,
        threshold: u8,
    ) -> Result<()> {
        require!(!verifiers.is_empty(), CsvError::InvalidThreshold);
        require!(verifiers.len() <= MAX_VERIFIERS, CsvError::VerifierSetFull);
        require!(
            threshold >= 1 && (threshold as usize) <= verifiers.len(),
            CsvError::InvalidThreshold
        );

        // Every identity must be a well-formed compressed key, and the set distinct.
        for (i, v) in verifiers.iter().enumerate() {
            require!(v[0] == 0x02 || v[0] == 0x03, CsvError::MalformedVerifierKey);
            require!(
                !verifiers[..i].iter().any(|other| other == v),
                CsvError::VerifierAlreadyExists
            );
        }

        let registry = &mut ctx.accounts.registry;
        registry.authority = ctx.accounts.authority.key();
        registry.threshold = threshold;
        registry.verifiers = verifiers;
        registry.bump = ctx.bumps.registry;

        emit!(VerifierRegistryInitialized {
            authority: registry.authority,
            threshold: registry.threshold,
            verifier_count: registry.verifiers.len() as u8,
        });

        Ok(())
    }

    /// Add a verifier to the set (authority-gated governance).
    pub fn add_verifier(ctx: Context<UpdateVerifierRegistry>, verifier: [u8; 33]) -> Result<()> {
        require!(
            verifier[0] == 0x02 || verifier[0] == 0x03,
            CsvError::MalformedVerifierKey
        );

        let registry = &mut ctx.accounts.registry;
        require!(registry.verifiers.len() < MAX_VERIFIERS, CsvError::VerifierSetFull);
        require!(
            !registry.verifiers.iter().any(|v| v == &verifier),
            CsvError::VerifierAlreadyExists
        );

        registry.verifiers.push(verifier);

        emit!(VerifierAdded { verifier });
        Ok(())
    }

    /// Remove a verifier from the set (authority-gated governance).
    /// Rejected if it would drop the set below the current threshold.
    pub fn remove_verifier(ctx: Context<UpdateVerifierRegistry>, verifier: [u8; 33]) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        let pos = registry
            .verifiers
            .iter()
            .position(|v| v == &verifier)
            .ok_or_else(|| error!(CsvError::VerifierNotFound))?;

        require!(
            registry.verifiers.len() - 1 >= registry.threshold as usize,
            CsvError::InvalidThreshold
        );

        registry.verifiers.remove(pos);

        emit!(VerifierRemoved { verifier });
        Ok(())
    }

    /// Update the signature threshold `M` (authority-gated governance).
    pub fn set_threshold(ctx: Context<UpdateVerifierRegistry>, threshold: u8) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        require!(
            threshold >= 1 && (threshold as usize) <= registry.verifiers.len(),
            CsvError::InvalidThreshold
        );

        registry.threshold = threshold;

        emit!(ThresholdUpdated { threshold });
        Ok(())
    }

    /// Transfer the verifier-registry governance authority (authority-gated).
    pub fn transfer_verifier_authority(
        ctx: Context<UpdateVerifierRegistry>,
        new_authority: Pubkey,
    ) -> Result<()> {
        require!(new_authority != Pubkey::default(), CsvError::NotAuthorized);
        ctx.accounts.registry.authority = new_authority;
        Ok(())
    }

    /// Create a new Sanad on Solana
    pub fn create_seal(
        ctx: Context<CreateSeal>,
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        state_root: [u8; 32],
    ) -> Result<()> {
        let sanad = &mut ctx.accounts.sanad_account;
        let owner = ctx.accounts.owner.key();
        let now = Clock::get()?.unix_timestamp;

        sanad.owner = owner;
        sanad.sanad_id = sanad_id;
        sanad.commitment = commitment;
        sanad.state_root = state_root;
        sanad.nullifier = [0u8; 32];
        sanad.asset_class = ASSET_CLASS_UNSPECIFIED;
        sanad.asset_id = [0u8; 32];
        sanad.metadata_hash = [0u8; 32];
        sanad.proof_system = PROOF_SYSTEM_UNSPECIFIED;
        sanad.state = SanadState::Created as u8;
        sanad.created_at = now;
        sanad.locked_at = 0;
        sanad.consumed_at = 0;
        sanad.minted_at = 0;
        sanad.refunded_at = 0;
        sanad.bump = ctx.bumps.sanad_account;

        emit!(SanadCreated {
            sanad_id,
            commitment,
            owner,
            account: sanad.key(),
            asset_class: sanad.asset_class,
            asset_id: sanad.asset_id,
            metadata_hash: sanad.metadata_hash,
            proof_system: sanad.proof_system,
        });

        Ok(())
    }

    /// Consume a Sanad (single-use enforcement)
    pub fn consume_seal(ctx: Context<ConsumeSeal>) -> Result<()> {
        let sanad = &mut ctx.accounts.sanad_account;
        let consumer = ctx.accounts.consumer.key();
        let now = Clock::get()?.unix_timestamp;

        require!(sanad.state != SanadState::Consumed as u8, CsvError::AlreadyConsumed);

        sanad.state = SanadState::Consumed as u8;
        sanad.consumed_at = now;

        emit!(SanadConsumed {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            consumer,
            account: sanad.key(),
        });

        Ok(())
    }

    /// Lock a Sanad for cross-chain transfer.
    /// Consumes the Sanad and creates a LockAccount PDA for refund/settlement support.
    pub fn lock_sanad(
        ctx: Context<LockSanad>,
        destination_chain: u8,
        destination_owner: [u8; 32],
    ) -> Result<()> {
        let sanad = &mut ctx.accounts.sanad_account;
        let registry = &mut ctx.accounts.registry;
        let lock_account = &mut ctx.accounts.lock_account;
        let owner = ctx.accounts.owner.key();
        let now = Clock::get()?.unix_timestamp;

        require!(sanad.state != SanadState::Consumed as u8, CsvError::AlreadyConsumed);
        require!(sanad.state != SanadState::Locked as u8, CsvError::AlreadyLocked);

        lock_account.lock = LockRecord {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner,
            destination_chain,
            destination_owner,
            asset_class: sanad.asset_class,
            asset_id: sanad.asset_id,
            metadata_hash: sanad.metadata_hash,
            proof_system: sanad.proof_system,
            locked_at: now,
            refunded: false,
            settled: false,
        };
        lock_account.bump = ctx.bumps.lock_account;

        registry.lock_count += 1;

        sanad.state = SanadState::Locked as u8;
        sanad.locked_at = now;

        emit!(SanadLocked {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner,
            destination_chain,
            destination_owner,
            locked_at: now,
        });

        emit!(SanadMetadataRecorded {
            sanad_id: sanad.sanad_id,
            asset_class: sanad.asset_class,
            asset_id: sanad.asset_id,
            metadata_hash: sanad.metadata_hash,
            proof_system: sanad.proof_system,
        });

        Ok(())
    }

    /// Materialize (mint) a Sanad on this destination chain from a verifier-signed
    /// §9.2 attestation. THIN REGISTRY: cross-chain validity was decided off-chain;
    /// authenticity here is a set of verifier signatures over the frozen digest, and
    /// uniqueness of `sanad_id` / `nullifier` / `lock_event_id` is enforced on-chain
    /// by the `init` of three permanent tombstone PDAs.
    ///
    /// # Arguments
    /// * `sanad_id` — unique sanad identifier; primary duplicate-mint key
    /// * `commitment` — commitment binding the sanad content/ownership
    /// * `source_chain` — `keccak256("csv.chain.<src>")`, the chain the sanad locked on
    /// * `destination_owner` — recipient identity bytes; hashed on-chain, full bytes emitted
    /// * `lock_event_id` — source-chain lock event id (settlement replay key)
    /// * `nullifier` — replay nullifier consumed by the source seal
    /// * `attestation_expiry` — u64 unix seconds; 0 = no expiry (bound over the digest)
    /// * `verifier_signatures` — 65-byte secp256k1 signatures over the §9.2 digest
    pub fn mint_sanad(
        ctx: Context<MintSanad>,
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        source_chain: [u8; 32],
        destination_owner: Vec<u8>,
        lock_event_id: [u8; 32],
        nullifier: [u8; 32],
        attestation_expiry: u64,
        verifier_signatures: Vec<Vec<u8>>,
    ) -> Result<()> {
        // Field sanity: every real mint carries non-zero replay keys.
        require!(sanad_id != [0u8; 32], CsvError::InvalidMintRequest);
        require!(commitment != [0u8; 32], CsvError::InvalidMintRequest);
        require!(source_chain != [0u8; 32], CsvError::InvalidMintRequest);
        require!(lock_event_id != [0u8; 32], CsvError::InvalidMintRequest);
        require!(nullifier != [0u8; 32], CsvError::InvalidMintRequest);
        require!(!destination_owner.is_empty(), CsvError::InvalidMintRequest);

        let now = Clock::get()?.unix_timestamp;

        // §9.2 expiry bound.
        if attestation_expiry != 0 {
            require!((now as u64) <= attestation_expiry, CsvError::AttestationExpired);
        }

        let destination_owner_hash =
            solana_program::keccak::hashv(&[destination_owner.as_slice()]).to_bytes();

        // §9 authentication: verify M-of-N verifier signatures over the frozen §9.2 digest.
        let digest = mint_attestation_digest(
            &sanad_id,
            &commitment,
            &source_chain,
            &destination_owner_hash,
            &lock_event_id,
            &nullifier,
            attestation_expiry,
        );
        require_verifier_threshold(&ctx.accounts.verifier_registry, &digest, &verifier_signatures)?;

        // Record the mint and consume the replay keys. `init` on each of these three
        // PDAs is the on-chain uniqueness enforcement (a second mint with any repeated
        // key fails because the corresponding account already exists). These accounts
        // are never closed, so a closed-then-reopened account cannot reuse a key.
        let mint_record = &mut ctx.accounts.mint_record;
        mint_record.sanad_id = sanad_id;
        mint_record.commitment = commitment;
        mint_record.source_chain = source_chain;
        mint_record.destination_owner_hash = destination_owner_hash;
        mint_record.lock_event_id = lock_event_id;
        mint_record.nullifier = nullifier;
        mint_record.minted_at = now;
        mint_record.bump = ctx.bumps.mint_record;

        let nullifier_record = &mut ctx.accounts.nullifier_record;
        nullifier_record.nullifier = nullifier;
        nullifier_record.sanad_id = sanad_id;
        nullifier_record.recorded_at = now;
        nullifier_record.bump = ctx.bumps.nullifier_record;

        let lock_event_record = &mut ctx.accounts.lock_event_record;
        lock_event_record.lock_event_id = lock_event_id;
        lock_event_record.sanad_id = sanad_id;
        lock_event_record.recorded_at = now;
        lock_event_record.bump = ctx.bumps.lock_event_record;

        emit!(SanadMinted {
            sanad_id,
            commitment,
            source_chain,
            destination_owner,
            lock_event_id,
            nullifier,
            minted_at: now,
        });
        emit!(NullifierRegistered { nullifier, sanad_id });

        Ok(())
    }

    /// Release a locked Sanad's source escrow to the operator on a verifier-signed
    /// §10 settlement receipt. THE OPERATOR CANNOT SELF-RELEASE: authority is a set
    /// of `threshold` distinct verifier signatures over the frozen §10 receipt digest
    /// — the SAME verifier set that authorizes the mint. Exactly one receipt may
    /// settle per `lock_event_id` (enforced by the `init` of the SettlementRecord PDA).
    ///
    /// NOTE: the Solana lock currently escrows no lamports, so this records the
    /// authoritative settlement (and blocks any later refund) without a value
    /// transfer; the lamport-escrow release plugs into this same authorization when
    /// the escrow lock lands.
    pub fn settle_lock(
        ctx: Context<SettleLock>,
        sanad_id: [u8; 32],
        lock_event_id: [u8; 32],
        destination_chain_id: [u8; 32],
        destination_mint_tx_ref: [u8; 32],
        operator_payout: Pubkey,
        receipt_expiry: u64,
        verifier_signatures: Vec<Vec<u8>>,
    ) -> Result<()> {
        require!(sanad_id != [0u8; 32], CsvError::InvalidSettlementRequest);
        require!(lock_event_id != [0u8; 32], CsvError::InvalidSettlementRequest);
        require!(destination_chain_id != [0u8; 32], CsvError::InvalidSettlementRequest);
        require!(destination_mint_tx_ref != [0u8; 32], CsvError::InvalidSettlementRequest);
        require!(operator_payout != Pubkey::default(), CsvError::InvalidSettlementRequest);

        let now = Clock::get()?.unix_timestamp;
        if receipt_expiry != 0 {
            require!((now as u64) <= receipt_expiry, CsvError::ReceiptExpired);
        }

        let lock = &ctx.accounts.lock_account.lock;
        require!(lock.sanad_id == sanad_id, CsvError::LockNotFound);
        require!(!lock.refunded, CsvError::AlreadyRefunded);
        require!(!lock.settled, CsvError::AlreadySettled);

        // §10 authentication: verify M-of-N verifier signatures over the frozen §10 digest.
        let digest = settlement_receipt_digest(
            &sanad_id,
            &lock_event_id,
            &destination_chain_id,
            &destination_mint_tx_ref,
            &operator_payout.to_bytes(),
            receipt_expiry,
        );
        require_verifier_threshold(&ctx.accounts.verifier_registry, &digest, &verifier_signatures)?;

        // Effects: mark the lock settled (terminal; blocks refund) and record the
        // release. The SettlementRecord `init` is the exactly-one-per-lock_event_id
        // replay guard.
        ctx.accounts.lock_account.lock.settled = true;

        let settlement = &mut ctx.accounts.settlement_record;
        settlement.lock_event_id = lock_event_id;
        settlement.sanad_id = sanad_id;
        settlement.destination_mint_tx_ref = destination_mint_tx_ref;
        settlement.operator_payout = operator_payout;
        settlement.released = true;
        settlement.released_at = now;
        settlement.bump = ctx.bumps.settlement_record;

        emit!(SettlementReleased {
            sanad_id,
            lock_event_id,
            operator_payout,
            destination_mint_tx_ref,
            released_at: now,
        });

        Ok(())
    }

    /// Refund a Sanad after the lock timeout has elapsed.
    /// Re-creates the SanadAccount and closes the LockAccount PDA to reclaim rent.
    /// A settled lock can NEVER be refunded (mutually exclusive with settlement).
    pub fn refund_sanad(ctx: Context<RefundSanad>, state_root: [u8; 32]) -> Result<()> {
        let lock_account = &ctx.accounts.lock_account;
        let sanad = &mut ctx.accounts.new_sanad_account;
        let claimant = ctx.accounts.claimant.key();
        let lock = &lock_account.lock;

        let now = Clock::get()?.unix_timestamp;
        require!(
            now >= lock.locked_at + ctx.accounts.registry.refund_timeout as i64,
            CsvError::RefundTimeoutNotExpired
        );
        require!(!lock.refunded, CsvError::AlreadyRefunded);
        require!(!lock.settled, CsvError::AlreadySettled);
        require!(lock.owner == claimant, CsvError::NotAuthorized);

        sanad.owner = claimant;
        sanad.sanad_id = lock.sanad_id;
        sanad.commitment = lock.commitment;
        sanad.state_root = state_root;
        sanad.nullifier = [0u8; 32];
        sanad.asset_class = lock.asset_class;
        sanad.asset_id = lock.asset_id;
        sanad.metadata_hash = lock.metadata_hash;
        sanad.proof_system = lock.proof_system;
        sanad.state = SanadState::Refunded as u8;
        sanad.created_at = now;
        sanad.refunded_at = now;
        sanad.locked_at = 0;
        sanad.consumed_at = 0;
        sanad.minted_at = 0;
        sanad.bump = ctx.bumps.new_sanad_account;

        ctx.accounts.registry.lock_count -= 1;

        emit!(SanadRefunded {
            sanad_id: lock.sanad_id,
            commitment: lock.commitment,
            claimant,
            reason: "timeout".to_string(),
            refunded_at: now,
        });

        Ok(())
    }

    /// Attach token/NFT/proof metadata to an unconsumed Sanad.
    pub fn record_sanad_metadata(
        ctx: Context<RecordSanadMetadata>,
        asset_class: u8,
        asset_id: [u8; 32],
        metadata_hash: [u8; 32],
        proof_system: u8,
    ) -> Result<()> {
        require!(asset_class <= ASSET_CLASS_PROOF_SANAD, CsvError::InvalidSanadMetadata);
        require!(
            asset_class == ASSET_CLASS_UNSPECIFIED || asset_id != [0u8; 32],
            CsvError::InvalidSanadMetadata
        );

        let sanad = &mut ctx.accounts.sanad_account;
        require!(sanad.state != SanadState::Consumed as u8, CsvError::AlreadyConsumed);

        sanad.asset_class = asset_class;
        sanad.asset_id = asset_id;
        sanad.metadata_hash = metadata_hash;
        sanad.proof_system = proof_system;

        emit!(SanadMetadataRecorded {
            sanad_id: sanad.sanad_id,
            asset_class,
            asset_id,
            metadata_hash,
            proof_system,
        });

        Ok(())
    }

    /// Transfer ownership of a Sanad
    pub fn transfer_sanad(ctx: Context<TransferSanad>, new_owner: Pubkey) -> Result<()> {
        let sanad = &mut ctx.accounts.sanad_account;
        let current_owner = ctx.accounts.current_owner.key();

        require!(sanad.owner == current_owner, CsvError::NotAuthorized);
        require!(sanad.state != SanadState::Consumed as u8, CsvError::AlreadyConsumed);
        require!(sanad.state != SanadState::Locked as u8, CsvError::AlreadyLocked);

        sanad.owner = new_owner;
        sanad.state = SanadState::Transferred as u8;

        emit!(SanadTransferred {
            sanad_id: sanad.sanad_id,
            from: current_owner,
            to: new_owner,
        });

        Ok(())
    }

    // ==================== View Functions ====================

    /// Get Sanad state — returns full state view
    pub fn get_sanad_state(ctx: Context<GetSanadState>) -> Result<GetSanadStateResponse> {
        let sanad = &ctx.accounts.sanad_account;
        Ok(GetSanadStateResponse {
            state: sanad.state,
            owner: sanad.owner,
            commitment: sanad.commitment,
            nullifier: sanad.nullifier,
            created_at: sanad.created_at,
            locked_at: sanad.locked_at,
            consumed_at: sanad.consumed_at,
            minted_at: sanad.minted_at,
            refunded_at: sanad.refunded_at,
        })
    }

    /// Check if seal is available (not consumed)
    pub fn is_seal_available(ctx: Context<GetSanadState>) -> Result<bool> {
        let sanad = &ctx.accounts.sanad_account;
        Ok(sanad.state != SanadState::Consumed as u8)
    }

    /// Check if seal is consumed
    pub fn is_seal_consumed(ctx: Context<GetSanadState>) -> Result<bool> {
        let sanad = &ctx.accounts.sanad_account;
        Ok(sanad.state == SanadState::Consumed as u8)
    }

    /// Check if refund is available
    pub fn can_refund(ctx: Context<CanRefund>) -> Result<bool> {
        let lock = &ctx.accounts.lock_account;
        let now = Clock::get()?.unix_timestamp;
        Ok(!lock.lock.refunded
            && !lock.lock.settled
            && now >= lock.lock.locked_at + ctx.accounts.registry.refund_timeout as i64)
    }

    /// Register a nullifier for a locally-created Sanad (prevents double-spend on a
    /// same-chain consume). Cross-chain mint replay is enforced by the mint-path
    /// NullifierRecord PDA, not this field.
    pub fn register_nullifier(ctx: Context<RegisterNullifier>, nullifier: [u8; 32]) -> Result<()> {
        let sanad = &mut ctx.accounts.sanad_account;

        require!(
            sanad.nullifier == [0u8; 32],
            CsvError::NullifierAlreadyRegistered
        );

        sanad.nullifier = nullifier;

        emit!(NullifierRegistered {
            nullifier,
            sanad_id: sanad.sanad_id,
        });

        Ok(())
    }
}

// ==================== Account Contexts ====================

/// Initialize the LockRegistry accounts
#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    #[account(
        init,
        payer = authority,
        space = LockRegistry::SIZE,
        seeds = [SEED_LOCK_REGISTRY],
        bump
    )]
    pub registry: Account<'info, LockRegistry>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Initialize the verifier registry accounts
#[derive(Accounts)]
pub struct InitializeVerifierRegistry<'info> {
    #[account(
        init,
        payer = authority,
        space = VerifierRegistry::SIZE,
        seeds = [SEED_VERIFIER_REGISTRY],
        bump
    )]
    pub registry: Account<'info, VerifierRegistry>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Mutate the verifier registry (authority-gated governance)
#[derive(Accounts)]
pub struct UpdateVerifierRegistry<'info> {
    #[account(
        mut,
        seeds = [SEED_VERIFIER_REGISTRY],
        bump = registry.bump,
        has_one = authority @ CsvError::NotAuthorized
    )]
    pub registry: Account<'info, VerifierRegistry>,

    pub authority: Signer<'info>,
}

/// Create a new seal accounts
#[derive(Accounts)]
#[instruction(sanad_id: [u8; 32], commitment: [u8; 32], state_root: [u8; 32])]
pub struct CreateSeal<'info> {
    #[account(
        init,
        payer = owner,
        space = SanadAccount::SIZE,
        seeds = [SEED_SANAD, owner.key().as_ref(), &sanad_id],
        bump
    )]
    pub sanad_account: Account<'info, SanadAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Consume a seal accounts
#[derive(Accounts)]
pub struct ConsumeSeal<'info> {
    #[account(
        mut,
        seeds = [SEED_SANAD, sanad_account.owner.as_ref(), &sanad_account.sanad_id],
        bump = sanad_account.bump,
        constraint = sanad_account.owner == consumer.key() @ CsvError::NotAuthorized
    )]
    pub sanad_account: Account<'info, SanadAccount>,

    pub consumer: Signer<'info>,
}

/// Lock a sanad accounts
#[derive(Accounts)]
#[instruction(destination_chain: u8, destination_owner: [u8; 32])]
pub struct LockSanad<'info> {
    #[account(
        mut,
        seeds = [SEED_SANAD, sanad_account.owner.as_ref(), &sanad_account.sanad_id],
        bump = sanad_account.bump,
        constraint = sanad_account.owner == owner.key() @ CsvError::NotAuthorized
    )]
    pub sanad_account: Account<'info, SanadAccount>,

    #[account(
        mut,
        seeds = [SEED_LOCK_REGISTRY],
        bump = registry.bump
    )]
    pub registry: Account<'info, LockRegistry>,

    #[account(
        init,
        payer = owner,
        space = LockAccount::SIZE,
        seeds = [b"lock", sanad_account.sanad_id.as_ref()],
        bump
    )]
    pub lock_account: Account<'info, LockAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Mint a sanad accounts (verifier-attested thin-registry mint).
///
/// The three replay-tombstone PDAs are created with `init`; a second mint that
/// repeats any of `sanad_id` / `nullifier` / `lock_event_id` fails because the
/// corresponding account already exists. `payer` merely funds rent and gas — it
/// holds NO mint authority (authority is the verifier signatures).
#[derive(Accounts)]
#[instruction(
    sanad_id: [u8; 32],
    commitment: [u8; 32],
    source_chain: [u8; 32],
    destination_owner: Vec<u8>,
    lock_event_id: [u8; 32],
    nullifier: [u8; 32]
)]
pub struct MintSanad<'info> {
    #[account(
        seeds = [SEED_VERIFIER_REGISTRY],
        bump = verifier_registry.bump
    )]
    pub verifier_registry: Account<'info, VerifierRegistry>,

    #[account(
        init,
        payer = payer,
        space = MintRecord::SIZE,
        seeds = [SEED_MINTED, sanad_id.as_ref()],
        bump
    )]
    pub mint_record: Account<'info, MintRecord>,

    #[account(
        init,
        payer = payer,
        space = NullifierRecord::SIZE,
        seeds = [SEED_NULLIFIER, nullifier.as_ref()],
        bump
    )]
    pub nullifier_record: Account<'info, NullifierRecord>,

    #[account(
        init,
        payer = payer,
        space = LockEventRecord::SIZE,
        seeds = [SEED_LOCK_EVENT, lock_event_id.as_ref()],
        bump
    )]
    pub lock_event_record: Account<'info, LockEventRecord>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Settle a source lock accounts (verifier-attested §10 receipt).
#[derive(Accounts)]
#[instruction(sanad_id: [u8; 32], lock_event_id: [u8; 32])]
pub struct SettleLock<'info> {
    #[account(
        seeds = [SEED_VERIFIER_REGISTRY],
        bump = verifier_registry.bump
    )]
    pub verifier_registry: Account<'info, VerifierRegistry>,

    #[account(
        mut,
        seeds = [b"lock", sanad_id.as_ref()],
        bump = lock_account.bump
    )]
    pub lock_account: Account<'info, LockAccount>,

    #[account(
        init,
        payer = payer,
        space = SettlementRecord::SIZE,
        seeds = [SEED_SETTLEMENT, lock_event_id.as_ref()],
        bump
    )]
    pub settlement_record: Account<'info, SettlementRecord>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Refund a sanad accounts
#[derive(Accounts)]
#[instruction(state_root: [u8; 32])]
pub struct RefundSanad<'info> {
    #[account(
        mut,
        seeds = [SEED_LOCK_REGISTRY],
        bump = registry.bump
    )]
    pub registry: Account<'info, LockRegistry>,

    /// CHECK: Original sanad account that was locked (for verification)
    #[account(
        seeds = [SEED_SANAD, original_sanad.owner.as_ref(), &original_sanad.sanad_id],
        bump = original_sanad.bump
    )]
    pub original_sanad: Account<'info, SanadAccount>,

    #[account(
        mut,
        seeds = [b"lock", &original_sanad.sanad_id],
        bump = lock_account.bump,
        close = claimant
    )]
    pub lock_account: Account<'info, LockAccount>,

    #[account(
        init,
        payer = claimant,
        space = SanadAccount::SIZE,
        seeds = [SEED_SANAD, claimant.key().as_ref(), &original_sanad.sanad_id, SEED_REFUND],
        bump
    )]
    pub new_sanad_account: Account<'info, SanadAccount>,

    #[account(mut)]
    pub claimant: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Transfer sanad accounts
#[derive(Accounts)]
#[instruction(new_owner: Pubkey)]
pub struct TransferSanad<'info> {
    #[account(
        mut,
        seeds = [SEED_SANAD, sanad_account.owner.as_ref(), &sanad_account.sanad_id],
        bump = sanad_account.bump
    )]
    pub sanad_account: Account<'info, SanadAccount>,

    pub current_owner: Signer<'info>,
}

/// Register nullifier accounts
#[derive(Accounts)]
#[instruction(nullifier: [u8; 32])]
pub struct RegisterNullifier<'info> {
    #[account(
        mut,
        seeds = [SEED_SANAD, sanad_account.owner.as_ref(), &sanad_account.sanad_id],
        bump = sanad_account.bump,
        constraint = sanad_account.owner == authority.key() @ CsvError::NotAuthorized
    )]
    pub sanad_account: Account<'info, SanadAccount>,

    pub authority: Signer<'info>,
}

/// Record metadata accounts
#[derive(Accounts)]
#[instruction(asset_class: u8, asset_id: [u8; 32], metadata_hash: [u8; 32], proof_system: u8)]
pub struct RecordSanadMetadata<'info> {
    #[account(
        mut,
        seeds = [SEED_SANAD, sanad_account.owner.as_ref(), &sanad_account.sanad_id],
        bump = sanad_account.bump,
        constraint = sanad_account.owner == authority.key() @ CsvError::NotAuthorized
    )]
    pub sanad_account: Account<'info, SanadAccount>,

    pub authority: Signer<'info>,
}

// ==================== View Function Accounts & Responses ====================

/// Response for get_sanad_state
#[derive(AnchorSerialize, AnchorDeserialize, Debug, Clone)]
pub struct GetSanadStateResponse {
    pub state: u8,
    pub owner: Pubkey,
    pub commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub created_at: i64,
    pub locked_at: i64,
    pub consumed_at: i64,
    pub minted_at: i64,
    pub refunded_at: i64,
}

/// Get Sanad state accounts
#[derive(Accounts)]
pub struct GetSanadState<'info> {
    #[account(
        seeds = [SEED_SANAD, sanad_account.owner.as_ref(), &sanad_account.sanad_id],
        bump = sanad_account.bump
    )]
    pub sanad_account: Account<'info, SanadAccount>,
}

/// Can refund accounts
#[derive(Accounts)]
pub struct CanRefund<'info> {
    #[account(
        seeds = [SEED_LOCK_REGISTRY],
        bump = registry.bump
    )]
    pub registry: Account<'info, LockRegistry>,

    #[account(
        seeds = [b"lock", &lock_account.lock.sanad_id],
        bump = lock_account.bump
    )]
    pub lock_account: Account<'info, LockAccount>,
}
