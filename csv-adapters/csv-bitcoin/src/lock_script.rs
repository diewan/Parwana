//! Taproot script-path CSV timelock for cross-chain lock outputs.
//!
//! A cross-chain lock is only meaningful to a destination-chain verifier if
//! the source BTC is *provably* immobile for the finality window: otherwise
//! the owner could spend the "locked" coin and still have a mint go through
//! elsewhere, a race a purely client-side height check cannot prevent.
//!
//! To get consensus-level enforcement we build a single-leaf Taproot tree
//! with a NUMS (nothing-up-my-sleeve) internal key, so the output has no
//! usable key-path spend — nobody knows the discrete log of the NUMS point.
//! The only way to spend it is the script path:
//! `<timeout_blocks> OP_CSV OP_DROP <owner_pubkey> OP_CHECKSIG`
//! which BIP-68/112 make unspendable until `timeout_blocks` confirmations
//! have accrued on the outpoint being spent.

use bitcoin::{
    ScriptBuf,
    opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP},
    script::Builder,
    secp256k1::{Secp256k1, Verification, XOnlyPublicKey},
    taproot::{TaprootBuilder, TaprootSpendInfo},
};

/// BIP-341 "nothing up my sleeve" x-only point, taken verbatim from the
/// BIP-174/371 reference PSBT test vectors shipped with the `bitcoin` crate
/// (`bitcoin::psbt` test fixtures). Used as the Taproot internal key so the
/// resulting output cannot be key-path spent by anyone.
pub const NUMS_INTERNAL_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// The NUMS internal key as an `XOnlyPublicKey`.
pub fn nums_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS_INTERNAL_KEY).expect("NUMS_INTERNAL_KEY is a valid x-only point")
}

/// Build the CSV-refund leaf script: `<timeout_blocks> OP_CSV OP_DROP
/// <owner_xonly> OP_CHECKSIG`. Only spendable once the input being spent has
/// accrued at least `timeout_blocks` confirmations (BIP-68 relative
/// locktime, block-height units), and only with `owner_xonly`'s signature.
pub fn refund_leaf_script(owner_xonly: &XOnlyPublicKey, timeout_blocks: u32) -> ScriptBuf {
    Builder::new()
        .push_int(timeout_blocks as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_slice(owner_xonly.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build the single-leaf Taproot spend info for a CSV-locked output owned by
/// `owner_xonly`. Returns the leaf script (needed to build the spending
/// witness) alongside the finalized spend info (needed for the output key
/// and control block).
pub fn build_lock_taproot<C: Verification>(
    secp: &Secp256k1<C>,
    owner_xonly: &XOnlyPublicKey,
    timeout_blocks: u32,
) -> (ScriptBuf, TaprootSpendInfo) {
    let leaf = refund_leaf_script(owner_xonly, timeout_blocks);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("single leaf at depth 0 is always a valid taproot tree")
        .finalize(secp, nums_internal_key())
        .expect("NUMS internal key + single leaf always finalizes");
    (leaf, spend_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    #[test]
    fn nums_key_is_a_valid_curve_point() {
        // Guards against a transcription error in NUMS_INTERNAL_KEY: an
        // invalid x-coordinate would make `from_slice` panic here instead of
        // silently producing the wrong point.
        let _ = nums_internal_key();
    }

    #[test]
    fn leaf_script_contains_pubkey_and_is_deterministic() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();

        let script_a = refund_leaf_script(&xonly, 144);
        let script_b = refund_leaf_script(&xonly, 144);
        assert_eq!(script_a, script_b);

        let bytes = script_a.as_bytes();
        assert!(bytes.windows(32).any(|w| w == xonly.serialize()));
    }

    #[test]
    fn taproot_tree_is_deterministic_and_script_path_only() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();

        let (leaf_a, info_a) = build_lock_taproot(&secp, &xonly, 144);
        let (leaf_b, info_b) = build_lock_taproot(&secp, &xonly, 144);
        assert_eq!(leaf_a, leaf_b);
        assert_eq!(info_a.output_key(), info_b.output_key());

        // Internal key must be the NUMS point, not the owner's key: nobody
        // must be able to key-path spend this output.
        assert_eq!(info_a.internal_key(), nums_internal_key());

        // A different timeout must yield a different output key.
        let (_, info_c) = build_lock_taproot(&secp, &xonly, 6);
        assert_ne!(info_a.output_key(), info_c.output_key());
    }
}
