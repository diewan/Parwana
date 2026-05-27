//! BIP-341 Taproot key derivation and output key tweaking
//!
//! Implements the tap_tweak computation needed to derive P2TR output keys
//! from internal keys and merkle roots.

use bitcoin::{
    Address, Network, ScriptBuf,
    key::{TapTweak, XOnlyPublicKey},
    secp256k1::Secp256k1,
    taproot::TaprootSpendInfo,
};

use csv_hash::Hash as CsvHash;

/// Tapret commitment for output key derivation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapretCommitment {
    pub protocol_id: [u8; 32],
    pub commitment: CsvHash,
}

impl TapretCommitment {
    pub fn new(protocol_id: [u8; 32], commitment: CsvHash) -> Self {
        Self {
            protocol_id,
            commitment,
        }
    }

    pub fn leaf_script(&self) -> ScriptBuf {
        use bitcoin::{
            opcodes::all::OP_RETURN,
            script::{Builder, PushBytesBuf},
        };
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&self.protocol_id);
        payload[32..].copy_from_slice(self.commitment.as_bytes());
        let push_bytes =
            PushBytesBuf::try_from(payload.to_vec()).expect("64-byte payload fits in PushBytesBuf");
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(push_bytes)
            .into_script()
    }
}

/// Derive a BIP-341 tweaked output key from an internal key and optional merkle root
///
/// Q = P + tapTweak(P || merkle_root) * G
pub fn derive_output_key(
    internal_key: XOnlyPublicKey,
    merkle_root: Option<bitcoin::taproot::TapNodeHash>,
) -> Result<XOnlyPublicKey, Bip341Error> {
    let secp = Secp256k1::new();
    let tweaked = internal_key.tap_tweak(&secp, merkle_root);
    // tweaked is (TweakedPublicKey, Parity) — we need the inner XOnlyPublicKey
    Ok(tweaked.0.to_x_only_public_key())
}

/// Build a Taproot output from spend info
pub struct TaprootOutput {
    pub output_key: XOnlyPublicKey,
    pub merkle_root: Option<bitcoin::taproot::TapNodeHash>,
    pub spend_info: Option<TaprootSpendInfo>,
}

impl TaprootOutput {
    pub fn to_address(&self, network: Network) -> Address {
        if let Some(ref spend_info) = self.spend_info {
            Address::p2tr_tweaked(spend_info.output_key(), network)
        } else {
            // Key-path only — create a tweaked key with no merkle root
            let secp = Secp256k1::new();
            let tweaked = self.output_key.tap_tweak(&secp, None);
            Address::p2tr_tweaked(tweaked.0, network)
        }
    }
}

/// BIP-341 error types
#[derive(Debug, thiserror::Error)]
pub enum Bip341Error {
    #[error("Invalid internal key")]
    InvalidKey,
}

/// Generate a test internal key pair for development
pub fn generate_test_keypair() -> (secp256k1::SecretKey, XOnlyPublicKey) {
    use secp256k1::rand::thread_rng as secp_rng;
    let secp = Secp256k1::new();
    let mut rng = secp_rng();
    let secret_key = secp256k1::SecretKey::new(&mut rng);
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let xonly = XOnlyPublicKey::from(public_key);
    (secret_key, xonly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_output_key_no_merkle_root() {
        let (_, internal_key) = generate_test_keypair();
        let output_key = derive_output_key(internal_key, None).unwrap();
        assert_eq!(output_key.serialize().len(), 32);
    }

    #[test]
    fn test_tapret_commitment_leaf_script() {
        let tapret = TapretCommitment::new([1u8; 32], CsvHash::new([2u8; 32]));
        let script = tapret.leaf_script();
        assert!(script.is_op_return());
        assert_eq!(script.len(), 66);
    }

    #[test]
    fn test_output_key_deterministic() {
        use secp256k1::SecretKey;

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0xAB; 32]).unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let internal_key = XOnlyPublicKey::from(public_key);

        let output1 = derive_output_key(internal_key, None).unwrap();
        let output2 = derive_output_key(internal_key, None).unwrap();
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_output_key_differs_by_merkle_root() {
        use std::str::FromStr;
        let (_, internal_key) = generate_test_keypair();
        let output_no_root = derive_output_key(internal_key, None).unwrap();

        // Create a fake merkle root
        let fake_root = bitcoin::taproot::TapNodeHash::from_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap();
        let output_with_root = derive_output_key(internal_key, Some(fake_root)).unwrap();
        assert_ne!(output_no_root, output_with_root);
    }
}
