use csv_hash::seal::SealPoint;
use serde::{Deserialize, Serialize};

/// Wire format for seal point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealPointWire {
    pub id: String,
    pub nonce: Option<u64>,
    pub version: Option<u64>,
}

impl From<SealPoint> for SealPointWire {
    fn from(seal: SealPoint) -> Self {
        Self {
            id: hex::encode(&seal.id),
            nonce: seal.nonce,
            version: seal.version,
        }
    }
}

impl TryFrom<SealPointWire> for SealPoint {
    type Error = String;

    fn try_from(wire: SealPointWire) -> Result<Self, String> {
        let id = hex::decode(&wire.id).map_err(|e| format!("Invalid id hex: {}", e))?;

        SealPoint::new(id, wire.nonce, wire.version).map_err(|e| e.to_string())
    }
}

/// Expected length of a Bitcoin txid / Sui object id / Aptos resource address /
/// Ethereum storage slot (all 32-byte identifiers on their respective chains).
pub const SEAL_ID32_LEN: usize = 32;
/// Expected length of an Ethereum contract address.
pub const SEAL_ETH_ADDR_LEN: usize = 20;
/// Maximum length of an Aptos resource key path.
pub const SEAL_APTOS_KEY_MAX_LEN: usize = 512;

/// A recipient-controlled single-use seal, pinned to a concrete per-chain encoding.
///
/// This is **not** a new seal primitive: every variant reduces to the existing
/// [`SealPoint`] via [`SealDefinition::to_seal_point`]. `SealDefinition` only pins
/// the chain-specific byte layout that `SealPoint`'s opaque `id` generalizes, so an
/// [`crate::invoice::Invoice`] can bind a seal the recipient actually controls on
/// the destination chain (the RGB blinded-seal analog).
///
/// Per-chain `SealPoint` mapping (the pinned encoding):
/// - **Bitcoin** — `id = txid(32) || vout(4, LE)`, `version = None`. UTXO OutPoint.
/// - **Sui** — `id = object_id(32)`, `version = Some(object_version)`. Owned object.
/// - **Aptos** — `id = resource_address(32) || key`, `version = None`. Move resource.
/// - **Ethereum** — `id = contract(20) || slot(32)`, `version = None`. Contract slot.
/// - **Solana** — `id = account(32)`, `version = None`. csv-seal `SanadAccount` the
///   recipient controls; the 32 bytes are the account's on-chain address (the PDA
///   whose `owner` field is the recipient's wallet pubkey).
///
/// The anti-replay nonce is supplied by the invoice, not the definition, and is
/// folded into the resulting `SealPoint.nonce` by [`SealDefinition::to_seal_point`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "chain", rename_all = "snake_case")]
pub enum SealDefinition {
    /// Bitcoin UTXO OutPoint (`txid` + `vout`).
    Bitcoin {
        /// 32-byte transaction id (internal byte order).
        #[serde(with = "crate::hexbytes")]
        txid: Vec<u8>,
        /// Output index within the transaction.
        vout: u32,
    },
    /// Sui owned object (`object_id` + `version`).
    Sui {
        /// 32-byte object id.
        #[serde(with = "crate::hexbytes")]
        object_id: Vec<u8>,
        /// Object version (Sui linear object version counter).
        version: u64,
    },
    /// Aptos Move resource (`resource_address` + `key`).
    Aptos {
        /// 32-byte account/resource address.
        #[serde(with = "crate::hexbytes")]
        resource_address: Vec<u8>,
        /// Struct key path identifying the resource within the account.
        #[serde(with = "crate::hexbytes")]
        key: Vec<u8>,
    },
    /// Ethereum contract storage slot (`contract` + `slot`).
    Ethereum {
        /// 20-byte contract address.
        #[serde(with = "crate::hexbytes")]
        contract: Vec<u8>,
        /// 32-byte storage slot.
        #[serde(with = "crate::hexbytes")]
        slot: Vec<u8>,
    },
    /// Solana csv-seal `SanadAccount` (`account`).
    Solana {
        /// 32-byte account address (the recipient-controlled `SanadAccount` PDA).
        #[serde(with = "crate::hexbytes")]
        account: Vec<u8>,
    },
}

impl SealDefinition {
    /// Construct a Bitcoin OutPoint seal, validating the txid length.
    ///
    /// # Errors
    /// Returns an error if `txid` is not exactly 32 bytes.
    pub fn bitcoin(txid: Vec<u8>, vout: u32) -> Result<Self, String> {
        if txid.len() != SEAL_ID32_LEN {
            return Err(format!("bitcoin txid must be {SEAL_ID32_LEN} bytes"));
        }
        Ok(Self::Bitcoin { txid, vout })
    }

    /// Construct a Sui owned-object seal, validating the object id length.
    ///
    /// # Errors
    /// Returns an error if `object_id` is not exactly 32 bytes.
    pub fn sui(object_id: Vec<u8>, version: u64) -> Result<Self, String> {
        if object_id.len() != SEAL_ID32_LEN {
            return Err(format!("sui object_id must be {SEAL_ID32_LEN} bytes"));
        }
        Ok(Self::Sui { object_id, version })
    }

    /// Construct an Aptos Move-resource seal, validating the address and key length.
    ///
    /// # Errors
    /// Returns an error if `resource_address` is not 32 bytes, the `key` is empty,
    /// or the `key` exceeds [`SEAL_APTOS_KEY_MAX_LEN`].
    pub fn aptos(resource_address: Vec<u8>, key: Vec<u8>) -> Result<Self, String> {
        if resource_address.len() != SEAL_ID32_LEN {
            return Err(format!(
                "aptos resource_address must be {SEAL_ID32_LEN} bytes"
            ));
        }
        if key.is_empty() {
            return Err("aptos key must not be empty".to_string());
        }
        if key.len() > SEAL_APTOS_KEY_MAX_LEN {
            return Err(format!("aptos key exceeds {SEAL_APTOS_KEY_MAX_LEN} bytes"));
        }
        Ok(Self::Aptos {
            resource_address,
            key,
        })
    }

    /// Construct an Ethereum storage-slot seal, validating the address and slot length.
    ///
    /// # Errors
    /// Returns an error if `contract` is not 20 bytes or `slot` is not 32 bytes.
    pub fn ethereum(contract: Vec<u8>, slot: Vec<u8>) -> Result<Self, String> {
        if contract.len() != SEAL_ETH_ADDR_LEN {
            return Err(format!(
                "ethereum contract must be {SEAL_ETH_ADDR_LEN} bytes"
            ));
        }
        if slot.len() != SEAL_ID32_LEN {
            return Err(format!("ethereum slot must be {SEAL_ID32_LEN} bytes"));
        }
        Ok(Self::Ethereum { contract, slot })
    }

    /// Construct a Solana csv-seal `SanadAccount` seal, validating the address length.
    ///
    /// # Errors
    /// Returns an error if `account` is not exactly 32 bytes.
    pub fn solana(account: Vec<u8>) -> Result<Self, String> {
        if account.len() != SEAL_ID32_LEN {
            return Err(format!("solana account must be {SEAL_ID32_LEN} bytes"));
        }
        Ok(Self::Solana { account })
    }

    /// Canonical chain identifier for this seal definition.
    pub fn chain(&self) -> &'static str {
        match self {
            Self::Bitcoin { .. } => "bitcoin",
            Self::Sui { .. } => "sui",
            Self::Aptos { .. } => "aptos",
            Self::Ethereum { .. } => "ethereum",
            Self::Solana { .. } => "solana",
        }
    }

    /// Reduce this definition to the underlying [`SealPoint`] primitive, folding an
    /// optional anti-replay `nonce` into `SealPoint.nonce`.
    ///
    /// The per-chain `id`/`version` layout is documented on [`SealDefinition`] and is
    /// the pinned encoding shared with the on-chain adapters.
    ///
    /// # Errors
    /// Returns an error if the resulting `id` violates [`SealPoint`]'s size bounds.
    pub fn to_seal_point(&self, nonce: Option<u64>) -> Result<SealPoint, String> {
        let (id, version) = match self {
            Self::Bitcoin { txid, vout } => {
                let mut id = Vec::with_capacity(txid.len() + 4);
                id.extend_from_slice(txid);
                id.extend_from_slice(&vout.to_le_bytes());
                (id, None)
            }
            Self::Sui { object_id, version } => (object_id.clone(), Some(*version)),
            Self::Aptos {
                resource_address,
                key,
            } => {
                let mut id = Vec::with_capacity(resource_address.len() + key.len());
                id.extend_from_slice(resource_address);
                id.extend_from_slice(key);
                (id, None)
            }
            Self::Ethereum { contract, slot } => {
                let mut id = Vec::with_capacity(contract.len() + slot.len());
                id.extend_from_slice(contract);
                id.extend_from_slice(slot);
                (id, None)
            }
            Self::Solana { account } => (account.clone(), None),
        };
        SealPoint::new(id, nonce, version).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_definitions() -> Vec<SealDefinition> {
        vec![
            SealDefinition::bitcoin(vec![0xAB; 32], 3).unwrap(),
            SealDefinition::sui(vec![0xCD; 32], 7).unwrap(),
            SealDefinition::aptos(vec![0xEF; 32], vec![1, 2, 3, 4]).unwrap(),
            SealDefinition::ethereum(vec![0x11; 20], vec![0x22; 32]).unwrap(),
            SealDefinition::solana(vec![0x33; 32]).unwrap(),
        ]
    }

    #[test]
    fn constructors_reject_bad_lengths() {
        assert!(SealDefinition::bitcoin(vec![0; 31], 0).is_err());
        assert!(SealDefinition::sui(vec![0; 33], 0).is_err());
        assert!(SealDefinition::aptos(vec![0; 31], vec![1]).is_err());
        assert!(SealDefinition::aptos(vec![0; 32], vec![]).is_err());
        assert!(SealDefinition::ethereum(vec![0; 19], vec![0; 32]).is_err());
        assert!(SealDefinition::ethereum(vec![0; 20], vec![0; 31]).is_err());
        assert!(SealDefinition::solana(vec![0; 31]).is_err());
        assert!(SealDefinition::solana(vec![0; 33]).is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        for def in all_definitions() {
            let json = serde_json::to_string(&def).unwrap();
            let back: SealDefinition = serde_json::from_str(&json).unwrap();
            assert_eq!(def, back);
        }
    }

    #[test]
    fn bitcoin_seal_point_pins_outpoint_layout() {
        let def = SealDefinition::bitcoin(vec![0xAB; 32], 0x04030201).unwrap();
        let sp = def.to_seal_point(Some(9)).unwrap();
        let mut expected = vec![0xAB; 32];
        expected.extend_from_slice(&0x04030201u32.to_le_bytes());
        assert_eq!(sp.id, expected);
        assert_eq!(sp.version, None);
        assert_eq!(sp.nonce, Some(9));
    }

    #[test]
    fn sui_seal_point_carries_version() {
        let def = SealDefinition::sui(vec![0xCD; 32], 42).unwrap();
        let sp = def.to_seal_point(None).unwrap();
        assert_eq!(sp.id, vec![0xCD; 32]);
        assert_eq!(sp.version, Some(42));
        assert_eq!(sp.nonce, None);
    }

    #[test]
    fn aptos_and_ethereum_seal_point_concatenation() {
        let aptos = SealDefinition::aptos(vec![0xEF; 32], vec![7, 8]).unwrap();
        let sp = aptos.to_seal_point(None).unwrap();
        let mut expected = vec![0xEF; 32];
        expected.extend_from_slice(&[7, 8]);
        assert_eq!(sp.id, expected);

        let eth = SealDefinition::ethereum(vec![0x11; 20], vec![0x22; 32]).unwrap();
        let sp = eth.to_seal_point(None).unwrap();
        let mut expected = vec![0x11; 20];
        expected.extend_from_slice(&[0x22; 32]);
        assert_eq!(sp.id, expected);
    }

    #[test]
    fn solana_seal_point_pins_account_layout() {
        let def = SealDefinition::solana(vec![0x33; 32]).unwrap();
        let sp = def.to_seal_point(Some(5)).unwrap();
        assert_eq!(sp.id, vec![0x33; 32]);
        assert_eq!(sp.version, None);
        assert_eq!(sp.nonce, Some(5));
    }

    #[test]
    fn distinct_chains_produce_distinct_chain_tags() {
        let tags: Vec<&str> = all_definitions().iter().map(|d| d.chain()).collect();
        assert_eq!(tags, vec!["bitcoin", "sui", "aptos", "ethereum", "solana"]);
    }
}
