//! Seal wallet for Bitcoin UTXO management with BIP-32/86 HD key derivation
//!
//! Implements BIP-86 key derivation path: m/86'/0'/0'/0/{index}

#[cfg(test)]
use bitcoin::Txid;
use bitcoin::{
    Address, Network, OutPoint, ScriptBuf,
    bip32::{DerivationPath as BitcoinDerivationPath, Xpriv, Xpub},
    key::TapTweak,
    secp256k1::{self, Secp256k1, SecretKey, XOnlyPublicKey},
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Mutex;

#[allow(unused_imports)]
use bitcoin_hashes::Hash;

use bitcoin::secp256k1::rand::{RngCore, rngs::OsRng};
use hex;

#[allow(unused_imports)]
use crate::types::{BitcoinSealPoint, UtxoProvenance};

/// BIP-86 purpose for single-key P2TR
const BIP86_PURPOSE: u32 = 86;

/// Minimum UTXO value in satoshis
/// For mainnet: 10,000 sats (0.0001 BTC) - prevents using dust/tiny UTXOs
/// For testnet/signet: 1,000 sats - lower threshold for testing
fn minimum_utxo_sat(network: Network) -> u64 {
    match network {
        Network::Bitcoin => 10_000,
        _ => 1_000, // Testnet, Signet, Regtest
    }
}

/// Coin type: 0 for mainnet, 1 for testnet/signet/regtest
fn coin_type(network: &Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        _ => 1,
    }
}

/// BIP-86 derivation path descriptor
#[derive(Clone, Debug)]
pub struct Bip86Path {
    pub account: u32,
    pub change: u32,
    pub index: u32,
}

impl Bip86Path {
    pub fn new(account: u32, change: u32, index: u32) -> Self {
        Self {
            account,
            change,
            index,
        }
    }
    pub fn external(account: u32, index: u32) -> Self {
        Self::new(account, 0, index)
    }
    pub fn internal(account: u32, index: u32) -> Self {
        Self::new(account, 1, index)
    }
    pub fn to_bitcoin_path(&self, network: &Network) -> BitcoinDerivationPath {
        let coin = coin_type(network);
        format!(
            "m/{}'/{}'/{}'/{}/{}",
            BIP86_PURPOSE, coin, self.account, self.change, self.index
        )
        .parse()
        .expect("valid BIP-32 path")
    }
    pub fn to_string(&self, network: &Network) -> String {
        let coin = coin_type(network);
        format!(
            "m/{}'/{}'/{}'/{}/{}",
            BIP86_PURPOSE, coin, self.account, self.change, self.index
        )
    }
}

/// UTXO entry in the wallet
#[derive(Clone, Debug)]
pub struct WalletUtxo {
    pub outpoint: OutPoint,
    pub amount_sat: u64,
    pub path: Bip86Path,
    pub reserved: bool,
    pub reserved_for: Option<String>,
    /// Actual scriptPubKey from blockchain (for correct sighash calculation)
    pub script_pubkey: Option<ScriptBuf>,
    /// Sanad ID this UTXO is associated with (for cross-chain lock lookups)
    pub sanad_id: Option<[u8; 32]>,
    /// Provenance of this UTXO (tracks origin to prevent spending non-spendable outputs)
    pub provenance: UtxoProvenance,
}

/// Derived Taproot key with spending info
#[derive(Clone, Debug)]
pub struct DerivedTaprootKey {
    pub internal_xonly: XOnlyPublicKey,
    pub output_key: bitcoin::key::TweakedPublicKey,
    pub path: Bip86Path,
    pub address: Address,
}

/// Seal wallet - manages UTXOs, HD key derivation, and seal tracking
pub struct SealWallet {
    master_key: Xpriv,
    network: Network,
    utxos: Mutex<HashMap<OutPoint, WalletUtxo>>,
    used_seals: Mutex<HashSet<Vec<u8>>>,
    secp: Secp256k1<secp256k1::All>,
    next_index: Mutex<HashMap<u32, u32>>,
    /// Explicit sanad_id -> seal mapping for cross-chain lock lookups
    sanad_seals: Mutex<HashMap<[u8; 32], (Vec<u8>, u32)>>,
    /// sanad_id -> tapret commitment embedded in the seal output's Taproot
    /// leaf. Required to reconstruct the key-path tweak when spending the seal
    /// (the output key is `internal + TapTweak(internal || merkle(commitment))`).
    sanad_commitments: Mutex<HashMap<[u8; 32], [u8; 32]>>,
}

impl SealWallet {
    pub fn from_mnemonic(
        mnemonic: &str,
        password: &str,
        network: Network,
    ) -> Result<Self, WalletError> {
        let seed = bip32::Mnemonic::new(mnemonic, bip32::Language::English)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?
            .to_seed(password);
        Self::from_seed(seed.as_bytes(), network)
    }

    pub fn from_seed(seed: &[u8; 64], network: Network) -> Result<Self, WalletError> {
        let btc_net = match network {
            Network::Bitcoin => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Signet => bitcoin::Network::Signet,
            Network::Regtest => bitcoin::Network::Regtest,
            _ => bitcoin::Network::Testnet,
        };
        let secp = Secp256k1::new();
        let master_key = Xpriv::new_master(btc_net, seed)
            .map_err(|e| WalletError::KeyDerivationFailed(e.to_string()))?;
        Ok(Self {
            master_key,
            network,
            utxos: Mutex::new(HashMap::new()),
            used_seals: Mutex::new(HashSet::new()),
            secp,
            next_index: Mutex::new(HashMap::new()),
            sanad_seals: Mutex::new(HashMap::new()),
            sanad_commitments: Mutex::new(HashMap::new()),
        })
    }

    pub fn generate_random(network: Network) -> Self {
        let mut seed = [0u8; 64];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed, network).expect("valid seed")
    }

    /// Return the master extended public key (xpub) as a string.
    /// This is safe to share publicly — it can derive addresses but not spend.
    pub fn xpub(&self) -> String {
        Xpub::from_priv(&self.secp, &self.master_key).to_string()
    }

    pub fn from_xpub(xpub: &str, network: Network) -> Result<Self, WalletError> {
        let extended_pub = Xpub::from_str(xpub)
            .map_err(|e| WalletError::InvalidKey(format!("Invalid xpub: {}", e)))?;
        if extended_pub.network != network.into() {
            return Err(WalletError::InvalidKey(format!(
                "xpub network mismatch: expected {:?}, got {:?}",
                network, extended_pub.network
            )));
        }
        let mut seed = [0u8; 64];
        OsRng.fill_bytes(&mut seed);
        let wallet = Self::from_seed(&seed, network)?;
        Ok(wallet)
    }

    pub fn derive_private_key(&self, path: &Bip86Path) -> Result<SecretKey, WalletError> {
        let btc_path = path.to_bitcoin_path(&self.network);
        let child = self
            .master_key
            .derive_priv(&self.secp, &btc_path)
            .map_err(|e| WalletError::KeyDerivationFailed(format!("{:?}", e)))?;
        Ok(child.private_key)
    }

    /// Derive a Taproot key at a specific path
    pub fn derive_key(&self, path: &Bip86Path) -> Result<DerivedTaprootKey, WalletError> {
        let secret_key = self.derive_private_key(path)?;
        let kp = secp256k1::Keypair::from_secret_key(&self.secp, &secret_key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&kp);
        // tap_tweak on XOnlyPublicKey returns (TweakedPublicKey, Parity)
        let (output_key, _) = xonly.tap_tweak(&self.secp, None);
        let address = Address::p2tr_tweaked(output_key, self.network);
        Ok(DerivedTaprootKey {
            internal_xonly: xonly,
            output_key,
            path: path.clone(),
            address,
        })
    }

    /// Get the owner secret key for a given path as a hex-encoded string.
    /// This is used for signing lock transactions in cross-chain transfers.
    pub fn get_owner_key_hex(&self, path: &Bip86Path) -> Result<String, WalletError> {
        let secret_key = self.derive_private_key(path)?;
        Ok(hex::encode(secret_key.secret_bytes()))
    }

    /// Produce a 64-byte Schnorr signature for the given sighash using the
    /// BIP-86 key-path tweak (merkle root = None). Use this only for plain
    /// key-path outputs whose taproot key commits to no script tree.
    pub fn sign_taproot_keypath(
        &self,
        path: &Bip86Path,
        sighash: &[u8; 32],
    ) -> Result<Vec<u8>, WalletError> {
        self.sign_taproot_keypath_with_merkle(path, sighash, None)
    }

    /// Produce a 64-byte Schnorr key-path signature tweaked by an explicit
    /// Taproot merkle root.
    ///
    /// Tapret commitment seals are P2TR outputs whose output key is
    /// `P + t·G` where `t = TapTweak(P || merkle_root)` and `merkle_root`
    /// commits to the tapret OP_RETURN leaf. Signing such an output with the
    /// plain BIP-86 tweak (`merkle_root = None`, as `sign_taproot_keypath`
    /// does) signs for the wrong output key and yields an invalid Schnorr
    /// signature that the network rejects. Pass the seal's real merkle root
    /// here so the tweak matches the on-chain output key.
    pub fn sign_taproot_keypath_with_merkle(
        &self,
        path: &Bip86Path,
        sighash: &[u8; 32],
        merkle_root: Option<bitcoin::taproot::TapNodeHash>,
    ) -> Result<Vec<u8>, WalletError> {
        let secret_key = self.derive_private_key(path)?;
        let kp = secp256k1::Keypair::from_secret_key(&self.secp, &secret_key);
        // TapTweak: kp -> secp256k1::TweakedKeypair
        let tweaked_kp = kp.tap_tweak(&self.secp, merkle_root);
        let msg = secp256k1::Message::from_digest_slice(sighash)
            .map_err(|e| WalletError::SigningFailed(e.to_string()))?;
        let sig = self
            .secp
            .sign_schnorr_no_aux_rand(&msg, &tweaked_kp.to_keypair());
        Ok(sig.as_ref().to_vec())
    }

    /// Produce a 64-byte Schnorr signature for the given sighash using the
    /// *untweaked* key. Use this for Taproot script-path spends, where the
    /// leaf script commits to the raw (BIP-86-derived, untweaked) x-only
    /// public key directly via `OP_CHECKSIG` — as opposed to
    /// `sign_taproot_keypath`, which signs against the tap-tweaked output
    /// key used for key-path spends.
    pub fn sign_taproot_scriptpath(
        &self,
        path: &Bip86Path,
        sighash: &[u8; 32],
    ) -> Result<Vec<u8>, WalletError> {
        let secret_key = self.derive_private_key(path)?;
        let kp = secp256k1::Keypair::from_secret_key(&self.secp, &secret_key);
        let msg = secp256k1::Message::from_digest_slice(sighash)
            .map_err(|e| WalletError::SigningFailed(e.to_string()))?;
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &kp);
        Ok(sig.as_ref().to_vec())
    }

    pub fn next_address(
        &self,
        account: u32,
    ) -> Result<(DerivedTaprootKey, Bip86Path), WalletError> {
        let mut ni = self.next_index.lock().unwrap_or_else(|e| e.into_inner());
        let idx = ni.entry(account).or_insert(0);
        let path = Bip86Path::external(account, *idx);
        let key = self.derive_key(&path)?;
        *idx += 1;
        Ok((key, path))
    }

    pub fn get_funding_address(
        &self,
        account: u32,
        index: u32,
    ) -> Result<DerivedTaprootKey, WalletError> {
        self.derive_key(&Bip86Path::external(account, index))
    }

    pub fn get_account_xpub(&self, account: u32) -> Result<String, WalletError> {
        let coin = coin_type(&self.network);
        let account_path: BitcoinDerivationPath =
            format!("m/{}'/{}'/{}'", BIP86_PURPOSE, coin, account)
                .parse()
                .map_err(|e| WalletError::KeyDerivationFailed(format!("{:?}", e)))?;
        let account_key = self
            .master_key
            .derive_priv(&self.secp, &account_path)
            .map_err(|e| WalletError::KeyDerivationFailed(format!("{:?}", e)))?;
        Ok(Xpub::from_priv(&self.secp, &account_key).to_string())
    }

    pub fn add_utxo(&self, outpoint: OutPoint, amount_sat: u64, path: Bip86Path) {
        self.add_utxo_with_provenance(
            outpoint,
            amount_sat,
            path,
            None,
            None,
            UtxoProvenance::Unknown,
        );
    }

    pub fn add_utxo_with_scriptpubkey(
        &self,
        outpoint: OutPoint,
        amount_sat: u64,
        path: Bip86Path,
        script_pubkey: Option<ScriptBuf>,
        sanad_id: Option<[u8; 32]>,
    ) {
        self.add_utxo_with_provenance(
            outpoint,
            amount_sat,
            path,
            script_pubkey,
            sanad_id,
            UtxoProvenance::RpcWallet,
        );
    }

    pub fn add_utxo_with_provenance(
        &self,
        outpoint: OutPoint,
        amount_sat: u64,
        path: Bip86Path,
        script_pubkey: Option<ScriptBuf>,
        sanad_id: Option<[u8; 32]>,
        provenance: UtxoProvenance,
    ) {
        self.utxos.lock().unwrap_or_else(|e| e.into_inner()).insert(
            outpoint,
            WalletUtxo {
                outpoint,
                amount_sat,
                path,
                reserved: false,
                reserved_for: None,
                script_pubkey,
                sanad_id,
                provenance,
            },
        );
    }
    pub fn balance(&self) -> u64 {
        self.utxos
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|u| !u.reserved)
            .map(|u| u.amount_sat)
            .sum()
    }
    pub fn utxo_count(&self) -> usize {
        self.utxos
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|u| !u.reserved)
            .count()
    }

    /// Register an explicit sanad_id -> seal (txid, vout) mapping for cross-chain lock lookups
    /// Also marks the corresponding UTXO as SanadAnchor to prevent it from being spent
    pub fn register_sanad_seal(&self, sanad_id: [u8; 32], txid: Vec<u8>, vout: u32) {
        // Mark the UTXO as SanadAnchor to prevent spending
        let txid_array: [u8; 32] = txid.clone().try_into().unwrap_or([0u8; 32]);
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                txid_array,
            )),
            vout,
        };
        let mut utxos = self.utxos.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(utxo) = utxos.get_mut(&outpoint) {
            utxo.provenance = UtxoProvenance::SanadAnchor;
        }

        self.sanad_seals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sanad_id, (txid, vout));
    }

    /// Get the sanad_seals map for lookup by seal_protocol
    pub fn get_sanad_seals(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], (Vec<u8>, u32)>> {
        self.sanad_seals.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record the tapret commitment embedded in a sanad's seal output, so the
    /// key-path tweak can be reconstructed when the seal is later spent.
    pub fn register_sanad_commitment(&self, sanad_id: [u8; 32], commitment: [u8; 32]) {
        self.sanad_commitments
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sanad_id, commitment);
    }

    /// Look up the tapret commitment for a sanad's seal output, if known.
    pub fn get_sanad_commitment(&self, sanad_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.sanad_commitments
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(sanad_id)
            .copied()
    }

    pub fn select_utxos(&self, target_sat: u64) -> Result<Vec<WalletUtxo>, WalletError> {
        let min_sat = minimum_utxo_sat(self.network);
        let mut available: Vec<_> = self
            .utxos
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|u| !u.reserved && u.amount_sat >= min_sat && u.provenance.is_spendable())
            .cloned()
            .collect();
        available.sort_by_key(|utxo| std::cmp::Reverse(utxo.amount_sat));
        let mut sel = Vec::new();
        let mut total = 0u64;
        for utxo in available {
            if total >= target_sat {
                break;
            }
            total += utxo.amount_sat;
            sel.push(utxo);
        }
        if total < target_sat {
            Err(WalletError::InsufficientFunds {
                available: total,
                needed: target_sat,
            })
        } else {
            Ok(sel)
        }
    }

    pub fn reserve_utxos(&self, ops: &[OutPoint], reason: &str) {
        let mut u = self.utxos.lock().unwrap_or_else(|e| e.into_inner());
        for op in ops {
            if let Some(x) = u.get_mut(op) {
                x.reserved = true;
                x.reserved_for = Some(reason.to_string());
            }
        }
    }
    pub fn unreserve_utxos(&self, ops: &[OutPoint]) {
        let mut u = self.utxos.lock().unwrap_or_else(|e| e.into_inner());
        for op in ops {
            if let Some(x) = u.get_mut(op) {
                x.reserved = false;
                x.reserved_for = None;
            }
        }
    }

    pub fn sign_with_key(
        &self,
        path: &Bip86Path,
        msg: &[u8; 32],
    ) -> Result<secp256k1::ecdsa::Signature, WalletError> {
        let sk = self.derive_private_key(path)?;
        let msg = secp256k1::Message::from_digest_slice(msg.as_ref())
            .map_err(|e| WalletError::SigningFailed(e.to_string()))?;
        Ok(self.secp.sign_ecdsa(&msg, &sk))
    }

    pub fn mark_seal_used(&self, seal: &BitcoinSealPoint) -> Result<(), WalletError> {
        let mut used = self.used_seals.lock().unwrap_or_else(|e| e.into_inner());
        let key = seal.to_vec();
        if used.contains(&key) {
            return Err(WalletError::SealAlreadyUsed);
        }
        used.insert(key);
        Ok(())
    }
    pub fn is_seal_used(&self, seal: &BitcoinSealPoint) -> bool {
        self.used_seals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&seal.to_vec())
    }

    pub fn network(&self) -> Network {
        self.network
    }
    pub fn secp(&self) -> &Secp256k1<secp256k1::All> {
        &self.secp
    }
    pub fn get_utxo(&self, op: &OutPoint) -> Option<WalletUtxo> {
        self.utxos
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(op)
            .cloned()
    }
    pub fn list_utxos(&self) -> Vec<WalletUtxo> {
        self.utxos
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Clear all UTXOs from the wallet (for refreshing from chain)
    pub fn clear_utxos(&self) {
        self.utxos.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Scan the blockchain for UTXOs belonging to this wallet's addresses
    ///
    /// This method checks all derived addresses up to `address_gap_limit` consecutive
    /// unused addresses to find UTXOs on the chain and add them to the wallet.
    ///
    /// Requires a callback that checks whether a given address has UTXOs and returns them.
    pub fn scan_chain_for_utxos<F>(
        &self,
        mut fetch_utxos: F,
        account: u32,
        address_gap_limit: usize,
    ) -> Result<usize, WalletError>
    where
        F: FnMut(&Address) -> Result<Vec<(OutPoint, u64)>, String>,
    {
        let mut discovered_count = 0;
        let mut consecutive_empty = 0;
        let mut index = 0;

        loop {
            if consecutive_empty >= address_gap_limit {
                break;
            }

            let path = Bip86Path::external(account, index);
            let derived = self.derive_key(&path)?;

            match fetch_utxos(&derived.address) {
                Ok(utxos) => {
                    if utxos.is_empty() {
                        consecutive_empty += 1;
                    } else {
                        consecutive_empty = 0;
                        for (outpoint, amount) in utxos {
                            self.add_utxo_with_provenance(
                                outpoint,
                                amount,
                                path.clone(),
                                None,
                                None,
                                UtxoProvenance::RpcWallet,
                            );
                            discovered_count += 1;
                        }
                    }
                }
                Err(e) => {
                    return Err(WalletError::KeyDerivationFailed(e));
                }
            }

            index += 1;
        }

        Ok(discovered_count)
    }

    /// Add a UTXO to the wallet from a known address and outpoint
    ///
    /// This is used when you manually fund an address by sending bitcoin to it,
    /// then register the UTXO once it's confirmed.
    pub fn add_utxo_from_address(
        &self,
        outpoint: OutPoint,
        amount_sat: u64,
        account: u32,
        index: u32,
    ) -> Result<(), WalletError> {
        let path = Bip86Path::external(account, index);
        let _derived = self.derive_key(&path)?;

        // Verify the outpoint belongs to this address
        // (In production, you'd verify the script_pubkey matches)
        self.add_utxo_with_provenance(
            outpoint,
            amount_sat,
            path,
            None,
            None,
            UtxoProvenance::ImportedFunding,
        );
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("No available UTXOs")]
    NoAvailableUtxos,
    #[error("Insufficient funds: available {available} sat, needed {needed} sat")]
    InsufficientFunds { available: u64, needed: u64 },
    #[error("UTXO not found")]
    UtxoNotFound,
    #[error("Seal already used")]
    SealAlreadyUsed,
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("PSBT error: {0}")]
    PsbtError(String),
    #[error("Script error: {0}")]
    ScriptError(String),
}

#[cfg(test)]
pub struct MockSealWallet {
    pub utxos: Vec<(OutPoint, u64)>,
    pub used_seals: Mutex<HashSet<Vec<u8>>>,
}

#[cfg(test)]
impl MockSealWallet {
    pub fn new() -> Self {
        Self {
            utxos: Vec::new(),
            used_seals: Mutex::new(HashSet::new()),
        }
    }
    pub fn add_utxo(&mut self, txid: [u8; 32], vout: u32, amount_sat: u64) {
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid));
        self.utxos.push((OutPoint::new(txid, vout), amount_sat));
    }
}

#[cfg(test)]
impl Default for MockSealWallet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_hashes::Hash;
    #[test]
    fn test_wallet_creation_from_random() {
        let w = SealWallet::generate_random(Network::Signet);
        assert_eq!(w.balance(), 0);
    }
    #[test]
    fn test_wallet_key_derivation() {
        let w = SealWallet::generate_random(Network::Signet);
        let k = w.derive_key(&Bip86Path::external(0, 0)).unwrap();
        // Signet taproot addresses start with "tb1p" (testnet bech32m)
        assert!(k.address.to_string().starts_with("tb1p"));
        assert!(k.address.script_pubkey().is_witness_program());
    }
    #[test]
    fn test_wallet_key_derivation_deterministic() {
        let seed = [42u8; 64];
        let w1 = SealWallet::from_seed(&seed, Network::Signet).unwrap();
        let w2 = SealWallet::from_seed(&seed, Network::Signet).unwrap();
        let k1 = w1.derive_key(&Bip86Path::external(0, 0)).unwrap();
        let k2 = w2.derive_key(&Bip86Path::external(0, 0)).unwrap();
        assert_eq!(k1.output_key, k2.output_key);
        assert_eq!(k1.address, k2.address);
    }
    #[test]
    fn test_wallet_different_paths() {
        let w = SealWallet::generate_random(Network::Signet);
        let k0 = w.derive_key(&Bip86Path::external(0, 0)).unwrap();
        let k1 = w.derive_key(&Bip86Path::external(0, 1)).unwrap();
        let k2 = w.derive_key(&Bip86Path::external(1, 0)).unwrap();
        assert_ne!(k0.output_key, k1.output_key);
        assert_ne!(k0.output_key, k2.output_key);
        assert_ne!(k1.output_key, k2.output_key);
    }
    #[test]
    fn test_wallet_utxo_selection() {
        let w = SealWallet::generate_random(Network::Signet);
        let path = Bip86Path::external(0, 0);
        let t1 = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]));
        let t2 = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([2u8; 32]));
        let t3 = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([3u8; 32]));
        w.add_utxo_with_provenance(
            OutPoint::new(t1, 0),
            50_000,
            path.clone(),
            None,
            None,
            UtxoProvenance::RpcWallet,
        );
        w.add_utxo_with_provenance(
            OutPoint::new(t2, 0),
            30_000,
            path.clone(),
            None,
            None,
            UtxoProvenance::RpcWallet,
        );
        w.add_utxo_with_provenance(
            OutPoint::new(t3, 0),
            20_000,
            path,
            None,
            None,
            UtxoProvenance::RpcWallet,
        );
        let sel = w.select_utxos(70_000).unwrap();
        assert_eq!(sel.len(), 2);
        assert_eq!(sel.iter().map(|u| u.amount_sat).sum::<u64>(), 80_000);
    }

    #[test]
    fn test_wallet_utxo_selection_filters_non_spendable() {
        let w = SealWallet::generate_random(Network::Signet);
        let path = Bip86Path::external(0, 0);
        let t1 = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]));
        let t2 = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([2u8; 32]));
        let t3 = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([3u8; 32]));
        // Add spendable UTXO
        w.add_utxo_with_provenance(
            OutPoint::new(t1, 0),
            50_000,
            path.clone(),
            None,
            None,
            UtxoProvenance::RpcWallet,
        );
        // Add SanadAnchor (non-spendable)
        w.add_utxo_with_provenance(
            OutPoint::new(t2, 0),
            100_000,
            path.clone(),
            None,
            None,
            UtxoProvenance::SanadAnchor,
        );
        // Add ConsumedSeal (non-spendable)
        w.add_utxo_with_provenance(
            OutPoint::new(t3, 0),
            100_000,
            path,
            None,
            None,
            UtxoProvenance::ConsumedSeal,
        );

        // Should only select the spendable UTXO, not the SanadAnchor or ConsumedSeal
        let sel = w.select_utxos(30_000).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].outpoint.vout, 0);
        assert_eq!(sel[0].provenance, UtxoProvenance::RpcWallet);
    }

    #[test]
    fn test_wallet_utxo_selection_filters_unknown() {
        let w = SealWallet::generate_random(Network::Signet);
        let path = Bip86Path::external(0, 0);
        let t1 = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]));
        let t2 = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([2u8; 32]));
        // Add spendable UTXO
        w.add_utxo_with_provenance(
            OutPoint::new(t1, 0),
            50_000,
            path.clone(),
            None,
            None,
            UtxoProvenance::RpcWallet,
        );
        // Add Unknown (non-spendable)
        w.add_utxo_with_provenance(
            OutPoint::new(t2, 0),
            100_000,
            path,
            None,
            None,
            UtxoProvenance::Unknown,
        );

        // Should only select the spendable UTXO, not the Unknown
        let sel = w.select_utxos(30_000).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].provenance, UtxoProvenance::RpcWallet);
    }
    #[test]
    fn test_wallet_insufficient_funds() {
        let w = SealWallet::generate_random(Network::Signet);
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]));
        w.add_utxo_with_provenance(
            OutPoint::new(txid, 0),
            10_000,
            Bip86Path::external(0, 0),
            None,
            None,
            UtxoProvenance::RpcWallet,
        );
        assert!(w.select_utxos(20_000).is_err());
    }
    #[test]
    fn test_wallet_reserve_utxos() {
        let w = SealWallet::generate_random(Network::Signet);
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]));
        let op = OutPoint::new(txid, 0);
        w.add_utxo_with_provenance(
            op,
            100_000,
            Bip86Path::external(0, 0),
            None,
            None,
            UtxoProvenance::RpcWallet,
        );
        assert_eq!(w.balance(), 100_000);
        w.reserve_utxos(&[op], "test");
        assert_eq!(w.balance(), 0);
        w.unreserve_utxos(&[op]);
        assert_eq!(w.balance(), 100_000);
    }
    #[test]
    fn test_seal_lifecycle() {
        let w = SealWallet::generate_random(Network::Signet);
        let seal = BitcoinSealPoint::new([1u8; 32], 0, Some(42));
        assert!(!w.is_seal_used(&seal));
        w.mark_seal_used(&seal).unwrap();
        assert!(w.is_seal_used(&seal));
        assert!(w.mark_seal_used(&seal).is_err());
    }
    #[test]
    fn test_derivation_path_string() {
        assert_eq!(
            Bip86Path::new(0, 0, 5).to_string(&Network::Bitcoin),
            "m/86'/0'/0'/0/5"
        );
    }
    #[test]
    fn test_wallet_with_sample_data() {
        let mut w = MockSealWallet::new();
        w.add_utxo([1u8; 32], 0, 100_000);
        assert_eq!(w.utxos.len(), 1);
    }
}
