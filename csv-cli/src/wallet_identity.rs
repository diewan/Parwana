use std::collections::HashMap;

use anyhow::Result;
use csv_hash::ChainId;
use csv_protocol::secret::SharedSecretHandle;

use crate::config::Chain;
use crate::state::UnifiedStateManager;

pub(crate) struct WalletIdentity {
    seed: [u8; 64],
}

impl WalletIdentity {
    pub(crate) fn from_state(state: &UnifiedStateManager) -> Result<Self> {
        let phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No wallet mnemonic found. Initialize or import a wallet first.")
        })?;
        Self::from_mnemonic(phrase)
    }

    pub(crate) fn from_mnemonic(phrase: &str) -> Result<Self> {
        let mnemonic = csv_keys::Mnemonic::from_phrase(phrase)
            .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;
        Ok(Self {
            seed: *mnemonic.to_seed(None).as_bytes(),
        })
    }

    pub(crate) fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    pub(crate) fn bitcoin_seed_hex(&self) -> String {
        hex::encode(self.seed)
    }

    pub(crate) fn address(&self, chain: &Chain, account: u32, index: u32) -> Result<String> {
        let chain_id = ChainId::new(chain.as_str());
        if chain.as_str() == "bitcoin" {
            let _factory = csv_coordinator::init_wallet_factory();
            let operations = csv_coordinator::get_wallet_operations(&chain_id)
                .ok_or_else(|| anyhow::anyhow!("Bitcoin wallet operations are unavailable"))?;
            return operations
                .derive_address(&self.seed, account, index)
                .map_err(|e| anyhow::anyhow!("Failed to derive Bitcoin address: {}", e));
        }

        let key = csv_keys::bip44::derive_key(&self.seed, &chain_id, account, index)
            .map_err(|e| anyhow::anyhow!("Failed to derive {} key: {}", chain, e))?;
        csv_keys::bip44::derive_address_from_key(key.expose_secret(), &chain_id)
            .map_err(|e| anyhow::anyhow!("Failed to derive {} address: {}", chain, e))
    }

    pub(crate) fn signing_handle(
        &self,
        chain: &Chain,
        account: u32,
        index: u32,
        _state: &UnifiedStateManager,
    ) -> Result<SharedSecretHandle> {
        if chain.as_str() == "bitcoin" {
            return Ok(SharedSecretHandle::from_seed(self.seed));
        }

        let key =
            csv_keys::bip44::derive_key(&self.seed, &ChainId::new(chain.as_str()), account, index)
                .map_err(|e| anyhow::anyhow!("Failed to derive {} signing key: {}", chain, e))?;

        let expected = self.address(chain, account, index)?;
        let actual = csv_keys::bip44::derive_address_from_key(
            key.expose_secret(),
            &ChainId::new(chain.as_str()),
        )
        .map_err(|e| anyhow::anyhow!("Failed to verify {} signing key: {}", chain, e))?;
        if actual != expected {
            return Err(anyhow::anyhow!(
                "Stored {} signing key resolves to {}, but wallet account resolves to {}; \
                 refusing to sign with a different account",
                chain,
                actual,
                expected
            ));
        }

        Ok(SharedSecretHandle::from_bytes(*key.expose_secret()))
    }

    pub(crate) fn signing_map(
        &self,
        chains: &[(&Chain, u32, u32)],
        state: &UnifiedStateManager,
    ) -> Result<HashMap<String, SharedSecretHandle>> {
        let mut result = HashMap::new();
        for (chain, account, index) in chains {
            result.insert(
                chain.as_str().to_string(),
                self.signing_handle(chain, *account, *index, state)?,
            );
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_bitcoin_signer_address_matches_wallet_address() {
        let mnemonic = csv_keys::Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let identity = WalletIdentity {
            seed: *mnemonic.to_seed(None).as_bytes(),
        };
        for name in ["ethereum", "sui", "aptos", "solana"] {
            let chain = Chain::new(name);
            let key =
                csv_keys::bip44::derive_key(identity.seed(), &ChainId::new(name), 0, 0).unwrap();
            let signer_address =
                csv_keys::bip44::derive_address_from_key(key.expose_secret(), &ChainId::new(name))
                    .unwrap();
            assert_eq!(identity.address(&chain, 0, 0).unwrap(), signer_address);
        }
    }
}
