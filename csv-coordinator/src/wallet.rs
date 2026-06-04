//! Wallet operations for chain-specific functionality
//!
//! This module provides a facade over chain adapter wallet operations,
//! allowing csv-cli to use wallet functionality without directly depending on chain adapters.

/// Bitcoin wallet operations
#[cfg(feature = "bitcoin")]
pub mod bitcoin {
    use csv_bitcoin;
    use bitcoin::{hashes::Hash, Network as BtcNetwork, OutPoint, Txid};

    /// Network type for wallet operations
    #[derive(Debug, Clone, Copy)]
    pub enum Network {
        Main,
        Test,
        Dev,
    }

    /// Comprehensive UTXO data with wallet integration
    #[derive(Debug, Clone)]
    pub struct WalletUtxo {
        pub txid: String,
        pub vout: u32,
        pub value: u64,
        pub scriptpubkey_hex: Option<String>,
        pub outpoint: OutPoint,
        pub derivation_path: csv_bitcoin::wallet::Bip86Path,
    }

    /// Derive a Bitcoin funding address from seed
    pub fn derive_funding_address(
        seed: &[u8],
        network: Network,
        account: u32,
        index: u32,
    ) -> anyhow::Result<String> {
        let btc_network = match network {
            Network::Main => BtcNetwork::Bitcoin,
            Network::Test => BtcNetwork::Signet,
            Network::Dev => BtcNetwork::Regtest,
        };

        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(anyhow::anyhow!("Seed must be at least 64 bytes"));
        }

        let wallet = csv_bitcoin::SealWallet::from_seed(&seed_array, btc_network)
            .map_err(|e| anyhow::anyhow!("Failed to create wallet from seed: {}", e))?;

        let key = wallet.get_funding_address(account, index)
            .map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

        Ok(key.address.to_string())
    }

    /// Scan for UTXOs on Bitcoin network with comprehensive wallet integration
    /// Returns the wallet with UTXOs added for signing operations
    pub async fn scan_utxos_with_wallet(
        seed: &[u8],
        network: Network,
        account: u32,
        gap_limit: usize,
        rpc_url: &str,
    ) -> anyhow::Result<(csv_bitcoin::SealWallet, Vec<WalletUtxo>)> {
        let btc_network = match network {
            Network::Main => BtcNetwork::Bitcoin,
            Network::Test => BtcNetwork::Signet,
            Network::Dev => BtcNetwork::Regtest,
        };

        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(anyhow::anyhow!("Seed must be at least 64 bytes"));
        }

        let wallet = csv_bitcoin::SealWallet::from_seed(&seed_array, btc_network)
            .map_err(|e| anyhow::anyhow!("Failed to create wallet from seed: {}", e))?;

        let mut wallet_utxos = Vec::new();

        for index in 0..gap_limit as u32 {
            let key = wallet.get_funding_address(account, index)
                .map_err(|e| anyhow::anyhow!("Failed to derive address at index {}: {}", index, e))?;
            let address_str = key.address.to_string();

            // Fetch UTXOs for this address using mempool RPC
            let url = format!("{}/address/{}/utxo", rpc_url, address_str);
            let response = reqwest::get(&url).await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let utxo_list: Vec<serde_json::Value> = resp.json()
                        .await
                        .unwrap_or_default();
                    
                    if !utxo_list.is_empty() {
                        for utxo in utxo_list {
                            let txid = utxo.get("txid").and_then(|v: &serde_json::Value| v.as_str()).unwrap_or("");
                            let vout = utxo.get("vout").and_then(|v: &serde_json::Value| v.as_u64()).unwrap_or(0) as u32;
                            let value = utxo.get("value").and_then(|v: &serde_json::Value| v.as_u64()).unwrap_or(0);

                            // Fetch scriptPubKey from the transaction endpoint
                            // The /address/{addr}/utxo endpoint doesn't return scriptpubkey, so we need to fetch it from /tx/{txid}
                            let scriptpubkey_hex = if !txid.is_empty() {
                                let tx_url = format!("{}/tx/{}", rpc_url, txid);
                                if let Ok(tx_resp) = reqwest::get(&tx_url).await {
                                    if tx_resp.status().is_success() {
                                        if let Ok(tx_data) = tx_resp.json::<serde_json::Value>().await {
                                            if let Some(vouts) = tx_data.get("vout").and_then(|v: &serde_json::Value| v.as_array()) {
                                                if let Some(vout_data) = vouts.get(vout as usize) {
                                                    vout_data.get("scriptpubkey").and_then(|v: &serde_json::Value| v.as_str()).map(|s: &str| s.to_string())
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            // Create OutPoint - mempool.space returns txids in display format (reversed bytes)
                            // Reverse to get internal byte order for Txid construction
                            let txid_bytes = match hex::decode(txid) {
                                Ok(bytes) if bytes.len() == 32 => {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&bytes);
                                    arr
                                },
                                _ => continue,
                            };
                            let mut internal_txid = txid_bytes;
                            internal_txid.reverse();
                            let txid_hash = Txid::from_byte_array(internal_txid);
                            let outpoint = OutPoint {
                                txid: txid_hash,
                                vout,
                            };

                            // Create Bip86Path
                            let derivation_path = csv_bitcoin::wallet::Bip86Path::external(account, index);

                            // Add UTXO to wallet with scriptPubKey if available
                            if let Some(ref spk_hex) = scriptpubkey_hex {
                                if let Ok(spk_bytes) = hex::decode(spk_hex) {
                                    let script_pubkey = bitcoin::ScriptBuf::from_bytes(spk_bytes);
                                    wallet.add_utxo_with_scriptpubkey(outpoint, value, derivation_path.clone(), Some(script_pubkey));
                                } else {
                                    wallet.add_utxo(outpoint, value, derivation_path.clone());
                                }
                            } else {
                                wallet.add_utxo(outpoint, value, derivation_path.clone());
                            }

                            wallet_utxos.push(WalletUtxo {
                                txid: txid.to_string(),
                                vout,
                                value,
                                scriptpubkey_hex,
                                outpoint,
                                derivation_path,
                            });
                        }
                    }
                }
                Ok(_resp) => {
                    // Non-success status - skip this address
                    continue;
                }
                Err(_) => {
                    // Request failed - skip this address
                    continue;
                }
            }
        }

        Ok((wallet, wallet_utxos))
    }

    /// Validate a UTXO on-chain - check transaction exists, is confirmed, and is unspent
    pub async fn validate_utxo_onchain(
        txid: &str,
        vout: u32,
        rpc_url: &str,
    ) -> anyhow::Result<(bool, bool, bool, Option<serde_json::Value>)> {
        // The txid from scan is in display format (reversed bytes from internal Bitcoin representation)
        // mempool.space API expects display format, so use it directly
        let tx_url = format!("{}/tx/{}", rpc_url, txid);
        let tx_response = reqwest::get(&tx_url).await;
        
        let (tx_exists, tx_data, is_confirmed) = match tx_response {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let status = data.get("status").and_then(|s| s.as_object());
                    let confirmed = status.and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false);
                    (true, Some(data), confirmed)
                } else {
                    (true, None, false)
                }
            }
            Ok(resp) if resp.status() == 404 => (false, None, false),
            Ok(_) => (true, None, false),
            Err(_) => (true, None, false),
        };

        if !tx_exists {
            return Ok((false, false, false, None));
        }

        // Check if UTXO is unspent
        let spend_url = format!("{}/tx/{}/outspend/{}", rpc_url, txid, vout);
        let spend_response = reqwest::get(&spend_url).await;
        
        let is_unspent = match spend_response {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(spend_status) = resp.json::<serde_json::Value>().await {
                    let spent = spend_status.get("spent").and_then(|v: &serde_json::Value| v.as_bool()).unwrap_or(false);
                    !spent
                } else {
                    false
                }
            }
            _ => false,
        };

        Ok((tx_exists, is_confirmed, is_unspent, tx_data))
    }

    /// Scan for UTXOs on Bitcoin network with comprehensive verification
    pub async fn scan_utxos(
        seed: &[u8],
        network: Network,
        account: u32,
        gap_limit: usize,
        rpc_url: &str,
    ) -> anyhow::Result<Vec<(String, u32, u64, Option<String>)>> {
        let btc_network = match network {
            Network::Main => BtcNetwork::Bitcoin,
            Network::Test => BtcNetwork::Signet,
            Network::Dev => BtcNetwork::Regtest,
        };

        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(anyhow::anyhow!("Seed must be at least 64 bytes"));
        }

        let wallet = csv_bitcoin::SealWallet::from_seed(&seed_array, btc_network)
            .map_err(|e| anyhow::anyhow!("Failed to create wallet from seed: {}", e))?;

        let mut utxos = Vec::new();

        for index in 0..gap_limit as u32 {
            let key = wallet.get_funding_address(account, index)
                .map_err(|e| anyhow::anyhow!("Failed to derive address at index {}: {}", index, e))?;
            let address_str = key.address.to_string();

            // Fetch UTXOs for this address using mempool RPC
            let url = format!("{}/address/{}/utxo", rpc_url, address_str);
            let response = reqwest::get(&url).await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let utxo_list: Vec<serde_json::Value> = resp.json()
                        .await
                        .unwrap_or_default();
                    
                    if !utxo_list.is_empty() {
                        for utxo in utxo_list {
                            let txid = utxo.get("txid").and_then(|v: &serde_json::Value| v.as_str()).unwrap_or("");
                            let vout = utxo.get("vout").and_then(|v: &serde_json::Value| v.as_u64()).unwrap_or(0) as u32;
                            let value = utxo.get("value").and_then(|v: &serde_json::Value| v.as_u64()).unwrap_or(0);

                            // Fetch scriptPubKey from the transaction endpoint
                            // The /address/{addr}/utxo endpoint doesn't return scriptpubkey, so we need to fetch it from /tx/{txid}
                            let scriptpubkey_hex = if !txid.is_empty() {
                                let tx_url = format!("{}/tx/{}", rpc_url, txid);
                                if let Ok(tx_resp) = reqwest::get(&tx_url).await {
                                    if tx_resp.status().is_success() {
                                        if let Ok(tx_data) = tx_resp.json::<serde_json::Value>().await {
                                            if let Some(vouts) = tx_data.get("vout").and_then(|v: &serde_json::Value| v.as_array()) {
                                                if let Some(vout_data) = vouts.get(vout as usize) {
                                                    vout_data.get("scriptpubkey").and_then(|v: &serde_json::Value| v.as_str()).map(|s: &str| s.to_string())
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            utxos.push((txid.to_string(), vout, value, scriptpubkey_hex));
                        }
                    }
                }
                Ok(_resp) => {
                    // Non-success status - skip this address
                    continue;
                }
                Err(_) => {
                    // Request failed - skip this address
                    continue;
                }
            }
        }

        Ok(utxos)
    }
}

/// Ethereum wallet operations
#[cfg(feature = "ethereum")]
pub mod ethereum {
    use csv_hash::ChainId;
    use csv_keys::bip44::derive_address_from_key;
    use csv_keys::bip44::derive_all_chain_keys;

    /// Network type for wallet operations
    #[derive(Debug, Clone, Copy)]
    pub enum Network {
        Main,
        Test,
        Dev,
    }

    /// Derive an Ethereum funding address from seed
    pub fn derive_funding_address(
        seed: &[u8],
        _network: Network,
        account: u32,
        _index: u32,
    ) -> anyhow::Result<String> {
        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(anyhow::anyhow!("Seed must be at least 64 bytes"));
        }

        // Derive keys for all chains
        let keys = derive_all_chain_keys(&seed_array, account);

        // Get the key for Ethereum
        let core_chain = ChainId::new("ethereum");
        let key = keys
            .get(&core_chain)
            .ok_or_else(|| anyhow::anyhow!("Failed to derive key for ethereum"))?;

        // Derive address from key
        let address = derive_address_from_key(key.as_bytes(), &core_chain)
            .map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

        Ok(address)
    }
}

/// Sui wallet operations
#[cfg(feature = "sui")]
pub mod sui {
    use csv_hash::ChainId;
    use csv_keys::bip44::derive_address_from_key;
    use csv_keys::bip44::derive_all_chain_keys;

    /// Network type for wallet operations
    #[derive(Debug, Clone, Copy)]
    pub enum Network {
        Main,
        Test,
        Dev,
    }

    /// Derive a Sui funding address from seed
    pub fn derive_funding_address(
        seed: &[u8],
        _network: Network,
        account: u32,
        _index: u32,
    ) -> anyhow::Result<String> {
        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(anyhow::anyhow!("Seed must be at least 64 bytes"));
        }

        // Derive keys for all chains
        let keys = derive_all_chain_keys(&seed_array, account);

        // Get the key for Sui
        let core_chain = ChainId::new("sui");
        let key = keys
            .get(&core_chain)
            .ok_or_else(|| anyhow::anyhow!("Failed to derive key for sui"))?;

        // Derive address from key
        let address = derive_address_from_key(key.as_bytes(), &core_chain)
            .map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

        Ok(address)
    }
}

/// Aptos wallet operations
#[cfg(feature = "aptos")]
pub mod aptos {
    use csv_hash::ChainId;
    use csv_keys::bip44::derive_address_from_key;
    use csv_keys::bip44::derive_all_chain_keys;

    /// Network type for wallet operations
    #[derive(Debug, Clone, Copy)]
    pub enum Network {
        Main,
        Test,
        Dev,
    }

    /// Derive an Aptos funding address from seed
    pub fn derive_funding_address(
        seed: &[u8],
        _network: Network,
        account: u32,
        _index: u32,
    ) -> anyhow::Result<String> {
        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(anyhow::anyhow!("Seed must be at least 64 bytes"));
        }

        // Derive keys for all chains
        let keys = derive_all_chain_keys(&seed_array, account);

        // Get the key for Aptos
        let core_chain = ChainId::new("aptos");
        let key = keys
            .get(&core_chain)
            .ok_or_else(|| anyhow::anyhow!("Failed to derive key for aptos"))?;

        // Derive address from key
        let address = derive_address_from_key(key.as_bytes(), &core_chain)
            .map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

        Ok(address)
    }
}

/// Solana wallet operations
#[cfg(feature = "solana")]
pub mod solana {
    use csv_hash::ChainId;
    use csv_keys::bip44::derive_address_from_key;
    use csv_keys::bip44::derive_all_chain_keys;

    /// Network type for wallet operations
    #[derive(Debug, Clone, Copy)]
    pub enum Network {
        Main,
        Test,
        Dev,
    }

    /// Derive a Solana funding address from seed
    pub fn derive_funding_address(
        seed: &[u8],
        _network: Network,
        account: u32,
        _index: u32,
    ) -> anyhow::Result<String> {
        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(anyhow::anyhow!("Seed must be at least 64 bytes"));
        }

        // Derive keys for all chains
        let keys = derive_all_chain_keys(&seed_array, account);

        // Get the key for Solana
        let core_chain = ChainId::new("solana");
        let key = keys
            .get(&core_chain)
            .ok_or_else(|| anyhow::anyhow!("Failed to derive key for solana"))?;

        // Derive address from key
        let address = derive_address_from_key(key.as_bytes(), &core_chain)
            .map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

        Ok(address)
    }
}
