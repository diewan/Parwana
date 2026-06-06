//! Tests for Bitcoin adapter factory

#[cfg(test)]
mod tests {
    use csv_adapter_factory::{AdapterFactory, AdapterConfig, BitcoinFactory, NetworkType, RpcEndpoint, RpcProtocol};
    use csv_hash::chain_id::ChainId;

    #[tokio::test]
    #[ignore = "Requires network access to actual Bitcoin RPC"]
    async fn test_bitcoin_factory_creates_adapters() {
        let factory = BitcoinFactory;
        let config = AdapterConfig {
            chain_id: ChainId::new("bitcoin"),
            network: NetworkType::Testnet,
            rpc_endpoints: vec![RpcEndpoint {
                url: "https://bitcoin-signet.g.alchemy.com/v2/".to_string(),
                protocol: RpcProtocol::Rest,
                api_key: None,
                priority: 0,
            }],
            private_key: Some("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string()),
            account: 0,
            index: 0,
            contract_address: None,
            program_id: None,
            utxos: vec![],
            sanad_seals: vec![],
        };

        let result = factory.create_adapter(config).await;
        assert!(result.is_ok(), "Factory should create Bitcoin adapter successfully");
        
        let adapter_result = result.unwrap();
        // chain_backend is Arc<dyn ChainBackend>, always present if creation succeeds
        assert!(adapter_result.chain_adapter.is_some(), "ChainAdapter should be created");
    }

    #[tokio::test]
    async fn test_bitcoin_factory_requires_rest_endpoint() {
        let factory = BitcoinFactory;
        let config = AdapterConfig {
            chain_id: ChainId::new("bitcoin"),
            network: NetworkType::Testnet,
            rpc_endpoints: vec![RpcEndpoint {
                url: "https://example.com".to_string(),
                protocol: RpcProtocol::Grpc,
                api_key: None,
                priority: 0,
            }],
            private_key: Some("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string()),
            account: 0,
            index: 0,
            contract_address: None,
            program_id: None,
            utxos: vec![],
            sanad_seals: vec![],
        };

        let result = factory.create_adapter(config).await;
        assert!(result.is_err(), "Factory should fail without REST endpoint");
    }

    #[tokio::test]
    async fn test_bitcoin_factory_requires_seed() {
        let factory = BitcoinFactory;
        let config = AdapterConfig {
            chain_id: ChainId::new("bitcoin"),
            network: NetworkType::Testnet,
            rpc_endpoints: vec![RpcEndpoint {
                url: "https://bitcoin-signet.g.alchemy.com/v2/".to_string(),
                protocol: RpcProtocol::Rest,
                api_key: None,
                priority: 0,
            }],
            private_key: None,
            account: 0,
            index: 0,
            contract_address: None,
            program_id: None,
            utxos: vec![],
            sanad_seals: vec![],
        };

        let result = factory.create_adapter(config).await;
        assert!(result.is_err(), "Factory should fail without seed");
    }
}
