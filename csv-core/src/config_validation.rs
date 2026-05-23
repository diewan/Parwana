use crate::chain_config::ChainCapabilities;

/// Validate that runtime config overlays match the compiled capability model.
/// This helper fails startup when config-derived operational parameters do not
/// match the protocol capability definitions.
pub fn validate_config_matches_capabilities(
    config_blocks: u64,
    capabilities: &ChainCapabilities,
) -> Result<(), String> {
    if config_blocks != capabilities.finality_depth as u64 {
        return Err(format!(
            "config.confirmation_blocks ({}) != capabilities.finality_depth ({})",
            config_blocks, capabilities.finality_depth
        ));
    }
    Ok(())
}
