//! Common contract types shared across all chains

use serde::{Deserialize, Serialize};

/// Contract version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVersion {
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: u32,
    /// Patch version
    pub patch: u32,
}

impl ContractVersion {
    /// Create a new contract version
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Current contract version
    pub const fn current() -> Self {
        Self {
            major: 1,
            minor: 0,
            patch: 0,
        }
    }
}

/// Contract address (chain-agnostic)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractAddress(pub Vec<u8>);

impl ContractAddress {
    /// Create a new contract address from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the address as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }
}

impl From<[u8; 20]> for ContractAddress {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<[u8; 32]> for ContractAddress {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes.to_vec())
    }
}

/// Contract function selector (4-byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FunctionSelector(pub [u8; 4]);

impl FunctionSelector {
    /// Create from bytes
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Contract event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEvent {
    /// Event name
    pub name: String,
    /// Event signature (for typed hashing)
    pub signature: String,
    /// Whether the event is anonymous
    pub anonymous: bool,
    /// Event parameters
    pub inputs: Vec<EventInput>,
}

/// Event input parameter
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventInput {
    /// Parameter name
    pub name: String,
    /// Parameter type
    pub r#type: String,
    /// Whether the parameter is indexed
    pub indexed: bool,
}

/// Contract method
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractMethod {
    /// Method name
    pub name: String,
    /// Method signature
    pub signature: String,
    /// Input parameters
    pub inputs: Vec<MethodInput>,
    /// Output types
    pub outputs: Vec<MethodOutput>,
}

/// Method input parameter
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodInput {
    /// Parameter name
    pub name: String,
    /// Parameter type
    pub r#type: String,
}

/// Method output parameter
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodOutput {
    /// Parameter type
    pub r#type: String,
}

/// Contract ABI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAbi {
    /// Contract name
    pub name: String,
    /// Contract version
    pub version: ContractVersion,
    /// Contract events
    pub events: Vec<ContractEvent>,
    /// Contract methods
    pub methods: Vec<ContractMethod>,
}

impl ContractAbi {
    /// Create a new contract ABI
    pub fn new(name: String, version: ContractVersion) -> Self {
        Self {
            name,
            version,
            events: Vec::new(),
            methods: Vec::new(),
        }
    }

    /// Add an event to the ABI
    pub fn add_event(&mut self, event: ContractEvent) {
        self.events.push(event);
    }

    /// Add a method to the ABI
    pub fn add_method(&mut self, method: ContractMethod) {
        self.methods.push(method);
    }

    /// Get a method by name
    pub fn get_method(&self, name: &str) -> Option<&ContractMethod> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// Get an event by name
    pub fn get_event(&self, name: &str) -> Option<&ContractEvent> {
        self.events.iter().find(|e| e.name == name)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}
