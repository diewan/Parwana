//! Event streaming for CSV operations.
//!
//! The [`EventStream`] provides a real-time stream of events emitted
//! by the CSV client and its managers, using tokio's broadcast channel.
//!
//! # Example
//!
//! ```ignore
//! use csv_sdk::prelude::*;
//! use futures::StreamExt;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! # let client = CsvClient::builder()
//! #     .with_chain(ChainId::new("bitcoin"))
//! #     .with_store_backend(StoreBackend::InMemory)
//! #     .build()?;
//! let mut events = client.watch();
//!
//! while let Some(event) = events.next().await {
//!     match event {
//!         Event::SanadCreated { sanad_id, chain } => {
//!             println!("Sanad created: {:?} on {}", sanad_id, chain);
//!         }
//!         Event::TransferCompleted { transfer_id, sanad_id, to_chain } => {
//!             println!("Transfer {} completed: sanad {:?} -> {}",
//!                      transfer_id, sanad_id, to_chain);
//!         }
//!         Event::Error { message, .. } => {
//!             eprintln!("Error: {}", message);
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use csv_core::{ChainId, SanadId};
#[cfg(feature = "tokio")]
use tokio::sync::broadcast;

/// Events emitted by the CSV client.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// A new Sanad was created.
    SanadCreated {
        /// The unique identifier of the Sanad.
        sanad_id: SanadId,
        /// The chain where the Sanad's seal is anchored.
        chain: ChainId,
    },

    /// A cross-chain transfer is in progress.
    TransferProgress {
        /// The unique transfer identifier.
        transfer_id: String,
        /// Source chain.
        from_chain: ChainId,
        /// Destination chain.
        to_chain: ChainId,
        /// Current step (e.g., "lock", "prove", "submit", "verify").
        step: String,
    },

    /// A cross-chain transfer completed successfully.
    TransferCompleted {
        /// The unique transfer identifier.
        transfer_id: String,
        /// The Sanad ID on the destination chain.
        sanad_id: SanadId,
        /// The destination chain.
        to_chain: ChainId,
    },

    /// An error occurred during an operation.
    Error {
        /// Human-readable error message.
        message: String,
        /// Machine-readable error code.
        code: String,
        /// Whether the operation can be retried.
        retryable: bool,
    },
}

/// A stream of CSV events.
///
/// Created via [`CsvClient::watch()`](crate::client::CsvClient::watch).
///
/// Use [`EventStream::recv()`] to asynchronously receive events.
#[cfg(feature = "tokio")]
pub struct EventStream {
    receiver: broadcast::Receiver<Event>,
}

#[cfg(feature = "tokio")]
impl EventStream {
    pub(crate) fn new(receiver: broadcast::Receiver<Event>) -> Self {
        Self { receiver }
    }

    /// Receive the next event.
    ///
    /// # Errors
    ///
    /// Returns an error if the sender is dropped or the receiver
    /// has lagged (missed events due to a full buffer).
    pub async fn recv(&mut self) -> Result<Event, EventRecvError> {
        self.receiver.recv().await.map_err(|e| match e {
            broadcast::error::RecvError::Closed => EventRecvError::Closed,
            broadcast::error::RecvError::Lagged(n) => EventRecvError::Lagged(n),
        })
    }
}

/// Error type for [`EventStream::recv()`].
#[derive(Debug, Clone, Copy)]
pub enum EventRecvError {
    /// The sender was dropped and no more events will be sent.
    Closed,
    /// The receiver lagged behind and missed this many events.
    Lagged(u64),
}

impl std::fmt::Display for EventRecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "event stream closed"),
            Self::Lagged(n) => write!(f, "receiver lagged behind by {} events", n),
        }
    }
}
