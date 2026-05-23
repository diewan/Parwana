module csv_seal {
    use std::string;
    use sui::object;
    use sui::tx_context;
    use sui::transfer;
    use sui::event;

    /// A seal object that can be consumed exactly once.
    /// Seals are created by the contract owner and distributed to users
    /// who then consume them to anchor commitments.
    struct Seal has key, store {
        id: object::UID,
        /// Nonce for replay resistance
        nonce: u64,
        /// Whether this seal has been consumed
        consumed: bool,
    }

    /// Event emitted when a seal is consumed with a commitment.
    struct AnchorEvent has copy, drop {
        /// The commitment hash being anchored
        commitment: vector<u8>,
        /// The object ID of the consumed seal
        seal_id: address,
        /// Timestamp of the anchoring (Unix epoch milliseconds)
        timestamp_ms: u64,
    }

    /// Dynamic field storing the commitment after seal consumption.
    struct AnchorData has copy, drop, store {
        commitment: vector<u8>,
    }

    /// Create a new seal with the given nonce.
    /// Only the contract owner (or authorized minter) should call this.
    public fun create_seal(nonce: u64, ctx: &mut tx_context::TxContext): Seal {
        Seal {
            id: object::new(ctx),
            nonce,
            consumed: false,
        }
    }

    /// Consume a seal and emit an AnchorEvent with the commitment.
    /// This function deletes the seal's usability by marking it consumed.
    ///
    /// # Arguments
    /// * `seal` - Mutable reference to the seal being consumed
    /// * `commitment` - The commitment hash to anchor
    /// * `ctx` - Transaction context
    public fun consume_seal(
        seal: &mut Seal,
        commitment: vector<u8>,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(!seal.consumed, 0);
        seal.consumed = true;

        event::emit(AnchorEvent {
            commitment,
            seal_id: object::uid_to_inner(&seal.id),
            timestamp_ms: tx_context::epoch(ctx),
        });
    }

    /// Check if a seal exists and has not been consumed.
    public fun is_seal_available(seal: &Seal): bool {
        !seal.consumed
    }

    /// Get the nonce of a seal.
    public fun nonce(seal: &Seal): u64 {
        seal.nonce
    }

    /// Get the object ID of a seal.
    public fun id(seal: &Seal): address {
        object::uid_to_inner(&seal.id)
    }

    /// Check if a seal has been consumed.
    public fun is_consumed(seal: &Seal): bool {
        seal.consumed
    }

    /// Transfer a seal to an address (only if not consumed).
    public fun transfer_seal(seal: Seal, to: address, _ctx: &mut tx_context::TxContext) {
        assert!(!seal.consumed, 0);
        transfer::public_transfer(seal, to);
    }
}