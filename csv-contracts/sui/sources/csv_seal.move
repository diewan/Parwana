module csv_seal::csv_seal {
    use sui::clock::{Self, Clock};
    use sui::event;
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    const E_ALREADY_CONSUMED: u64 = 1;
    const E_ALREADY_LOCKED: u64 = 2;
    const E_NOT_LOCKED: u64 = 3;

    public struct Sanad has key, store {
        id: UID,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        owner: address,
        consumed: bool,
        locked: bool,
        created_ms: u64,
    }

    public struct SanadCreated has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        object_id: address,
    }

    public struct SanadConsumed has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        object_id: address,
    }

    public struct SanadLocked has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        object_id: address,
        destination_chain: vector<u8>,
        destination_owner: vector<u8>,
    }

    public struct SanadRefunded has copy, drop {
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        owner: address,
        object_id: address,
    }

    public entry fun create_seal(
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let owner = tx_context::sender(ctx);
        let sanad = Sanad {
            id: object::new(ctx),
            sanad_id,
            commitment,
            state_root,
            owner,
            consumed: false,
            locked: false,
            created_ms: clock::timestamp_ms(clock),
        };

        event::emit(SanadCreated {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner,
            object_id: object::uid_to_address(&sanad.id),
        });

        transfer::transfer(sanad, owner);
    }

    public entry fun consume_seal(sanad: &mut Sanad, ctx: &mut TxContext) {
        assert!(!sanad.consumed, E_ALREADY_CONSUMED);
        sanad.consumed = true;

        event::emit(SanadConsumed {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner: tx_context::sender(ctx),
            object_id: object::uid_to_address(&sanad.id),
        });
    }

    public entry fun lock_sanad(
        sanad: &mut Sanad,
        destination_chain: vector<u8>,
        destination_owner: vector<u8>,
        ctx: &mut TxContext,
    ) {
        assert!(!sanad.consumed, E_ALREADY_CONSUMED);
        assert!(!sanad.locked, E_ALREADY_LOCKED);
        sanad.locked = true;
        sanad.consumed = true;

        event::emit(SanadLocked {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner: tx_context::sender(ctx),
            object_id: object::uid_to_address(&sanad.id),
            destination_chain,
            destination_owner,
        });
    }

    public entry fun mint_sanad(
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        state_root: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        create_seal(sanad_id, commitment, state_root, clock, ctx);
    }

    public entry fun refund_sanad(sanad: &mut Sanad, ctx: &mut TxContext) {
        assert!(sanad.locked, E_NOT_LOCKED);
        sanad.locked = false;
        sanad.consumed = false;

        event::emit(SanadRefunded {
            sanad_id: sanad.sanad_id,
            commitment: sanad.commitment,
            owner: tx_context::sender(ctx),
            object_id: object::uid_to_address(&sanad.id),
        });
    }
}
