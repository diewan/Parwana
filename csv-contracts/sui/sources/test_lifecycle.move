//! Source-side lifecycle suite: lock / refund / transfer (SUI-LOCK-001).
//!
//! Covers the invariants the cross-chain lock path depends on:
//!   * `lock_sanad` derives `lockEventId` from the executing transaction's digest,
//!     byte-identical to the off-chain `csv_tagged_hash("csv.mint.lock-event.v1", ..)`
//!   * `locked_at` / `refunded_at` are real `Clock` milliseconds, so `REFUND_TIMEOUT_MS`
//!     measures 24 hours and not ~86,400 epochs
//!   * `seal.owner` tracks the object: `transfer_sanad` moves it, and `lock_sanad`
//!     re-anchors it to the sender even after a raw `public_transfer`
//!   * refund is authorized by the current owner only, and only after the timeout

#[test_only]
module csv_seal::test_lifecycle {
    use sui::test_scenario::{Self, Scenario};
    use sui::clock::{Self, Clock};
    use sui::transfer;
    use csv_seal::csv_seal::{Self, Seal};

    const OWNER: address = @0xA1;
    const RECIPIENT: address = @0xBEEF;
    const STRANGER: address = @0xBAD;

    const STATE_LOCKED: u8 = 3;
    const STATE_REFUNDED: u8 = 7;

    const REFUND_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

    /// Abort codes mirrored from `csv_seal` (module constants are not public).
    const ETIMEOUT_NOT_EXPIRED: u64 = 22;
    const ENOT_AUTHORIZED: u64 = 23;

    fun bytes32(fill: u8): vector<u8> {
        let mut v = vector::empty<u8>();
        let mut i = 0u64;
        while (i < 32) {
            vector::push_back(&mut v, fill);
            i = i + 1;
        };
        v
    }

    fun sanad_id(): vector<u8> { bytes32(0x11) }
    fun commitment(): vector<u8> { bytes32(0x22) }
    fun source_chain(): vector<u8> { bytes32(0x33) }
    fun destination_chain(): vector<u8> { bytes32(0x44) }

    /// Create a seal owned by `OWNER` and leave it in the sender's inventory.
    fun begin_with_seal(): Scenario {
        let mut scenario = test_scenario::begin(OWNER);
        {
            let seal = csv_seal::create_seal(
                sanad_id(),
                commitment(),
                OWNER,
                test_scenario::ctx(&mut scenario),
            );
            transfer::public_transfer(seal, OWNER);
        };
        scenario
    }

    fun new_clock(scenario: &mut Scenario): Clock {
        clock::create_for_testing(test_scenario::ctx(scenario))
    }

    // ==================== Lock-event identity ====================

    /// Cross-implementation vector: the same digest and output index fed to the Rust
    /// `csv_tagged_hash("csv.mint.lock-event.v1", tx_digest || u32_le(0))` produces this
    /// value. The Rust side asserts the identical constant.
    #[test]
    fun test_lock_event_id_matches_offchain_vector() {
        let expected = x"c07e02ce3a004f8f071cbb6d89f4e57f3d0aa0f80e848d09af755672e4e67076";
        assert!(csv_seal::lock_event_id_for_digest(bytes32(0x07)) == expected, 0);
    }

    #[test]
    fun test_lock_binds_the_transactions_own_digest() {
        let mut scenario = begin_with_seal();

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let mut seal = test_scenario::take_from_sender<Seal>(&scenario);
            let mut clock = new_clock(&mut scenario);
            clock::set_for_testing(&mut clock, 1_700_000_000_000);

            let ctx = test_scenario::ctx(&mut scenario);
            let expected = csv_seal::lock_event_id_for_digest(*ctx.digest());

            csv_seal::lock_sanad(&mut seal, source_chain(), destination_chain(), &clock, ctx);

            assert!(csv_seal::state(&seal) == STATE_LOCKED, 0);
            assert!(csv_seal::seal_lock_event_id(&seal) == expected, 1);
            assert!(csv_seal::seal_source_chain(&seal) == source_chain(), 2);
            assert!(csv_seal::locked_at(&seal) == 1_700_000_000_000, 3);

            clock::destroy_for_testing(clock);
            test_scenario::return_to_sender(&scenario, seal);
        };

        test_scenario::end(scenario);
    }

    // ==================== Refund timing ====================

    #[test]
    fun test_refund_succeeds_exactly_at_the_24h_boundary() {
        let mut scenario = begin_with_seal();

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let mut seal = test_scenario::take_from_sender<Seal>(&scenario);
            let mut clock = new_clock(&mut scenario);
            clock::set_for_testing(&mut clock, 1_000_000);
            csv_seal::lock_sanad(
                &mut seal, source_chain(), destination_chain(), &clock,
                test_scenario::ctx(&mut scenario),
            );

            // One millisecond short of the timeout the refund must still be closed;
            // at the boundary it opens. Under the old epoch-counter arithmetic this
            // point was ~236 years away and the refund was unreachable.
            clock::set_for_testing(&mut clock, 1_000_000 + REFUND_TIMEOUT_MS);
            csv_seal::refund_sanad(&mut seal, &clock, test_scenario::ctx(&mut scenario));

            assert!(csv_seal::state(&seal) == STATE_REFUNDED, 0);
            assert!(csv_seal::refunded_at(&seal) == 1_000_000 + REFUND_TIMEOUT_MS, 1);

            clock::destroy_for_testing(clock);
            test_scenario::return_to_sender(&scenario, seal);
        };

        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = ETIMEOUT_NOT_EXPIRED, location = csv_seal)]
    fun test_refund_before_timeout_is_rejected() {
        let mut scenario = begin_with_seal();

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let mut seal = test_scenario::take_from_sender<Seal>(&scenario);
            let mut clock = new_clock(&mut scenario);
            clock::set_for_testing(&mut clock, 1_000_000);
            csv_seal::lock_sanad(
                &mut seal, source_chain(), destination_chain(), &clock,
                test_scenario::ctx(&mut scenario),
            );

            clock::set_for_testing(&mut clock, 1_000_000 + REFUND_TIMEOUT_MS - 1);
            csv_seal::refund_sanad(&mut seal, &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_to_sender(&scenario, seal);
        };

        test_scenario::end(scenario);
    }

    // ==================== Ownership tracking ====================

    #[test]
    fun test_transfer_sanad_moves_the_owner_field() {
        let mut scenario = begin_with_seal();

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let seal = test_scenario::take_from_sender<Seal>(&scenario);
            assert!(csv_seal::owner(&seal) == OWNER, 0);
            csv_seal::transfer_sanad(seal, RECIPIENT, test_scenario::ctx(&mut scenario));
        };

        test_scenario::next_tx(&mut scenario, RECIPIENT);
        {
            let seal = test_scenario::take_from_sender<Seal>(&scenario);
            assert!(csv_seal::owner(&seal) == RECIPIENT, 1);
            test_scenario::return_to_sender(&scenario, seal);
        };

        test_scenario::end(scenario);
    }

    /// A raw `public_transfer` bypasses `transfer_sanad`, so `seal.owner` goes stale.
    /// `lock_sanad` re-anchors it to the sender — who, holding a `&mut` on an owned
    /// object, is necessarily the real owner.
    #[test]
    fun test_lock_reanchors_owner_after_raw_transfer() {
        let mut scenario = begin_with_seal();

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let seal = test_scenario::take_from_sender<Seal>(&scenario);
            transfer::public_transfer(seal, RECIPIENT);
        };

        test_scenario::next_tx(&mut scenario, RECIPIENT);
        {
            let mut seal = test_scenario::take_from_sender<Seal>(&scenario);
            assert!(csv_seal::owner(&seal) == OWNER, 0); // stale

            let clock = new_clock(&mut scenario);
            csv_seal::lock_sanad(
                &mut seal, source_chain(), destination_chain(), &clock,
                test_scenario::ctx(&mut scenario),
            );
            assert!(csv_seal::owner(&seal) == RECIPIENT, 1);

            clock::destroy_for_testing(clock);
            test_scenario::return_to_sender(&scenario, seal);
        };

        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = ENOT_AUTHORIZED, location = csv_seal)]
    fun test_refund_by_non_owner_is_rejected() {
        let mut scenario = begin_with_seal();

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let mut seal = test_scenario::take_from_sender<Seal>(&scenario);
            let mut clock = new_clock(&mut scenario);
            clock::set_for_testing(&mut clock, 1_000_000);
            csv_seal::lock_sanad(
                &mut seal, source_chain(), destination_chain(), &clock,
                test_scenario::ctx(&mut scenario),
            );
            clock::destroy_for_testing(clock);
            transfer::public_transfer(seal, STRANGER);
        };

        // STRANGER holds the object but `seal.owner` is OWNER, and a locked seal cannot be
        // re-anchored (lock_sanad aborts on an already-locked seal), so refund stays closed.
        test_scenario::next_tx(&mut scenario, STRANGER);
        {
            let mut seal = test_scenario::take_from_sender<Seal>(&scenario);
            let mut clock = new_clock(&mut scenario);
            clock::set_for_testing(&mut clock, 1_000_000 + REFUND_TIMEOUT_MS);
            csv_seal::refund_sanad(&mut seal, &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_to_sender(&scenario, seal);
        };

        test_scenario::end(scenario);
    }
}
