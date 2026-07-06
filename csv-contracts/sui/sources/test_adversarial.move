//! Adversarial suite for the RFC-0012 thin-registry mint (TRM-SUI-CTR-001).
//!
//! Covers the mint authenticity + anti-replay contract:
//!   * happy path (M=1 and M-of-N)
//!   * duplicate sanadId / nullifier / lockEventId rejection
//!   * forged signature (non-verifier signer)
//!   * tampered field (signature over a different digest than submitted)
//!   * insufficient / duplicate-signer signatures vs threshold
//!   * expired attestation
//!   * fail-closed on an unconfigured registry
//!   * zero-field rejection
//!
//! Signatures are produced with the real secp256k1 test primitives
//! (`secp256k1_keypair_from_seed` / `secp256k1_sign`), so these exercise the native
//! ecrecover path the production mint uses — not mocks.

#[test_only]
module csv_seal::test_adversarial {
    use sui::test_scenario::{Self, Scenario};
    use sui::clock::{Self, Clock};
    use sui::ecdsa_k1;
    use sui::address;
    use sui::hash;
    use csv_seal::csv_seal::{Self, Registry, AdminCap, Seal};

    const ADMIN: address = @0xA1;
    const RECIPIENT: address = @0xBEEF;

    /// secp256k1_sign / ecrecover hash selector: SHA-256 (matches the §9.2 digest).
    const SHA256: u8 = 1;

    // ==================== Fixtures ====================

    /// 32 bytes all set to `fill` (non-zero unless `fill == 0`).
    fun bytes32(fill: u8): vector<u8> {
        let mut v = vector::empty<u8>();
        let mut i = 0u64;
        while (i < 32) {
            vector::push_back(&mut v, fill);
            i = i + 1;
        };
        v
    }

    // Deterministic 32-byte keypair seeds (distinct fills => distinct keypairs).
    fun seed_verifier_1(): vector<u8> { bytes32(0x01) }
    fun seed_verifier_2(): vector<u8> { bytes32(0x02) }
    fun seed_attacker(): vector<u8> { bytes32(0x03) }

    fun sanad_id(): vector<u8> { bytes32(0x11) }
    fun commitment(): vector<u8> { bytes32(0x22) }
    fun source_chain(): vector<u8> { bytes32(0x33) }
    fun lock_event_id(): vector<u8> { bytes32(0x44) }
    fun nullifier(): vector<u8> { bytes32(0x55) }

    fun dest_owner_hash(recipient: address): vector<u8> {
        hash::keccak256(&address::to_bytes(recipient))
    }

    // ==================== Setup helpers ====================

    /// Seed a fresh scenario with a shared `Registry` and the `AdminCap` held by ADMIN.
    fun begin_configured(seeds: vector<vector<u8>>, threshold: u64): Scenario {
        let mut scenario = test_scenario::begin(ADMIN);
        csv_seal::init_for_testing(test_scenario::ctx(&mut scenario));

        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<AdminCap>(&scenario);
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let mut i = 0;
            while (i < vector::length(&seeds)) {
                let kp = ecdsa_k1::secp256k1_keypair_from_seed(vector::borrow(&seeds, i));
                csv_seal::add_verifier(&admin_cap, &mut registry, *ecdsa_k1::public_key(&kp));
                i = i + 1;
            };
            if (threshold > 0) {
                csv_seal::set_threshold(&admin_cap, &mut registry, threshold);
            };
            test_scenario::return_shared(registry);
            test_scenario::return_to_sender(&scenario, admin_cap);
        };
        scenario
    }

    /// Sign the §9.2 preimage for the given mint fields with the keypair from `seed`.
    /// Returns a recoverable 65-byte signature over `sha256(preimage)`.
    fun sign_mint(
        registry: &Registry,
        seed: vector<u8>,
        sanad_id: vector<u8>,
        commitment: vector<u8>,
        source_chain: vector<u8>,
        recipient: address,
        lock_event_id: vector<u8>,
        nullifier: vector<u8>,
        expiry: u64,
    ): vector<u8> {
        let preimage = csv_seal::mint_attestation_preimage(
            registry,
            sanad_id,
            commitment,
            source_chain,
            dest_owner_hash(recipient),
            lock_event_id,
            nullifier,
            expiry,
        );
        let kp = ecdsa_k1::secp256k1_keypair_from_seed(&seed);
        ecdsa_k1::secp256k1_sign(ecdsa_k1::private_key(&kp), &preimage, SHA256, true)
    }

    fun new_clock(scenario: &mut Scenario): Clock {
        clock::create_for_testing(test_scenario::ctx(scenario))
    }

    // ==================== Happy paths ====================

    #[test]
    fun test_mint_happy_path() {
        let mut scenario = begin_configured(vector[seed_verifier_1()], 1);

        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);
            let sig = sign_mint(
                &registry, seed_verifier_1(),
                sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0,
            );
            csv_seal::mint_sanad(
                &mut registry,
                sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0,
                vector[sig],
                &clock,
                test_scenario::ctx(&mut scenario),
            );

            assert!(csv_seal::is_sanad_minted(&registry, sanad_id()), 0);
            assert!(csv_seal::is_nullifier_used(&registry, nullifier()), 1);
            assert!(csv_seal::is_lock_event_recorded(&registry, lock_event_id()), 2);

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };

        // The materialized seal is an owned object held by the recipient.
        test_scenario::next_tx(&mut scenario, RECIPIENT);
        {
            let seal = test_scenario::take_from_sender<Seal>(&scenario);
            assert!(csv_seal::owner(&seal) == RECIPIENT, 3);
            assert!(csv_seal::sanad_id(&seal) == sanad_id(), 4);
            test_scenario::return_to_sender(&scenario, seal);
        };

        test_scenario::end(scenario);
    }

    #[test]
    fun test_mint_m_of_n_happy() {
        let mut scenario = begin_configured(vector[seed_verifier_1(), seed_verifier_2()], 2);

        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);
            let sig1 = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            let sig2 = sign_mint(&registry, seed_verifier_2(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            csv_seal::mint_sanad(
                &mut registry,
                sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0,
                vector[sig1, sig2],
                &clock,
                test_scenario::ctx(&mut scenario),
            );
            assert!(csv_seal::is_sanad_minted(&registry, sanad_id()), 0);
            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    // ==================== Duplicate / replay rejection ====================

    #[test]
    #[expected_failure(abort_code = 1)]
    fun test_duplicate_sanad_rejected() {
        let mut scenario = begin_configured(vector[seed_verifier_1()], 1);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);

            let sig_a = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            csv_seal::mint_sanad(&mut registry, sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0, vector[sig_a], &clock, test_scenario::ctx(&mut scenario));

            // Same sanadId, fresh nullifier + lockEvent -> must trip the sanad duplicate guard.
            let sig_b = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, bytes32(0x66), bytes32(0x77), 0);
            csv_seal::mint_sanad(&mut registry, sanad_id(), commitment(), source_chain(), RECIPIENT, bytes32(0x66), bytes32(0x77), 0, vector[sig_b], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 2)]
    fun test_duplicate_nullifier_rejected() {
        let mut scenario = begin_configured(vector[seed_verifier_1()], 1);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);

            let sig_a = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            csv_seal::mint_sanad(&mut registry, sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0, vector[sig_a], &clock, test_scenario::ctx(&mut scenario));

            // Fresh sanadId + lockEvent, REUSED nullifier -> must trip the nullifier replay guard.
            let sig_b = sign_mint(&registry, seed_verifier_1(), bytes32(0x88), commitment(), source_chain(), RECIPIENT, bytes32(0x99), nullifier(), 0);
            csv_seal::mint_sanad(&mut registry, bytes32(0x88), commitment(), source_chain(), RECIPIENT, bytes32(0x99), nullifier(), 0, vector[sig_b], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 3)]
    fun test_duplicate_lock_event_rejected() {
        let mut scenario = begin_configured(vector[seed_verifier_1()], 1);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);

            let sig_a = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            csv_seal::mint_sanad(&mut registry, sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0, vector[sig_a], &clock, test_scenario::ctx(&mut scenario));

            // Fresh sanadId + nullifier, REUSED lockEventId -> must trip the lock-event guard.
            let sig_b = sign_mint(&registry, seed_verifier_1(), bytes32(0x88), commitment(), source_chain(), RECIPIENT, lock_event_id(), bytes32(0x99), 0);
            csv_seal::mint_sanad(&mut registry, bytes32(0x88), commitment(), source_chain(), RECIPIENT, lock_event_id(), bytes32(0x99), 0, vector[sig_b], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    // ==================== Authenticity rejection ====================

    #[test]
    #[expected_failure(abort_code = 5)]
    fun test_forged_signature_rejected() {
        let mut scenario = begin_configured(vector[seed_verifier_1()], 1);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);

            // Correct digest, but signed by an attacker key that is NOT in the verifier set.
            let sig = sign_mint(&registry, seed_attacker(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            csv_seal::mint_sanad(&mut registry, sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0, vector[sig], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure]
    fun test_tampered_field_rejected() {
        let mut scenario = begin_configured(vector[seed_verifier_1()], 1);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);

            // Verifier signs a digest over commitment 0x22, but the mint call submits 0xAB.
            // ecrecover over the submitted preimage yields a different key => rejected.
            let sig = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            csv_seal::mint_sanad(&mut registry, sanad_id(), bytes32(0xAB), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0, vector[sig], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 4)]
    fun test_insufficient_signatures_rejected() {
        let mut scenario = begin_configured(vector[seed_verifier_1(), seed_verifier_2()], 2);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);

            // Threshold 2, but only one signature supplied.
            let sig = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            csv_seal::mint_sanad(&mut registry, sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0, vector[sig], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 4)]
    fun test_duplicate_signer_not_counted() {
        let mut scenario = begin_configured(vector[seed_verifier_1(), seed_verifier_2()], 2);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);

            // Two signatures, both from verifier 1: distinct count is 1 < threshold 2.
            let sig = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            csv_seal::mint_sanad(&mut registry, sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0, vector[sig, sig], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 7)]
    fun test_expired_attestation_rejected() {
        let mut scenario = begin_configured(vector[seed_verifier_1()], 1);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let mut clock = new_clock(&mut scenario);
            // expiry = 1000s; advance the clock to 2000s (2_000_000 ms).
            clock::set_for_testing(&mut clock, 2_000_000);

            let sig = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 1000);
            csv_seal::mint_sanad(&mut registry, sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 1000, vector[sig], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 11)]
    fun test_unconfigured_registry_fails_closed() {
        // Verifier added but threshold never set (stays 0): mint must fail closed.
        let mut scenario = begin_configured(vector[seed_verifier_1()], 0);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);

            let sig = sign_mint(&registry, seed_verifier_1(), sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0);
            csv_seal::mint_sanad(&mut registry, sanad_id(), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0, vector[sig], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 9)]
    fun test_zero_field_rejected() {
        let mut scenario = begin_configured(vector[seed_verifier_1()], 1);
        test_scenario::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = test_scenario::take_shared<Registry>(&scenario);
            let clock = new_clock(&mut scenario);

            // All-zero sanadId is rejected before signature checks (no valid sig needed).
            csv_seal::mint_sanad(&mut registry, bytes32(0), commitment(), source_chain(), RECIPIENT, lock_event_id(), nullifier(), 0, vector[], &clock, test_scenario::ctx(&mut scenario));

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(registry);
        };
        test_scenario::end(scenario);
    }
}
