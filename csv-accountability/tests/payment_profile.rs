use csv_accountability::{
    ActionIntent, IntentError, PAYMENT_ACTION_TYPE, PAYMENT_PROFILE_ID, PaymentCodec,
    PaymentIntentV1, ProfileCodec, ProfileId, default_registry,
};

fn payment() -> PaymentIntentV1 {
    PaymentIntentV1 {
        payer_id: "org:payer-acme".into(),
        merchant_id: "merchant:coffee-42".into(),
        recipient_account_digest: [7; 32],
        amount_minor: 2_500,
        cap_minor: 5_000,
        currency: "USD".into(),
        expires_at: 1_800_000_000,
        payment_reference: "invoice:2026-0042".into(),
    }
}

#[test]
fn payment_profile_round_trips_and_is_registered() {
    let profile = payment();
    let bytes = profile.canonical_bytes().unwrap();
    assert_eq!(
        PaymentIntentV1::from_canonical_bytes(&bytes).unwrap(),
        profile
    );

    let registry = default_registry();
    let id = ProfileId::new(PAYMENT_PROFILE_ID).unwrap();
    let descriptor = registry
        .descriptor(&id)
        .expect("payment profile is registered");
    assert_eq!(descriptor.action_type, PAYMENT_ACTION_TYPE);
    assert_eq!(
        registry.decode_profile(&id, &bytes).unwrap(),
        profile.stable_target()
    );

    let codec = PaymentCodec::default();
    let intent = ActionIntent::new(
        codec.descriptor(),
        &codec,
        bytes,
        b"agent:payment".to_vec(),
        100,
        [9; 32],
        vec![],
    )
    .unwrap();
    assert_eq!(intent.profile_id.as_str(), PAYMENT_PROFILE_ID);
}

#[test]
fn cap_recipient_currency_expiry_and_canonical_form_fail_closed() {
    let valid = payment();

    let mut over_cap = valid.clone();
    over_cap.amount_minor = over_cap.cap_minor + 1;
    assert_eq!(
        over_cap.validate(),
        Err(IntentError::EmptyField("cap_minor"))
    );

    let mut missing_recipient = valid.clone();
    missing_recipient.recipient_account_digest = [0; 32];
    assert_eq!(
        missing_recipient.validate(),
        Err(IntentError::EmptyField("recipient_account_digest"))
    );

    let mut invalid_currency = valid.clone();
    invalid_currency.currency = "usd".into();
    assert_eq!(
        invalid_currency.validate(),
        Err(IntentError::EmptyField("currency"))
    );

    let mut no_expiry = valid.clone();
    no_expiry.expires_at = 0;
    assert_eq!(
        no_expiry.validate(),
        Err(IntentError::EmptyField("expires_at"))
    );

    let mut trailing = valid.canonical_bytes().unwrap();
    trailing.push(0);
    assert_eq!(
        PaymentIntentV1::from_canonical_bytes(&trailing),
        Err(IntentError::MalformedProfileBytes)
    );
}

#[test]
fn every_security_field_changes_the_intent_commitment() {
    let codec = PaymentCodec::default();
    let make = |profile: PaymentIntentV1| {
        ActionIntent::new(
            codec.descriptor(),
            &codec,
            profile.canonical_bytes().unwrap(),
            b"agent:payment".to_vec(),
            100,
            [9; 32],
            vec![],
        )
        .unwrap()
        .parameters_commitment
    };
    let original = payment();
    let baseline = make(original.clone());

    let mut recipient = original.clone();
    recipient.recipient_account_digest = [8; 32];
    assert_ne!(baseline, make(recipient));

    let mut amount = original.clone();
    amount.amount_minor += 1;
    assert_ne!(baseline, make(amount));

    let mut cap = original.clone();
    cap.cap_minor += 1;
    assert_ne!(baseline, make(cap));

    let mut currency = original.clone();
    currency.currency = "EUR".into();
    assert_ne!(baseline, make(currency));

    let mut expiry = original;
    expiry.expires_at += 1;
    assert_ne!(baseline, make(expiry));
}
