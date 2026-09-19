//! Protocol-level tests: anonymity holds for one spend, identity falls out on
//! two, cut-and-choose catches a forged identity, and honest cases settle.

use digital_euro_wallet::blind_sig::IssuerKeypair;
use digital_euro_wallet::error::Error;
use digital_euro_wallet::field::Fp;
use digital_euro_wallet::identity::LIMBS;
use digital_euro_wallet::token::recover_identity;
use digital_euro_wallet::{
    withdraw, Issuer, Merchant, Settlement, SpendProof, Token, Wallet, WalletId,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

const EXPIRY: u64 = 1_800_000_000;
const NOW: u64 = 1_780_000_000;
const AMOUNT: u64 = 10_00;

struct World {
    issuer: Issuer,
    alice: Wallet<StdRng>,
    alice_id: WalletId,
    bakery: Merchant<StdRng>,
    kiosk: Merchant<StdRng>,
    rng: StdRng,
}

/// 1024-bit modulus keeps the test suite quick; the demo uses 2048.
fn world(seed: u64) -> World {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut issuer = Issuer::new(IssuerKeypair::generate(1024, &mut rng));
    let public_key = issuer.public_key();
    let alice_id = WalletId::from_bytes(rng.gen());
    issuer.open_account(alice_id, 100_00);
    World {
        alice: Wallet::new(
            alice_id,
            public_key.clone(),
            StdRng::seed_from_u64(seed + 1),
        ),
        alice_id,
        bakery: Merchant::new(
            *b"BAKERY01",
            public_key.clone(),
            StdRng::seed_from_u64(seed + 2),
        ),
        kiosk: Merchant::new(*b"KIOSK_02", public_key, StdRng::seed_from_u64(seed + 3)),
        issuer,
        rng,
    }
}

fn spend(
    wallet: &mut Wallet<StdRng>,
    merchant: &mut Merchant<StdRng>,
    serial: &[u8; 16],
    timestamp: u64,
) -> (Token, SpendProof) {
    let request = merchant.request_payment(AMOUNT, timestamp).unwrap();
    let (token, proof) = wallet.pay(serial, request.challenge).unwrap();
    merchant
        .accept(&request, token.clone(), proof.clone(), timestamp)
        .expect("merchant accepts");
    (token, proof)
}

#[test]
fn honest_payment_settles_and_stays_anonymous() {
    let mut w = world(10);
    let token = withdraw(&mut w.alice, &mut w.issuer, AMOUNT, EXPIRY, 8, &mut w.rng).unwrap();

    assert_eq!(w.issuer.balance_of(&w.alice_id), Some(100_00 - AMOUNT));
    assert_eq!(w.alice.offline_balance(), AMOUNT);
    assert_eq!(w.issuer.outstanding_cents(), AMOUNT);

    spend(&mut w.alice, &mut w.bakery, &token.payload.serial, NOW);
    for receipt in w.bakery.drain_deposits() {
        assert_eq!(
            w.issuer.redeem(&receipt),
            Settlement::Credited {
                amount_cents: AMOUNT
            }
        );
    }
    assert_eq!(w.issuer.outstanding_cents(), 0);
    assert!(!w.issuer.is_suspended(&w.alice_id));
}

#[test]
fn sealed_element_refuses_a_second_spend() {
    let mut w = world(11);
    let token = withdraw(&mut w.alice, &mut w.issuer, AMOUNT, EXPIRY, 8, &mut w.rng).unwrap();
    spend(&mut w.alice, &mut w.bakery, &token.payload.serial, NOW);

    let request = w.kiosk.request_payment(AMOUNT, NOW + 60).unwrap();
    assert_eq!(
        w.alice.pay(&token.payload.serial, request.challenge),
        Err(Error::TokenAlreadySpent)
    );
}

#[test]
fn double_spend_reveals_the_payer() {
    let mut w = world(12);
    let token = withdraw(&mut w.alice, &mut w.issuer, AMOUNT, EXPIRY, 8, &mut w.rng).unwrap();

    spend(&mut w.alice, &mut w.bakery, &token.payload.serial, NOW);
    w.alice.crack_secure_element();
    spend(&mut w.alice, &mut w.kiosk, &token.payload.serial, NOW + 60);

    let mut settlements = Vec::new();
    for receipt in w.bakery.drain_deposits() {
        settlements.push(w.issuer.redeem(&receipt));
    }
    for receipt in w.kiosk.drain_deposits() {
        settlements.push(w.issuer.redeem(&receipt));
    }

    assert_eq!(
        settlements[0],
        Settlement::Credited {
            amount_cents: AMOUNT
        }
    );
    match &settlements[1] {
        Settlement::DoubleSpend(report) => {
            assert_eq!(report.culprit.as_ref().unwrap(), &w.alice_id);
            assert!(report.account_known);
            assert_eq!(report.first_merchant, *b"BAKERY01");
            assert_eq!(report.second_merchant, *b"KIOSK_02");
        }
        other => panic!("expected a double-spend report, got {other:?}"),
    }
    assert!(w.issuer.is_suspended(&w.alice_id));
}

#[test]
fn one_point_hides_the_identity_perfectly() {
    // For any candidate slope there is an intercept fitting the observed
    // point, so a single spend constrains the identity by exactly nothing.
    let mut w = world(13);
    let token = withdraw(&mut w.alice, &mut w.issuer, AMOUNT, EXPIRY, 4, &mut w.rng).unwrap();
    let (_, proof) = spend(&mut w.alice, &mut w.bakery, &token.payload.serial, NOW);

    let mut rng = StdRng::seed_from_u64(99);
    for _ in 0..1000 {
        let guess = Fp::random(&mut rng);
        let implied_intercept = proof.response[0].sub(guess.mul(proof.challenge));
        assert_eq!(
            guess.mul(proof.challenge).add(implied_intercept),
            proof.response[0]
        );
    }
}

#[test]
fn duplicate_deposit_of_the_same_receipt_is_idempotent() {
    let mut w = world(14);
    let token = withdraw(&mut w.alice, &mut w.issuer, AMOUNT, EXPIRY, 8, &mut w.rng).unwrap();
    spend(&mut w.alice, &mut w.bakery, &token.payload.serial, NOW);

    let receipts = w.bakery.drain_deposits();
    assert_eq!(
        w.issuer.redeem(&receipts[0]),
        Settlement::Credited {
            amount_cents: AMOUNT
        }
    );
    assert_eq!(w.issuer.redeem(&receipts[0]), Settlement::DuplicateDeposit);
    assert!(!w.issuer.is_suspended(&w.alice_id));
}

#[test]
fn reused_challenge_does_not_unmask_anyone() {
    // A colluding merchant that replays its own challenge gains two copies of
    // the same point, which is still one point.
    let mut w = world(15);
    let token = withdraw(&mut w.alice, &mut w.issuer, AMOUNT, EXPIRY, 8, &mut w.rng).unwrap();
    let request = w.bakery.request_payment(AMOUNT, NOW).unwrap();
    let (_, first) = w
        .alice
        .pay(&token.payload.serial, request.challenge)
        .unwrap();
    w.alice.crack_secure_element();
    let (_, second) = w
        .alice
        .pay(&token.payload.serial, request.challenge)
        .unwrap();

    assert_eq!(first, second);
    assert!(recover_identity(&first, &second).is_none());
}

#[test]
fn cut_and_choose_rejects_a_forged_identity() {
    let mut w = world(16);
    let (mut request, session) = w.alice.begin_withdrawal(AMOUNT, EXPIRY, 6).unwrap();
    let cut = w.issuer.cut(&request, &mut w.rng).unwrap();
    let mut opening = w.alice.answer_cut(&session, &cut).unwrap();

    // Tamper with one opened candidate: swap in a slope that is not Alice's.
    let victim = opening
        .openings
        .iter_mut()
        .find(|(index, _)| *index != cut.keep)
        .unwrap();
    victim.1.lines.coefficients[0].0 = Fp::new(1234);
    victim.1.payload.commitment = victim.1.lines.commitment();
    request.candidates[victim.0].commitment = victim.1.payload.commitment;
    request.candidates[victim.0] = digital_euro_wallet::wallet::Candidate {
        commitment: victim.1.payload.commitment,
        blinded_message: w
            .issuer
            .public_key()
            .blind(&victim.1.payload.digest(), &victim.1.blinding_factor),
    };

    match w.issuer.issue(&request, &cut, &opening) {
        Err(Error::IdentityNotEmbedded { .. }) => {}
        other => panic!("expected the forged identity to be caught, got {other:?}"),
    }
}

#[test]
fn cut_and_choose_rejects_a_broken_commitment() {
    let mut w = world(17);
    let (request, session) = w.alice.begin_withdrawal(AMOUNT, EXPIRY, 6).unwrap();
    let cut = w.issuer.cut(&request, &mut w.rng).unwrap();
    let mut opening = w.alice.answer_cut(&session, &cut).unwrap();
    opening.openings[0].1.lines.nonce[0] ^= 0xff;

    match w.issuer.issue(&request, &cut, &opening) {
        Err(Error::CommitmentMismatch { .. }) => {}
        other => panic!("expected a commitment mismatch, got {other:?}"),
    }
}

#[test]
fn merchant_rejects_a_tampered_token() {
    let mut w = world(18);
    let mut token = withdraw(&mut w.alice, &mut w.issuer, AMOUNT, EXPIRY, 6, &mut w.rng).unwrap();
    let request = w.bakery.request_payment(AMOUNT, NOW).unwrap();
    let (_, proof) = w
        .alice
        .pay(&token.payload.serial, request.challenge)
        .unwrap();

    token.payload.amount_cents = 50_00; // inflate the face value
    assert_eq!(
        w.bakery.accept(&request, token, proof, NOW),
        Err(Error::InvalidTokenSignature)
    );
}

#[test]
fn merchant_rejects_an_answer_to_a_different_challenge() {
    let mut w = world(19);
    let token = withdraw(&mut w.alice, &mut w.issuer, AMOUNT, EXPIRY, 6, &mut w.rng).unwrap();
    let bakery_request = w.bakery.request_payment(AMOUNT, NOW).unwrap();
    let kiosk_request = w.kiosk.request_payment(AMOUNT, NOW).unwrap();
    let (token, proof) = w
        .alice
        .pay(&token.payload.serial, kiosk_request.challenge)
        .unwrap();

    assert_eq!(
        w.bakery.accept(&bakery_request, token, proof, NOW),
        Err(Error::ChallengeMismatch)
    );
}

#[test]
fn expired_token_is_refused() {
    let mut w = world(20);
    let token = withdraw(&mut w.alice, &mut w.issuer, AMOUNT, NOW - 1, 6, &mut w.rng).unwrap();
    let request = w.bakery.request_payment(AMOUNT, NOW).unwrap();
    let (token, proof) = w
        .alice
        .pay(&token.payload.serial, request.challenge)
        .unwrap();

    assert!(matches!(
        w.bakery.accept(&request, token, proof, NOW),
        Err(Error::Expired { .. })
    ));
}

#[test]
fn garbage_responses_recover_no_valid_identity() {
    // A wallet that answers with noise breaks the linear relation, so the
    // solver returns slopes that are not a well-formed identity.
    let mut rng = StdRng::seed_from_u64(21);
    let first = SpendProof {
        challenge: Fp::new(11),
        response: [(); LIMBS].map(|_| Fp::random(&mut rng)),
    };
    let second = SpendProof {
        challenge: Fp::new(17),
        response: [(); LIMBS].map(|_| Fp::random(&mut rng)),
    };
    let recovered = recover_identity(&first, &second).unwrap();
    assert!(
        recovered.is_err(),
        "random points must not decode to an identity"
    );
}

#[test]
fn withdrawal_needs_funds_and_a_known_account() {
    let mut w = world(22);
    let (request, _) = w.alice.begin_withdrawal(500_00, EXPIRY, 4).unwrap();
    assert!(matches!(
        w.issuer.cut(&request, &mut w.rng),
        Err(Error::InsufficientFunds { .. })
    ));

    let stranger_key = w.issuer.public_key();
    let stranger_id = WalletId::from_bytes([9u8; 32]);
    let mut stranger = Wallet::new(stranger_id, stranger_key, StdRng::seed_from_u64(77));
    let (request, _) = stranger.begin_withdrawal(AMOUNT, EXPIRY, 4).unwrap();
    assert!(matches!(
        w.issuer.cut(&request, &mut w.rng),
        Err(Error::UnknownAccount(_))
    ));
}
