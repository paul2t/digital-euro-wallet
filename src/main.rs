//! Command-line acceptance harness for the offline digital euro wallet.
//!
//! `cargo test` checks the pieces in isolation. This binary drives whole
//! protocol runs end to end and asserts the outcome of each, including two
//! properties that only make sense in aggregate:
//!
//! * value conservation across issuance and settlement, and
//! * the cut-and-choose soundness bound, measured empirically against `1/n`.
//!
//! ```text
//! digital-euro-wallet check       # every scenario, PASS/FAIL, exit code
//! digital-euro-wallet soundness   # measure the forgery escape rate
//! ```

// Amounts are written as cents with the euros split off (`10_00` is 10.00 €),
// the same convention the library's tests and example use.
#![allow(clippy::inconsistent_digit_grouping)]

use digital_euro_wallet::blind_sig::{IssuerKeypair, IssuerPublicKey};
use digital_euro_wallet::error::Error;
use digital_euro_wallet::field::Fp;
use digital_euro_wallet::identity::LIMBS;
use digital_euro_wallet::token::recover_identity;
use digital_euro_wallet::wallet::{Candidate, CandidateOpening};
use digital_euro_wallet::{
    withdraw, ElementState, Issuer, Merchant, SecretLines, Settlement, SpendProof, TokenPayload,
    Wallet, WalletId,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::io::Write as _;
use std::process::ExitCode;
use std::time::Instant;

const EXPIRY: u64 = 1_800_000_000;
const NOW: u64 = 1_780_000_000;

/// Lines a scenario wants printed underneath its verdict.
type Notes = Vec<String>;
/// `Ok(())` is a pass; `Err` carries why it failed.
type Outcome = std::result::Result<(), String>;
type Scenario = fn(&Config, &mut Notes) -> Outcome;

macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !($cond) {
            return Err(format!($($arg)*));
        }
    };
}

macro_rules! note {
    ($notes:expr, $($arg:tt)*) => { $notes.push(format!($($arg)*)) };
}

struct Config {
    keypair: IssuerKeypair,
    seed: u64,
    amount: u64,
    candidates: usize,
    opening_balance: u64,
    trials: usize,
}

/// One wallet, two merchants, one backend — the cast every scenario needs.
struct World {
    issuer: Issuer,
    alice: Wallet<StdRng>,
    alice_id: WalletId,
    bakery: Merchant<StdRng>,
    kiosk: Merchant<StdRng>,
    rng: StdRng,
}

fn world(cfg: &Config, seed: u64) -> World {
    let mut rng = StdRng::seed_from_u64(seed);
    // The RSA key is generated once and shared: scenarios need independent
    // ledgers, not independent issuer keys.
    let mut issuer = Issuer::new(cfg.keypair.clone());
    let public_key = issuer.public_key();
    let alice_id = WalletId::from_bytes(rng.gen());
    issuer.open_account(alice_id, cfg.opening_balance);
    World {
        alice: Wallet::new(
            alice_id,
            public_key.clone(),
            StdRng::seed_from_u64(seed ^ 0xa1),
        ),
        alice_id,
        bakery: Merchant::new(
            *b"BAKERY01",
            public_key.clone(),
            StdRng::seed_from_u64(seed ^ 0xb2),
        ),
        kiosk: Merchant::new(*b"KIOSK_02", public_key, StdRng::seed_from_u64(seed ^ 0xc3)),
        issuer,
        rng,
    }
}

// ───────────────────────────── scenarios ─────────────────────────────

/// Fund, spend once, settle: the merchant is paid and the payer stays unnamed.
fn honest_lifecycle(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed);
    let start = w.issuer.balance_of(&w.alice_id).unwrap();

    let token = withdraw(
        &mut w.alice,
        &mut w.issuer,
        cfg.amount,
        EXPIRY,
        cfg.candidates,
        &mut w.rng,
    )
    .map_err(|e| format!("withdrawal failed: {e}"))?;

    ensure!(
        w.issuer.balance_of(&w.alice_id) == Some(start - cfg.amount),
        "online account was not debited by the face value"
    );
    ensure!(
        w.alice.offline_balance() == cfg.amount,
        "offline balance should hold the new token"
    );
    ensure!(
        w.issuer.outstanding_cents() == cfg.amount,
        "issuer should carry the token as outstanding"
    );

    let request = w
        .bakery
        .request_payment(cfg.amount, NOW)
        .map_err(|e| e.to_string())?;
    let (token_copy, proof) = w
        .alice
        .pay(&token.payload.serial, &request)
        .map_err(|e| format!("sealed element refused an honest payment: {e}"))?;
    w.bakery
        .accept(&request, token_copy, proof, NOW)
        .map_err(|e| format!("merchant refused an honest payment: {e}"))?;
    ensure!(
        w.alice.offline_balance() == 0,
        "spent token is still counted as available"
    );

    let receipts = w.bakery.drain_deposits();
    ensure!(receipts.len() == 1, "expected exactly one pending receipt");
    match w.issuer.redeem(&receipts[0]) {
        Settlement::Credited { amount_cents } => ensure!(
            amount_cents == cfg.amount,
            "credited {amount_cents}c, expected {}c",
            cfg.amount
        ),
        other => return Err(format!("expected Credited, got {other:?}")),
    }
    ensure!(
        !w.issuer.is_suspended(&w.alice_id),
        "an honest payer must not be suspended"
    );
    ensure!(
        w.issuer.outstanding_cents() == 0,
        "redeemed token still outstanding"
    );

    note!(
        notes,
        "serial {} settled for {}c",
        hex(&token.payload.serial),
        cfg.amount
    );
    note!(notes, "issuer learned the token, never the payer");
    Ok(())
}

/// An intact secure element simply will not answer twice.
fn sealed_element_refuses_a_replay(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 1);
    let token = withdraw(
        &mut w.alice,
        &mut w.issuer,
        cfg.amount,
        EXPIRY,
        cfg.candidates,
        &mut w.rng,
    )
    .map_err(|e| e.to_string())?;
    let serial = token.payload.serial;

    let first = w
        .bakery
        .request_payment(cfg.amount, NOW)
        .map_err(|e| e.to_string())?;
    let (t, p) = w.alice.pay(&serial, &first).map_err(|e| e.to_string())?;
    w.bakery
        .accept(&first, t, p, NOW)
        .map_err(|e| e.to_string())?;

    ensure!(
        w.alice.state() == ElementState::Sealed,
        "element should still be sealed"
    );
    let second = w
        .kiosk
        .request_payment(cfg.amount, NOW + 60)
        .map_err(|e| e.to_string())?;
    match w.alice.pay(&serial, &second) {
        Err(Error::TokenAlreadySpent) => {
            note!(notes, "second spend refused in hardware, before any maths");
            Ok(())
        }
        Err(other) => Err(format!("expected TokenAlreadySpent, got {other}")),
        Ok(_) => Err("a sealed element answered a second challenge".into()),
    }
}

/// The whole point: two challenges on one token solve for the payer.
fn double_spend_unmasks_the_payer(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 2);
    let token = withdraw(
        &mut w.alice,
        &mut w.issuer,
        cfg.amount,
        EXPIRY,
        cfg.candidates,
        &mut w.rng,
    )
    .map_err(|e| e.to_string())?;
    let serial = token.payload.serial;

    let first = w
        .bakery
        .request_payment(cfg.amount, NOW)
        .map_err(|e| e.to_string())?;
    let (t1, p1) = w.alice.pay(&serial, &first).map_err(|e| e.to_string())?;
    w.bakery
        .accept(&first, t1, p1.clone(), NOW)
        .map_err(|e| e.to_string())?;

    // Roll back the anti-replay state and spend the same token elsewhere.
    w.alice.crack_secure_element();
    let second = w
        .kiosk
        .request_payment(cfg.amount, NOW + 60)
        .map_err(|e| e.to_string())?;
    let (t2, p2) = w
        .alice
        .pay(&serial, &second)
        .map_err(|e| format!("cracked element should answer again: {e}"))?;
    w.kiosk
        .accept(&second, t2, p2.clone(), NOW + 60)
        .map_err(|e| format!("offline merchant cannot detect this, but refused: {e}"))?;
    ensure!(
        p1.challenge != p2.challenge,
        "distinct transactions must yield distinct challenges"
    );

    let mut settlements = Vec::new();
    for receipt in w.bakery.drain_deposits() {
        settlements.push(w.issuer.redeem(&receipt));
    }
    for receipt in w.kiosk.drain_deposits() {
        settlements.push(w.issuer.redeem(&receipt));
    }

    ensure!(
        matches!(settlements[0], Settlement::Credited { .. }),
        "first deposit should settle normally, got {:?}",
        settlements[0]
    );
    let report = match &settlements[1] {
        Settlement::DoubleSpend(report) => report,
        other => return Err(format!("expected DoubleSpend, got {other:?}")),
    };
    let recovered = report
        .culprit
        .as_ref()
        .map_err(|e| format!("solver produced no valid identity: {e}"))?;
    ensure!(
        *recovered == w.alice_id,
        "recovered {recovered}, expected {}",
        w.alice_id
    );
    ensure!(
        report.account_known,
        "recovered identity did not match a known account"
    );
    ensure!(
        report.serial == serial,
        "fraud report names the wrong serial"
    );
    ensure!(
        w.issuer.is_suspended(&w.alice_id),
        "double spender was not suspended"
    );

    // Confirm the algebra directly, independent of the issuer's bookkeeping.
    let solved = recover_identity(&p1, &p2)
        .ok_or("recover_identity refused two distinct challenges")?
        .map_err(|e| e.to_string())?;
    ensure!(
        solved == w.alice_id,
        "direct solve disagreed with the issuer"
    );

    note!(notes, "x1 = {}, x2 = {}", p1.challenge, p2.challenge);
    note!(notes, "I = (y1-y2)(x1-x2)^-1 = {recovered}");
    note!(notes, "account suspended, value clawed back");
    Ok(())
}

/// Same token, same challenge: a retry, not fraud. Nobody gets named.
fn repeated_challenge_keeps_the_payer_anonymous(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 3);
    let token = withdraw(
        &mut w.alice,
        &mut w.issuer,
        cfg.amount,
        EXPIRY,
        cfg.candidates,
        &mut w.rng,
    )
    .map_err(|e| e.to_string())?;
    let serial = token.payload.serial;

    let request = w
        .bakery
        .request_payment(cfg.amount, NOW)
        .map_err(|e| e.to_string())?;
    w.alice.crack_secure_element();
    let (t1, p1) = w.alice.pay(&serial, &request).map_err(|e| e.to_string())?;
    let (t2, p2) = w.alice.pay(&serial, &request).map_err(|e| e.to_string())?;
    ensure!(p1 == p2, "the same challenge must give the same answer");

    w.bakery
        .accept(&request, t1, p1.clone(), NOW)
        .map_err(|e| e.to_string())?;
    w.bakery
        .accept(&request, t2, p2.clone(), NOW)
        .map_err(|e| e.to_string())?;
    let receipts = w.bakery.drain_deposits();
    ensure!(receipts.len() == 2, "expected two receipts");

    ensure!(
        matches!(w.issuer.redeem(&receipts[0]), Settlement::Credited { .. }),
        "first deposit should be credited"
    );
    match w.issuer.redeem(&receipts[1]) {
        Settlement::DuplicateDeposit => {}
        other => return Err(format!("expected DuplicateDeposit, got {other:?}")),
    }
    ensure!(
        !w.issuer.is_suspended(&w.alice_id),
        "a duplicate deposit must not suspend anyone"
    );
    ensure!(
        recover_identity(&p1, &p2).is_none(),
        "two points on the same abscissa must not yield an identity"
    );

    note!(
        notes,
        "paid once, deposited twice — no identity extractable"
    );
    Ok(())
}

/// A wallet that lies about its identity is caught unless it survives the cut.
fn cut_and_choose_catches_a_forged_identity(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 4);
    let public_key = w.issuer.public_key();
    let (mut request, session) = w
        .alice
        .begin_withdrawal(cfg.amount, EXPIRY, cfg.candidates)
        .map_err(|e| e.to_string())?;

    let cut = w
        .issuer
        .cut(&request, &mut w.rng)
        .map_err(|e| e.to_string())?;
    // Forge a candidate the issuer is certain to open.
    let target = (cut.keep + 1) % cfg.candidates;
    let (candidate, forged) = forged_candidate(cfg, &public_key, &mut w.rng);
    request.candidates[target] = candidate;

    let mut opening = w
        .alice
        .answer_cut(&session, &cut)
        .map_err(|e| e.to_string())?;
    let slot = opening
        .openings
        .iter_mut()
        .find(|(index, _)| *index == target)
        .ok_or("the forged candidate should be among the opened ones")?;
    slot.1 = forged;

    match w.issuer.issue(&request, &cut, &opening) {
        Err(Error::IdentityNotEmbedded { index }) => {
            ensure!(index == target, "blamed candidate {index}, forged {target}");
            note!(
                notes,
                "candidate {target} opened: slopes were not the account identity"
            );
            Ok(())
        }
        Err(other) => Err(format!("expected IdentityNotEmbedded, got {other}")),
        Ok(_) => Err("the issuer signed a token with a forged identity".into()),
    }
}

/// One point per line excludes no slope at all — that is the secrecy claim.
fn one_point_hides_every_slope(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 5);
    let token = withdraw(
        &mut w.alice,
        &mut w.issuer,
        cfg.amount,
        EXPIRY,
        cfg.candidates,
        &mut w.rng,
    )
    .map_err(|e| e.to_string())?;
    let request = w
        .bakery
        .request_payment(cfg.amount, NOW)
        .map_err(|e| e.to_string())?;
    let (_, proof) = w
        .alice
        .pay(&token.payload.serial, &request)
        .map_err(|e| e.to_string())?;

    // For any slope whatsoever there is exactly one intercept through the
    // observed point, so a single observation rules nothing out.
    let mut rng = StdRng::seed_from_u64(cfg.seed ^ 0xfeed);
    let samples = 2000;
    for _ in 0..samples {
        for limb in 0..LIMBS {
            let y = proof.response[limb];
            let candidate_slope = Fp::random(&mut rng);
            let implied_intercept = y.sub(candidate_slope.mul(proof.challenge));
            ensure!(
                candidate_slope.mul(proof.challenge).add(implied_intercept) == y,
                "limb {limb}: no intercept fits an admissible slope"
            );
        }
    }
    ensure!(
        !proof.challenge.is_zero(),
        "x = 0 must never be issued: f(0) = s leaks only the intercept"
    );

    note!(
        notes,
        "{samples} slopes per limb tried; every one stays consistent"
    );
    Ok(())
}

/// Offline terminals still catch anything the signature covers.
fn merchant_rejects_a_tampered_token(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 6);
    let token = withdraw(
        &mut w.alice,
        &mut w.issuer,
        cfg.amount,
        EXPIRY,
        cfg.candidates,
        &mut w.rng,
    )
    .map_err(|e| e.to_string())?;
    let request = w
        .bakery
        .request_payment(cfg.amount, NOW)
        .map_err(|e| e.to_string())?;
    let (mut tampered, proof) = w
        .alice
        .pay(&token.payload.serial, &request)
        .map_err(|e| e.to_string())?;

    tampered.payload.commitment[0] ^= 0xff;
    match w.bakery.accept(&request, tampered, proof, NOW) {
        Err(Error::InvalidTokenSignature) => {
            note!(
                notes,
                "commitment flipped, blind signature no longer verifies"
            );
            Ok(())
        }
        Err(other) => Err(format!("expected InvalidTokenSignature, got {other}")),
        Ok(_) => Err("terminal accepted a token with a rewritten commitment".into()),
    }
}

/// A sale the element will not honour — wrong amount, or past expiry — is
/// refused before any point leaves the element, so it costs the payer nothing.
fn refused_sale_does_not_burn_the_token(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 7);
    let token = withdraw(
        &mut w.alice,
        &mut w.issuer,
        cfg.amount,
        EXPIRY,
        cfg.candidates,
        &mut w.rng,
    )
    .map_err(|e| e.to_string())?;
    let serial = token.payload.serial;

    let short = w
        .bakery
        .request_payment(cfg.amount - 1, NOW)
        .map_err(|e| e.to_string())?;
    match w.alice.pay(&serial, &short) {
        Err(Error::AmountMismatch { .. }) => {}
        Err(other) => return Err(format!("expected AmountMismatch, got {other}")),
        Ok(_) => return Err("element answered a request for the wrong amount".into()),
    }

    let late = EXPIRY + 1;
    let stale = w
        .bakery
        .request_payment(cfg.amount, late)
        .map_err(|e| e.to_string())?;
    match w.alice.pay(&serial, &stale) {
        Err(Error::Expired { expiry, now }) => ensure!(
            expiry == EXPIRY && now == late,
            "wrong expiry values reported"
        ),
        Err(other) => return Err(format!("expected Expired, got {other}")),
        Ok(_) => return Err("element answered after expiry".into()),
    }

    ensure!(
        w.alice.offline_balance() == cfg.amount,
        "a refused sale cost the payer the token"
    );
    let exact = w
        .bakery
        .request_payment(cfg.amount, NOW)
        .map_err(|e| e.to_string())?;
    let (t, p) = w
        .alice
        .pay(&serial, &exact)
        .map_err(|e| format!("token unusable after a refused sale: {e}"))?;
    w.bakery
        .accept(&exact, t, p, NOW)
        .map_err(|e| e.to_string())?;

    note!(notes, "wrong amount and expired sale refused, token intact");
    note!(notes, "the exact payment afterwards went through");
    Ok(())
}

/// Noise instead of honest answers must not frame an innocent account.
fn garbage_answers_accuse_nobody(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut rng = StdRng::seed_from_u64(cfg.seed + 8);
    let attempts = 1000;
    let mut framed = 0usize;
    for _ in 0..attempts {
        let first = SpendProof {
            challenge: Fp::random(&mut rng),
            response: [(); LIMBS].map(|_| Fp::random(&mut rng)),
        };
        let second = SpendProof {
            challenge: Fp::random(&mut rng),
            response: [(); LIMBS].map(|_| Fp::random(&mut rng)),
        };
        if first.challenge == second.challenge {
            continue;
        }
        let recovered =
            recover_identity(&first, &second).ok_or("distinct challenges should be solvable")?;
        if recovered.is_ok() {
            framed += 1;
        }
    }
    // Every limb would have to land inside its 52-bit budget by chance:
    // (2^52/p)^5 is about 2^-45.
    ensure!(
        framed == 0,
        "{framed} of {attempts} random answer pairs decoded to a well-formed identity"
    );
    note!(
        notes,
        "{attempts} random pairs, none decoded to a valid identity"
    );
    Ok(())
}

/// Many tokens, two merchants: no cent is created or destroyed.
fn ledger_conserves_value(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 9);
    let start = w.issuer.balance_of(&w.alice_id).unwrap();
    let count = 4usize;

    let mut serials = Vec::new();
    for _ in 0..count {
        let token = withdraw(
            &mut w.alice,
            &mut w.issuer,
            cfg.amount,
            EXPIRY,
            cfg.candidates,
            &mut w.rng,
        )
        .map_err(|e| format!("withdrawal failed: {e}"))?;
        serials.push(token.payload.serial);
    }
    let funded = count as u64 * cfg.amount;
    ensure!(
        w.issuer.balance_of(&w.alice_id) == Some(start - funded),
        "online balance does not reflect {count} withdrawals"
    );
    ensure!(
        w.issuer.outstanding_cents() == funded,
        "outstanding float should be {funded}c"
    );
    ensure!(
        w.alice.offline_balance() == funded,
        "offline balance should be {funded}c"
    );

    // Spend each token once, alternating between the two terminals.
    for (index, serial) in serials.iter().enumerate() {
        let timestamp = NOW + index as u64 * 37;
        let accepted = if index % 2 == 0 {
            let r = w
                .bakery
                .request_payment(cfg.amount, timestamp)
                .map_err(|e| e.to_string())?;
            ensure!(!r.challenge.is_zero(), "degenerate challenge issued");
            let (t, p) = w.alice.pay(serial, &r).map_err(|e| e.to_string())?;
            w.bakery.accept(&r, t, p, timestamp)
        } else {
            let r = w
                .kiosk
                .request_payment(cfg.amount, timestamp)
                .map_err(|e| e.to_string())?;
            ensure!(!r.challenge.is_zero(), "degenerate challenge issued");
            let (t, p) = w.alice.pay(serial, &r).map_err(|e| e.to_string())?;
            w.kiosk.accept(&r, t, p, timestamp)
        };
        accepted.map_err(|e| format!("payment {index} refused: {e}"))?;
    }
    ensure!(w.alice.offline_balance() == 0, "all tokens should be spent");

    let mut credited = 0u64;
    for receipt in w
        .bakery
        .drain_deposits()
        .into_iter()
        .chain(w.kiosk.drain_deposits())
    {
        match w.issuer.redeem(&receipt) {
            Settlement::Credited { amount_cents } => credited += amount_cents,
            other => return Err(format!("honest deposit did not settle: {other:?}")),
        }
    }

    let remaining = w.issuer.balance_of(&w.alice_id).unwrap();
    ensure!(
        credited == funded,
        "merchants were credited {credited}c, funded {funded}c"
    );
    ensure!(
        w.issuer.outstanding_cents() == 0,
        "float did not unwind to zero"
    );
    ensure!(
        remaining + credited == start,
        "conservation broken: {remaining}c on account + {credited}c credited != {start}c"
    );
    ensure!(
        !w.issuer.is_suspended(&w.alice_id),
        "honest payer suspended"
    );

    note!(
        notes,
        "{count} tokens issued and settled across 2 terminals"
    );
    note!(
        notes,
        "{remaining}c on account + {credited}c credited = {start}c"
    );
    Ok(())
}

/// Unknown accounts and overdrafts never reach the signing step.
fn funding_requires_a_funded_account(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 10);

    let (too_big, _) = w
        .alice
        .begin_withdrawal(cfg.opening_balance + 1, EXPIRY, cfg.candidates)
        .map_err(|e| e.to_string())?;
    match w.issuer.cut(&too_big, &mut w.rng) {
        Err(Error::InsufficientFunds { .. }) => {}
        other => return Err(format!("expected InsufficientFunds, got {other:?}")),
    }

    let stranger_id = WalletId::from_bytes([9u8; 32]);
    let mut stranger = Wallet::new(
        stranger_id,
        w.issuer.public_key(),
        StdRng::seed_from_u64(77),
    );
    let (request, _) = stranger
        .begin_withdrawal(cfg.amount, EXPIRY, cfg.candidates)
        .map_err(|e| e.to_string())?;
    match w.issuer.cut(&request, &mut w.rng) {
        Err(Error::UnknownAccount(_)) => {}
        other => return Err(format!("expected UnknownAccount, got {other:?}")),
    }

    note!(
        notes,
        "overdraft and unknown-account withdrawals both refused"
    );
    Ok(())
}

// ─────────────────────────── forgery helper ───────────────────────────

/// Builds a candidate whose lines carry slopes that are *not* the account's
/// identity, together with the opening that would reveal them.
fn forged_candidate<R: Rng + ?Sized>(
    cfg: &Config,
    public_key: &IssuerPublicKey,
    rng: &mut R,
) -> (Candidate, CandidateOpening) {
    let mut coefficients = [(Fp::ZERO, Fp::ZERO); LIMBS];
    for slot in coefficients.iter_mut() {
        *slot = (Fp::random(rng), Fp::random(rng));
    }
    let lines = SecretLines {
        coefficients,
        nonce: rng.gen(),
    };
    let payload = TokenPayload {
        serial: rng.gen(),
        amount_cents: cfg.amount,
        expiry_epoch: EXPIRY,
        commitment: lines.commitment(),
    };
    let blinding_factor = public_key.blinding_factor(rng);
    let blinded_message = public_key.blind(&payload.digest(), &blinding_factor);
    (
        Candidate {
            commitment: payload.commitment,
            blinded_message,
        },
        CandidateOpening {
            payload,
            lines,
            blinding_factor,
        },
    )
}

// ──────────────────────────── commands ────────────────────────────

fn run_check(cfg: &Config) -> bool {
    let scenarios: &[(&str, Scenario)] = &[
        (
            "honest lifecycle settles and stays anonymous",
            honest_lifecycle,
        ),
        (
            "sealed element refuses a replay",
            sealed_element_refuses_a_replay,
        ),
        (
            "double spend unmasks the payer",
            double_spend_unmasks_the_payer,
        ),
        (
            "repeated challenge keeps the payer anonymous",
            repeated_challenge_keeps_the_payer_anonymous,
        ),
        (
            "cut-and-choose catches a forged identity",
            cut_and_choose_catches_a_forged_identity,
        ),
        ("one point hides every slope", one_point_hides_every_slope),
        (
            "terminal rejects a tampered token",
            merchant_rejects_a_tampered_token,
        ),
        (
            "refused sale does not burn the token",
            refused_sale_does_not_burn_the_token,
        ),
        (
            "garbage answers accuse nobody",
            garbage_answers_accuse_nobody,
        ),
        ("ledger conserves value", ledger_conserves_value),
        (
            "funding requires a funded account",
            funding_requires_a_funded_account,
        ),
    ];

    println!("acceptance scenarios");
    let mut failed = 0usize;
    for (name, scenario) in scenarios {
        let mut notes = Notes::new();
        let started = Instant::now();
        let outcome = scenario(cfg, &mut notes);
        let elapsed = started.elapsed();
        match outcome {
            Ok(()) => println!("  PASS  {name}  ({} ms)", elapsed.as_millis()),
            Err(why) => {
                failed += 1;
                println!("  FAIL  {name}  ({} ms)", elapsed.as_millis());
                println!("          -> {why}");
            }
        }
        for line in notes {
            println!("          {line}");
        }
    }

    let total = scenarios.len();
    println!("\n  {} passed, {failed} failed, of {total}", total - failed);
    failed == 0
}

/// A cheating wallet forges exactly one of `n` candidates and wins only if the
/// issuer happens to keep that one, so the escape rate should sit near `1/n`.
fn run_soundness(cfg: &Config) -> bool {
    let n = cfg.candidates;
    let trials = cfg.trials;
    println!("cut-and-choose soundness: {trials} forgery attempts, n = {n}");

    let mut rng = StdRng::seed_from_u64(cfg.seed ^ 0x5011d);
    let mut issuer = Issuer::new(cfg.keypair.clone());
    let public_key = issuer.public_key();
    let alice_id = WalletId::from_bytes(rng.gen());
    let mut alice = Wallet::new(
        alice_id,
        public_key.clone(),
        StdRng::seed_from_u64(cfg.seed ^ 0xbad),
    );

    let mut escaped = 0usize;
    let mut caught = 0usize;
    let started = Instant::now();

    for trial in 0..trials {
        // Fresh funds each trial, so an escape never starves the next one.
        issuer.open_account(alice_id, cfg.opening_balance);

        let (mut request, session) = match alice.begin_withdrawal(cfg.amount, EXPIRY, n) {
            Ok(pair) => pair,
            Err(error) => {
                println!("  trial {trial} aborted: {error}");
                return false;
            }
        };

        // The forged candidate is chosen before the issuer cuts.
        let target = rng.gen_range(0..n);
        let (candidate, forged) = forged_candidate(cfg, &public_key, &mut rng);
        request.candidates[target] = candidate;

        let cut = match issuer.cut(&request, &mut rng) {
            Ok(cut) => cut,
            Err(error) => {
                println!("  trial {trial} aborted: {error}");
                return false;
            }
        };
        let mut opening = match alice.answer_cut(&session, &cut) {
            Ok(opening) => opening,
            Err(error) => {
                println!("  trial {trial} aborted: {error}");
                return false;
            }
        };
        if cut.keep != target {
            match opening.openings.iter_mut().find(|(i, _)| *i == target) {
                Some(slot) => slot.1 = forged,
                None => {
                    println!("  trial {trial} aborted: forged candidate was not opened");
                    return false;
                }
            }
        }

        match issuer.issue(&request, &cut, &opening) {
            Ok(_) => {
                escaped += 1;
                if cut.keep != target {
                    println!("  UNSOUND: an opened forgery was signed on trial {trial}");
                    return false;
                }
            }
            Err(_) => {
                caught += 1;
                if cut.keep == target {
                    println!("  unexpected: an unopened candidate was rejected on trial {trial}");
                    return false;
                }
            }
        }
    }

    let observed = escaped as f64 / trials as f64;
    let expected = 1.0 / n as f64;
    // Four standard deviations of a Binomial(trials, 1/n) count.
    let sigma = (trials as f64 * expected * (1.0 - expected)).sqrt();
    let tolerance = 4.0 * sigma / trials as f64;
    let within = (observed - expected).abs() <= tolerance;

    println!(
        "  caught {caught}, escaped {escaped}  ({} ms)",
        started.elapsed().as_millis()
    );
    println!("  observed escape rate {observed:.4}, expected 1/n = {expected:.4}");
    println!(
        "  4-sigma band +/-{tolerance:.4}  ->  {}",
        if within { "consistent" } else { "OUT OF BAND" }
    );
    println!("  every escape was an unopened candidate; every opened forgery was caught");
    if !within {
        println!("\n  FAIL: escape rate inconsistent with the 1/n bound");
    }
    within
}

// ───────────────────────────── plumbing ─────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn usage() {
    println!(
        "digital-euro-wallet - offline digital euro protocol harness

USAGE:
    digital-euro-wallet [COMMAND] [OPTIONS]

COMMANDS:
    check        Run every acceptance scenario and report PASS/FAIL (default)
    soundness    Measure the cut-and-choose forgery escape rate against 1/n
    all          check, then soundness

OPTIONS:
    --seed <N>          RNG seed                        (default 2026)
    --key-bits <N>      RSA modulus size in bits        (default 2048)
    --candidates <N>    cut-and-choose candidates, n    (default 20)
    --amount <CENTS>    token face value                (default 1000)
    --balance <CENTS>   opening online balance          (default 100000)
    --trials <N>        forgery attempts for soundness  (default 200)
    -h, --help          Show this message

Exit code is 0 when everything passes, 1 otherwise.
For a narrated single run: cargo run --release --example offline_payment"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut command = "check";
    let mut seed = 2026u64;
    let mut key_bits = 2048u64;
    let mut candidates = 20usize;
    let mut amount = 10_00u64;
    let mut balance = 1000_00u64;
    let mut trials = 200usize;

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-h" | "--help" => {
                usage();
                return ExitCode::SUCCESS;
            }
            "check" => command = "check",
            "soundness" => command = "soundness",
            "all" => command = "all",
            "--seed" | "--key-bits" | "--candidates" | "--amount" | "--balance" | "--trials" => {
                let raw = match args.get(index + 1) {
                    Some(raw) => raw,
                    None => {
                        eprintln!("error: {arg} needs a value");
                        return ExitCode::FAILURE;
                    }
                };
                let parsed: u64 = match raw.parse() {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        eprintln!("error: {arg} expects a number, got '{raw}'");
                        return ExitCode::FAILURE;
                    }
                };
                match arg {
                    "--seed" => seed = parsed,
                    "--key-bits" => key_bits = parsed,
                    "--candidates" => candidates = parsed as usize,
                    "--amount" => amount = parsed,
                    "--balance" => balance = parsed,
                    "--trials" => trials = parsed as usize,
                    _ => unreachable!(),
                }
                index += 1;
            }
            other => {
                eprintln!("error: unrecognised argument '{other}'\n");
                usage();
                return ExitCode::FAILURE;
            }
        }
        index += 1;
    }

    if candidates < 2 {
        eprintln!("error: --candidates must be at least 2");
        return ExitCode::FAILURE;
    }
    if key_bits < 512 {
        eprintln!("error: --key-bits must be at least 512");
        return ExitCode::FAILURE;
    }
    if trials < 1 {
        eprintln!("error: --trials must be at least 1");
        return ExitCode::FAILURE;
    }
    if amount == 0 || balance < amount {
        eprintln!("error: --amount must be non-zero and --balance at least --amount");
        return ExitCode::FAILURE;
    }

    println!("digital euro wallet - offline e-cash harness");
    print!("  generating the issuer's RSA-{key_bits} blind signing key ... ");
    let _ = std::io::stdout().flush();
    let started = Instant::now();
    let mut key_rng = StdRng::seed_from_u64(seed);
    let keypair = IssuerKeypair::generate(key_bits, &mut key_rng);
    println!("done in {} ms", started.elapsed().as_millis());
    println!(
        "  seed {seed}, n = {candidates} candidates, {amount}c tokens, {balance}c opening balance\n"
    );

    let cfg = Config {
        keypair,
        seed,
        amount,
        candidates,
        opening_balance: balance,
        trials,
    };

    let ok = match command {
        "check" => run_check(&cfg),
        "soundness" => run_soundness(&cfg),
        "all" => {
            let checked = run_check(&cfg);
            println!();
            let sound = run_soundness(&cfg);
            checked && sound
        }
        _ => unreachable!(),
    };

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
