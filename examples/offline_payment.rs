//! End-to-end walk through the offline digital euro protocol.
//!
//! Run with `cargo run --release --example offline_payment`.

use digital_euro_wallet::blind_sig::IssuerKeypair;
use digital_euro_wallet::{withdraw, ElementState, Issuer, Merchant, Settlement, Wallet, WalletId};
use rand::{rngs::StdRng, Rng, SeedableRng};

const CANDIDATES: usize = 20;
const EXPIRY: u64 = 1_800_000_000;
const NOW: u64 = 1_780_000_000;

fn main() {
    let mut rng = StdRng::seed_from_u64(2026);

    println!("── setting up the Eurosystem backend (RSA-2048 blind signing key)");
    let issuer_key = IssuerKeypair::generate(2048, &mut rng);
    let mut issuer = Issuer::new(issuer_key);
    let public_key = issuer.public_key();

    let alice_id = WalletId::from_bytes(rng.gen());
    issuer.open_account(alice_id, 50_00);
    let mut alice = Wallet::new(alice_id, public_key.clone(), StdRng::seed_from_u64(1));
    println!("   Alice's wallet identity: {}…", alice_id.short());
    println!(
        "   online account balance:  {} cents",
        issuer.balance_of(&alice_id).unwrap()
    );

    let mut bakery = Merchant::new(*b"BAKERY01", public_key.clone(), StdRng::seed_from_u64(2));
    let mut kiosk = Merchant::new(*b"KIOSK_02", public_key.clone(), StdRng::seed_from_u64(3));

    println!("\n── funding: one 10.00 € token, cut-and-choose over {CANDIDATES} candidates");
    let token =
        withdraw(&mut alice, &mut issuer, 10_00, EXPIRY, CANDIDATES, &mut rng).expect("withdrawal");
    println!("   token serial:            {}", hex(&token.payload.serial));
    println!("   issuer never saw it, yet certified the identity inside it");
    println!(
        "   online balance now:      {} cents",
        issuer.balance_of(&alice_id).unwrap()
    );
    println!(
        "   offline balance:         {} cents",
        alice.offline_balance()
    );

    println!("\n── offline payment at the bakery (both devices air-gapped)");
    let request = bakery.request_payment(10_00, NOW).unwrap();
    println!("   challenge x1 = {}", request.challenge);
    let (paid_token, proof) = alice.pay(&token.payload.serial, request.challenge).unwrap();
    let first_point = proof.response[0];
    bakery
        .accept(&request, paid_token, proof, NOW)
        .expect("bakery accepts");
    println!("   response  y1 = {first_point} (first limb) — reveals nothing about I");

    println!("\n── the secure element is sealed: a second spend is refused");
    let retry = kiosk.request_payment(10_00, NOW + 60).unwrap();
    match alice.pay(&token.payload.serial, retry.challenge) {
        Err(error) => println!("   {error}"),
        Ok(_) => unreachable!("a sealed element must refuse"),
    }

    println!("\n── attacker rolls back the element's anti-replay state");
    alice.crack_secure_element();
    assert_eq!(alice.state(), ElementState::Cracked);
    let (cloned_token, second_proof) = alice.pay(&token.payload.serial, retry.challenge).unwrap();
    println!("   challenge x2 = {}", retry.challenge);
    println!(
        "   response  y2 = {} (first limb)",
        second_proof.response[0]
    );
    kiosk
        .accept(&retry, cloned_token, second_proof, NOW + 60)
        .expect("kiosk accepts — it cannot tell, offline");

    println!("\n── merchants come back online and deposit");
    for receipt in bakery.drain_deposits() {
        report(issuer.redeem(&receipt), "bakery");
    }
    for receipt in kiosk.drain_deposits() {
        report(issuer.redeem(&receipt), "kiosk");
    }

    println!("\n── aftermath");
    println!(
        "   account suspended:       {}",
        issuer.is_suspended(&alice_id)
    );
    println!(
        "   online balance:          {} cents",
        issuer.balance_of(&alice_id).unwrap()
    );
}

fn report(settlement: Settlement, who: &str) {
    match settlement {
        Settlement::Credited { amount_cents } => {
            println!("   {who}: credited {amount_cents} cents, payer stays anonymous")
        }
        Settlement::DuplicateDeposit => println!("   {who}: duplicate deposit, ignored"),
        Settlement::Rejected(error) => println!("   {who}: rejected — {error}"),
        Settlement::DoubleSpend(report) => {
            println!("   {who}: DOUBLE SPEND on serial {}", hex(&report.serial));
            match &report.culprit {
                Ok(identity) => println!(
                    "          identity recovered: {identity}\n          known account: {}",
                    report.account_known
                ),
                Err(error) => println!("          slopes were not a valid identity — {error}"),
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
