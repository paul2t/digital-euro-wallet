//! Protocol-level tests: partial payments, re-spending, holding limits,
//! replay protection, certification, funding and defunding, and what a lost
//! device or a cracked element does to the money supply.

// Amounts are written as cents with the euros split off (`100_00` is 100.00 €),
// the same convention the example and the harness binary use.
#![allow(clippy::inconsistent_digit_grouping)]

use digital_euro_wallet::{
    defund, enrol, fund, pay, AccountId, DeviceCertificate, ElementState, Error, Issuer, Keypair,
    Wallet,
};
use rand::{rngs::StdRng, SeedableRng};

const LIMIT: u64 = 500_00;
/// 512-bit keys keep the suite quick; the harness and example use 2048.
const KEY_BITS: u64 = 512;

type Device = Wallet<StdRng>;

struct World {
    issuer: Issuer,
    alice_account: AccountId,
    alice: Device,
    bakery: Device,
    supplier: Device,
}

fn world(seed: u64) -> World {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut issuer = Issuer::new(Keypair::generate(KEY_BITS, &mut rng));
    let alice_account = AccountId([1; 16]);
    let bakery_account = AccountId([2; 16]);
    let supplier_account = AccountId([3; 16]);
    issuer.open_account(alice_account, 100_00);
    issuer.open_account(bakery_account, 0);
    issuer.open_account(supplier_account, 0);

    let device = |account, n: u64, issuer: &mut Issuer, rng: &mut StdRng| {
        enrol(
            issuer,
            account,
            LIMIT,
            KEY_BITS,
            StdRng::seed_from_u64(seed * 10 + n),
            rng,
        )
        .unwrap()
    };
    let alice = device(alice_account, 1, &mut issuer, &mut rng);
    let bakery = device(bakery_account, 2, &mut issuer, &mut rng);
    let supplier = device(supplier_account, 3, &mut issuer, &mut rng);
    World {
        issuer,
        alice_account,
        alice,
        bakery,
        supplier,
    }
}

// ─────────────────────── spending part of a balance ───────────────────────

#[test]
fn funding_moves_value_from_the_account_to_the_device() {
    let mut w = world(1);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    assert_eq!(w.alice.balance(), 10_00);
    assert_eq!(w.issuer.balance_of(&w.alice_account), Some(90_00));
    assert_eq!(w.issuer.offline_float(), 10_00);
}

#[test]
fn paying_part_of_the_balance_leaves_the_rest_spendable() {
    let mut w = world(2);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();

    pay(&mut w.alice, &mut w.bakery, 6_00).unwrap();
    assert_eq!(w.alice.balance(), 4_00);
    assert_eq!(w.bakery.balance(), 6_00);

    // The 4 € left over is ordinary balance, spendable later.
    pay(&mut w.alice, &mut w.supplier, 4_00).unwrap();
    assert_eq!(w.alice.balance(), 0);
    assert_eq!(w.supplier.balance(), 4_00);
}

#[test]
fn received_value_is_immediately_respendable_offline() {
    let mut w = world(3);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    pay(&mut w.alice, &mut w.bakery, 6_00).unwrap();

    // The bakery never went online: it pays its supplier out of Alice's money.
    pay(&mut w.bakery, &mut w.supplier, 5_00).unwrap();
    assert_eq!(w.bakery.balance(), 1_00);
    assert_eq!(w.supplier.balance(), 5_00);
}

#[test]
fn payments_leave_the_issuer_none_the_wiser() {
    let mut w = world(4);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    let float = w.issuer.offline_float();
    pay(&mut w.alice, &mut w.bakery, 6_00).unwrap();
    pay(&mut w.bakery, &mut w.supplier, 5_00).unwrap();
    assert_eq!(w.issuer.offline_float(), float);
    assert_eq!(
        w.alice.balance() + w.bakery.balance() + w.supplier.balance(),
        10_00
    );
}

// ─────────────────────── refusals cost nothing ───────────────────────

#[test]
fn insufficient_funds_are_refused_before_any_debit() {
    let mut w = world(5);
    fund(&mut w.alice, &mut w.issuer, 5_00).unwrap();
    assert_eq!(
        pay(&mut w.alice, &mut w.bakery, 6_00),
        Err(Error::InsufficientFunds {
            requested: 6_00,
            available: 5_00
        })
    );
    assert_eq!(w.alice.balance(), 5_00);
    // The payee's reservation was released too.
    assert_eq!(w.bakery.reserved(), 0);
    assert_eq!(w.bakery.headroom(), LIMIT);
}

#[test]
fn payee_over_its_holding_limit_refuses_before_the_payer_is_debited() {
    let mut w = world(6);
    fund(&mut w.alice, &mut w.issuer, 100_00).unwrap();
    // Fill the bakery to within 50 € of its limit.
    w.issuer.open_account(AccountId([2; 16]), LIMIT);
    fund(&mut w.bakery, &mut w.issuer, LIMIT - 50_00).unwrap();

    assert_eq!(
        w.bakery.request_payment(60_00),
        Err(Error::HoldingLimitExceeded {
            requested: 60_00,
            headroom: 50_00
        })
    );
    assert_eq!(w.alice.balance(), 100_00, "the payer was never asked");
}

#[test]
fn open_requests_reserve_room_so_they_cannot_jointly_overflow() {
    let mut w = world(7);
    let first = w.bakery.request_payment(300_00).unwrap();
    assert_eq!(w.bakery.headroom(), LIMIT - 300_00);
    assert!(matches!(
        w.bakery.request_payment(300_00),
        Err(Error::HoldingLimitExceeded { .. })
    ));
    assert!(w.bakery.cancel_request(&first.nonce));
    assert_eq!(w.bakery.headroom(), LIMIT);
}

#[test]
fn funding_over_the_holding_limit_is_refused_and_the_account_untouched() {
    let mut w = world(8);
    w.issuer.open_account(w.alice_account, 1_000_00);
    assert!(matches!(
        fund(&mut w.alice, &mut w.issuer, LIMIT + 1),
        Err(Error::HoldingLimitExceeded { .. })
    ));
    assert_eq!(w.issuer.balance_of(&w.alice_account), Some(1_000_00));
    assert_eq!(w.issuer.offline_float(), 0);
}

#[test]
fn funding_beyond_the_account_balance_is_refused_and_the_reservation_released() {
    let mut w = world(9);
    assert!(matches!(
        fund(&mut w.alice, &mut w.issuer, 200_00),
        Err(Error::InsufficientFunds { .. })
    ));
    assert_eq!(w.alice.balance(), 0);
    assert_eq!(w.alice.reserved(), 0);
}

// ─────────────────────── replay and tampering ───────────────────────

#[test]
fn a_replayed_transfer_is_credited_once() {
    let mut w = world(10);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    let request = w.bakery.request_payment(6_00).unwrap();
    let transfer = w.alice.pay(&request).unwrap();

    assert_eq!(w.bakery.receive(&transfer), Ok(6_00));
    // Resending the same signed transfer — after a dropped connection, say —
    // is harmless.
    assert_eq!(w.bakery.receive(&transfer), Err(Error::AlreadyCredited));
    assert_eq!(w.bakery.balance(), 6_00);
}

#[test]
fn a_transfer_cannot_be_redirected_to_another_device() {
    let mut w = world(11);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    let request = w.bakery.request_payment(6_00).unwrap();
    let mut transfer = w.alice.pay(&request).unwrap();

    assert_eq!(w.supplier.receive(&transfer), Err(Error::NotForThisDevice));
    transfer.payee = w.supplier.device();
    assert_eq!(w.supplier.receive(&transfer), Err(Error::InvalidSignature));
}

#[test]
fn an_inflated_transfer_breaks_the_payer_signature() {
    let mut w = world(12);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    let request = w.bakery.request_payment(6_00).unwrap();
    let mut transfer = w.alice.pay(&request).unwrap();
    transfer.amount_cents = 60_00;
    assert_eq!(w.bakery.receive(&transfer), Err(Error::InvalidSignature));
}

#[test]
fn a_transfer_answering_no_open_request_is_refused() {
    let mut w = world(13);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    let request = w.bakery.request_payment(6_00).unwrap();
    w.bakery.cancel_request(&request.nonce);
    let transfer = w.alice.pay(&request).unwrap();
    assert_eq!(w.bakery.receive(&transfer), Err(Error::UnknownRequest));

    // The payer's debit is not undone: once a device has paid, nothing offline
    // can reverse it. This is the abandoned-transaction gap a real protocol
    // has to close; the model leaves it open and says so.
    assert_eq!(w.alice.balance(), 4_00);
    assert_eq!(w.bakery.balance(), 0);
}

// ─────────────────────── certification ───────────────────────

fn rogue_certificate(seed: u64) -> (DeviceCertificate, Keypair) {
    // A key "certified" by someone other than the Eurosystem.
    let mut rng = StdRng::seed_from_u64(seed);
    let mut rogue = Issuer::new(Keypair::generate(KEY_BITS, &mut rng));
    let account = AccountId([9; 16]);
    rogue.open_account(account, 0);
    let keypair = Keypair::generate(KEY_BITS, &mut rng);
    let certificate = rogue
        .certify_device(account, &keypair.public, LIMIT, &mut rng)
        .unwrap();
    (certificate, keypair)
}

#[test]
fn a_device_without_a_eurosystem_certificate_cannot_be_installed() {
    let w = world(14);
    let (certificate, keypair) = rogue_certificate(99);
    assert!(matches!(
        Wallet::new(
            certificate,
            keypair,
            w.issuer.public_key(),
            StdRng::seed_from_u64(0)
        ),
        Err(Error::InvalidCertificate)
    ));
}

#[test]
fn the_payer_refuses_to_pay_an_uncertified_device() {
    let mut w = world(15);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    let mut request = w.bakery.request_payment(6_00).unwrap();
    request.payee = rogue_certificate(98).0;
    assert_eq!(w.alice.pay(&request), Err(Error::InvalidCertificate));
    assert_eq!(w.alice.balance(), 10_00);
}

#[test]
fn a_device_cannot_pay_itself() {
    let mut w = world(16);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    let request = w.alice.request_payment(6_00).unwrap();
    assert_eq!(w.alice.pay(&request), Err(Error::SelfPayment));
    assert_eq!(w.alice.balance(), 10_00);
}

#[test]
fn only_the_issuer_can_map_a_device_to_its_account() {
    // The certificate the payee sees carries a device pseudonym and no
    // account; the mapping lives with the issuer, which never sees payments.
    let w = world(17);
    assert_eq!(
        w.issuer.account_of(&w.alice.device()),
        Some(w.alice_account)
    );
}

// ─────────────────────── defunding ───────────────────────

#[test]
fn defunding_returns_value_to_the_account() {
    let mut w = world(18);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    pay(&mut w.alice, &mut w.bakery, 6_00).unwrap();
    defund(&mut w.alice, &mut w.issuer, 4_00).unwrap();
    assert_eq!(w.alice.balance(), 0);
    assert_eq!(w.issuer.balance_of(&w.alice_account), Some(94_00));
    assert_eq!(w.issuer.offline_float(), 6_00);
}

#[test]
fn a_defunding_order_cannot_be_cashed_twice() {
    let mut w = world(19);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    let order = w.alice.defund(4_00).unwrap();
    assert_eq!(w.issuer.defund(&order), Ok(4_00));
    assert_eq!(w.issuer.defund(&order), Err(Error::Replay));
    assert_eq!(w.issuer.balance_of(&w.alice_account), Some(94_00));
}

// ─────────────────────── loss and compromise ───────────────────────

#[test]
fn a_lost_device_takes_its_balance_with_it() {
    let mut w = world(20);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    drop(w.alice);
    // The account stays debited and the value stays "on devices" for good.
    assert_eq!(w.issuer.balance_of(&w.alice_account), Some(90_00));
    assert_eq!(w.issuer.offline_float(), 10_00);
}

#[test]
fn a_cracked_element_creates_money_that_shows_up_only_in_aggregate() {
    let mut w = world(21);
    fund(&mut w.alice, &mut w.issuer, 10_00).unwrap();
    w.alice.crack_secure_element();
    assert_eq!(w.alice.state(), ElementState::Cracked);

    // The same 10 € paid out twice. Both payees accept: the transfers carry a
    // genuine certificate and a genuine signature.
    pay(&mut w.alice, &mut w.bakery, 10_00).unwrap();
    pay(&mut w.alice, &mut w.supplier, 10_00).unwrap();
    assert_eq!(w.bakery.balance() + w.supplier.balance(), 20_00);

    // Offline, nothing notices. Online, the float only goes negative once
    // more value leaves the circuit than ever entered it.
    defund(&mut w.bakery, &mut w.issuer, 10_00).unwrap();
    assert_eq!(w.issuer.offline_float(), 0);
    defund(&mut w.supplier, &mut w.issuer, 10_00).unwrap();
    assert_eq!(w.issuer.offline_float(), -10_00);
}
