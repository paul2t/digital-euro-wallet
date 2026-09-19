//! End-to-end walk through the offline digital euro.
//!
//! Run with `cargo run --release --example offline_payment`.

// Amounts are written as cents with the euros split off (`10_00` is 10.00 €).
#![allow(clippy::inconsistent_digit_grouping)]

use digital_euro_wallet::{defund, enrol, fund, pay, AccountId, Issuer, Keypair, Wallet};
use rand::{rngs::StdRng, SeedableRng};

const KEY_BITS: u64 = 2048;
/// A parameter of the model, not a figure published by the ECB.
const HOLDING_LIMIT: u64 = 500_00;

fn main() {
    let mut rng = StdRng::seed_from_u64(2026);

    println!("── the Eurosystem and three accounts");
    let mut issuer = Issuer::new(Keypair::generate(KEY_BITS, &mut rng));
    let alice_account = AccountId([0xa1; 16]);
    let bakery_account = AccountId([0xb2; 16]);
    let mill_account = AccountId([0xc3; 16]);
    issuer.open_account(alice_account, 50_00);
    issuer.open_account(bakery_account, 0);
    issuer.open_account(mill_account, 0);

    let mut device = |account, seed, issuer: &mut Issuer| {
        enrol(
            issuer,
            account,
            HOLDING_LIMIT,
            KEY_BITS,
            StdRng::seed_from_u64(seed),
            &mut rng,
        )
        .expect("enrolment")
    };
    let mut alice = device(alice_account, 1, &mut issuer);
    let mut bakery = device(bakery_account, 2, &mut issuer);
    let mut mill = device(mill_account, 3, &mut issuer);
    println!("   Alice's phone: device {}", alice.device().short());
    println!("   bakery till:   device {}", bakery.device().short());
    println!("   flour mill:    device {}", mill.device().short());
    println!("   holding limit: {} per device", euros(HOLDING_LIMIT));

    println!("\n── funding: Alice moves 10 € from her account onto her phone (online)");
    fund(&mut alice, &mut issuer, 10_00).expect("funding");
    println!(
        "   account {}, phone {}",
        euros(account(&issuer, alice_account)),
        euros(alice.balance())
    );

    println!("\n── offline: Alice buys bread for 6 €");
    pay(&mut alice, &mut bakery, 6_00).expect("bread");
    println!(
        "   phone {}, bakery {}",
        euros(alice.balance()),
        euros(bakery.balance())
    );
    println!("   nothing split, nothing sent back: 4 € simply stay on the phone");

    println!("\n── offline: the bakery pays the mill 5 € out of what it just received");
    pay(&mut bakery, &mut mill, 5_00).expect("flour");
    println!(
        "   bakery {}, mill {}",
        euros(bakery.balance()),
        euros(mill.balance())
    );
    println!(
        "   the issuer has seen none of this; its float is still {}",
        float(&issuer)
    );

    println!("\n── offline: Alice tries to spend 6 € again, with 4 € left");
    match pay(&mut alice, &mut bakery, 6_00) {
        Err(error) => println!("   refused: {error}"),
        Ok(_) => unreachable!("an intact element never overdraws"),
    }
    println!("   phone still {}, nothing lost", euros(alice.balance()));

    println!("\n── offline: she spends the 4 € at the mill instead");
    pay(&mut alice, &mut mill, 4_00).expect("spend the rest");
    println!(
        "   phone {}, mill {}",
        euros(alice.balance()),
        euros(mill.balance())
    );

    println!("\n── defunding: the mill moves its takings back online");
    defund(&mut mill, &mut issuer, 9_00).expect("defunding");
    println!(
        "   mill's account {}, float {}",
        euros(account(&issuer, mill_account)),
        float(&issuer)
    );

    println!("\n── a lost phone");
    fund(&mut alice, &mut issuer, 20_00).expect("funding");
    drop(alice);
    println!("   20 € funded, then the phone is lost. There is no recovery:");
    println!(
        "   Alice's account stays at {}; the 20 € stay counted in the float, now {}",
        euros(account(&issuer, alice_account)),
        float(&issuer)
    );

    println!("\n── a cracked secure element");
    let mut mallory = new_mallory(&mut issuer);
    fund(&mut mallory, &mut issuer, 10_00).expect("funding");
    mallory.crack_secure_element();
    pay(&mut mallory, &mut bakery, 10_00).expect("first spend");
    pay(&mut mallory, &mut mill, 10_00).expect("second spend of the same 10 €");
    println!("   10 € funded, paid out twice; both payees accepted genuine signatures");
    println!(
        "   Mallory's phone still shows {}",
        euros(mallory.balance())
    );
    let bakery_takings = bakery.balance();
    defund(&mut bakery, &mut issuer, bakery_takings).expect("defunding");
    let mill_takings = mill.balance();
    defund(&mut mill, &mut issuer, mill_takings).expect("defunding");

    // Value the issuer knows must still exist on devices: Alice's lost 20 €
    // and whatever Mallory's phone holds.
    let on_devices = 20_00 + mallory.balance();
    let float_cents = issuer.offline_float();
    println!(
        "   after the payees defund, the issuer's float is {} — positive, so",
        float(&issuer)
    );
    println!("   from the issuer's side nothing looks wrong");
    println!(
        "   but devices still hold {} (Alice's lost phone + Mallory's)",
        euros(on_devices)
    );
    println!(
        "   {} was created out of nothing, and nothing on record says which",
        euros((on_devices as i128 - float_cents) as u64)
    );
    println!("   device minted it: payments were never reported to anyone.");
}

fn new_mallory(issuer: &mut Issuer) -> Wallet<StdRng> {
    let account = AccountId([0xdd; 16]);
    issuer.open_account(account, 10_00);
    let mut rng = StdRng::seed_from_u64(666);
    enrol(
        issuer,
        account,
        HOLDING_LIMIT,
        KEY_BITS,
        StdRng::seed_from_u64(4),
        &mut rng,
    )
    .expect("enrolment")
}

fn account(issuer: &Issuer, account: AccountId) -> u64 {
    issuer.balance_of(&account).expect("known account")
}

fn float(issuer: &Issuer) -> String {
    let cents = issuer.offline_float();
    let sign = if cents < 0 { "-" } else { "" };
    let cents = cents.unsigned_abs();
    format!("{sign}{}.{:02} €", cents / 100, cents % 100)
}

fn euros(cents: u64) -> String {
    format!("{}.{:02} €", cents / 100, cents % 100)
}
