//! Command-line acceptance harness for the offline digital euro wallet.
//!
//! `cargo test` checks the pieces in isolation. This binary drives whole runs
//! across several devices and asserts the outcome of each, including
//! properties that only make sense in aggregate:
//!
//! ```text
//! digital-euro-wallet check   # every scenario, PASS/FAIL, exit code
//! digital-euro-wallet fuzz    # random operations, invariants after each one
//! ```

// Amounts are written as cents with the euros split off (`10_00` is 10.00 €),
// the same convention the library's tests and example use.
#![allow(clippy::inconsistent_digit_grouping)]

use digital_euro_wallet::{
    defund, enrol, fund, pay, AccountId, DeviceCertificate, Error, Issuer, Keypair, Wallet,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::ExitCode;
use std::time::Instant;

type Device = Wallet<StdRng>;
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
    issuer_key: Keypair,
    key_bits: u64,
    seed: u64,
    limit: u64,
    devices: usize,
    ops: usize,
}

/// A backend and one device per account, each account opened with the given
/// online balance.
struct World {
    issuer: Issuer,
    accounts: Vec<AccountId>,
    devices: Vec<Device>,
}

fn world(cfg: &Config, seed: u64, balances: &[u64]) -> World {
    let mut rng = StdRng::seed_from_u64(seed);
    // The issuer key is generated once and shared: scenarios need independent
    // ledgers, not independent Eurosystems.
    let mut issuer = Issuer::new(cfg.issuer_key.clone());
    let mut accounts = Vec::new();
    let mut devices = Vec::new();
    for (index, balance) in balances.iter().enumerate() {
        let account = AccountId(rng.gen());
        issuer.open_account(account, *balance);
        let device = enrol(
            &mut issuer,
            account,
            cfg.limit,
            cfg.key_bits,
            StdRng::seed_from_u64(seed ^ (index as u64 + 1) << 32),
            &mut rng,
        )
        .expect("enrolment of a known account");
        accounts.push(account);
        devices.push(device);
    }
    World {
        issuer,
        accounts,
        devices,
    }
}

/// Two distinct devices, mutably, out of one vector.
fn pair(devices: &mut [Device], a: usize, b: usize) -> (&mut Device, &mut Device) {
    assert_ne!(a, b);
    if a < b {
        let (left, right) = devices.split_at_mut(b);
        (&mut left[a], &mut right[0])
    } else {
        let (left, right) = devices.split_at_mut(a);
        (&mut right[0], &mut left[b])
    }
}

fn euros(cents: u64) -> String {
    format!("{}.{:02} €", cents / 100, cents % 100)
}

// ───────────────────────────── scenarios ─────────────────────────────

/// The question that started this: pay 6 € out of 10 €, keep the 4 €.
fn partial_payment_keeps_the_rest(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed, &[100_00, 0, 0]);
    fund(&mut w.devices[0], &mut w.issuer, 10_00).map_err(|e| e.to_string())?;

    let (alice, bakery) = pair(&mut w.devices, 0, 1);
    pay(alice, bakery, 6_00).map_err(|e| format!("6 € payment failed: {e}"))?;
    ensure!(
        alice.balance() == 4_00,
        "Alice should keep 4 €, has {}",
        euros(alice.balance())
    );
    ensure!(bakery.balance() == 6_00, "bakery should hold 6 €");

    let (alice, kiosk) = pair(&mut w.devices, 0, 2);
    pay(alice, kiosk, 4_00).map_err(|e| format!("spending the 4 € left failed: {e}"))?;
    ensure!(alice.balance() == 0, "Alice should be empty");
    ensure!(kiosk.balance() == 4_00, "kiosk should hold 4 €");

    note!(
        notes,
        "10 € funded, 6 € to the bakery, the 4 € left spent at the kiosk"
    );
    Ok(())
}

/// Money received offline can be paid on at once, still offline.
fn received_value_is_respendable(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 1, &[100_00, 0, 0]);
    fund(&mut w.devices[0], &mut w.issuer, 10_00).map_err(|e| e.to_string())?;
    let float = w.issuer.offline_float();

    let (alice, bakery) = pair(&mut w.devices, 0, 1);
    pay(alice, bakery, 6_00).map_err(|e| e.to_string())?;
    let (bakery, supplier) = pair(&mut w.devices, 1, 2);
    pay(bakery, supplier, 5_00).map_err(|e| format!("bakery could not re-spend: {e}"))?;
    let (supplier, alice) = pair(&mut w.devices, 2, 0);
    pay(supplier, alice, 2_00).map_err(|e| format!("supplier could not re-spend: {e}"))?;

    let total: u64 = w.devices.iter().map(Device::balance).sum();
    ensure!(
        total == 10_00,
        "value not conserved: {} on devices",
        euros(total)
    );
    ensure!(
        w.issuer.offline_float() == float,
        "the issuer's view changed during offline payments"
    );
    note!(
        notes,
        "alice -> bakery -> supplier -> alice, all offline, 10 € conserved"
    );
    note!(notes, "the issuer's books did not move");
    Ok(())
}

/// A payment the payer's element refuses costs neither side anything.
fn refused_payment_costs_nothing(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 2, &[100_00, 0]);
    fund(&mut w.devices[0], &mut w.issuer, 5_00).map_err(|e| e.to_string())?;

    let (alice, bakery) = pair(&mut w.devices, 0, 1);
    match pay(alice, bakery, 6_00) {
        Err(Error::InsufficientFunds { .. }) => {}
        other => return Err(format!("expected InsufficientFunds, got {other:?}")),
    }
    ensure!(
        alice.balance() == 5_00,
        "payer was debited for a refused payment"
    );
    ensure!(
        bakery.reserved() == 0,
        "payee kept a reservation for a dead request"
    );

    // A payee whose certificate the Eurosystem never signed gets nothing.
    let mut request = bakery.request_payment(1_00).map_err(|e| e.to_string())?;
    request.payee = rogue_certificate(cfg);
    match alice.pay(&request) {
        Err(Error::InvalidCertificate) => {}
        other => return Err(format!("expected InvalidCertificate, got {other:?}")),
    }
    ensure!(alice.balance() == 5_00, "payer paid an uncertified device");

    note!(
        notes,
        "overdraft and uncertified payee both refused before any debit"
    );
    Ok(())
}

fn rogue_certificate(cfg: &Config) -> DeviceCertificate {
    let mut rng = StdRng::seed_from_u64(cfg.seed ^ 0x0bad);
    let mut rogue = Issuer::new(Keypair::generate(512, &mut rng));
    let account = AccountId([0xee; 16]);
    rogue.open_account(account, 0);
    let key = Keypair::generate(512, &mut rng);
    rogue
        .certify_device(account, &key.public, cfg.limit, &mut rng)
        .expect("rogue certification")
}

/// The payee's holding limit is enforced before the payer is debited.
fn holding_limit_checked_before_debit(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 3, &[cfg.limit, cfg.limit]);
    fund(&mut w.devices[0], &mut w.issuer, cfg.limit).map_err(|e| e.to_string())?;
    fund(&mut w.devices[1], &mut w.issuer, cfg.limit - 1_00).map_err(|e| e.to_string())?;

    let (alice, bakery) = pair(&mut w.devices, 0, 1);
    match pay(alice, bakery, 2_00) {
        Err(Error::HoldingLimitExceeded { headroom, .. }) => {
            ensure!(headroom == 1_00, "headroom reported as {headroom}")
        }
        other => return Err(format!("expected HoldingLimitExceeded, got {other:?}")),
    }
    ensure!(alice.balance() == cfg.limit, "payer was debited anyway");
    pay(alice, bakery, 1_00).map_err(|e| format!("payment within headroom refused: {e}"))?;
    ensure!(
        bakery.balance() == cfg.limit,
        "bakery should now be exactly at its limit"
    );

    note!(
        notes,
        "2 € refused with 1 € of room; 1 € accepted, bakery at its limit"
    );
    Ok(())
}

/// Replaying or tampering with a transfer gains nothing.
fn transfers_resist_replay_and_tampering(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 4, &[100_00, 0, 0]);
    fund(&mut w.devices[0], &mut w.issuer, 10_00).map_err(|e| e.to_string())?;

    let request = w.devices[1]
        .request_payment(6_00)
        .map_err(|e| e.to_string())?;
    let transfer = w.devices[0].pay(&request).map_err(|e| e.to_string())?;

    let mut inflated = transfer.clone();
    inflated.amount_cents = 60_00;
    ensure!(
        w.devices[1].receive(&inflated) == Err(Error::InvalidSignature),
        "an inflated transfer was not rejected"
    );
    let mut redirected = transfer.clone();
    redirected.payee = w.devices[2].device();
    ensure!(
        w.devices[2].receive(&redirected) == Err(Error::InvalidSignature),
        "a redirected transfer was not rejected"
    );
    ensure!(
        w.devices[1].receive(&transfer) == Ok(6_00),
        "the genuine transfer was not credited"
    );
    ensure!(
        w.devices[1].receive(&transfer) == Err(Error::AlreadyCredited),
        "a replayed transfer was not refused"
    );
    ensure!(
        w.devices[1].balance() == 6_00,
        "payee credited more than once"
    );

    note!(
        notes,
        "inflated and redirected copies rejected; the replay credited nothing"
    );
    Ok(())
}

/// Value goes back online, and a defunding order cannot be cashed twice.
fn defunding_round_trip(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 5, &[100_00]);
    let account = w.accounts[0];
    fund(&mut w.devices[0], &mut w.issuer, 30_00).map_err(|e| e.to_string())?;
    let order = w.devices[0].defund(12_00).map_err(|e| e.to_string())?;
    ensure!(w.issuer.defund(&order) == Ok(12_00), "defunding refused");
    ensure!(
        w.issuer.defund(&order) == Err(Error::Replay),
        "a defunding order was cashed twice"
    );
    ensure!(
        w.issuer.balance_of(&account) == Some(82_00),
        "account should hold 82 €, holds {:?}",
        w.issuer.balance_of(&account)
    );
    ensure!(w.issuer.offline_float() == 18_00, "float should be 18 €");
    note!(notes, "30 € funded, 12 € defunded, replayed order refused");
    Ok(())
}

/// No recovery: a lost device takes its balance with it.
fn lost_device_strands_its_balance(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 6, &[100_00]);
    let account = w.accounts[0];
    fund(&mut w.devices[0], &mut w.issuer, 40_00).map_err(|e| e.to_string())?;
    w.devices.clear(); // dropped in the river
    ensure!(
        w.issuer.balance_of(&account) == Some(60_00),
        "the account was made whole"
    );
    ensure!(
        w.issuer.offline_float() == 40_00,
        "the lost value should stay counted as offline"
    );
    note!(
        notes,
        "40 € gone with the device; the float carries it forever"
    );
    Ok(())
}

/// A cracked element pays out value it does not have. Offline nobody can
/// tell; online it shows up only in aggregate, with no pointer to the source.
fn cracked_element_counterfeits(cfg: &Config, notes: &mut Notes) -> Outcome {
    let mut w = world(cfg, cfg.seed + 7, &[100_00, 0, 0]);
    fund(&mut w.devices[0], &mut w.issuer, 10_00).map_err(|e| e.to_string())?;
    w.devices[0].crack_secure_element();

    for payee in [1, 2] {
        let (mallory, victim) = pair(&mut w.devices, 0, payee);
        pay(mallory, victim, 10_00)
            .map_err(|e| format!("payee {payee} refused a genuine-looking transfer: {e}"))?;
    }
    let circulating = w.devices[1].balance() + w.devices[2].balance();
    ensure!(
        circulating == 20_00,
        "expected 20 € in circulation from 10 € funded"
    );

    for payee in [1, 2] {
        defund(&mut w.devices[payee], &mut w.issuer, 10_00)
            .map_err(|e| format!("defunding refused: {e}"))?;
    }
    ensure!(
        w.issuer.offline_float() == -10_00,
        "float should be -10 €, is {}",
        w.issuer.offline_float()
    );
    ensure!(
        w.devices[0].balance() == 10_00,
        "the cracked element should still show its 10 €"
    );
    note!(
        notes,
        "10 € funded; 20 € paid out and defunded, 10 € still on the element"
    );
    note!(
        notes,
        "20 € created; the -10 € float shows it happened, not where"
    );
    Ok(())
}

// ──────────────────────────── commands ────────────────────────────

fn run_check(cfg: &Config) -> bool {
    let scenarios: &[(&str, Scenario)] = &[
        (
            "pay 6 € of 10 €, keep and spend the 4 €",
            partial_payment_keeps_the_rest,
        ),
        (
            "received value is re-spendable offline",
            received_value_is_respendable,
        ),
        (
            "refused payment costs nothing",
            refused_payment_costs_nothing,
        ),
        (
            "holding limit checked before debit",
            holding_limit_checked_before_debit,
        ),
        (
            "transfers resist replay and tampering",
            transfers_resist_replay_and_tampering,
        ),
        ("defunding round trip", defunding_round_trip),
        (
            "lost device strands its balance",
            lost_device_strands_its_balance,
        ),
        ("cracked element counterfeits", cracked_element_counterfeits),
    ];

    println!("acceptance scenarios");
    let mut failed = 0usize;
    for (name, scenario) in scenarios {
        let mut notes = Notes::new();
        let started = Instant::now();
        let outcome = scenario(cfg, &mut notes);
        let elapsed = started.elapsed().as_millis();
        match outcome {
            Ok(()) => println!("  PASS  {name}  ({elapsed} ms)"),
            Err(why) => {
                failed += 1;
                println!("  FAIL  {name}  ({elapsed} ms)");
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

/// Random fundings, payments, and defundings across many honest devices,
/// with every invariant checked after every operation:
///
/// * no device ever exceeds its holding limit;
/// * value on devices equals the issuer's offline float;
/// * online balances plus the float equal the money that existed at the start;
/// * a refused operation changes nothing, anywhere.
fn run_fuzz(cfg: &Config) -> bool {
    let n = cfg.devices;
    println!("fuzz: {} operations across {n} devices", cfg.ops);
    let started = Instant::now();
    let opening = 3 * cfg.limit / 2;
    let mut w = world(cfg, cfg.seed ^ 0xf022, &vec![opening; n]);
    let money = opening as u128 * n as u128;
    let mut rng = StdRng::seed_from_u64(cfg.seed ^ 0x5eed);
    let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();

    for step in 0..cfg.ops {
        let before = snapshot(&w);
        let a = rng.gen_range(0..n);
        // Amounts up to half the limit, so every kind of refusal gets hit.
        let amount = rng.gen_range(1..=cfg.limit / 2);
        let (kind, result) = match rng.gen_range(0..10) {
            0..=1 => ("fund", fund(&mut w.devices[a], &mut w.issuer, amount)),
            2 => ("defund", defund(&mut w.devices[a], &mut w.issuer, amount)),
            _ => {
                let b = (a + rng.gen_range(1..n)) % n;
                let (payer, payee) = pair(&mut w.devices, a, b);
                ("pay", pay(payer, payee, amount))
            }
        };
        let label = match &result {
            Ok(_) => format!("{kind}: ok"),
            Err(error) => {
                if snapshot(&w) != before {
                    println!("  FAIL at step {step}: refused {kind} ({error}) changed state");
                    return false;
                }
                let name = format!("{error:?}");
                let name = name.split([' ', '{', '(']).next().unwrap_or("").to_string();
                format!("{kind}: refused, {name}")
            }
        };
        *outcomes.entry(label).or_default() += 1;

        if let Err(why) = check_invariants(&w, cfg.limit, money) {
            println!("  FAIL at step {step} after {kind}: {why}");
            return false;
        }
    }

    for (label, count) in &outcomes {
        println!("  {count:>6}  {label}");
    }
    let on_devices: u64 = w.devices.iter().map(Device::balance).sum();
    println!(
        "  final: {} on devices, float {} cents  ({} ms)",
        euros(on_devices),
        w.issuer.offline_float(),
        started.elapsed().as_millis()
    );
    println!("  every invariant held after every operation");
    true
}

/// Balances and reservations of every device, and every online account.
fn snapshot(w: &World) -> (Vec<(u64, u64)>, Vec<Option<u64>>, i128) {
    (
        w.devices
            .iter()
            .map(|d| (d.balance(), d.reserved()))
            .collect(),
        w.accounts.iter().map(|a| w.issuer.balance_of(a)).collect(),
        w.issuer.offline_float(),
    )
}

fn check_invariants(w: &World, limit: u64, money: u128) -> Outcome {
    for (index, device) in w.devices.iter().enumerate() {
        ensure!(
            device.balance() <= limit,
            "device {index} holds {} over a {} limit",
            device.balance(),
            limit
        );
        ensure!(device.reserved() == 0, "device {index} kept a reservation");
    }
    let on_devices: u128 = w.devices.iter().map(|d| d.balance() as u128).sum();
    ensure!(
        on_devices as i128 == w.issuer.offline_float(),
        "{on_devices} on devices but float says {}",
        w.issuer.offline_float()
    );
    let online: u128 = w
        .accounts
        .iter()
        .map(|a| w.issuer.balance_of(a).unwrap_or(0) as u128)
        .sum();
    ensure!(
        online + on_devices == money,
        "money supply moved: {online} online + {on_devices} offline != {money}"
    );
    Ok(())
}

// ───────────────────────────── plumbing ─────────────────────────────

fn usage() {
    println!(
        "digital-euro-wallet - offline digital euro harness

USAGE:
    digital-euro-wallet [COMMAND] [OPTIONS]

COMMANDS:
    check        Run every acceptance scenario and report PASS/FAIL (default)
    fuzz         Random fundings, payments, and defundings; invariants checked
                 after every operation
    all          check, then fuzz

OPTIONS:
    --seed <N>          RNG seed                               (default 2026)
    --key-bits <N>      RSA modulus size for issuer and devices (default 2048)
    --limit <CENTS>     per-device offline holding limit        (default 50000)
    --devices <N>       devices in the fuzz run                 (default 6)
    --ops <N>           operations in the fuzz run              (default 400)
    -h, --help          Show this message

The holding limit is a parameter of the model, not a figure from the ECB.
Exit code is 0 when everything passes, 1 otherwise.
For a narrated run: cargo run --release --example offline_payment"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut command = "check";
    let mut seed = 2026u64;
    let mut key_bits = 2048u64;
    let mut limit = 500_00u64;
    let mut devices = 6usize;
    let mut ops = 400usize;

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-h" | "--help" => {
                usage();
                return ExitCode::SUCCESS;
            }
            "check" => command = "check",
            "fuzz" => command = "fuzz",
            "all" => command = "all",
            "--seed" | "--key-bits" | "--limit" | "--devices" | "--ops" => {
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
                    "--limit" => limit = parsed,
                    "--devices" => devices = parsed as usize,
                    "--ops" => ops = parsed as usize,
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

    if key_bits < 512 || key_bits % 2 != 0 {
        eprintln!("error: --key-bits must be even and at least 512");
        return ExitCode::FAILURE;
    }
    if limit < 20_00 {
        eprintln!("error: --limit must be at least 2000 cents (the scenarios pay up to 20 €)");
        return ExitCode::FAILURE;
    }
    if devices < 2 {
        eprintln!("error: --devices must be at least 2");
        return ExitCode::FAILURE;
    }

    println!("digital euro wallet - offline harness");
    print!("  generating the Eurosystem's RSA-{key_bits} key ... ");
    let _ = std::io::stdout().flush();
    let started = Instant::now();
    let issuer_key = Keypair::generate(key_bits, &mut StdRng::seed_from_u64(seed));
    println!("done in {} ms", started.elapsed().as_millis());
    println!(
        "  seed {seed}, {} holding limit per device, device keys RSA-{key_bits}\n",
        euros(limit)
    );

    let cfg = Config {
        issuer_key,
        key_bits,
        seed,
        limit,
        devices,
        ops,
    };

    let ok = match command {
        "check" => run_check(&cfg),
        "fuzz" => run_fuzz(&cfg),
        "all" => {
            let checked = run_check(&cfg);
            println!();
            let fuzzed = run_fuzz(&cfg);
            checked && fuzzed
        }
        _ => unreachable!(),
    };

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
