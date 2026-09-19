# digital-euro-wallet

A Rust model of the offline digital euro wallet: cash-like anonymity for ordinary
payments, with the payer's device identity falling out of the algebra the moment a
token is spent twice.

The scheme is Chaum–Fiat–Naor style e-cash — a 2-of-2 secret sharing line per
identity limb, blind RSA issuance, and cut-and-choose to stop a wallet from
embedding a fake identity.

```
   online funding                 offline payment              settlement
   ──────────────                 ───────────────              ──────────
   wallet ──n candidates──► issuer
   wallet ◄───── cut ────── issuer    merchant ────x────► wallet
   wallet ──n-1 openings──► issuer    merchant ◄──(x,y)─── wallet
   wallet ◄blind signature─ issuer    merchant ──receipt──► issuer
```

## Run it

```bash
cargo test                                      # 21 unit + protocol tests
cargo run --release --example offline_payment   # narrated end-to-end run
cargo build --release                           # builds the harness executable
```

The example funds a 10 € token, spends it at a bakery, shows the sealed secure
element refusing a second spend, then cracks the element, double-spends at a
kiosk, and watches the backend recover the wallet identity at settlement.

### The harness executable

`cargo build --release` produces `target/release/digital-euro-wallet`
(`.exe` on Windows), an acceptance harness that drives whole protocol runs and
asserts the outcome of each. It exits non-zero if anything fails.

```bash
digital-euro-wallet check        # 11 end-to-end scenarios, PASS/FAIL (default)
digital-euro-wallet soundness    # measure the forgery escape rate against 1/n
digital-euro-wallet all          # both
digital-euro-wallet --help       # --seed, --key-bits, --candidates, --amount, …
```

`check` covers what `cargo test` does not reach as a whole-system property:
value conservation across issuance and settlement (no cent created or
destroyed over four tokens and two terminals), and the claim that a single
point excludes no slope, sampled 2000 times per limb.

`soundness` puts a number on the cut-and-choose bound. A cheating wallet forges
one of `n` candidates and is signed only if the issuer happens to keep that one,
so the escape rate should sit at `1/n`; the harness runs the attack repeatedly
and checks the observed rate against a four-sigma binomial band, while asserting
that *every* forgery the issuer opened was caught. At the default `n = 20`:

```
  caught 190, escaped 10
  observed escape rate 0.0500, expected 1/n = 0.0500
```

## How the pieces map to the maths

| Concept | Where |
| --- | --- |
| `f(x) = I·x + s mod p` | `src/token.rs` — `SecretLines::respond` |
| `I = (y₁−y₂)(x₁−x₂)⁻¹` | `src/token.rs` — `recover_identity` |
| `F_p`, `p = 2^61 − 1` | `src/field.rs` |
| 256-bit `I` split into 5 × 52-bit slopes | `src/identity.rs` |
| Blind signature `m·rᵉ → sᵈ → s·r⁻¹` | `src/blind_sig.rs` |
| Cut-and-choose verification | `src/issuer.rs` — `Issuer::issue` |
| Challenge `x = H(merchant‖ts‖amount‖nonce)` | `src/token.rs` — `derive_challenge` |
| Sealed vs. cracked secure element | `src/wallet.rs` — `ElementState` |

### Why five lines instead of one

`p = 2^61 − 1` keeps every field operation inside a `u128`, so the hot path needs
no bignum. A 256-bit identity does not fit in one such field element, so it is cut
into five 52-bit limbs, each the slope of its own line. All five lines are
evaluated at the *same* merchant challenge, so one double-spend yields two points
per line and every limb is recovered together.

### Why the intercept is fresh per token

The intercept `s` is the only thing hiding the slope. Reusing an intercept across
two tokens would let two single spends of *different* tokens be combined into two
points on one line — an anonymity break with no double-spend at all. Each
candidate draws fresh intercepts for every limb.

### Why the merchant derives the challenge from the sale

If a merchant could pick `x` freely it could replay a previous `x`, and two points
sharing an abscissa determine nothing. `derive_challenge` binds `x` to merchant
id, timestamp, amount and nonce; `x = 0` is refused because `f(0) = s` leaks the
intercept and nothing else. The `reused_challenge_does_not_unmask_anyone` test
pins this down: replaying a challenge leaves the payer anonymous, which is the
correct — and deliberate — outcome.

## Settlement outcomes

`Issuer::redeem` returns one of:

- `Credited` — first sighting of the serial, merchant paid, payer anonymous.
- `DuplicateDeposit` — same serial, same challenge, same answer: a merchant
  depositing twice. Paid once, no fraud inferred.
- `DoubleSpend(FraudReport)` — two distinct challenges on one serial. Contains
  the recovered `WalletId`, both merchant ids, and whether the identity matches a
  registered account.
- `Rejected(Error)` — bad signature, or two answers on the same challenge that
  differ, which is a forged response rather than a double-spend.

## Security scope

This is a reference model, written to be read. It is **not** production
cryptography:

- Schoolbook `modpow`, no constant-time discipline, no blinding against timing or
  fault attacks on the issuer key.
- A hash-expansion full-domain hash rather than a reviewed scheme (RSA-FDH per
  RFC 9474, or a blind Schnorr / BBS construction).
- No secure-element attestation, no transport security between devices, no key
  storage story. A merchant offline cannot verify that the payer's answer lies on
  the committed lines at all — it accepts on the strength of the issuer's
  signature and the element's tamper resistance, exactly as a shopkeeper accepts a
  banknote. Garbage answers are caught only at settlement, where they decode to
  slopes outside the identity's bit budget.
- Not modelled: denominations and change, offline holding limits, expiry-driven
  re-anchoring, revocation lists, staged or partial anonymity revocation, and
  every legal or data-protection requirement that would govern a real disclosure.

Cut-and-choose over `n` candidates leaves a cheating wallet a `1/n` chance of
getting a forged identity certified — measurable with
`digital-euro-wallet soundness`. The example uses `n = 20`; tests use smaller
values for speed. `1/20` is a deliberately generous bound for a reference model:
a real deployment would either raise `n` or replace cut-and-choose with a
zero-knowledge proof that the identity is embedded, which costs one proof instead
of `n` blinded candidates per token.

## Layout

```
src/field.rs      F_p arithmetic
src/identity.rs   WalletId ↔ limb slopes
src/hash.rs       domain-separated SHA-256
src/blind_sig.rs  RSA blind signatures, prime generation, Miller-Rabin
src/token.rs      payload, lines, proofs, double-spend solver
src/wallet.rs     secure element, withdrawal, payment
src/merchant.rs   challenge issuance, offline acceptance, deposits
src/issuer.rs     accounts, cut-and-choose, ledger, settlement
src/main.rs       acceptance harness executable (check / soundness)

examples/offline_payment.rs   narrated end-to-end run
tests/protocol.rs             protocol-level tests
```

Dependencies are pinned to versions that build on Rust 1.75 (`sha2`,
`num-bigint`, `num-integer`, `num-traits`, `rand`), and that minimum is declared
as `rust-version` in `Cargo.toml` so cargo enforces it and clippy stops
suggesting standard-library APIs that only exist on newer toolchains.

`cargo clippy --all-targets -- -D warnings` is clean. Two lints are suppressed
deliberately rather than fixed, each with the reason recorded at the site:
`should_implement_trait` on `Fp`, because the reduction mod `p` should stay
visible at the call site instead of hiding behind `+`, and
`inconsistent_digit_grouping`, because amounts are written as cents with the
euros split off (`100_00` is 100.00 €).
