# digital-euro-wallet

A Rust model of the offline digital euro as the ECB has described it: value held
as a balance on a secure element, paid directly from one certified device to
another, settled locally, and immediately re-spendable offline.

```
   online                            offline, device to device
   ──────                            ─────────────────────────
   account ──funding───► device A    device B ──PaymentRequest──► device A
   account ◄─defunding── device A    device B ◄──────Transfer──── device A
```

Pay 6 € out of 10 € and the payer's element keeps 4 €. There is nothing to split
and no change to hand back, because there are no tokens, only a balance. The payee
can spend its 6 € straight away, still offline.

## Run it

```bash
cargo test                                      # 25 unit and protocol tests
cargo run --release --example offline_payment   # narrated run
cargo build --release                           # builds the harness executable
```

The example funds Alice's phone with 10 € and buys 6 € of bread. The bakery then
pays the flour mill 5 € out of that money, never going online. Alice's overdraft
is refused and she spends her remaining 4 €. After that the example shows what a
lost phone and a cracked secure element do to the money supply.

### The harness executable

`target/release/digital-euro-wallet` (`.exe` on Windows) drives whole runs
across several devices and exits non-zero if anything fails.

```bash
digital-euro-wallet check    # 8 end-to-end scenarios, PASS/FAIL (default)
digital-euro-wallet fuzz     # random operations, invariants after every one
digital-euro-wallet all      # both
digital-euro-wallet --help   # --seed, --key-bits, --limit, --devices, --ops
```

`fuzz` runs random fundings, payments and defundings across many devices,
with amounts large enough to hit every kind of refusal. After *every*
operation it checks that:

- no device exceeds its holding limit and no reservation is left dangling;
- the value on devices equals the issuer's offline float;
- online balances plus the float equal the money that existed at the start;
- a refused operation changed nothing anywhere.

## What comes from the ECB, and what is this model's own

**Described by the ECB and the offline project** (see sources below):

- Offline value sits in an applet on a secure element that "debits and credits
  a balance".
- It moves directly between certified devices and settles locally between them.
- It is "immediately re-spendable offline".
- It is funded from, and defunded to, an online digital euro account.
- Double-spending prevention rests on tamper-resistant hardware. Two devices
  with no shared record cannot stop a double spend by cryptography alone.
- Transaction details are visible only to the payer and payee. Nothing is
  reported to banks or the central bank.
- There is reportedly no recovery for funds on a lost, damaged or stolen device.

**This model's own choices.** The ECB has not published a wire protocol:

- The messages (`PaymentRequest`, `Transfer`, `FundingRequest`, `Funding`,
  `Defunding`), their signatures, and the nonce and counter replay protection.
- **The payee reserves room under its holding limit before the payer is
  debited.** A payment can fail on the payee's side, so the reservation is made
  when the request is issued, not when the transfer arrives. Once the payer has
  paid, the credit cannot fail. On the payer's side, every check that could
  cause a refusal runs before the debit. A refused payment costs nobody
  anything.
- **The holding limit** is a per-device parameter (500 € by default), not an
  ECB figure. The ECB's own calibration covers overall digital euro holdings,
  and was still in progress in the sources consulted.
- **Device certificates omit the account.** The payee sees a device pseudonym;
  only the issuer can map it back to an account, and the issuer never sees
  payments.
- **The offline float** (funded minus defunded) is the issuer's only view of
  offline money.

## What a cracked secure element does

The whole design rests on the element refusing to spend value it does not have.
`crack_secure_element()` models that failing: the element keeps signing payments
without debiting itself.

- **Offline, nobody can tell.** The payee sees a genuine certificate and a
  genuine signature.
- **Online, the issuer sees only the float.** Counterfeiting pushes the value
  actually on devices above the float, and the issuer cannot see what is
  actually on devices. It notices only if more is defunded than was ever
  funded, which drives the float negative. That may never happen.
- **Even then there is no culprit.** Payments are never reported, so nothing on
  record links the extra money to the device that made it.

In the example, a cracked phone funded with 10 € pays out 20 € and still shows
10 €, so 20 € is created from nothing. After the payees defund, the issuer's
float reads a healthy +10 €.

This is a real weakness of hardware-only designs, not an artefact of the model.
The alternative this repository used to implement is Chaum–Fiat–Naor e-cash,
whose double-spending *reveals the culprit's identity* algebraically. That
approach costs divisibility and re-spendability, which is why it was dropped. It
is kept at the git tag `cfn-model`.

## Lost devices

Funding debits the online account, and nothing ever credits it back except
defunding, which needs the device. Lose the device and the value goes with it.
The float keeps counting it for good. This matches what has been reported about
the digital euro: offline funds on a lost device are treated like lost cash.

## Security scope

This is a reference model, written to be read. It is **not** production
cryptography:

- RSA with a hash-expansion full-domain hash, schoolbook modexp, no
  constant-time discipline. A real secure element would use an elliptic-curve
  scheme in hardware, with the key generated on-chip and never exported.
- The secure element is a Rust struct. Its "tamper resistance" is Rust's type
  system, and `crack_secure_element()` is how the model turns it off.
- Not modelled: device revocation, secure-element attestation, transport
  security, the legal framework. Transaction recovery is modelled only as far as
  resending a signed transfer, which is safe because each request nonce is
  credited once. If the payee abandons a request after the payer has paid, the
  payer's debit is not undone. The test
  `a_transfer_answering_no_open_request_is_refused` pins that gap down.

## Layout

```
src/signature.rs    RSA-FDH signatures, prime generation, Miller-Rabin
src/hash.rs         domain-separated SHA-256
src/id.rs           AccountId, DeviceId
src/certificate.rs  Eurosystem-signed device certificates
src/message.rs      payment, transfer, funding, and defunding messages
src/wallet.rs       the secure-element applet: balance, pay, receive, fund
src/issuer.rs       accounts, device certification, funding, defunding, float
src/lib.rs          enrol / fund / defund / pay helpers
src/main.rs         harness executable (check / fuzz)

examples/offline_payment.rs   narrated run
tests/protocol.rs             protocol-level tests
```

Dependencies are pinned to versions that build on Rust 1.75 (`sha2`,
`num-bigint`, `num-integer`, `num-traits`, `rand`). That minimum is declared as
`rust-version` in `Cargo.toml`, so cargo enforces it and clippy stops suggesting
standard-library APIs that only exist on newer toolchains.

`cargo clippy --all-targets -- -D warnings` is clean. Two lints are suppressed
on purpose, with the reason recorded where each applies. `inconsistent_digit_grouping`
is off because amounts are written as cents with the euros split off (`100_00`
is 100.00 €). `should_implement_trait` no longer applies, since the field
arithmetic went with the CFN model.

## Sources

- [OMFIF — The offline digital euro: when the secure element fails, what remains?](https://www.omfif.org/2026/09/the-offline-digital-euro-when-the-secure-element-fails-what-remains/)
  (quotes the ECB's description of the balance model and hardware-based
  double-spend protection)
- [Nexi — ECB awards G+D, Nexi and Capgemini the offline digital euro solution](https://www.nexigroup.com/en/media-relations/news/2025/10/ecb-digital-euro/)
- [ECB — The offline digital euro, ERPB, 9 April 2026](https://www.ecb.europa.eu/euro/digital_euro/timeline/profuse/shared/pdf/ecb.dep260409_Item_1_ECB_Presentation_Offline_Digital_Euro.en.pdf)
- [Wikipedia — Digital euro](https://en.wikipedia.org/wiki/Digital_euro) (no
  loss recovery for offline funds; holding-limit calibration)
