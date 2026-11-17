# LEZ: private account ↔ public DEX pool in one transaction (PoC)

On the [Logos Execution Zone](https://github.com/logos-blockchain/logos-execution-zone) `dev`
branch (the upcoming 0.4), a **private account can swap against a public AMM pool PDA in a single
privacy-preserving transaction**. On LEZ 0.2 a private user had to deshield to a fresh ephemeral
public account, swap, then re-shield. That is no longer needed.

> Alice holds AAA in a private account → one tx → the public pool's reserves are updated, and
> Alice holds BBB in the same (or a new) private account. Alice never has a public account.

This repo holds a minimal token program, a constant-product AMM and state-machine tests, applied
as a patch on top of LEZ `dev`.

## Run

```sh
./run.sh          # real proofs (slow, see "Proof run" below)
DEV=1 ./run.sh    # RISC0_DEV_MODE=1: same execution and boundary checks, fake seals
```

`run.sh` clones `logos-execution-zone`, checks out dev commit `86df4f6f0a` and applies
`patches/0001-poc-private-dex-swap.patch` (the files are also in `src/` for reading). It then runs
`cargo test --release -p lee --lib -- private_dex_swap`. That commit is the last dev commit
before dev moved to risc0 3.1, so it needs `r0vm`/`cargo-risczero` **3.0.x** (`rzup`). Nothing in
the LEE execution model changed in that bump.

| File (in LEZ) | What |
|---|---|
| `lee/state_machine/test_methods/guest/src/bin/poc_token.rs` | A fungible token: a holding is the token's actor state on any account, public or private. Deployed twice, as AAA and BBB. |
| `lee/state_machine/test_methods/guest/src/bin/poc_amm.rs` | A constant-product pool at a public PDA. It holds the pool state plus both vaults on one account. |
| `lee/state_machine/src/state/tests/private_dex_swap.rs` | The tests. |

## Why it works on LEZ dev

1. **Hybrid call graphs.** One transaction runs public and private actors together, linked by
   sync messages. The circuit records a *boundary*: the ordered messages crossing
   private→public and public→private (`BoundaryStep`, `ProvenExecution.boundary`).
2. **The proof fixes the boundary, not the public state.** The sequencer re-runs the public part
   against the **live** state. It only checks that the run reproduces the proven boundary
   exactly. The pool's reserves are never committed in the proof, so other trades can move the
   pool within the same block.
3. **Blinded aliases.** The private account is addressed as `account_id.blinded(factor)`, opened
   inside the circuit (`PrivateWitness.address_openings`, `SenderPresentation::Blinded`). The
   transaction only carries one-time aliases, never the account id.
4. **Accounts hold one actor state per program.** The same private account holds AAA and BBB,
   and the pool PDA holds the AMM state and both vaults.

## The swap

Root: a public call to `Actor(pool, amm)`, with
`Swap { trader: alias_in, token_in: AAA, amount_in, amount_out, recipient: alias_out }`.

```
pool/amm     --Transfer(amount_in → pool)--------------> alias_in/AAA    [public → private]
alias_in/AAA --Credit(amount_in)-----------------------> pool/AAA        [private → public]
pool/amm     --Transfer(amount_out → alias_out), PDA---> pool/BBB
pool/BBB     --Credit(amount_out)----------------------> alias_out/BBB   [public → private]
```

**Design constraint.** Every message crossing back into the private side must not depend on the
live reserves. Otherwise the proof would be bound to one pool state. So the trader names
`amount_out` (their minimum, quote × (1 − slippage)). The pool checks the constant-product
invariant (after fee) against the reserves it finds at execution time and keeps any surplus.

## Tests

| Test | Shows |
|---|---|
| `private_account_swaps_in_one_tx_after_the_pool_moved` | Alice proves against the pool's state S0. Bob's public swap then moves the pool. Alice's tx still settles. Same private account: AAA debited, BBB credited, old note nullified. Alice's account id is not in the tx bytes. The aliases have no public state. The boundary has the shape above. |
| `private_swap_reverts_when_the_price_moved_beyond_the_bound` | Bob moves the price past Alice's 1% bound. The pool refuses, the pool is unchanged, and Alice's note is not spent, so she re-quotes and re-proves. |
| `private_swap_can_pay_out_into_a_fresh_private_account` | BBB lands in a brand-new private account (init witness, blinded alias). |
| `public_account_swaps_directly` | The same pool serves public traders. |

## Proof run

All 4 tests pass with **real proofs** (`RISC0_DEV_MODE` unset) on 16 cores / 60 GB RAM, using
r0vm 3.0.5. The three private-swap tests each generate a succinct receipt of the
privacy-preserving circuit. It composes the token-program transitions run privately for
Alice's holdings. Settlement (`V03State::transition_from_privacy_preserving_transaction`)
verifies that receipt against the circuit image id (`PRIVACY_PRESERVING_CIRCUIT_ID`); a fake
receipt would be rejected. The public part is then re-executed against the live pool.

```
running 4 tests
test state::tests::private_dex_swap::private_account_swaps_in_one_tx_after_the_pool_moved ... ok
test state::tests::private_dex_swap::private_swap_can_pay_out_into_a_fresh_private_account ... ok
test state::tests::private_dex_swap::private_swap_reverts_when_the_price_moved_beyond_the_bound ... ok
test state::tests::private_dex_swap::public_account_swaps_directly ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 310 filtered out; finished in 1268.97s
real 21m15.9s   user 294m42.1s
```

The panic message `amm: price moved beyond the trader's bound` in the output is expected: it is
the pool refusing in the revert test. On this CPU-only machine, proving takes about 7 minutes per
swap.

## What is visible on-chain

- **Visible:** the pool, the direction, `amount_in`, `amount_out` (the trader's bound, not the
  realised price), and two one-time aliases. They are tied to each other only within this tx.
- **Not visible:** which private account paid or received, or any link to the same user's other
  swaps (when the blinding factors are fresh per swap, as the LEZ wallet already does per
  message).

## Caveats

- **Gas.** The PoC is fee-less. On dev, a privacy-preserving tx pays its fee in-proof from a
  private payer (`FeeTransfer`), so gas also comes from the private balance. Not exercised here.
- **Surplus.** A price better than the bound accrues to the pool (LPs). An exact variable output
  would need the output sent as an async message to `alias_out` and claimed in a later private
  tx. That is still no public account, but it takes two txs.
- **Authorization.** A private witness holding its key is authorized for every message in its
  own tx. The wallet/SDK must simulate the call graph and check that the AMM only pulls
  `amount_in`.
- **Not production code.** The token and AMM are minimal sketches: one pool per AMM deployment,
  no LP shares, no init instruction (the test seeds state directly). The `lez-programs`
  token/amm are still on LEZ v0.2.5 and would need porting to the actor model.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option, like
LEZ itself.
