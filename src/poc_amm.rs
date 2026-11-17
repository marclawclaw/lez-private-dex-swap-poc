//! PoC constant-product AMM in the LEE actor model.
//!
//! The pool lives at the public PDA `P = for_public_pda(amm, POOL_SEED)`. One account holds:
//! - under the AMM program: the pool state (token ids, reserves, fee),
//! - under each token program: the vault holding of that token.
//!
//! `Swap` is "exact in, *chosen* out": the trader names both `amount_in` and `amount_out`, and
//! the pool accepts if the constant-product invariant (after fee) still holds at the reserves it
//! finds *when it executes*. Any surplus stays in the pool. That makes every message crossing
//! back into a private trader independent of the live reserves, so a private trader's proof
//! does not commit to any pool state: the pool may move within the block, and the swap still
//! settles as long as the price stayed within the trader's slippage bound.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Actor},
    program::{PdaSeed, ReceiveInput, Response, SyncMessage},
};

const POOL_SEED: PdaSeed = PdaSeed::new([0xA0; 32]);
const BPS: u128 = 10_000;

#[derive(BorshSerialize, BorshDeserialize)]
struct Pool {
    token_a: AccountId,
    token_b: AccountId,
    reserve_a: u128,
    reserve_b: u128,
    fee_bps: u128,
}

#[derive(BorshSerialize, BorshDeserialize)]
enum AmmMessage {
    Swap {
        /// Holder paying `amount_in` of `token_in`; any address that resolves to an authorized
        /// holding in this transaction (a signer, or a private account by a blinded alias).
        trader: AccountId,
        token_in: AccountId,
        amount_in: u128,
        amount_out: u128,
        /// Where `amount_out` of the other token goes (may be another blinded alias).
        recipient: AccountId,
    },
}

#[derive(BorshSerialize, BorshDeserialize)]
enum TokenMessage {
    Transfer { to: AccountId, amount: u128 },
}

/// Largest output the pool pays for `amount_in` at reserves `(reserve_in, reserve_out)`.
fn max_out(pool: &Pool, reserve_in: u128, reserve_out: u128, amount_in: u128) -> u128 {
    let in_after_fee = amount_in
        .checked_mul(BPS - pool.fee_bps)
        .expect("amm: overflow");
    let numerator = in_after_fee.checked_mul(reserve_out).expect("amm: overflow");
    let denominator = reserve_in
        .checked_mul(BPS)
        .and_then(|r| r.checked_add(in_after_fee))
        .expect("amm: overflow");
    numerator / denominator
}

lee_core::actor_entrypoint!(raw handle_message);

fn handle_message(input: &ReceiveInput) -> Response {
    let amm = input.receiver.program_account_id;
    let pool_id = input.receiver.account_id;
    assert_eq!(
        pool_id,
        AccountId::for_public_pda(&amm, &POOL_SEED),
        "amm: receiver is not the pool PDA"
    );
    let mut pool: Pool = borsh::from_slice(&input.pre_state).expect("amm: pool is initialized");
    let AmmMessage::Swap {
        trader,
        token_in,
        amount_in,
        amount_out,
        recipient,
    } = borsh::from_slice(&input.message).expect("amm message decodes");

    assert!(amount_in > 0 && amount_out > 0, "amm: zero amount");
    let token_out = if token_in == pool.token_a {
        let quote = max_out(&pool, pool.reserve_a, pool.reserve_b, amount_in);
        assert!(amount_out <= quote, "amm: price moved beyond the trader's bound");
        pool.reserve_a += amount_in;
        pool.reserve_b -= amount_out;
        pool.token_b
    } else if token_in == pool.token_b {
        let quote = max_out(&pool, pool.reserve_b, pool.reserve_a, amount_in);
        assert!(amount_out <= quote, "amm: price moved beyond the trader's bound");
        pool.reserve_b += amount_in;
        pool.reserve_a -= amount_out;
        pool.token_a
    } else {
        panic!("amm: token_in is not in this pool");
    };

    Response::set_state(borsh::to_vec(&pool).expect("pool encodes"))
        // 1. Pull `amount_in` from the trader's holding into the pool vault. The trader's holding
        //    authorizes it (signer or private witness); a failure aborts the whole transaction.
        .send_sync(
            Actor::new(trader, token_in),
            &TokenMessage::Transfer {
                to: pool_id,
                amount: amount_in,
            },
        )
        // 2. Pay `amount_out` from the vault, which the AMM owns as its PDA.
        .send(
            SyncMessage::new(
                Actor::new(pool_id, token_out),
                &TokenMessage::Transfer {
                    to: recipient,
                    amount: amount_out,
                },
            )
            .with_pda_seeds([POOL_SEED]),
        )
}
