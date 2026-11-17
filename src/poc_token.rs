//! PoC fungible token in the LEE actor model.
//!
//! A holding is the token program's actor state on any account (public or private): a `u128`
//! balance, little-endian, empty when zero. One bytecode deployed at two addresses gives two
//! distinct tokens (AAA and BBB), since dispatch and ownership follow the deployment address.
//!
//! - `Transfer { to, amount }` debits the receiving holding (must be authorized: signed, a
//!   private witness holding the key, or a PDA the calling program owns) and credits
//!   `Actor(to, this token)` with a *synchronous* `Credit`, so the credit lands in the same
//!   transaction whether `to` is public or private.
//! - `Credit(amount)` is accepted only from another holding of this same token.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Actor},
    program::{ReceiveInput, Response},
};

#[derive(BorshSerialize, BorshDeserialize)]
enum TokenMessage {
    Transfer { to: AccountId, amount: u128 },
    Credit(u128),
}

fn read(state: &[u8]) -> u128 {
    if state.is_empty() {
        return 0;
    }
    u128::from_le_bytes(state.try_into().expect("a holding is a 16-byte balance"))
}

fn write(balance: u128) -> Vec<u8> {
    if balance == 0 {
        Vec::new()
    } else {
        balance.to_le_bytes().to_vec()
    }
}

lee_core::actor_entrypoint!(raw handle_message);

fn handle_message(input: &ReceiveInput) -> Response {
    let token = input.receiver.program_account_id;
    let message: TokenMessage = borsh::from_slice(&input.message).expect("token message decodes");
    match message {
        TokenMessage::Transfer { to, amount } => {
            assert!(input.is_authorized, "token: holder did not authorize");
            let post = read(&input.pre_state)
                .checked_sub(amount)
                .expect("token: insufficient balance");
            Response::set_state(write(post))
                .send_sync(Actor::new(to, token), &TokenMessage::Credit(amount))
        }
        TokenMessage::Credit(amount) => {
            assert!(
                input.from_own_program(),
                "token: a credit only comes from a holding of this token"
            );
            let post = read(&input.pre_state)
                .checked_add(amount)
                .expect("token: balance overflow");
            Response::set_state(write(post))
        }
    }
}
