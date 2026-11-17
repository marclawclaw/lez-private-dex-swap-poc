//! PoC: a private account swaps against a public AMM pool in ONE privacy-preserving transaction,
//! with no deshield → ephemeral public account → reshield detour.
//!
//! Alice holds AAA in a private account. The transaction's root is a public call to the pool
//! PDA. The pool pulls AAA from Alice's holding (a private actor, reached through a blinded
//! alias) and pays BBB back into a private holding (same account or a fresh one, again by a
//! blinded alias). The proof commits only to the *boundary* (the messages crossing between
//! private and public actors), not to the pool's state: the sequencer re-runs the public part
//! against the live pool. So the pool can move between proving and inclusion, and the swap still
//! settles as long as the price stayed within the trader's bound.

use lee_core::execution_state::BoundaryStep;

use super::*;
use crate::privacy_preserving_transaction::circuit::ProgramCatalog;

const TOKEN_A: AccountId = AccountId::new([0xAA; 32]);
const TOKEN_B: AccountId = AccountId::new([0xBB; 32]);
const POOL_SEED: PdaSeed = PdaSeed::new([0xA0; 32]);
const FEE_BPS: u128 = 30;
const RESERVE: u128 = 1_000_000;
const ALICE_AAA: u128 = 50_000;
const BOB_AAA: u128 = 500_000;
/// Blinding factors for Alice's one-time aliases: the in-alias she pays from and the out-alias
/// she is paid at. Fresh per swap in a wallet, so no two swaps share an on-chain address.
const F_IN: [u8; 32] = [0x11; 32];
const F_OUT: [u8; 32] = [0x22; 32];

// Host mirrors of the guest types (borsh-compatible).
#[derive(BorshSerialize, borsh::BorshDeserialize, Debug, PartialEq, Eq)]
struct Pool {
    token_a: AccountId,
    token_b: AccountId,
    reserve_a: u128,
    reserve_b: u128,
    fee_bps: u128,
}

#[derive(BorshSerialize)]
enum AmmMessage {
    Swap {
        trader: AccountId,
        token_in: AccountId,
        amount_in: u128,
        amount_out: u128,
        recipient: AccountId,
    },
}

fn amm_id() -> AccountId {
    AccountId::from_builtin_program(crate::test_methods::poc_amm().id())
}

fn pool_id() -> AccountId {
    AccountId::for_public_pda(&amm_id(), &POOL_SEED)
}

fn balance(amount: u128) -> ActorState {
    if amount == 0 {
        ActorState::empty()
    } else {
        ActorState::from(amount.to_le_bytes().to_vec())
    }
}

fn quote(reserve_in: u128, reserve_out: u128, amount_in: u128) -> u128 {
    let in_after_fee = amount_in * (10_000 - FEE_BPS);
    in_after_fee * reserve_out / (reserve_in * 10_000 + in_after_fee)
}

fn pool_actors() -> [Actor; 3] {
    let pool = pool_id();
    [
        Actor::new(pool, amm_id()),
        Actor::new(pool, TOKEN_A),
        Actor::new(pool, TOKEN_B),
    ]
}

fn catalog() -> ProgramCatalog {
    ProgramCatalog::from([
        (amm_id(), crate::test_methods::poc_amm()),
        (TOKEN_A, crate::test_methods::poc_token()),
        (TOKEN_B, crate::test_methods::poc_token()),
    ])
}

struct Dex {
    state: V03State,
    alice: TestPrivateKeys,
    alice_account: Account,
    bob: TestPublicKeys,
}

impl Dex {
    fn new() -> Self {
        let alice = test_private_account_keys_1();
        let alice_account = Account {
            nonce: Nonce(7),
            ..Account::default().with_actor_state(TOKEN_A, balance(ALICE_AAA))
        };
        let bob = test_public_account_keys_2();

        let mut state = V03State::new()
            .with_programs([crate::test_methods::poc_amm()])
            .with_programs_at([
                (TOKEN_A, crate::test_methods::poc_token(), true),
                (TOKEN_B, crate::test_methods::poc_token(), true),
            ])
            .with_private_account(&alice, &alice_account);
        let pool = Pool {
            token_a: TOKEN_A,
            token_b: TOKEN_B,
            reserve_a: RESERVE,
            reserve_b: RESERVE,
            fee_bps: FEE_BPS,
        };
        state.force_insert_account(
            pool_id(),
            Account::default()
                .with_actor_state(amm_id(), ActorState::from(borsh::to_vec(&pool).unwrap()))
                .with_actor_state(TOKEN_A, balance(RESERVE))
                .with_actor_state(TOKEN_B, balance(RESERVE)),
        );
        state.force_insert_account(
            bob.account_id(),
            Account::default().with_actor_state(TOKEN_A, balance(BOB_AAA)),
        );
        Self {
            state,
            alice,
            alice_account,
            bob,
        }
    }

    fn pool(&self) -> Pool {
        let account = self.state.get_account_by_id(pool_id());
        borsh::from_slice(account.data.actor_state(amm_id())).unwrap()
    }

    fn holding(&self, account_id: AccountId, token: AccountId) -> u128 {
        let state = self.state.get_account_by_id(account_id);
        let raw = state.data.actor_state(token);
        if raw.is_empty() {
            0
        } else {
            u128::from_le_bytes(raw.as_ref().try_into().unwrap())
        }
    }

    fn alice_id(&self) -> AccountId {
        self.alice.account_id()
    }

    /// Alice's wallet: simulate against the pool as she sees it now, then prove. `recipient`
    /// is where BBB lands; `extra_witness` is a fresh private account receiving it, if any.
    fn prove_alice_swap(
        &self,
        amount_in: u128,
        amount_out: u128,
        recipient: AccountId,
        extra_witness: Option<PrivateWitness>,
    ) -> PrivacyPreservingTransaction {
        let alice_commitment = Commitment::new(&self.alice_id(), &self.alice_account);
        let alice_witness = PrivateWitness {
            address_openings: BTreeSet::from([F_IN, F_OUT]),
            ..update_witness(
                &self.alice,
                self.alice_account.clone(),
                self.state
                    .get_proof_for_commitment(&alice_commitment)
                    .expect("Alice's commitment is in state"),
            )
        };
        let pool_account = self.state.get_account_by_id(pool_id());
        let simulation = Simulation {
            public_actor_states: pool_actors()
                .into_iter()
                .map(|actor| {
                    (
                        actor,
                        pool_account
                            .data
                            .actor_state(actor.program_account_id)
                            .clone(),
                    )
                })
                .collect(),
            admitted_accounts: None,
        };
        let swap = AmmMessage::Swap {
            trader: self.alice_id().blinded(&F_IN),
            token_in: TOKEN_A,
            amount_in,
            amount_out,
            recipient,
        };
        let proven = execute_and_prove(
            ProvingInput {
                public_context: PublicExecutionContext::new(pool_actors(), []),
                private_witnesses: std::iter::once(alice_witness)
                    .chain(extra_witness)
                    .collect(),
                ..proving_input(root(pool_actors()[0], &swap))
            },
            &simulation,
            &catalog(),
            // Alice's AAA holding presents itself to the vault under the in-alias, never under
            // her account id.
            |_| SenderPresentation::Blinded(F_IN),
            |_, _| false,
            no_seal,
        )
        .expect("Alice's swap proves");
        private_tx(proven, vec![], &[])
    }

    /// Bob trades AAA→BBB publicly at the current price, moving the pool.
    fn bob_swaps(&mut self, amount_in: u128) {
        let pool = self.pool();
        let amount_out = quote(pool.reserve_a, pool.reserve_b, amount_in);
        let bob_id = self.bob.account_id();
        let mut actors = pool_actors().to_vec();
        actors.extend([Actor::new(bob_id, TOKEN_A), Actor::new(bob_id, TOKEN_B)]);
        let tx = public_tx(
            pool_actors()[0],
            actors,
            vec![self.state.get_account_by_id(bob_id).nonce],
            AmmMessage::Swap {
                trader: bob_id,
                token_in: TOKEN_A,
                amount_in,
                amount_out,
                recipient: bob_id,
            },
            &[&self.bob.signing_key],
        );
        self.state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("Bob's public swap settles");
    }

    fn alice_nullifier(&self) -> Nullifier {
        Nullifier::for_account_update(
            &Commitment::new(&self.alice_id(), &self.alice_account),
            &self.alice.nsk(),
        )
    }

    fn assert_vaults_match_reserves(&self) {
        let pool = self.pool();
        assert_eq!(self.holding(pool_id(), TOKEN_A), pool.reserve_a);
        assert_eq!(self.holding(pool_id(), TOKEN_B), pool.reserve_b);
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Alice proves against the pool at block start; Bob's public swap moves the pool before hers is
/// applied; hers still settles in a single transaction, with no public account of hers.
#[test]
fn private_account_swaps_in_one_tx_after_the_pool_moved() {
    let mut dex = Dex::new();
    let amount_in = 10_000;
    let quoted = quote(RESERVE, RESERVE, amount_in);
    let amount_out = quoted * 99 / 100; // 1% slippage tolerance
    let alias_out = dex.alice_id().blinded(&F_OUT);

    let tx = dex.prove_alice_swap(amount_in, amount_out, alias_out, None);

    // What the chain sees: the pool's actors, the amounts, and two one-time aliases. Never
    // Alice's account id.
    let bytes = borsh::to_vec(&tx).unwrap();
    assert!(
        !contains(&bytes, dex.alice_id().as_ref()),
        "the transaction must not carry Alice's account id"
    );
    assert!(contains(&bytes, dex.alice_id().blinded(&F_IN).as_ref()));
    assert!(contains(&bytes, alias_out.as_ref()));
    let boundary = &tx.message.execution.boundary;
    assert!(
        matches!(
            boundary.as_slice(),
            [
                BoundaryStep::PublicToPrivate(_), // pool → Alice's AAA: Transfer(amount_in)
                BoundaryStep::PrivateToPublic(_), // Alice's AAA → vault: Credit(amount_in)
                BoundaryStep::EndPublicSubtree,
                BoundaryStep::EndPrivateSubtree,
                BoundaryStep::PublicToPrivate(_), // vault → Alice's BBB: Credit(amount_out)
                BoundaryStep::EndPrivateSubtree,
            ]
        ),
        "unexpected boundary {boundary:#?}"
    );

    // Someone else's swap lands first, in the same block: the price Alice proved at is gone.
    dex.bob_swaps(3_000);
    let moved = dex.pool();
    let quoted_now = quote(moved.reserve_a, moved.reserve_b, amount_in);
    assert!(quoted_now < quoted, "Bob's trade worsened Alice's price");
    assert!(quoted_now >= amount_out, "but still within her bound");

    dex.state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .expect("the proof holds against the moved pool: it never fixed the pool's state");

    // Pool: both trades applied on top of each other; the surplus over Alice's bound stays.
    let pool = dex.pool();
    assert_eq!(pool.reserve_a, moved.reserve_a + amount_in);
    assert_eq!(pool.reserve_b, moved.reserve_b - amount_out);
    dex.assert_vaults_match_reserves();

    // Alice: same private account, AAA debited and BBB credited, old version nullified.
    let expected = Account {
        nonce: dex
            .alice_account
            .nonce
            .private_account_nonce_increment(&dex.alice.nsk()),
        ..Account::default()
            .with_actor_state(TOKEN_A, balance(ALICE_AAA - amount_in))
            .with_actor_state(TOKEN_B, balance(amount_out))
    };
    assert!(
        dex.state
            .private_state
            .0
            .contains(&Commitment::new(&dex.alice_id(), &expected))
    );
    assert!(dex.state.is_spent(&dex.alice_nullifier()));

    // No public account was created or touched for Alice: the aliases stay empty.
    for alias in [dex.alice_id().blinded(&F_IN), alias_out] {
        assert_eq!(dex.state.get_account_by_id(alias), Account::default());
    }
}

/// If the pool moved past Alice's bound, the public part refuses and nothing of hers changes:
/// her note is not spent, so she simply re-quotes and re-proves.
#[test]
fn private_swap_reverts_when_the_price_moved_beyond_the_bound() {
    let mut dex = Dex::new();
    let amount_in = 10_000;
    let amount_out = quote(RESERVE, RESERVE, amount_in) * 99 / 100;
    let tx = dex.prove_alice_swap(
        amount_in,
        amount_out,
        dex.alice_id().blinded(&F_OUT),
        None,
    );

    dex.bob_swaps(100_000);
    let moved = dex.pool();
    assert!(quote(moved.reserve_a, moved.reserve_b, amount_in) < amount_out);

    let result = dex.state.transition_from_privacy_preserving_transaction(&tx, 1, 0);
    let error = format!("{result:?}");
    assert!(
        error.contains("price moved beyond the trader's bound"),
        "expected the pool to refuse, got {error}"
    );
    assert_eq!(dex.pool(), moved);
    dex.assert_vaults_match_reserves();
    assert!(!dex.state.is_spent(&dex.alice_nullifier()));
}

/// BBB can land in a brand-new private account instead of the paying one.
#[test]
fn private_swap_can_pay_out_into_a_fresh_private_account() {
    let mut dex = Dex::new();
    let fresh = test_private_account_keys_2();
    let fresh_alias = fresh.account_id().blinded(&F_OUT);
    let amount_in = 10_000;
    let amount_out = quote(RESERVE, RESERVE, amount_in) * 99 / 100;

    let tx = dex.prove_alice_swap(
        amount_in,
        amount_out,
        fresh_alias,
        Some(PrivateWitness {
            address_openings: BTreeSet::from([F_OUT]),
            ..init_witness(&fresh)
        }),
    );
    assert!(!contains(&borsh::to_vec(&tx).unwrap(), fresh.account_id().as_ref()));

    dex.state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .expect("the swap settles");

    let fresh_account = Account {
        nonce: Nonce::default().private_account_nonce_increment(&fresh.nsk()),
        ..Account::default().with_actor_state(TOKEN_B, balance(amount_out))
    };
    assert!(
        dex.state
            .private_state
            .0
            .contains(&Commitment::new(&fresh.account_id(), &fresh_account))
    );
    dex.assert_vaults_match_reserves();
}

/// Sanity: the same pool serves public traders directly.
#[test]
fn public_account_swaps_directly() {
    let mut dex = Dex::new();
    dex.bob_swaps(10_000);
    let bob = dex.bob.account_id();
    assert_eq!(dex.holding(bob, TOKEN_A), BOB_AAA - 10_000);
    assert_eq!(
        dex.holding(bob, TOKEN_B),
        quote(RESERVE, RESERVE, 10_000)
    );
    dex.assert_vaults_match_reserves();
}
