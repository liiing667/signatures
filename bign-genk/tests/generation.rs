//! Generation lifecycle tests for [`bign_genk::KGenerator`].
//!
//! These tests exercise only the public API and model how a (EC)DSA signer drives the
//! generator: it accepts a context once per signing attempt, consumes candidates, retries
//! inside the same generation after a failure, and accepts a fresh context for the next
//! signing attempt.

use belt_block::BeltBlock;
use belt_hash::BeltHash;
use bign_genk::bigint::U256;
use hex_literal::hex;

type Genk<'a> = bign_genk::KGenerator<'a, BeltBlock, U256>;

/// BIGN P-256 curve order `q` (big-endian).
const Q: [u8; 32] =
    hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC");

/// Fixed-vector secret key and message digest (see `bign_gek_1` in the crate unit tests).
const X: [u8; 32] =
    hex!("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269");
const H_A: [u8; 32] =
    hex!("ABEF9725 D4C5A835 97A367D1 4494CC25 42F20F65 9DDFECC9 61A3EC55 0CBA8C75");
const H_B: [u8; 32] =
    hex!("9D02EE44 6FB6A29F E5C982D4 B13AF9D3 E90861BC 4CEF27CF 306BFB0B 174A154A");

const DATA_A: [u8; 4] = hex!("DEAD BEEF");
const DATA_B: [u8; 4] = hex!("CAFE F00D");

/// First fixed-vector candidate for the empty associated data context.
const EXPECTED_EMPTY_CONTEXT_K: [u8; 32] =
    hex!("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E");

fn next_k(kgen: &mut Genk<'_>) -> [u8; 32] {
    let mut k = [0u8; 32];
    kgen.fill_next_k(&mut k);
    k
}

/// Fixed vectors remain unchanged, including for the empty associated data context.
#[test]
fn fixed_vectors_and_empty_context_are_unchanged() {
    let q = U256::from_be_slice(&Q);
    let mut kgen = Genk::new::<BeltHash>(&X, &H_A, &[], &q);

    assert_eq!(kgen.generation(), 0);
    assert_eq!(next_k(&mut kgen), EXPECTED_EMPTY_CONTEXT_K);
}

/// A signer consumes a candidate, and retries after a failure stay in the same generation.
#[test]
fn retries_are_consumed_inside_one_generation() {
    let q = U256::from_be_slice(&Q);
    let mut kgen = Genk::new::<BeltHash>(&X, &H_A, &DATA_A, &q);

    let first = next_k(&mut kgen);

    // Simulate two rejected signatures (e.g. zero `r`): each retry consumes another candidate
    // but the generation in progress never changes.
    let retry_1 = next_k(&mut kgen);
    let retry_2 = next_k(&mut kgen);
    assert_eq!(kgen.generation(), 0);
    assert_ne!(first, retry_1);
    assert_ne!(retry_1, retry_2);
}

/// Accepting a changed context starts a new generation with a reset state instead of replaying
/// candidates from the previous one.
#[test]
fn new_context_resets_state_and_generation() {
    let q = U256::from_be_slice(&Q);
    let mut kgen = Genk::new::<BeltHash>(&X, &H_A, &DATA_A, &q);
    let previous = [next_k(&mut kgen), next_k(&mut kgen), next_k(&mut kgen)];

    kgen.accept_context::<BeltHash>(&X, &H_B, &DATA_B);
    assert_eq!(kgen.generation(), 1);

    let mut fresh = Genk::new::<BeltHash>(&X, &H_B, &DATA_B, &q);
    assert_eq!(next_k(&mut kgen), next_k(&mut fresh));

    let first = next_k(&mut kgen);
    assert!(previous.iter().all(|old| *old != first));
}

/// Alternating contexts produce distinct `k` sequences, and re-accepting a context deterministically
/// restarts its sequence from the first candidate.
#[test]
fn alternating_contexts_are_independent_and_deterministic() {
    let q = U256::from_be_slice(&Q);
    let mut kgen = Genk::new::<BeltHash>(&X, &H_A, &DATA_A, &q);

    let a_1 = next_k(&mut kgen);
    let a_1_retry = next_k(&mut kgen);

    kgen.accept_context::<BeltHash>(&X, &H_B, &DATA_B);
    let b_1 = next_k(&mut kgen);
    let b_1_retry = next_k(&mut kgen);

    kgen.accept_context::<BeltHash>(&X, &H_A, &DATA_A);
    assert_eq!(kgen.generation(), 2);
    let a_2 = next_k(&mut kgen);
    let a_2_retry = next_k(&mut kgen);

    kgen.accept_context::<BeltHash>(&X, &H_B, &DATA_B);
    let b_2 = next_k(&mut kgen);

    // Re-accepted contexts restart their own sequence from scratch...
    assert_eq!(a_2, a_1);
    assert_eq!(a_2_retry, a_1_retry);
    assert_eq!(b_2, b_1);

    // ...while different contexts never share candidates or retry sequences.
    assert_ne!(a_1, b_1);
    assert_ne!(a_1_retry, b_1_retry);
}

/// A full signing lifecycle: failure recovery inside a generation, then a clean new generation
/// for the next signing attempt, even when the empty context is involved.
#[test]
fn signing_lifecycle_recovers_and_restarts_cleanly() {
    let q = U256::from_be_slice(&Q);
    let mut kgen = Genk::new::<BeltHash>(&X, &H_A, &DATA_A, &q);

    // Attempt 1: the first two candidates lead to rejected signatures, the third is "signed".
    let rejected = [next_k(&mut kgen), next_k(&mut kgen)];
    let signed = next_k(&mut kgen);
    assert_eq!(kgen.generation(), 0);
    assert!(rejected.iter().all(|k| *k != signed));

    // Attempt 2 starts with an empty context: it must reproduce the fixed vector exactly rather
    // than any state left over from attempt 1.
    kgen.accept_context::<BeltHash>(&X, &H_A, &[]);
    assert_eq!(kgen.generation(), 1);
    assert_eq!(next_k(&mut kgen), EXPECTED_EMPTY_CONTEXT_K);

    // Attempt 3 goes back to the attempt-1 context and replays its first candidate.
    kgen.accept_context::<BeltHash>(&X, &H_A, &DATA_A);
    assert_eq!(kgen.generation(), 2);
    assert_eq!(next_k(&mut kgen), rejected[0]);
}
