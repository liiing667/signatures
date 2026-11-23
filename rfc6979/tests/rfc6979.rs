//! RFC6979 test vectors.
//!
//! <https://datatracker.ietf.org/doc/html/rfc6979#appendix-A>

use hex_literal::hex;
use rfc6979::{
    KGenerator, KGeneratorError, KGeneratorStage,
    bigint::{U128, U256, U576},
};
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;

/// Test vector used by RFC6979
const EXAMPLE_MSG: &str = "sample";

/// "Detailed Example" from RFC6979 Appendix A.1.
///
/// Example for ECDSA on the curve K-163 described in FIPS 186-4 (also known as "ansix9t163k1"
/// in X9.62), defined over a field GF(2^163)
#[test]
fn k163_sha256() {
    let q = U256::from_be_hex("000000000000000000000004000000000000000000020108A2E0CC0D99F8A5EF");
    let x = hex!("009A4D6792295A7F730FC3F2B49CBC0F62E862272F");
    let h = Sha256::digest(EXAMPLE_MSG);

    let mut kgen = KGenerator::<Sha256, U256>::new(&x, &h, b"", &q);
    let mut k = [0u8; 21];
    kgen.fill_next_k(&mut k);
    assert_eq!(k, hex!("023AF4074C90A02B3FE61D286D5C87F425E6BDD81B"));
}

/// Example from RFC6979 Appendix A.2.7.
#[test]
fn p521_sha512() {
    let q = U576::from_be_hex(
        "00000000000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    );
    let x = hex!(
        "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
    );
    let h = Sha512::digest(EXAMPLE_MSG);

    let mut kgen = KGenerator::<Sha512, U576>::new(&x, &h, b"", &q);
    let mut k = [0u8; 66];
    kgen.fill_next_k(&mut k);

    let expected_k = hex!(
        "01DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3"
    );
    assert_eq!(k, expected_k);
}

/// Ensure things are working with the SHA-3 crate, which doesn't support `block_api`.
/// (this is largely an HMAC-DRBG test)
#[test]
fn non_block_api() {
    let q = U128::from_u128(0xffffffffffffffffffffffff);
    let x = hex!("000000000000000000000000");
    let h = hex!("080808080808080808080808");

    let mut kgen = KGenerator::<Sha3_256, U128>::new(&x, &h, b"", &q);
    let mut k = [0u8; 12];
    kgen.fill_next_k(&mut k);
    assert_eq!(k, hex!("d460ac6531e9743d3829850f"));
}

/// Private key for RFC6979 NIST P-256/SHA-256 test case (Appendix A.2.5).
const P256_KEY: [u8; 32] =
    hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");

/// Curve order for NIST P-256.
const P256_ORDER: U256 =
    U256::from_be_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

#[test]
fn successive_candidates_advance_and_consume_once() {
    let h = Sha256::digest(EXAMPLE_MSG);
    let mut kgen = KGenerator::<Sha256, U256>::new(&P256_KEY, &h, b"", &P256_ORDER);
    assert_eq!(kgen.stage(), KGeneratorStage::Initialized);
    assert_eq!(kgen.candidate_index(), 0);
    assert_eq!(kgen.attempt_index(), 0);

    let mut k1 = [0u8; 32];
    let info1 = kgen.fill_next_k_with_info(&mut k1);
    assert_eq!(
        k1,
        hex!("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60")
    );
    assert_eq!(info1.index, 1);
    assert_eq!(info1.attempt, 1);
    assert_eq!(info1.skipped, 0);
    assert_eq!(kgen.stage(), KGeneratorStage::CandidateGenerated);
    assert_eq!(kgen.candidate_index(), 1);
    assert_eq!(kgen.attempt_index(), 1);

    kgen.consume_candidate(info1)
        .expect("first candidate should be consumable");
    assert_eq!(kgen.stage(), KGeneratorStage::CandidateConsumed);
    assert!(matches!(
        kgen.consume_candidate(info1),
        Err(KGeneratorError::CandidateAlreadyConsumed)
    ));

    let mut k2 = [0u8; 32];
    let info2 = kgen.fill_next_k_with_info(&mut k2);
    assert_eq!(info2.index, 2);
    assert_eq!(info2.attempt, 2);
    assert_eq!(info2.skipped, 0);
    assert_ne!(k1, k2);
    assert_eq!(kgen.candidate_index(), 2);
    assert_eq!(kgen.attempt_index(), 2);
    assert_eq!(kgen.abandoned_candidates(), 0);

    kgen.consume_candidate(info2)
        .expect("second candidate should be consumable");
}

#[test]
fn unconsumed_candidate_is_abandoned_on_retry() {
    let h = Sha256::digest(EXAMPLE_MSG);
    let mut kgen = KGenerator::<Sha256, U256>::new(&P256_KEY, &h, b"", &P256_ORDER);

    let mut k1 = [0u8; 32];
    let info1 = kgen.fill_next_k_with_info(&mut k1);

    let mut k2 = [0u8; 32];
    let info2 = kgen.fill_next_k_with_info(&mut k2);

    assert_eq!(info2.abandoned, 1);
    assert_eq!(kgen.abandoned_candidates(), 1);
    assert_ne!(k1, k2);
    assert!(matches!(
        kgen.consume_candidate(info1),
        Err(KGeneratorError::CandidateStale)
    ));
    kgen.consume_candidate(info2)
        .expect("latest candidate should remain consumable");
}

#[test]
fn context_binding_rejects_cross_message_use() {
    let h1 = Sha256::digest(EXAMPLE_MSG);
    let h2 = Sha256::digest(b"another message");

    let mut kgen = KGenerator::<Sha256, U256>::new(&P256_KEY, &h1, b"ad", &P256_ORDER);
    let mut context_id = [0u8; 32];
    context_id.copy_from_slice(kgen.context_id());

    let mut k1 = [0u8; 32];
    let info1 = kgen
        .fill_next_k_with_context(&P256_KEY, &h1, b"ad", &mut k1)
        .expect("matching context should produce a candidate");
    assert_eq!(info1.index, 1);

    let before = (
        kgen.candidate_index(),
        kgen.attempt_index(),
        kgen.stage(),
    );

    let mut k2 = [0u8; 32];
    assert!(matches!(
        kgen.fill_next_k_with_context(&P256_KEY, &h2, b"ad", &mut k2),
        Err(KGeneratorError::ContextMismatch)
    ));
    assert_eq!(k2, [0u8; 32]);
    assert_eq!(
        (
            kgen.candidate_index(),
            kgen.attempt_index(),
            kgen.stage(),
        ),
        before
    );

    assert!(matches!(
        kgen.fill_next_k_with_context(&P256_KEY, &h1, b"different data", &mut k2),
        Err(KGeneratorError::ContextMismatch)
    ));

    let mut different_key = P256_KEY;
    different_key[0] ^= 0x01;
    assert!(matches!(
        kgen.fill_next_k_with_context(&different_key, &h1, b"ad", &mut k2),
        Err(KGeneratorError::ContextMismatch)
    ));

    let mut k3 = [0u8; 32];
    let info2 = kgen
        .fill_next_k_with_context(&P256_KEY, &h1, b"ad", &mut k3)
        .expect("matching context should resume after rejected attempts");
    assert_eq!(info2.index, 2);
    assert_ne!(k3, k1);

    let mut control = KGenerator::<Sha256, U256>::new(&P256_KEY, &h1, b"ad", &P256_ORDER);
    let mut control_k1 = [0u8; 32];
    let mut control_k2 = [0u8; 32];
    control.fill_next_k_with_info(&mut control_k1);
    control.fill_next_k_with_info(&mut control_k2);
    assert_eq!(k1, control_k1);
    assert_eq!(k3, control_k2);

    let mut fresh = KGenerator::<Sha256, U256>::new(&P256_KEY, &h2, b"ad", &P256_ORDER);
    assert_ne!(fresh.context_id(), &context_id[..]);

    let mut fresh_k = [0u8; 32];
    fresh
        .fill_next_k_with_context(&P256_KEY, &h2, b"ad", &mut fresh_k)
        .expect("fresh generator should accept its own context");
    assert_ne!(fresh_k, k1);
}

#[test]
fn equivalent_key_encoding_has_same_context_and_candidate() {
    let h = Sha256::digest(EXAMPLE_MSG);
    let mut padded_key = [0u8; 33];
    padded_key[1..].copy_from_slice(&P256_KEY);

    let mut canonical = KGenerator::<Sha256, U256>::new(&P256_KEY, &h, b"", &P256_ORDER);
    let mut padded = KGenerator::<Sha256, U256>::new(&padded_key, &h, b"", &P256_ORDER);

    assert_eq!(canonical.context_id(), padded.context_id());

    let mut canonical_k = [0u8; 32];
    let mut padded_k = [0u8; 32];
    canonical.fill_next_k(&mut canonical_k);
    padded.fill_next_k(&mut padded_k);
    assert_eq!(canonical_k, padded_k);
}

#[test]
fn additional_data_changes_candidate_stream() {
    let h = Sha256::digest(EXAMPLE_MSG);
    let mut empty = KGenerator::<Sha256, U256>::new(&P256_KEY, &h, b"", &P256_ORDER);
    let mut with_data = KGenerator::<Sha256, U256>::new(&P256_KEY, &h, b"extra", &P256_ORDER);

    assert_ne!(empty.context_id(), with_data.context_id());

    let mut empty_k = [0u8; 32];
    let mut with_data_k = [0u8; 32];
    empty.fill_next_k(&mut empty_k);
    with_data.fill_next_k(&mut with_data_k);
    assert_ne!(empty_k, with_data_k);
}

#[test]
fn rejected_candidates_advance_the_generator() {
    // A 9-bit modulus forces roughly half of the generated candidates to be
    // outside `[1, q-1]`, exercising the internal advancement path.
    let q = U256::from_u64(0x100);
    let x = [0x01, 0x02];
    let h = [0x03, 0x04];
    let mut kgen = KGenerator::<Sha256, U256>::new(&x, &h, b"", &q);

    let expected: [[u8; 2]; 8] = [
        [0x00, 0x10],
        [0x00, 0xac],
        [0x00, 0x45],
        [0x00, 0x15],
        [0x00, 0x56],
        [0x00, 0x4b],
        [0x00, 0xdd],
        [0x00, 0x7b],
    ];

    let mut previous = [0u8; 2];
    for (i, expected_k) in expected.iter().enumerate() {
        let mut k = [0u8; 2];
        let info = kgen.fill_next_k_with_info(&mut k);
        assert_eq!(&k, expected_k);
        assert_eq!(
            info.index,
            u64::try_from(i + 1).expect("candidate index must fit in u64")
        );
        if i > 0 {
            assert_ne!(k, previous);
        }
        previous = k;
        kgen.consume_candidate(info)
            .expect("candidate should be consumable");
    }

    assert_eq!(kgen.attempt_index(), 19);
    assert_eq!(kgen.skipped_candidates(), 11);
    assert_eq!(kgen.abandoned_candidates(), 0);
    assert_eq!(kgen.stage(), KGeneratorStage::CandidateConsumed);
}

#[test]
fn retry_consumer_uses_distinct_candidates_and_results() {
    let h = Sha256::digest(EXAMPLE_MSG);
    let mut kgen = KGenerator::<Sha256, U256>::new(&P256_KEY, &h, b"", &P256_ORDER);

    let mut first_k = [0u8; 32];
    let mut first_result = [0u8; 32];

    for round in 0..3 {
        let mut k = [0u8; 32];
        let info = kgen.fill_next_k_with_info(&mut k);

        // Stand-in for an ECDSA signature consumer: the result must depend on
        // the nonce, so reusing a nonce would also reproduce the result.
        let mut hasher = Sha256::new();
        hasher.update(k.as_slice());
        hasher.update(h.as_slice());
        let result = hasher.finalize();

        if round == 0 {
            first_k = k;
            first_result.copy_from_slice(result.as_slice());
        } else {
            assert_ne!(k, first_k);
            assert_ne!(result.as_slice(), &first_result[..]);
        }

        kgen.consume_candidate(info)
            .expect("candidate should be consumable");
    }

    assert_eq!(kgen.candidate_index(), 3);
    assert_eq!(kgen.attempt_index(), 3);
}
