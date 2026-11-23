//! Tests ensuring parameters, keys, signature bounds and verification
//! consumers are all bound to the same DSA parameter group.
//!
//! Two distinct (small, hazmat-only) parameter groups are constructed and
//! components are then cross-used between them.

#![cfg(feature = "hazmat")]

use crypto_bigint::BoxedUint;
use dsa::{Components, KeySize, Signature, SigningKey, VerifyingKey};
use getrandom::{SysRng, rand_core::UnwrapErr};
use signature::{SignatureEncoding, Signer, Verifier, hazmat::PrehashVerifier};

/// A small DSA parameter group: `p = 23`, `q = 11`, `g = 4`.
///
/// `4^11 mod 23 == 1` and `4 != 1`, so `g` generates the order-`q` subgroup.
fn group_a() -> Components {
    Components::from_components_unchecked(
        BoxedUint::from(23_u8),
        BoxedUint::from(11_u8),
        BoxedUint::from(4_u8),
    )
    .expect("valid group A components")
}

/// A second, distinct small DSA parameter group: `p = 47`, `q = 23`, `g = 2`.
///
/// `2^23 mod 47 == 1` and `2 != 1`, so `g` generates the order-`q` subgroup.
fn group_b() -> Components {
    Components::from_components_unchecked(
        BoxedUint::from(47_u8),
        BoxedUint::from(23_u8),
        BoxedUint::from(2_u8),
    )
    .expect("valid group B components")
}

/// Group A keypair: `x = 5`, `y = g^x mod p = 4^5 mod 23 = 12`.
fn group_a_keypair() -> (VerifyingKey, SigningKey) {
    let components = group_a();
    let verifying_key = VerifyingKey::from_components(components, BoxedUint::from(12_u8))
        .expect("valid y for A");
    let signing_key = SigningKey::from_components(verifying_key.clone(), BoxedUint::from(5_u8))
        .expect("valid x for A");
    (verifying_key, signing_key)
}

/// Group B keypair: `x = 7`, `y = g^x mod p = 2^7 mod 47 = 34`.
fn group_b_keypair() -> (VerifyingKey, SigningKey) {
    let components = group_b();
    let verifying_key = VerifyingKey::from_components(components, BoxedUint::from(34_u8))
        .expect("valid y for B");
    let signing_key = SigningKey::from_components(verifying_key.clone(), BoxedUint::from(7_u8))
        .expect("valid x for B");
    (verifying_key, signing_key)
}

#[test]
fn groups_are_distinct() {
    let (a, b) = (group_a(), group_b());
    assert!(a.eq_components(&a));
    assert!(b.eq_components(&b));
    assert!(!a.eq_components(&b));
}

#[test]
fn well_formed_keys_are_accepted() {
    let (verifying_key, signing_key) = group_a_keypair();
    assert_eq!(**verifying_key.y(), BoxedUint::from(12_u8));
    assert_eq!(**signing_key.x(), BoxedUint::from(5_u8));

    let (verifying_key_b, signing_key_b) = group_b_keypair();
    assert_eq!(**verifying_key_b.y(), BoxedUint::from(34_u8));
    assert_eq!(**signing_key_b.x(), BoxedUint::from(7_u8));
}

#[test]
fn public_component_outside_group_is_rejected() {
    // `y < 2`
    assert!(VerifyingKey::from_components(group_a(), BoxedUint::from(1_u8)).is_err());

    // `y >= p` cannot be an element of the order-`q` subgroup of `Z_p*`
    assert!(VerifyingKey::from_components(group_a(), BoxedUint::from(23_u8)).is_err());
    assert!(VerifyingKey::from_components(group_a(), BoxedUint::from(24_u8)).is_err());

    // A public component valid for group B must not be accepted against group A
    assert!(VerifyingKey::from_components(group_a(), BoxedUint::from(34_u8)).is_err());

    // `p - 1` is outside the order-`q` subgroup (and even though it reduces to
    // `-1 mod p`, the explicit range check rejects it before any arithmetic).
    assert!(VerifyingKey::from_components(group_b(), BoxedUint::from(46_u8)).is_err());
}

#[test]
fn private_component_from_other_group_is_rejected() {
    let (verifying_key_a, _) = group_a_keypair();

    // `x = 0`
    assert!(SigningKey::from_components(verifying_key_a.clone(), BoxedUint::from(0_u8)).is_err());

    // `x >= q` (q_a = 11)
    assert!(SigningKey::from_components(verifying_key_a.clone(), BoxedUint::from(11_u8)).is_err());

    // Group B's private component (`x = 7`) is inside the numeric range
    // `0 < x < q_a`, but `g_a^7 mod p_a = 8 != y_a = 12`, so it must not be
    // accepted as the private component of group A's public key.
    assert!(SigningKey::from_components(verifying_key_a.clone(), BoxedUint::from(7_u8)).is_err());

    // The matching private component still works.
    assert!(SigningKey::from_components(verifying_key_a, BoxedUint::from(5_u8)).is_ok());
}

#[test]
fn signature_bounds_are_enforced_against_the_parameter_group() {
    let group_a = group_a();
    let group_b = group_b();

    // Values inside `0 < r, s < q_a` are accepted for group A.
    assert!(
        Signature::from_components_with_parameters(
            BoxedUint::from(3_u8),
            BoxedUint::from(7_u8),
            &group_a
        )
        .is_ok()
    );

    // Zero is rejected even though it is numerically smaller than `q`.
    assert!(
        Signature::from_components_with_parameters(
            BoxedUint::from(0_u8),
            BoxedUint::from(7_u8),
            &group_a
        )
        .is_err()
    );

    // `r == q_a` and `s == q_a` are out of bounds for group A.
    assert!(
        Signature::from_components_with_parameters(
            BoxedUint::from(11_u8),
            BoxedUint::from(7_u8),
            &group_a
        )
        .is_err()
    );
    assert!(
        Signature::from_components_with_parameters(
            BoxedUint::from(3_u8),
            BoxedUint::from(11_u8),
            &group_a
        )
        .is_err()
    );

    // Values larger than `q_a` cannot enter a verification consumer of group A.
    assert!(
        Signature::from_components_with_parameters(
            BoxedUint::from(12_u8),
            BoxedUint::from(100_u8),
            &group_a
        )
        .is_err()
    );

    // Cross-group: the same values that are valid for group B's larger `q`
    // (`q_b = 23`) must still be rejected by group A's constructor.
    assert!(
        Signature::from_components_with_parameters(
            BoxedUint::from(15_u8),
            BoxedUint::from(20_u8),
            &group_a
        )
        .is_err()
    );
    assert!(
        Signature::from_components_with_parameters(
            BoxedUint::from(15_u8),
            BoxedUint::from(20_u8),
            &group_b
        )
        .is_ok()
    );
}

#[test]
fn out_of_bounds_signature_is_rejected_by_verification_consumer() {
    let (verifying_key_a, _) = group_a_keypair();

    // Build the malformed signature through the unbound, legacy constructor,
    // then confirm the verification consumer of group A rejects it.
    let oversized = Signature::from_components(
        BoxedUint::from(11_u8), // r == q_a
        BoxedUint::from(7_u8),
    )
    .expect("legacy constructor only checks for non-zero values");

    assert!(verifying_key_a.verify(b"anything", &oversized).is_err());
    assert!(
        verifying_key_a
            .verify_prehash(&[1u8, 2, 3, 4], &oversized)
            .is_err()
    );

    // DER-decoded signatures with out-of-range `r`/`s` are rejected too.
    let der = oversized.to_bytes();
    let decoded = Signature::try_from(der.as_ref()).expect("DER decoding succeeds");
    assert!(verifying_key_a.verify(b"anything", &decoded).is_err());
}

#[test]
fn in_range_signatures_can_only_be_built_for_their_own_group() {
    let (verifying_key_a, _) = group_a_keypair();

    let signature = Signature::from_components_with_parameters(
        BoxedUint::from(3_u8),
        BoxedUint::from(7_u8),
        verifying_key_a.components(),
    )
    .expect("in-range signature");

    // The signature's parts are inside group A's order, so it is a
    // well-formed signature object for group A's verification consumer.
    assert!(signature.r() < verifying_key_a.components().q());
    assert!(signature.s() < verifying_key_a.components().q());

    // The exact same numeric `r`/`s` cannot be constructed as a signature of
    // another group when they exceed that group's smaller order (covered by
    // `signature_bounds_are_enforced_against_the_parameter_group`), and the
    // legacy unbound constructor remains available for non-zero values only.
    assert!(Signature::from_components(
        BoxedUint::from(0_u8),
        BoxedUint::from(7_u8)
    )
    .is_none());
}

/// End-to-end check using two freshly generated, standard-size parameter
/// groups: every object built for one group must be rejected when paired with
/// the other group.
#[test]
#[allow(deprecated)]
fn generated_groups_keep_their_own_keys_and_signatures() {
    let mut rng = UnwrapErr(SysRng);

    let components_a =
        Components::try_generate_from_rng_with_key_size(&mut rng, KeySize::DSA_1024_160)
            .expect("group A generation");
    let components_b =
        Components::try_generate_from_rng_with_key_size(&mut rng, KeySize::DSA_1024_160)
            .expect("group B generation");

    let signing_key_a =
        SigningKey::try_generate_from_rng_with_components(&mut rng, components_a.clone())
            .expect("group A keypair");
    let signing_key_b =
        SigningKey::try_generate_from_rng_with_components(&mut rng, components_b.clone())
            .expect("group B keypair");

    // The two generated parameter groups differ.
    assert!(!components_a.eq_components(&components_b));

    // A private component generated for group B cannot be paired with a public
    // key of group A, even though both groups use the same sizes.
    assert!(SigningKey::from_components(
        signing_key_a.verifying_key().clone(),
        signing_key_b.x().get()
    )
    .is_err());

    // A public component generated for group B is not a valid group A key.
    assert!(VerifyingKey::from_components(
        components_a.clone(),
        signing_key_b.verifying_key().y().get()
    )
    .is_err());

    let signature = signing_key_a.sign(b"cross group message");

    // The signature is bound by its own group's `q` and verifies against its
    // own verification consumer.
    assert!(signature.r() < components_a.q());
    assert!(signature.s() < components_a.q());
    signing_key_a
        .verifying_key()
        .verify(b"cross group message", &signature)
        .expect("signature verifies with its own group");

    // Rebuilding the same `r`/`s` as a signature of the other parameter group
    // (both groups use the same size, so the numeric `q`-bound check passes)
    // still never verifies against group B's consumer.
    let foreign = Signature::from_components_with_parameters(
        signature.r().get(),
        signature.s().get(),
        &components_b,
    )
    .expect("foreign group has an equally sized q");
    assert!(signing_key_b
        .verifying_key()
        .verify(b"cross group message", &foreign)
        .is_err());
}
