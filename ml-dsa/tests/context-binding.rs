//! Verification must bind the decoded signature, the context string, the message representative
//! `µ`, and the identity of the verifying key to the same verification attempt.

#![allow(clippy::unwrap_used, reason = "tests")]

use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, Signature, SigningKey};
use signature::{Keypair, SignatureEncoding, digest::Update};

fn check<P: MlDsaParams>() {
    let signing_key = SigningKey::<P>::from_seed(&Seed::from([0x11; 32]));
    let other_key = SigningKey::<P>::from_seed(&Seed::from([0x22; 32]));
    let verifying_key = signing_key.verifying_key();
    let other_verifying_key = other_key.verifying_key();
    let expanded_key = signing_key.expanded_key();

    let msg = b"message bound to one context";
    // Same length on purpose: a length-only check must not be sufficient.
    let ctx_a = b"context-A";
    let ctx_b = b"context-B";
    let empty: &[u8] = b"";
    let long_ctx = [0x33; 255];
    let oversized_ctx = [0x44; 256];

    // Empty and non-empty contexts continue to work with the ordinary verifier.
    let sig_empty = expanded_key.sign_deterministic(msg, empty).unwrap();
    assert!(verifying_key.verify_with_context(msg, empty, &sig_empty));
    assert!(!verifying_key.verify_with_context(msg, ctx_a, &sig_empty));

    let sig_a = expanded_key.sign_deterministic(msg, ctx_a).unwrap();
    assert!(verifying_key.verify_with_context(msg, ctx_a, &sig_a));
    assert!(!verifying_key.verify_with_context(msg, ctx_b, &sig_a));
    assert!(!verifying_key.verify_with_context(msg, empty, &sig_a));

    let sig_long = expanded_key.sign_deterministic(msg, &long_ctx).unwrap();
    assert!(verifying_key.verify_with_context(msg, &long_ctx, &sig_long));
    assert!(expanded_key
        .sign_deterministic(msg, &oversized_ctx)
        .is_err());
    assert!(!verifying_key.verify_with_context(msg, &oversized_ctx, &sig_long));

    // A µ is bound to the key and context that produced it.
    let mu_long = verifying_key
        .compute_mu(
            |h| {
                h.update(msg);
                Ok(())
            },
            &long_ctx,
        )
        .unwrap();
    assert!(verifying_key.verify_mu(&mu_long, &sig_long));
    assert!(verifying_key.verify_mu_with_context(&mu_long, &long_ctx, &sig_long));
    assert!(!verifying_key.verify_mu_with_context(&mu_long, &oversized_ctx, &sig_long));
    assert!(verifying_key
        .compute_mu(|_| panic!("context too long"), &oversized_ctx)
        .is_err());

    let mu_a = verifying_key
        .compute_mu(
            |h| {
                h.update(msg);
                Ok(())
            },
            ctx_a,
        )
        .unwrap();
    assert!(verifying_key.verify_mu(&mu_a, &sig_a));
    assert!(verifying_key.verify_mu_with_context(&mu_a, ctx_a, &sig_a));
    assert!(!verifying_key.verify_mu_with_context(&mu_a, ctx_b, &sig_a));
    assert!(!verifying_key.verify_mu_with_context(&mu_a, empty, &sig_a));

    // The signer can compute the same bound µ, which keeps the signing and verification
    // identities on the same value.
    let signer_mu = expanded_key
        .compute_mu(
            |h| {
                h.update(msg);
                Ok(())
            },
            ctx_a,
        )
        .unwrap();
    assert_eq!(signer_mu, mu_a);
    assert!(verifying_key.verify_mu_with_context(&signer_mu, ctx_a, &sig_a));

    // Reusing a cached µ across a context change must be rejected.
    let mu_b = verifying_key
        .compute_mu(
            |h| {
                h.update(msg);
                Ok(())
            },
            ctx_b,
        )
        .unwrap();
    assert!(!verifying_key.verify_mu(&mu_b, &sig_a));
    assert!(!verifying_key.verify_mu_with_context(&mu_b, ctx_b, &sig_a));

    let mu_empty = verifying_key
        .compute_mu(
            |h| {
                h.update(msg);
                Ok(())
            },
            empty,
        )
        .unwrap();
    assert!(verifying_key.verify_mu(&mu_empty, &sig_empty));
    assert!(verifying_key.verify_mu_with_context(&mu_empty, empty, &sig_empty));
    assert!(!verifying_key.verify_mu_with_context(&mu_empty, ctx_a, &sig_empty));

    // A µ computed for a different verifying key cannot be used with this key, and a signer
    // refuses to sign one.
    let foreign_mu = other_verifying_key
        .compute_mu(
            |h| {
                h.update(msg);
                Ok(())
            },
            ctx_a,
        )
        .unwrap();
    assert!(!verifying_key.verify_mu(&foreign_mu, &sig_a));
    assert!(!verifying_key.verify_mu_with_context(&foreign_mu, ctx_a, &sig_a));
    assert!(expanded_key.try_sign_mu_deterministic(&foreign_mu).is_err());

    // Signature decoding is part of verification: a byte string that merely has the right total
    // length but contains a malformed hint encoding must be rejected.
    let encoded = sig_a.to_bytes();
    assert!(verifying_key.verify_bytes_with_context(msg, ctx_a, encoded.as_slice()));
    assert!(!verifying_key.verify_bytes_with_context(msg, ctx_b, encoded.as_slice()));
    let encoded_slice = encoded.as_slice();
    assert!(!verifying_key.verify_bytes_with_context(
        msg,
        ctx_a,
        &encoded_slice[..encoded_slice.len() - 1],
    ));

    let mut malformed = encoded.clone();
    let last = malformed.len() - 1;
    malformed[last] = 0xFF;
    assert!(Signature::<P>::try_from(malformed.as_slice()).is_err());
    assert!(!verifying_key.verify_bytes_with_context(msg, ctx_a, malformed.as_slice()));
    assert!(!verifying_key.verify_encoded_with_context(msg, ctx_a, &malformed));
}

#[test]
fn context_binding_44() {
    check::<MlDsa44>();
}

#[test]
fn context_binding_65() {
    check::<MlDsa65>();
}

#[test]
fn context_binding_87() {
    check::<MlDsa87>();
}
