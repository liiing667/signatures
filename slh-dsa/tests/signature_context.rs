#![cfg(feature = "alloc")]

use signature::{Keypair, SignatureEncoding, Signer, Verifier};
use slh_dsa::{Shake128f, Signature, SigningKey, VerifyingKey};

#[test]
fn truncated_and_extended_signatures_are_not_accepted_objects() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let message = b"signature boundary";
    let context = b"boundary context";
    let signature = signing_key
        .try_sign_with_context(message, context, None)
        .unwrap();
    let encoded = signature.to_bytes();

    let truncated = &encoded[..encoded.len() - 1];
    assert!(Signature::<Shake128f>::try_from(truncated).is_err());

    let mut extended = encoded.to_vec();
    extended.push(0);
    assert!(Signature::<Shake128f>::try_from(extended.as_slice()).is_err());

    let reparsed = Signature::<Shake128f>::try_from(encoded.as_slice()).unwrap();
    assert_eq!(reparsed.to_bytes(), encoded);
    assert_eq!(reparsed.encoded_len(), encoded.len());
    verifying_key
        .try_verify_with_context(message, context, &reparsed)
        .unwrap();
}

#[test]
fn context_and_key_identity_follow_signature_into_retry() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let other_signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let message = b"same message, different contexts";
    let original_context = b"original context";
    let other_context = b"other context";

    let signature = signing_key
        .try_sign_with_context(message, original_context, None)
        .unwrap();

    verifying_key
        .try_verify_with_context(message, original_context, &signature)
        .unwrap();
    assert!(verifying_key
        .try_verify_with_context(message, other_context, &signature)
        .is_err());
    assert!(other_signing_key
        .verifying_key()
        .try_verify_with_context(message, original_context, &signature)
        .is_err());

    let retried = signing_key
        .try_sign_with_context(message, original_context, None)
        .unwrap();
    assert_eq!(retried.to_bytes(), signature.to_bytes());
    verifying_key
        .try_verify_with_context(message, original_context, &retried)
        .unwrap();
    assert!(verifying_key
        .try_verify_with_context(message, other_context, &retried)
        .is_err());
}

#[test]
fn truncated_and_extended_verifying_keys_are_not_accepted_objects() {
    let mut rng = rand::rng();
    let encoded = SigningKey::<Shake128f>::new(&mut rng)
        .verifying_key()
        .to_bytes();

    assert!(VerifyingKey::<Shake128f>::try_from(&encoded[..encoded.len() - 1]).is_err());

    let mut extended = encoded.to_vec();
    extended.push(0);
    assert!(VerifyingKey::<Shake128f>::try_from(extended.as_slice()).is_err());

    let reparsed = VerifyingKey::<Shake128f>::try_from(encoded.as_slice()).unwrap();
    assert_eq!(reparsed.to_bytes(), encoded);
}

#[test]
fn empty_context_matches_default_trait_consumer() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let message = b"default trait and explicit empty context";

    let default_signature: Signature<Shake128f> = signing_key.sign(message);
    let empty_context_signature = signing_key
        .try_sign_with_context(message, &[], None)
        .unwrap();

    verifying_key.verify(message, &default_signature).unwrap();
    verifying_key
        .try_verify_with_context(message, &[], &empty_context_signature)
        .unwrap();
    verifying_key
        .try_verify_with_context(message, &[], &default_signature)
        .unwrap();
    verifying_key
        .verify(message, &empty_context_signature)
        .unwrap();
}
