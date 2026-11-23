//! PKCS#8 private key tests

#![cfg(feature = "pkcs8")]
use ed25519::pkcs8::{
    DecodePrivateKey, DecodePublicKey, Error, KeyError, KeypairBytes, PublicKeyBytes, spki,
};
use hex_literal::hex;

#[cfg(feature = "alloc")]
use ed25519::pkcs8::{EncodePrivateKey, EncodePublicKey};

/// Ed25519 PKCS#8 v1 private key encoded as ASN.1 DER.
const PKCS8_V1_DER: &[u8] = include_bytes!("examples/pkcs8-v1.der");

/// Ed25519 PKCS#8 v2 private key + public key encoded as ASN.1 DER.
const PKCS8_V2_DER: &[u8] = include_bytes!("examples/pkcs8-v2.der");

/// Ed25519 `SubjectPublicKeyInfo` encoded as ASN.1 DER.
const PUBLIC_KEY_DER: &[u8] = include_bytes!("examples/pubkey.der");

/// Ed25519 PKCS#8 v2 keypair whose public key BIT STRING has a non-zero
/// number of unused bits, i.e. a malformed public key.
const PKCS8_V2_PUBLIC_KEY_UNUSED_BITS_DER: &[u8] = &hex!(
    "3072020101300506032b657004220420
     d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842
     a01f301d060a2a864886f70d01090914310f0c0d437572646c65204368616972
     7381210119bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad
     703166e0"
);

/// Ed25519 PKCS#8 v2 keypair whose public key is 31 bytes instead of 32.
const PKCS8_V2_SHORT_PUBLIC_KEY_DER: &[u8] = &hex!(
    "3071020101300506032b657004220420
     d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842
     a01f301d060a2a864886f70d01090914310f0c0d437572646c65204368616972
     7381200019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad
     703166"
);

/// Ed25519 PKCS#8 v2 keypair whose AlgorithmIdentifier has (disallowed)
/// parameters.
const PKCS8_V2_ALGORITHM_PARAMETERS_DER: &[u8] = &hex!(
    "3074020101300706032b6570050004220420
     d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842
     a01f301d060a2a864886f70d01090914310f0c0d437572646c65204368616972
     7381210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad
     703166e1"
);

/// Ed25519 `SubjectPublicKeyInfo` whose AlgorithmIdentifier has (disallowed)
/// parameters.
const PUBLIC_KEY_ALGORITHM_PARAMETERS_DER: &[u8] = &hex!(
    "302c300706032b6570050003210019bf4409
     6984cdfe8541bac167dc3b96c85086aa30b6
     b6cb0c5c38ad703166e1"
);

#[test]
fn decode_pkcs8_v1() {
    let keypair = KeypairBytes::from_pkcs8_der(PKCS8_V1_DER).unwrap();

    // Extracted with:
    // $ openssl asn1parse -inform der -in tests/examples/pkcs8-v1.der
    assert_eq!(
        keypair.secret_key,
        &hex!("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842")[..]
    );

    assert_eq!(keypair.public_key, None);
}

#[test]
fn decode_pkcs8_v2() {
    let keypair = KeypairBytes::from_pkcs8_der(PKCS8_V2_DER).unwrap();

    // Extracted with:
    // $ openssl asn1parse -inform der -in tests/examples/pkcs8-v2.der
    assert_eq!(
        keypair.secret_key,
        &hex!("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842")[..]
    );

    assert_eq!(
        keypair.public_key.unwrap().0,
        hex!("19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1")
    );
}

#[test]
fn decode_public_key() {
    let public_key = PublicKeyBytes::from_public_key_der(PUBLIC_KEY_DER).unwrap();

    // Extracted with:
    // $ openssl pkey -inform der -in tests/examples/pkcs8-v1.der -pubout -text
    assert_eq!(
        public_key.as_ref(),
        &hex!("19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1")
    );
}

#[test]
fn cross_import_consistency() {
    let keypair_v1 = KeypairBytes::from_pkcs8_der(PKCS8_V1_DER).unwrap();
    let keypair_v2 = KeypairBytes::from_pkcs8_der(PKCS8_V2_DER).unwrap();
    let public_key = PublicKeyBytes::from_public_key_der(PUBLIC_KEY_DER).unwrap();

    // PKCS#8 v1 and v2 encodings of the same keypair agree on the secret key.
    assert_eq!(keypair_v1.secret_key, keypair_v2.secret_key);

    // The public part of the keypair agrees with a standalone SPKI import.
    assert_eq!(keypair_v2.public_key, Some(public_key));
    assert_eq!(PublicKeyBytes::try_from(&keypair_v2).unwrap(), public_key);

    // A v1 keypair carries no public key.
    assert_eq!(keypair_v1.public_key, None);
    assert!(PublicKeyBytes::try_from(&keypair_v1).is_err());

    // `TryFrom`-based recovery agrees with `DecodePrivateKey` consumption.
    let recovered = KeypairBytes::try_from(PKCS8_V2_DER).unwrap();
    assert_eq!(recovered.secret_key, keypair_v2.secret_key);
    assert_eq!(recovered.public_key, keypair_v2.public_key);
    assert_eq!(PublicKeyBytes::try_from(PUBLIC_KEY_DER).unwrap(), public_key);

    // The raw 64-byte identity agrees with the PKCS#8 v2 import.
    let raw = keypair_v2.to_bytes().expect("v2 keypair has a public key");
    let raw_keypair = KeypairBytes::from_bytes(&raw);
    assert_eq!(raw_keypair.secret_key, keypair_v2.secret_key);
    assert_eq!(raw_keypair.public_key, Some(public_key));

    // A v1 keypair has no raw 64-byte identity.
    assert_eq!(keypair_v1.to_bytes(), None);
}

#[test]
fn decode_rejects_malformed_public_key() {
    // A malformed public key is an error, not something to silently drop:
    // every import path has to agree on the same object.
    assert_eq!(
        KeypairBytes::from_pkcs8_der(PKCS8_V2_PUBLIC_KEY_UNUSED_BITS_DER).err(),
        Some(Error::from(KeyError::Invalid))
    );

    assert_eq!(
        KeypairBytes::from_pkcs8_der(PKCS8_V2_SHORT_PUBLIC_KEY_DER).err(),
        Some(Error::from(KeyError::Invalid))
    );
}

#[test]
fn decode_rejects_algorithm_parameters() {
    assert_eq!(
        KeypairBytes::from_pkcs8_der(PKCS8_V2_ALGORITHM_PARAMETERS_DER).err(),
        Some(Error::ParametersMalformed)
    );

    assert_eq!(
        PublicKeyBytes::from_public_key_der(PUBLIC_KEY_ALGORITHM_PARAMETERS_DER).err(),
        Some(spki::Error::KeyMalformed)
    );
}

#[test]
fn cross_import_rejects_mismatched_documents() {
    // A public key document is not a keypair.
    assert!(KeypairBytes::from_pkcs8_der(PUBLIC_KEY_DER).is_err());

    // A keypair document is not a public key.
    assert!(PublicKeyBytes::from_public_key_der(PKCS8_V1_DER).is_err());
    assert!(PublicKeyBytes::from_public_key_der(PKCS8_V2_DER).is_err());
}

#[cfg(feature = "alloc")]
#[test]
fn encode_pkcs8_v1() {
    let pk = KeypairBytes::from_pkcs8_der(PKCS8_V1_DER).unwrap();
    let pk_der = pk.to_pkcs8_der().unwrap();
    assert_eq!(pk_der.as_bytes(), PKCS8_V1_DER);
}

#[cfg(feature = "alloc")]
#[test]
fn encode_pkcs8_v2() {
    let pk = KeypairBytes::from_pkcs8_der(PKCS8_V2_DER).unwrap();
    let pk2 = KeypairBytes::from_pkcs8_der(pk.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    assert_eq!(pk.secret_key, pk2.secret_key);
    assert_eq!(pk.public_key, pk2.public_key);
}

#[cfg(feature = "alloc")]
#[test]
fn encode_public_key() {
    let pk = PublicKeyBytes::from_public_key_der(PUBLIC_KEY_DER).unwrap();
    let pk_der = pk.to_public_key_der().unwrap();
    assert_eq!(pk_der.as_ref(), PUBLIC_KEY_DER);
}

#[cfg(feature = "alloc")]
#[test]
fn cross_import_encode_consistency() {
    let keypair_v1 = KeypairBytes::from_pkcs8_der(PKCS8_V1_DER).unwrap();
    let keypair_v2 = KeypairBytes::from_pkcs8_der(PKCS8_V2_DER).unwrap();

    // Re-encoding the public part of the keypair produces the same SPKI
    // document as the standalone public key import.
    let public_key = PublicKeyBytes::try_from(&keypair_v2).unwrap();
    assert_eq!(
        public_key.to_public_key_der().unwrap().as_ref(),
        PUBLIC_KEY_DER
    );

    // Re-encoding then re-importing yields the same keypair identity.
    let reimported_v1 =
        KeypairBytes::from_pkcs8_der(keypair_v1.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    assert_eq!(reimported_v1.secret_key, keypair_v1.secret_key);
    assert_eq!(reimported_v1.public_key, keypair_v1.public_key);

    let reimported_v2 =
        KeypairBytes::from_pkcs8_der(keypair_v2.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    assert_eq!(reimported_v2.secret_key, keypair_v2.secret_key);
    assert_eq!(reimported_v2.public_key, keypair_v2.public_key);
}

#[cfg(feature = "pem")]
#[test]
fn cross_import_pem_consistency() {
    const PKCS8_V1_PEM: &str = include_str!("examples/pkcs8-v1.pem");
    const PKCS8_V2_PEM: &str = include_str!("examples/pkcs8-v2.pem");
    const PUBLIC_KEY_PEM: &str = include_str!("examples/pubkey.pem");

    let keypair_v1 = KeypairBytes::from_pkcs8_pem(PKCS8_V1_PEM).unwrap();
    let keypair_v2 = KeypairBytes::from_pkcs8_pem(PKCS8_V2_PEM).unwrap();
    let public_key = PublicKeyBytes::from_public_key_pem(PUBLIC_KEY_PEM).unwrap();

    // PEM and DER imports agree on the same object.
    assert_eq!(
        keypair_v1.secret_key,
        KeypairBytes::from_pkcs8_der(PKCS8_V1_DER)
            .unwrap()
            .secret_key
    );
    assert_eq!(keypair_v1.public_key, None);
    assert_eq!(
        keypair_v2.secret_key,
        KeypairBytes::from_pkcs8_der(PKCS8_V2_DER)
            .unwrap()
            .secret_key
    );
    assert_eq!(keypair_v2.public_key, Some(public_key));
    assert_eq!(
        public_key,
        PublicKeyBytes::from_public_key_der(PUBLIC_KEY_DER).unwrap()
    );

    // `FromStr`-based recovery agrees as well.
    assert_eq!(
        PKCS8_V2_PEM.parse::<KeypairBytes>().unwrap().secret_key,
        keypair_v2.secret_key
    );
    assert_eq!(PUBLIC_KEY_PEM.parse::<PublicKeyBytes>().unwrap(), public_key);
}
