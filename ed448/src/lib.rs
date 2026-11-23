#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![allow(non_snake_case)]

//! # Using Ed448 generically over algorithm implementations/providers
//!
//! By using the `ed448` crate, you can write code which signs and verifies
//! messages using the Ed448 signature algorithm generically over any
//! supported Ed448 implementation (see the next section for available
//! providers).
//!
//! This allows consumers of your code to plug in whatever implementation they
//! want to use without having to add all potential Ed448 libraries you'd
//! like to support as optional dependencies.
//!
//! ## Example
//!
//! ```
//! use ed448::signature::{Signer, Verifier};
//!
//! pub struct HelloSigner<S>
//! where
//!     S: Signer<ed448::Signature>
//! {
//!     pub signing_key: S
//! }
//!
//! impl<S> HelloSigner<S>
//! where
//!     S: Signer<ed448::Signature>
//! {
//!     pub fn sign(&self, person: &str) -> ed448::Signature {
//!         // NOTE: use `try_sign` if you'd like to be able to handle
//!         // errors from external signing services/devices (e.g. HSM/KMS)
//!         // <https://docs.rs/signature/latest/signature/trait.Signer.html#tymethod.try_sign>
//!         self.signing_key.sign(format_message(person).as_bytes())
//!     }
//! }
//!
//! pub struct HelloVerifier<V> {
//!     pub verifying_key: V
//! }
//!
//! impl<V> HelloVerifier<V>
//! where
//!     V: Verifier<ed448::Signature>
//! {
//!     pub fn verify(
//!         &self,
//!         person: &str,
//!         signature: &ed448::Signature
//!     ) -> Result<(), ed448::Error> {
//!         self.verifying_key.verify(format_message(person).as_bytes(), signature)
//!     }
//! }
//!
//! fn format_message(person: &str) -> String {
//!     format!("Hello, {}!", person)
//! }
//! ```

mod hex;

#[cfg(feature = "pkcs8")]
pub mod pkcs8;

#[cfg(feature = "serde")]
mod serde;

pub use signature::{self, Error, SignatureEncoding};

use core::fmt;

#[cfg(feature = "pkcs8")]
pub use crate::pkcs8::{
    KeypairBytes, PublicKeyBytes,
    spki::{
        AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier,
        der::{AnyRef, oid::ObjectIdentifier},
    },
};

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
use pkcs8::spki::{
    SignatureBitStringEncoding,
    der::{self, asn1::BitString},
};

/// Size of a single component of an Ed448 signature.
pub const COMPONENT_SIZE: usize = 57;

/// Size of an `R` or `s` component of an Ed448 signature when serialized
/// as bytes.
pub type ComponentBytes = [u8; COMPONENT_SIZE];

/// Ed448 signature serialized as a byte array.
pub type SignatureBytes = [u8; Signature::BYTE_SIZE];

/// Ed448 base field modulus `p = 2^448 - 2^224 - 1`, little-endian.
const FIELD_MODULUS: ComponentBytes = {
    let mut modulus = [0xFF; COMPONENT_SIZE];
    modulus[28] = 0xFE;
    modulus[COMPONENT_SIZE - 1] = 0x00;
    modulus
};

/// Ed448 base field element `1`, little-endian.
const FIELD_ONE: ComponentBytes = {
    let mut one = [0x00; COMPONENT_SIZE];
    one[0] = 0x01;
    one
};

/// Ed448 base field element `p - 1`, little-endian.
const FIELD_MODULUS_MINUS_ONE: ComponentBytes = {
    let mut value = FIELD_MODULUS;
    value[0] = 0xFE;
    value
};

/// Ed448 group order `L`, little-endian.
const GROUP_ORDER: ComponentBytes = [
    0xF3, 0x44, 0x58, 0xAB, 0x92, 0xC2, 0x78, 0x23, 0x55, 0x8F, 0xC5, 0x8D, 0x72, 0xC2, 0x6C, 0x21,
    0x90, 0x36, 0xD6, 0xAE, 0x49, 0xDB, 0x4E, 0xC4, 0xE9, 0x23, 0xCA, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00,
];

/// Compare two little-endian integers encoded as components.
fn component_lt(lhs: &ComponentBytes, rhs: &ComponentBytes) -> bool {
    for (lhs_byte, rhs_byte) in lhs.iter().rev().zip(rhs.iter().rev()) {
        if lhs_byte != rhs_byte {
            return lhs_byte < rhs_byte;
        }
    }

    false
}

/// Check whether a component is a canonically-encoded Curve448 point.
pub(crate) fn is_canonical_point(component: &ComponentBytes) -> bool {
    // The most significant bit of the final octet is the sign of the
    // x-coordinate; the remaining seven bits are unused and must be zero.
    let final_octet = component[COMPONENT_SIZE - 1];

    if final_octet & 0x7F != 0 {
        return false;
    }

    // The y-coordinate is encoded little-endian in the first 56 octets.
    let mut y = *component;
    y[COMPONENT_SIZE - 1] = 0;

    if !component_lt(&y, &FIELD_MODULUS) {
        return false;
    }

    // Points with x = 0 (i.e. y = 1 or y = p - 1) must have a clear sign bit.
    if final_octet & 0x80 != 0 && (y == FIELD_ONE || y == FIELD_MODULUS_MINUS_ONE) {
        return false;
    }

    true
}

/// Check whether a component is a canonically-encoded Ed448 scalar.
pub(crate) fn is_canonical_scalar(component: &ComponentBytes) -> bool {
    component_lt(component, &GROUP_ORDER)
}

/// Ed448 signature.
///
/// This type represents a container for the byte serialization of an Ed448
/// signature, and does not necessarily represent well-formed field or curve
/// elements.
///
/// The fallible [`Signature::from_slice`] parser rejects signatures whose `R`
/// or `s` components are not canonically encoded. The infallible
/// [`Signature::from_bytes`] and [`Signature::from_components`] constructors
/// operate on raw bytes and preserve them as-is.
///
/// Signature verification libraries are expected to reject invalid field
/// elements at the time a signature is verified.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct Signature {
    R: ComponentBytes,
    s: ComponentBytes,
}

impl Signature {
    /// Size of an encoded Ed448 signature in bytes (114-bytes).
    pub const BYTE_SIZE: usize = COMPONENT_SIZE * 2;

    /// Parse an Ed448 signature from a byte slice.
    #[must_use]
    pub fn from_bytes(bytes: &SignatureBytes) -> Self {
        let mut R = [0; COMPONENT_SIZE];
        let mut s = [0; COMPONENT_SIZE];

        let components = bytes.split_at(COMPONENT_SIZE);
        R.copy_from_slice(components.0);
        s.copy_from_slice(components.1);

        Self { R, s }
    }

    /// Parse an Ed448 signature from a byte slice.
    ///
    /// # Errors
    /// - Returns [`Error`] if the input byte slice is not 114-bytes.
    /// - Returns [`Error`] if the `R` or `s` component is not canonically
    ///   encoded.
    pub fn from_slice(bytes: &[u8]) -> signature::Result<Self> {
        let bytes = SignatureBytes::try_from(bytes).map_err(|_| Error::new())?;
        let signature = Self::from_bytes(&bytes);
        signature.validate()?;
        Ok(signature)
    }

    /// Validate that the `R` and `s` components are canonically encoded.
    ///
    /// # Errors
    /// - Returns [`Error`] if either component is not canonically encoded.
    pub fn validate(&self) -> signature::Result<()> {
        if !is_canonical_point(&self.R) || !is_canonical_scalar(&self.s) {
            return Err(Error::new());
        }

        Ok(())
    }

    /// Bytes for the `R` component of a signature.
    #[must_use]
    pub fn r_bytes(&self) -> &ComponentBytes {
        &self.R
    }

    /// Bytes for the `s` component of a signature.
    #[must_use]
    pub fn s_bytes(&self) -> &ComponentBytes {
        &self.s
    }

    /// Return the inner byte array.
    #[must_use]
    pub fn to_bytes(&self) -> SignatureBytes {
        let mut ret = [0u8; Self::BYTE_SIZE];
        let (R, s) = ret.split_at_mut(COMPONENT_SIZE);
        R.copy_from_slice(&self.R);
        s.copy_from_slice(&self.s);
        ret
    }

    /// Create a [`Signature`] from the serialized `r` and `s` component values
    /// which comprise the signature.
    pub fn from_components(r: impl Into<ComponentBytes>, s: impl Into<ComponentBytes>) -> Self {
        Self {
            R: r.into(),
            s: s.into(),
        }
    }
}

impl SignatureEncoding for Signature {
    type Repr = SignatureBytes;

    fn to_bytes(&self) -> SignatureBytes {
        self.to_bytes()
    }
}

impl From<Signature> for SignatureBytes {
    fn from(sig: Signature) -> SignatureBytes {
        sig.to_bytes()
    }
}

impl From<&Signature> for SignatureBytes {
    fn from(sig: &Signature) -> SignatureBytes {
        sig.to_bytes()
    }
}

impl From<SignatureBytes> for Signature {
    fn from(bytes: SignatureBytes) -> Self {
        Signature::from_bytes(&bytes)
    }
}

impl From<&SignatureBytes> for Signature {
    fn from(bytes: &SignatureBytes) -> Self {
        Signature::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Self::from_slice(bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ed448::Signature")
            .field("R", self.r_bytes())
            .field("s", self.s_bytes())
            .finish()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:X}")
    }
}

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
impl SignatureBitStringEncoding for Signature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::new(0, self.to_bytes())
    }
}

#[cfg(feature = "pkcs8")]
impl AssociatedAlgorithmIdentifier for Signature {
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs8::ALGORITHM_ID;
}
