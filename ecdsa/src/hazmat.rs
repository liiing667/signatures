//! Low-level ECDSA primitives.
//!
//! <div class="warning">
//! <b>Security️ Warning: Hazardous Materials!</b>
//!
//! YOU PROBABLY DON'T WANT TO USE THESE!
//!
//! These primitives are easy-to-misuse low-level interfaces.
//!
//! If you are an end user / non-expert in cryptography, do not use these!
//! Failure to use them correctly can lead to catastrophic failures including
//! FULL PRIVATE KEY RECOVERY!
//! </div>

use crate::{EcdsaCurve, Error, RecoveryId, Result, Signature};
use elliptic_curve::{
    CurveArithmetic, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar,
    bigint::{BitOps, Encoding},
    ff::PrimeField,
    group::{Curve as _, Group},
    ops::{Invert, MulByGeneratorVartime, Reduce},
    point::AffineCoordinates,
    scalar::IsHigh,
};

#[cfg(feature = "digest")]
use digest::{Digest, block_api::BlockSizeUser};

/// Sign a prehashed message digest using the provided secret scalar and
/// ephemeral scalar, returning an ECDSA signature.
///
/// Accepts the following arguments:
///
/// - `d`: signing key. MUST BE UNIFORMLY RANDOM!!!
/// - `k`: ephemeral scalar value. MUST BE UNIFORMLY RANDOM!!!
/// - `z`: message digest to sign. MUST BE OUTPUT OF A CRYPTOGRAPHICALLY SECURE DIGEST ALGORITHM!
///
/// # Low-S Normalization
///
/// This function will apply low-S normalization if `<C as EcdsaCurve>::NORMALIZE_S` is true.
///
/// # Returns
///
/// ECDSA [`Signature`] and a [`RecoveryId`] which can be used to recover the verifying key for a
/// given signature.
///
/// # Errors
///
/// This will return an error if a zero-scalar was generated. It can be tried again with a
/// different `k`.
#[allow(non_snake_case)]
pub fn sign_prehashed<C>(
    d: &NonZeroScalar<C>,
    k: &NonZeroScalar<C>,
    z: &[u8],
) -> Result<(Signature<C>, RecoveryId)>
where
    C: EcdsaCurve + CurveArithmetic,
{
    // Reduce message hash into an element of the scalar field for `C`.
    let z = bytes2scalar::<C>(z);

    // Compute scalar inversion of 𝑘.
    let k_inv = k.invert();

    // Compute 𝑹 = 𝑘×𝑮.
    let R = ProjectivePoint::<C>::mul_by_generator(k).to_affine();

    // Lift x-coordinate of 𝑹 (element of base field) into a serialized big
    // integer, then reduce it into an element of the scalar field.
    let r = bytes2scalar::<C>(&R.x());

    // Compute 𝒔 as a signature over 𝒓 and 𝒛.
    let s = *k_inv * (z + (r * d.as_ref()));

    // NOTE: `Signature::from_scalars` checks that both `r` and `s` are non-zero.
    let mut signature = Signature::from_scalars(r, s)?;

    // Compute recovery ID.
    let x_is_reduced = r.to_repr() != R.x();
    let y_is_odd = R.y_is_odd();
    let mut recovery_id = RecoveryId::new(y_is_odd.into(), x_is_reduced);

    // Apply low-S normalization if the curve is configured for it
    if C::NORMALIZE_S {
        recovery_id.0 ^= s.is_high().unwrap_u8();
        signature = signature.normalize_s();
    }

    Ok((signature, recovery_id))
}

/// Try to sign the given message digest deterministically using the method
/// described in [RFC6979] for computing ECDSA ephemeral scalar `k`.
///
/// Accepts the following parameters:
/// - `d`: signing key. MUST BE UNIFORMLY RANDOM!!!
/// - `z`: message digest to be signed, i.e. `H(m)`. Does not have to be reduced in advance.
/// - `ad`: optional additional data, e.g. added entropy from an RNG
///
/// [RFC6979]: https://datatracker.ietf.org/doc/html/rfc6979
pub fn sign_prehashed_rfc6979<C, D>(
    d: &NonZeroScalar<C>,
    z: &[u8],
    ad: &[u8],
) -> (Signature<C>, RecoveryId)
where
    C: EcdsaCurve + CurveArithmetic,
    D: Digest + BlockSizeUser,
{
    sign_prehashed_rfc6979_with_evidence::<C, D>(d, z, ad).0
}

/// Evidence describing how RFC6979 selected and consumed a nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rfc6979SigningEvidence {
    /// Digest binding the private key, message digest, additional data, and
    /// curve order used for this signing operation.
    pub input_digest: [u8; 32],

    /// One-based index of the accepted candidate.
    pub candidate_index: u64,

    /// Total number of DRBG outputs considered, including rejected candidates.
    pub attempt_index: u64,

    /// Number of candidates or signatures rejected before acceptance.
    pub retries: u32,

    /// Whether the final signature was accepted by the scalar consumer.
    pub signature_accepted: bool,
}

/// Sign a prehashed message using RFC6979, returning evidence about the nonce
/// state transition.
///
/// The generator is bound to `d`, `z`, and `ad` for the whole operation.
/// Rejected candidates and rejected signatures consume their candidate and
/// advance to the next one; the same `k` is never presented to the signature
/// consumer twice.
///
/// # Panics
///
/// Panics only if the generator's frozen input context changes during one
/// signing operation, which indicates an internal invariant violation.
///
/// [RFC6979]: https://datatracker.ietf.org/doc/html/rfc6979
pub fn sign_prehashed_rfc6979_with_evidence<C, D>(
    d: &NonZeroScalar<C>,
    z: &[u8],
    ad: &[u8],
) -> ((Signature<C>, RecoveryId), Rfc6979SigningEvidence)
where
    C: EcdsaCurve + CurveArithmetic,
    D: Digest + BlockSizeUser,
{
    let order = C::ORDER;
    let d_bytes = d.to_repr();
    let mut kgen = rfc6979::KGenerator::<D, C::Uint>::new(&d_bytes, z, ad, &order);
    let mut retries = 0u32;

    loop {
        let mut k_bytes = FieldBytes::<C>::default();
        let info = kgen
            .fill_next_k_with_context(&d_bytes, z, ad, &mut k_bytes)
            .expect("KGenerator context must remain fixed for one signing operation");

        if let Some(k) = NonZeroScalar::<C>::from_repr(k_bytes).into_option() {
            if let Ok(ret) = sign_prehashed(d, &k, z) {
                kgen.consume_candidate(info)
                    .expect("candidate must be pending after generation");

                let mut input_digest = [0u8; 32];
                let context_id = kgen.context_id();
                let digest_len = context_id.len().min(input_digest.len());
                input_digest[..digest_len].copy_from_slice(&context_id[..digest_len]);

                return (
                    ret,
                    Rfc6979SigningEvidence {
                        input_digest,
                        candidate_index: info.index,
                        attempt_index: info.attempt,
                        retries,
                        signature_accepted: true,
                    },
                );
            }
        }

        kgen.consume_candidate(info)
            .expect("candidate must be pending after generation");
        retries = retries.saturating_add(1);
    }
}

/// Verify the prehashed message against the provided ECDSA signature.
///
/// Accepts the following arguments:
///
/// - `q`: public key with which to verify the signature.
/// - `z`: message digest to verify. MUST BE OUTPUT OF A CRYPTOGRAPHICALLY SECURE DIGEST ALGORITHM!
/// - `signature`: purported signature to verify against the key and message.
///
/// # Errors
/// Returns [`Error`] if the signature failed to verify.
pub fn verify_prehashed<C>(q: &ProjectivePoint<C>, z: &[u8], signature: &Signature<C>) -> Result<()>
where
    C: EcdsaCurve + CurveArithmetic,
{
    let (r, s) = signature.split_scalars();

    if C::NORMALIZE_S && s.is_high().into() {
        return Err(Error::new());
    }

    let z = bytes2scalar::<C>(z);
    let s_inv = *s.invert_vartime();
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    let x = ProjectivePoint::<C>::mul_by_generator_and_mul_add_vartime(&u1, &u2, q)
        .to_affine()
        .x();

    if *r == bytes2scalar::<C>(&x) {
        Ok(())
    } else {
        Err(Error::new())
    }
}

/// Convert the provided bytestring into a `Scalar` for the given curve, interpreting it as big
/// endian, zero-padding or truncating it to the bit length of `n` (curve order) if necessary,
/// and then reducing it mod `n`.
pub(crate) fn bytes2scalar<C: EcdsaCurve + CurveArithmetic>(mut bytes: &[u8]) -> Scalar<C> {
    // Compute number of bytes in `n` (curve order)
    let n_bits = C::ORDER.bits();
    let n_bytes = usize::try_from(n_bits.div_ceil(8)).expect("overflow");
    if bytes.len() > n_bytes {
        bytes = &bytes[..n_bytes];
    }

    <Scalar<C> as Reduce<C::Uint>>::reduce(&C::Uint::from_be_slice_truncated(bytes, n_bits))
}
