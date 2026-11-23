#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

//! ## Usage
//!
//! See also: [`KGenerator`] documentation.
//!
//! ```
//! use hex_literal::hex;
//! use rfc6979::bigint::U256;
//! use sha2::{Digest, Sha256};
//!
//! // NIST P-256 field modulus
//! const NIST_P256_MODULUS: U256 = U256::from_be_hex(
//!     "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
//! );
//!
//! // Private key for RFC6979 NIST P256/SHA256 test case (see RFC6979 Appendix A.2.5).
//! // WARNING: don't hardcode private keys in your source code!
//! const RFC6979_KEY: [u8; 32] =
//!     hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
//!
//! // Test message for RFC6979 NIST P256/SHA256 test case
//! const RFC6979_MSG: &[u8] = b"sample";
//!
//! // Expected K for RFC6979 NIST P256/SHA256 test case
//! const RFC6979_EXPECTED_K: [u8; 32] =
//!     hex!("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
//!
//! let h = Sha256::digest(RFC6979_MSG);
//! let aad = b"";
//! let mut kgen = rfc6979::KGenerator::<Sha256, U256>::new(&RFC6979_KEY, &h, aad, &NIST_P256_MODULUS);
//!
//! let mut k = [0u8; U256::BYTES];
//! kgen.fill_next_k(&mut k);
//! assert_eq!(k, RFC6979_EXPECTED_K);
//! ```

mod hmac_drbg;

pub use bigint;
pub use hmac;
pub use hmac::digest::array::typenum::consts;

use crate::hmac_drbg::HmacDrbg;
use bigint::{Encoding, Limb, Unsigned};
use core::fmt;
use hmac::digest::{Digest, OutputSizeUser, array::Array, block_api::BlockSizeUser};

/// Deterministic generator for the ephemeral scalar `k` as used by (EC)DSA.
///
/// A generator is bound to the exact inputs it was initialized with: the
/// private key, message digest, additional data, and curve order. Candidate
/// generation advances a single state machine; it never resets or replays an
/// earlier candidate.
///
/// Use [`KGenerator::fill_next_k_with_context`] when the caller can supply the
/// original inputs. It rejects a different message, additional data, or key
/// instead of silently continuing the nonce stream for another signing
/// operation. [`KGenerator::fill_next_k`] is the backwards-compatible fast path
/// for a generator which is already known to belong to a single operation.
/// Changing the additional data is a context change and requires a new
/// generator.
pub struct KGenerator<'a, D: OutputSizeUser, U> {
    drbg: HmacDrbg<D>,
    q: &'a U,

    /// Digest binding this generator to its initialization inputs.
    context: Array<u8, D::OutputSize>,

    /// Number of candidates returned to the caller.
    candidate_index: u64,

    /// Number of DRBG outputs considered, including rejected candidates.
    attempt_index: u64,

    /// Number of candidates rejected for being zero or outside `[1, q-1]`.
    skipped_candidates: u64,

    /// Number of generated candidates abandoned before being consumed.
    abandoned_candidates: u64,

    /// Current candidate lifecycle state.
    stage: KGeneratorStage,

    /// Candidate index awaiting consumption, if any.
    pending_candidate: Option<u64>,

    /// Most recently consumed candidate index.
    last_consumed: Option<u64>,
}

/// Lifecycle state of a [`KGenerator`] candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KGeneratorStage {
    /// The generator has been initialized but no candidate has been requested.
    Initialized,

    /// A candidate has been generated and is awaiting a signature consumer.
    CandidateGenerated,

    /// The most recently generated candidate has been consumed.
    CandidateConsumed,
}

/// Evidence describing one candidate produced by a [`KGenerator`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateInfo {
    /// One-based index of the returned candidate.
    pub index: u64,

    /// Total number of DRBG outputs considered after this candidate, including
    /// candidates rejected for being out of range.
    pub attempt: u64,

    /// Number of out-of-range candidates skipped while producing this
    /// candidate.
    pub skipped: u64,

    /// Number of earlier generated candidates abandoned by this call because
    /// they were not consumed first.
    pub abandoned: u64,
}

/// Errors returned by the context-bound [`KGenerator`] API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KGeneratorError {
    /// The supplied key, digest, or additional data does not match the inputs
    /// frozen when the generator was created.
    ContextMismatch,

    /// The candidate was already consumed by a signature consumer.
    CandidateAlreadyConsumed,

    /// The candidate belongs to an older generation and can no longer be
    /// consumed.
    CandidateStale,

    /// The candidate index was never produced by this generator.
    CandidateUnknown,
}

impl fmt::Display for KGeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextMismatch => f.write_str("KGenerator input context mismatch"),
            Self::CandidateAlreadyConsumed => f.write_str("candidate was already consumed"),
            Self::CandidateStale => f.write_str("candidate is stale"),
            Self::CandidateUnknown => f.write_str("candidate was not generated by this KGenerator"),
        }
    }
}

impl core::error::Error for KGeneratorError {}

impl<'a, D, U> KGenerator<'a, D, U>
where
    D: BlockSizeUser + Digest,
    U: Unsigned + Encoding,
{
    /// Initialize `k` generator.
    ///
    /// Accepts the following parameters and inputs:
    ///
    /// - `x`: secret key, encoded as `int2octets(x)` using `q`
    /// - `h`: raw hash/digest of input message, encoded as `bits2octets(h)`
    /// - `data`: additional associated data, e.g. CSRNG output used as added entropy
    /// - `q`: field modulus
    pub fn new(x: &[u8], h: &[u8], data: &[u8], q: &'a U) -> Self {
        // Freeze the canonical encodings of `x` and `h`. Both are exactly
        // `rlen = ceil(qlen / 8)` octets, independently of the slice layout
        // supplied by the caller.
        let mut x_scratch = q.to_be_bytes();
        let mut h_scratch = q.to_be_bytes();
        let (x_ref, h_ref) = canonical_inputs(
            x,
            h,
            q,
            x_scratch.as_mut(),
            h_scratch.as_mut(),
        );

        let context = context_digest::<D, U>(x_ref, h_ref, data, q);
        let drbg = HmacDrbg::<D>::new(x_ref, h_ref, data);
        x_scratch.as_mut().fill(0);
        h_scratch.as_mut().fill(0);

        Self {
            drbg,
            q,
            context,
            candidate_index: 0,
            attempt_index: 0,
            skipped_candidates: 0,
            abandoned_candidates: 0,
            stage: KGeneratorStage::Initialized,
            pending_candidate: None,
            last_consumed: None,
        }
    }

    /// Generate a candidate `k` value.
    ///
    /// This may be called repeatedly in the event a particular `k` is unsuitable, e.g. the
    /// resulting `r` value is zero. Each call advances the generator and returns a fresh
    /// candidate; it never replays the previous candidate.
    pub fn fill_next_k(&mut self, k: &mut [u8]) {
        let _ = self.fill_next_k_with_info(k);
    }

    /// Generate a candidate `k` value and return evidence about its position in
    /// the generator's state machine.
    ///
    /// If the previous candidate was generated but not consumed, it is marked as
    /// abandoned and the generator advances to the next candidate. The same
    /// candidate is therefore never returned twice.
    pub fn fill_next_k_with_info(&mut self, k: &mut [u8]) -> CandidateInfo {
        let abandoned: u64 = if self.pending_candidate.is_some() { 1 } else { 0 };
        if abandoned != 0 {
            self.abandoned_candidates = self.abandoned_candidates.saturating_add(1);
        }

        debug_assert_eq!(self.q.bits().div_ceil(8).try_into(), Ok(k.len()));

        let mut skipped = 0u64;
        loop {
            self.attempt_index = self.attempt_index.saturating_add(1);
            self.drbg.fill_bytes(k);
            let candidate_k = bits2int(k, self.q);
            if ((!candidate_k.is_zero()) & candidate_k.ct_lt(self.q)).to_bool() {
                int2octets(&candidate_k, self.q, k);
                self.skipped_candidates = self.skipped_candidates.saturating_add(skipped);
                self.candidate_index = self.candidate_index.saturating_add(1);
                self.pending_candidate = Some(self.candidate_index);
                self.stage = KGeneratorStage::CandidateGenerated;

                return CandidateInfo {
                    index: self.candidate_index,
                    attempt: self.attempt_index,
                    skipped,
                    abandoned,
                };
            }

            skipped = skipped.saturating_add(1);
        }
    }

    /// Generate the next candidate after verifying that `x`, `h`, and `data`
    /// match the inputs frozen by [`KGenerator::new`].
    ///
    /// A mismatch returns [`KGeneratorError::ContextMismatch`] before the
    /// generator state or output buffer is touched. This prevents one generator
    /// from producing a nonce stream for a second message or for different
    /// additional data.
    ///
    /// # Errors
    ///
    /// Returns [`KGeneratorError::ContextMismatch`] if the supplied inputs do
    /// not match the generator's context.
    pub fn fill_next_k_with_context(
        &mut self,
        x: &[u8],
        h: &[u8],
        data: &[u8],
        k: &mut [u8],
    ) -> Result<CandidateInfo, KGeneratorError> {
        self.check_context(x, h, data)?;
        Ok(self.fill_next_k_with_info(k))
    }

    /// Check whether `x`, `h`, and `data` match the generator's frozen input
    /// context.
    ///
    /// # Errors
    ///
    /// Returns [`KGeneratorError::ContextMismatch`] when any input differs from
    /// the value supplied to [`KGenerator::new`].
    pub fn check_context(
        &self,
        x: &[u8],
        h: &[u8],
        data: &[u8],
    ) -> Result<(), KGeneratorError> {
        let mut x_scratch = self.q.to_be_bytes();
        let mut h_scratch = self.q.to_be_bytes();
        let (x_ref, h_ref) = canonical_inputs(
            x,
            h,
            self.q,
            x_scratch.as_mut(),
            h_scratch.as_mut(),
        );

        let candidate_context = context_digest::<D, U>(x_ref, h_ref, data, self.q);
        let matches = ct_eq(candidate_context.as_ref(), self.context.as_ref());
        x_scratch.as_mut().fill(0);
        h_scratch.as_mut().fill(0);

        if matches {
            Ok(())
        } else {
            Err(KGeneratorError::ContextMismatch)
        }
    }

    /// Mark a generated candidate as consumed by its signature consumer.
    ///
    /// # Errors
    ///
    /// Returns [`KGeneratorError::CandidateAlreadyConsumed`] if the candidate
    /// was already consumed, [`KGeneratorError::CandidateStale`] if it belongs
    /// to an older generation, or [`KGeneratorError::CandidateUnknown`] if the
    /// index was never produced.
    pub fn consume_candidate(
        &mut self,
        info: CandidateInfo,
    ) -> Result<(), KGeneratorError> {
        if self.stage == KGeneratorStage::CandidateGenerated
            && self.pending_candidate == Some(info.index)
        {
            self.pending_candidate = None;
            self.last_consumed = Some(info.index);
            self.stage = KGeneratorStage::CandidateConsumed;
            return Ok(());
        }

        if self.last_consumed == Some(info.index) {
            return Err(KGeneratorError::CandidateAlreadyConsumed);
        }

        if info.index == 0 || info.index > self.candidate_index {
            return Err(KGeneratorError::CandidateUnknown);
        }

        Err(KGeneratorError::CandidateStale)
    }

    /// Digest binding this generator to its private key, message digest,
    /// additional data, and curve order.
    pub fn context_id(&self) -> &[u8] {
        self.context.as_ref()
    }

    /// One-based index of the most recently returned candidate.
    pub fn candidate_index(&self) -> u64 {
        self.candidate_index
    }

    /// Total number of DRBG outputs considered, including rejected candidates.
    pub fn attempt_index(&self) -> u64 {
        self.attempt_index
    }

    /// Total number of candidates skipped because they were zero or outside
    /// `[1, q-1]`.
    pub fn skipped_candidates(&self) -> u64 {
        self.skipped_candidates
    }

    /// Total number of generated candidates abandoned before consumption.
    pub fn abandoned_candidates(&self) -> u64 {
        self.abandoned_candidates
    }

    /// Current candidate lifecycle stage.
    pub fn stage(&self) -> KGeneratorStage {
        self.stage
    }
}

/// Convert a big-endian private key slice into the fixed-width `rlen`
/// `int2octets(x)` encoding.
///
/// Shorter inputs are left-padded with zeroes and longer inputs are truncated
/// to their least significant `rlen` octets, matching the integer encoding
/// defined by RFC6979.
fn int2octets_bytes<'a, U>(x: &[u8], q: &U, out: &'a mut [u8]) -> &'a [u8]
where
    U: Unsigned + Encoding,
{
    let rlen: usize = q
        .bits()
        .div_ceil(8)
        .try_into()
        .expect("modulus width must fit in usize");

    debug_assert!(out.len() >= rlen);
    let out = &mut out[..rlen];
    out.fill(0);

    let src = if x.len() > rlen {
        &x[x.len() - rlen..]
    } else {
        x
    };

    out[rlen - src.len()..].copy_from_slice(src);
    out
}

/// Canonicalize the private key and message digest used to initialize a
/// [`KGenerator`].
fn canonical_inputs<'a, U>(
    x: &[u8],
    h: &[u8],
    q: &U,
    x_out: &'a mut [u8],
    h_out: &'a mut [u8],
) -> (&'a [u8], &'a [u8])
where
    U: Unsigned + Encoding,
{
    let x_ref = int2octets_bytes(x, q, x_out);
    let h_ref = bits2octets(h, q, h_out);
    (x_ref, h_ref)
}

/// Hash the canonical initialization inputs into a stable context identity.
fn context_digest<D, U>(
    x: &[u8],
    h: &[u8],
    data: &[u8],
    q: &U,
) -> D::Output
where
    D: Digest,
    U: Encoding,
{
    let q_bytes = q.to_be_bytes();
    let q_slice: &[u8] = q_bytes.as_ref();
    let mut digest = D::new();
    digest.update(b"rfc6979/KGenerator/context/v1");

    for field in [x, h, data, q_slice] {
        let len = u64::try_from(field.len()).expect("input length must fit in u64");
        digest.update(len.to_be_bytes());
        digest.update(field);
    }

    digest.finalize()
}

/// Constant-time comparison for equal-length context digests.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (a_byte, b_byte) in a.iter().zip(b) {
        diff |= *a_byte ^ *b_byte;
    }

    diff == 0
}

impl<'a, D, U> fmt::Debug for KGenerator<'a, D, U>
where
    D: BlockSizeUser + Digest,
    U: Unsigned + Encoding,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KGenerator").finish_non_exhaustive()
    }
}

/// `bits2int` transform as defined in [RFC6979 §2.3.2]: "Bit String to Integer"
///
/// From the RFC:
///
/// >  The bits2int transform takes as input a sequence of blen bits and
/// >  outputs a non-negative integer that is less than 2^qlen.  It consists
/// >  of the following steps:
/// >
/// >  1. The sequence is first truncated or expanded to length qlen:
/// >
/// >  *  if qlen < blen, then the qlen leftmost bits are kept, and
/// >     subsequent bits are discarded;
/// >
/// >  *  otherwise, qlen-blen bits (of value zero) are added to the
/// >     left of the sequence (i.e., before the input bits in the
/// >     sequence order).
/// >
/// >  2. The resulting sequence is then converted to an integer value
/// >     using the big-endian convention: if input bits are called b_0
/// >     (leftmost) to b_(qlen-1) (rightmost), then the resulting value
/// >     is:
/// >
/// >        b_0*2^(qlen-1) + b_1*2^(qlen-2) + ... + b_(qlen-1)*2^0
/// >
/// >  The bits2int transform can also be described in the following way:
/// >  the input bit sequence (of length blen) is transformed into an
/// >  integer using the big-endian convention.  Then, if blen is greater
/// >  than qlen, the resulting integer is divided by two to the power
/// >  blen-qlen (Euclidian division: the remainder is discarded); in many
/// >  software implementations of arithmetics on big integers, that
/// >  division is equivalent to a "right shift" by blen-qlen bits.
///
/// [RFC6979 §2.3.2]: https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.2
#[inline]
#[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
fn bits2int<U>(mut b: &[u8], q: &U) -> U
where
    U: Unsigned + Encoding,
{
    debug_assert!(!b.is_empty());

    let qlen = q.bits();
    let mut blen = u32::try_from(b.len())
        .ok()
        .and_then(|len| len.checked_mul(8))
        .expect("overflow");

    let bits_diff = blen.saturating_sub(qlen);

    // Ensure `b` is within one octet of the length of `q`. This helps ensure we don't exceed the
    // capacity of `U`. This effectively emulates the right shift described in the RFC by truncating
    // the least significant bytes.
    let bytes_to_discard = (bits_diff >> 3) as usize;
    if bytes_to_discard > 0 {
        b = &b[..b.len() - bytes_to_discard];
        blen -= (bytes_to_discard as u32) * 8;
    }

    let mut int = U::from_be_slice_truncated(b, blen);
    int.shr_assign(blen.saturating_sub(qlen));
    int
}

/// `int2octets` transform as defined in [RFC6979 §2.3.3]: "Integer to Octet String"
///
/// From the RFC:
///
/// > An integer value x less than q (and, in particular, a value that has
/// > been taken modulo q) can be converted into a sequence of rlen bits,
/// > where rlen = 8*ceil(qlen/8).  This is the sequence of bits obtained
/// > by big-endian encoding.  In other words, the sequence bits x_i (for i
/// > ranging from 0 to rlen-1) are such that:
/// >
/// > x = x_0*2^(rlen-1) + x_1*2^(rlen-2) + ... + x_(rlen-1)
/// >
/// > We call this transform int2octets.  Since rlen is a multiple of 8
/// > (the smallest multiple of 8 that is not smaller than qlen), then the
/// > resulting sequence of bits is also a sequence of octets, hence the
/// > name.
///
/// [RFC6979 §2.3.3]: https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.3
#[allow(clippy::as_conversions)]
fn int2octets<'a, U: Unsigned>(x: &U, q: &U, out: &'a mut [u8]) -> &'a [u8] {
    debug_assert!(x < q);
    let qlen = q.bits();
    let rlen = qlen.div_ceil(8) as usize; // NOTE: rlen in RFC is bits; we use bytes

    debug_assert!(out.len() >= rlen);
    let out = &mut out[..rlen];

    let xlimbs: &[Limb] = x.as_ref();
    for (limb, chunk) in xlimbs.iter().zip(out.rchunks_mut(Limb::BYTES)) {
        let bytes = limb.to_be_bytes();
        let offset = Limb::BYTES.saturating_sub(chunk.len());
        chunk.copy_from_slice(&bytes[offset..]);
    }

    out
}

/// `bits2octets` transform as defined in [RFC6979 §2.3.4]: "Bit String to Octet String"
///
/// From the RFC:
///
/// > The bits2octets transform takes as input a sequence of blen bits and
/// > outputs a sequence of rlen bits.  It consists of the following steps:
/// >
/// > 1. The input sequence b is converted into an integer value z1
/// >    through the bits2int transform:
/// >
/// >       z1 = bits2int(b)
/// >
/// > 2. z1 is reduced modulo q, yielding z2 (an integer between 0 and
/// >    q-1, inclusive):
/// >
/// >       z2 = z1 mod q
/// >
/// >    Note that since z1 is less than 2^qlen, that modular reduction
/// >    can be implemented with a simple conditional subtraction:
/// >    z2 = z1-q if that value is non-negative; otherwise, z2 = z1.
/// >
/// > 3.  z2 is transformed into a sequence of octets (a sequence of rlen
/// >    bits) by applying int2octets.
///
/// [RFC6979 §2.3.3]: https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.3
fn bits2octets<'a, U>(b: &[u8], q: &U, out: &'a mut [u8]) -> &'a [u8]
where
    U: Unsigned + Encoding,
{
    let z1 = bits2int(b, q);
    let mut z2 = z1.wrapping_sub(q);

    // Perform modular reduction via conditional subtraction, since we know `z1` is the same bit
    // length as `q` and therefore only one such subtraction is required.
    // (see description of this approach in the rustdoc)
    z2.ct_assign(&z1, z1.ct_lt(q));
    int2octets(&z2, q, out)
}

#[cfg(test)]
mod tests {
    mod bits2int {
        use crate::bits2int;
        use bigint::{BitOps, BoxedUint, U256};

        #[test]
        fn left_pads_when_blen_is_shorter_than_qlen() {
            let q = U256::from_u64(0x800);
            assert_eq!(bits2int(&[0x2a], &q), U256::from_u64(0x2a));
        }

        #[test]
        fn keeps_exact_qlen_bits() {
            let q = U256::from_u64(0x80);
            assert_eq!(bits2int(&[0xab], &q), U256::from_u64(0xab));
        }

        // K-163 inspired test case
        #[test]
        fn discards_trailing_bytes_then_shifts_remaining_bits() {
            let q = U256::ONE.shl_vartime(162);
            let b = [0xff; 32];

            assert_eq!(
                bits2int(&b, &q),
                U256::from_be_hex(
                    "000000000000000000000007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                )
            );
        }

        #[test]
        fn truncates_leftmost_bits_on_byte_boundary() {
            let q = U256::from_u64(0x80);
            assert_eq!(bits2int(&[0xab, 0xcd], &q), U256::from_u64(0xab));
        }

        #[test]
        fn truncates_leftmost_bits_across_partial_byte() {
            let q = U256::from_u64(0x800);
            assert_eq!(bits2int(&[0xab, 0xcd], &q), U256::from_u64(0xabc));
        }

        #[test]
        fn boxed_matches_fixed_for_short_input() {
            let q = U256::from_be_hex(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            );
            let q_boxed = BoxedUint::from_be_slice(&q.to_be_bytes(), q.bits_precision()).unwrap();
            let h = [0xab; 20];
            assert_eq!(bits2int(&h, &q_boxed), bits2int(&h, &q),);
        }
    }

    mod int2octets {
        use crate::int2octets;
        use bigint::U256;

        #[test]
        fn encodes_single_octet() {
            let q = U256::from_u64(0x80);
            let x = U256::from_u64(0x2a);
            let mut out = [0u8; 32];
            assert_eq!(int2octets(&x, &q, &mut out), &[0x2a]);
        }

        #[test]
        fn left_pads_to_qlen_octets() {
            let q = U256::from_u64(0x800);
            let x = U256::from_u64(0x2a);
            let mut out = [0u8; 32];
            assert_eq!(int2octets(&x, &q, &mut out), &[0x00, 0x2a]);
        }

        #[test]
        fn int2octets_preserves_full_width_value() {
            let q = U256::from_u64(0x800);
            let x = U256::from_u64(0x7ff);
            let mut out = [0u8; 32];
            assert_eq!(int2octets(&x, &q, &mut out), &[0x07, 0xff]);
        }
    }

    mod bits2octets {
        use crate::bits2octets;
        use bigint::{BoxedUint, U256};

        const EXAMPLE_Q: U256 =
            U256::from_be_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

        #[test]
        fn already_reduced() {
            let q = U256::from_u64(0x80);
            let mut out = [0u8; 32];
            assert_eq!(bits2octets(&[0x2a], &q, &mut out), &[0x2a]);
        }

        #[test]
        fn needs_reduction() {
            let q = U256::from_u64(0x80);
            let mut out = [0u8; 32];
            assert_eq!(bits2octets(&[0xff], &q, &mut out), &[0x7f]);
        }

        #[test]
        fn left_pads_when_blen_is_shorter_than_qlen() {
            let h = [0xab; 20];
            let mut out = [0u8; 32];

            assert_eq!(
                bits2octets(&h, &EXAMPLE_Q, &mut out),
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                ],
            );
        }

        #[test]
        fn boxed_left_pads_short_hash_to_rlen() {
            let boxed_q = BoxedUint::from_be_slice(&EXAMPLE_Q.to_be_bytes(), 256).unwrap();
            let h = [0xab; 20];
            let mut out = [0u8; 32];

            assert_eq!(
                bits2octets(&h, &boxed_q, &mut out),
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                ],
            );
        }

        #[test]
        fn boxed_160_bit_hash_with_256_bit_q() {
            let q = U256::from_be_hex(
                "87A8E61DB4B6663CFFBBD19C6519599998CEEF608660DD0F25D2CE4EDDBF8A9B",
            );

            let boxed_q = BoxedUint::from_be_slice(&q.to_be_bytes(), 256).unwrap();

            let h = [
                0x81, 0x53, 0x2b, 0x5b, 0xe0, 0x21, 0xe9, 0xb6, 0xe9, 0x87, 0xf3, 0x37, 0x66, 0x31,
                0x97, 0x4e, 0xa3, 0x1b, 0x72, 0x37,
            ];

            let mut out = [0u8; 32];
            let actual = bits2octets(&h, &boxed_q, &mut out);
            assert_eq!(&actual[..12], &[0u8; 12]);
            assert_eq!(&actual[12..], &h);
        }
    }
}
