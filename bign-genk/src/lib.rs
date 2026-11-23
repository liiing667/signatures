#![no_std]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]
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
//! use bign_genk::bigint::U256;
//! use belt_hash::{Digest, BeltHash};
//! use belt_block::BeltBlock;
//!
//! // BIGN P-256 curve order `q` (big-endian)
//! const BIGNP256_ORDER: [u8; 32] =
//!     hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC");
//!
//! // Public key for STB 34.101.45 Bign P256/BeltHash test case
//! const KEY: [u8; 32] =
//!     hex!("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269");
//!
//! // Test message for STB 34.101.45 BignP256/BeltHash test case
//! const MSG: [u8; 13] =
//!     hex!("B194BAC8 0A08F53B 366D008E 58");
//!
//! // Expected K for STB 34.101.45 Bign P256/BeltHash test case
//! const EXPECTED_K: [u8; 32] =
//!     hex!("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E");
//!
//! // `q` is big-endian in the STB 34.101.45 tables;
//! let q = U256::from_be_slice(&BIGNP256_ORDER);
//!
//! let h = BeltHash::digest(MSG);
//! let mut kgen = bign_genk::KGenerator::<BeltBlock, U256>::new::<BeltHash>(&KEY, &h, &[], &q);
//!
//! let mut k = [0u8; 32];
//! kgen.fill_next_k(&mut k);
//! assert_eq!(k, EXPECTED_K);
//! ```

pub use bigint;
pub use cipher::Array;
pub use cipher::typenum::consts;

use belt_hash::BeltHash;
use bigint::{Encoding, Unsigned};
use cipher::{
    BlockCipherEncrypt, BlockSizeUser, KeyInit, array::ArraySize, typenum::Unsigned as _,
};
use core::fmt;
use digest::{Digest, const_oid::AssociatedOid};

type BlockArray<C> = <<C as BlockSizeUser>::BlockSize as ArraySize>::ArrayType<u8>;

/// Deterministic generator for the ephemeral scalar `k` as defined by STB 34.101.45 (BIGN).
///
/// - `C`: block cipher used by `belt-wbl` (`belt-block`).
/// - `U`: [`bigint`] integer type holding the curve order `q`.
///
/// # Generation lifecycle
///
/// A generator owns a mutable belt-wbl state `r` and evolves it every time a candidate is
/// produced. All of this evolution happens within a *generation*: a generation starts whenever a
/// context is accepted ([`KGenerator::new`] for the initial context,
/// [`KGenerator::accept_context`] for a subsequent one) and covers every candidate produced for
/// that context, including the retries performed after an unsuitable `k` or a failed signature.
///
/// Accepting a new context starts a new generation: the belt-wbl state `r` is reset to the new
/// message digest and the belt-block key `θ` is re-derived from the new associated data, so no
/// state from the previous generation leaks into the next one. A retry
/// ([`KGenerator::fill_next_k`]) never crosses a generation boundary on its own: it keeps
/// evolving the state of the generation that is currently in progress.
pub struct KGenerator<'a, C, U>
where
    C: BlockSizeUser + Clone + BlockCipherEncrypt + KeyInit,
    U: Unsigned + Encoding,
    BlockArray<C>: Copy,
{
    /// `belt-block` keyed with `θ`.
    cipher: C,
    /// Internal state `r = r₁ ‖ r₂ ‖ ... ‖ r_n`, where `r_i ∈ {0,1}^128`.
    r: [Array<u8, C::BlockSize>; 4],
    /// `n = ℓ/64` (2, 3 or 4): number of 128-bit blocks.
    n: usize,
    /// Field modulus.
    q: &'a U,
    /// Monotonic generation counter. Incremented every time a context is accepted, i.e. once by
    /// [`KGenerator::new`] and again by every [`KGenerator::accept_context`] call.
    generation: u64,
}

impl<'a, C, U> KGenerator<'a, C, U>
where
    C: BlockSizeUser + Clone + BlockCipherEncrypt + KeyInit,
    U: Unsigned + Encoding,
    BlockArray<C>: Copy,
{
    /// Initialize the `k` generator.
    ///
    /// Accepts the following parameters and inputs:
    ///
    /// - `x`: secret key
    /// - `h`: hash/digest of an input message: must be reduced modulo `q` in advance
    /// - `data`: additional associated data `t`, e.g. CSRNG output used as added entropy
    /// - `q`: curve order, as a [`bigint`] integer (the candidate `k` is compared against it)
    ///
    /// Accepting the initial context starts the first generation of the generator.
    #[must_use]
    pub fn new<M: AssociatedOid>(x: &[u8], h: &[u8], data: &[u8], q: &'a U) -> Self {
        let (cipher, r, n) = Self::accept::<M>(x, h, data);

        Self {
            cipher,
            r,
            n,
            q,
            generation: 0,
        }
    }

    /// Accept a new context and start a new generation.
    ///
    /// The generator is re-seeded exactly as if it had been constructed with
    /// [`KGenerator::new`] using `x`, `h` and `data`: the belt-block key `θ` is re-derived from
    /// `x` and the associated data `data`, and the belt-wbl state `r` is reset to `h`. Any state
    /// accumulated while producing candidates for previous contexts (including in-flight retry
    /// state) is discarded, so subsequent [`KGenerator::fill_next_k`] calls emit candidates of
    /// the new generation rather than replaying the old ones.
    ///
    /// Call this between independent signing attempts, e.g. when the message digest or the added
    /// entropy changes. Retries of the *same* attempt must keep calling
    /// [`KGenerator::fill_next_k`] instead, so that they evolve the current generation as
    /// required by STB 34.101.45.
    ///
    /// The parameters have the same meaning and validity requirements as in [`KGenerator::new`].
    pub fn accept_context<M: AssociatedOid>(&mut self, x: &[u8], h: &[u8], data: &[u8]) {
        let (cipher, r, n) = Self::accept::<M>(x, h, data);

        self.cipher = cipher;
        self.r = r;
        self.n = n;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Index of the generation currently in progress.
    ///
    /// Starts at zero for the context accepted by [`KGenerator::new`] and is incremented by
    /// every [`KGenerator::accept_context`] call. Candidates produced while the same generation
    /// is active share an evolved belt-wbl state; accepting a new context starts a fresh
    /// generation with a reset state.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Derive a fresh belt-block key `θ` and the initial belt-wbl state `r` from a context.
    ///
    /// Shared by [`KGenerator::new`] and [`KGenerator::accept_context`] so that accepting the
    /// initial context and accepting a subsequent one perform exactly the same initialization.
    fn accept<M: AssociatedOid>(
        x: &[u8],
        h: &[u8],
        data: &[u8],
    ) -> (C, [Array<u8, C::BlockSize>; 4], usize) {
        let len = x.len();
        assert_eq!(len, h.len());
        assert!(len == 32 || len == 48 || len == 64);

        // n = ℓ/64 (2, 3 or 4)
        let n = len / C::BlockSize::USIZE;

        // 2: θ ← belt-hash(OID(h) ‖ ⟨d⟩ ‖ t)
        let mut hasher = BeltHash::new();
        hasher.update([0x06, (M::OID.len() - 1) as u8]);
        hasher.update(M::OID);
        hasher.update(x);
        hasher.update(data);
        let theta = hasher.finalize();

        // belt-block(θ)
        let cipher = C::new_from_slice(&theta).expect("Invalid key length");

        // 3. r ← H
        // r = r₁ ‖ r₂ ‖ ... ‖ r_n, where r_i ∈ {0,1}^128
        let mut r = [Array::<u8, C::BlockSize>::default(); 4];
        for (i, chunk) in h.chunks(C::BlockSize::USIZE).enumerate().take(n) {
            r[i][..chunk.len()].copy_from_slice(chunk);
        }

        (cipher, r, n)
    }

    /// Generate a candidate `k` value.
    ///
    /// This may be called repeatedly in the event a particular `k` is unsuitable, e.g. the
    /// resulting `r` value is zero. Every call advances the belt-wbl state of the generation
    /// that is currently in progress; the generation itself only changes when a new context is
    /// accepted via [`KGenerator::accept_context`].
    pub fn fill_next_k(&mut self, k: &mut [u8]) {
        let bs = C::BlockSize::USIZE;
        let n = self.n;
        assert_eq!(k.len(), n * bs);

        loop {
            // One `belt-wbl` encryption: `2n` rounds with `⟨i⟩` running over `1..=2n`.
            for i in 1..=(2 * n as u32) {
                let s = match n {
                    2 => {
                        // 4.1) s ← r₁
                        self.r[0]
                    }
                    3 => {
                        // 4.2.a) s ← r₁ ⊕ r₂
                        let s = xor_blocks::<C>(&self.r[0], &self.r[1]);
                        // 4.2.b) r₁ ← r₂
                        self.r[0] = self.r[1];
                        s
                    }
                    4 => {
                        // 4.3.a) s ← r₁ ⊕ r₂ ⊕ r₃
                        let mut s = xor_blocks::<C>(&self.r[0], &self.r[1]);
                        xor_assign(&mut s, &self.r[2]);
                        // 4.3.b) r₁ ← r₂
                        self.r[0] = self.r[1];
                        // 4.3.c) r₂ ← r₃
                        self.r[1] = self.r[2];
                        s
                    }
                    _ => unreachable!(),
                };

                // 4.4: r_(n-1) ← belt-block(s, θ) ⊕ r_n ⊕ ⟨i⟩_128
                let mut encrypted = s;
                self.cipher.encrypt_block(&mut encrypted);

                // ⊕ r_n
                xor_assign(&mut encrypted, &self.r[n - 1]);

                // ⊕ ⟨i⟩_128
                xor_assign(&mut encrypted, &i.to_le_bytes());

                // r_(n-1)
                self.r[n - 2] = encrypted;

                // 4.5: r_n ← s
                self.r[n - 1] = s;
            }

            for (j, chunk) in self.r.iter().enumerate().take(n) {
                k[j * bs..(j + 1) * bs].copy_from_slice(chunk);
            }

            // Assert: k ∈ {1, 2, ..., q-1}
            //
            // `k` is the little-endian octet string `r₁ ‖ r₂ ‖ ... ‖ r_n`; decode it as a
            // little-endian integer and range-check it in constant time against `q`.
            let repr = <U::Repr>::try_from(&k[..]).expect("k must equal the modulus width");
            let candidate = U::from_le_bytes(repr);

            if ((!candidate.is_zero()) & candidate.ct_lt(self.q)).to_bool() {
                return; // 5-6: k ← r, return
            }
        }
    }
}

impl<'a, C, U> fmt::Debug for KGenerator<'a, C, U>
where
    C: BlockSizeUser + Clone + BlockCipherEncrypt + KeyInit,
    U: Unsigned + Encoding,
    BlockArray<C>: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KGenerator").finish_non_exhaustive()
    }
}

/// XOR two blocks of arbitrary size
#[inline]
fn xor_blocks<C>(
    a: &Array<u8, C::BlockSize>,
    b: &Array<u8, C::BlockSize>,
) -> Array<u8, C::BlockSize>
where
    C: BlockSizeUser,
    BlockArray<C>: Copy,
{
    let mut result = *a;
    xor_assign(&mut result, b);
    result
}

/// XOR-assignment
#[inline]
fn xor_assign(a: &mut [u8], b: &[u8]) {
    for (a_byte, b_byte) in a.iter_mut().zip(b.iter()) {
        *a_byte ^= b_byte;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bash_hash::{BashHash384, BashHash512};
    use belt_block::BeltBlock;
    use belt_hash::BeltHash;
    use bigint::{U256, U384, U512};
    use hex_literal::hex;

    macro_rules! gek_tests {
        ($($name:ident: $uint:ty, $oid:ty, $d:expr, $q:expr, $h:expr, $expected:expr;)+) => {
            $(
                #[test]
                fn $name() {
                    let q = <$uint>::from_be_slice(&$q);
                    let mut kgen = KGenerator::<BeltBlock, $uint>::new::<$oid>(&$d, &$h, &[], &q);

                    let expected = $expected;
                    let mut buf = [0u8; 64];
                    let k = &mut buf[..expected.len()];
                    kgen.fill_next_k(k);

                    assert_eq!(&k[..], &expected[..]);
                }
            )+
        };
    }

    gek_tests! {
        bign_gek_1: U256, BeltHash,
            hex!("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC"),
            hex!("ABEF9725 D4C5A835 97A367D1 4494CC25 42F20F65 9DDFECC9 61A3EC55 0CBA8C75"),
            hex!("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E");

        bign_gek_2: U256, BeltHash,
            hex!("79628979 DF369BEB 94DEF329 9476AED4 14F39148 AA69E31A 7397E8AA 70578AB3"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC"),
            hex!("9D02EE44 6FB6A29F E5C982D4 B13AF9D3 E90861BC 4CEF27CF 306BFB0B 174A154A"),
            hex!("0BA66DA6 214E48A7 01F22695 BA9CD6D5 67DE17A1 C6010624 88728ED8 BBF48ED0");

        bign_gek_3: U384, BashHash384,
            hex!("84C21DBF 7B3C2372 DC21386C 216FA16C 9EF10AEA F9F96A87 2FD8058F 2780BA93 0F08BE3B EC804161 37E11A23 2D93B50E"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74"),
            hex!("64334AF8 30D33F63 E9ACDFA1 84E32522 103FFF5C 6860110A 2CD369ED BC04387C 501D8F92 F749AE4D E15A8305 C353D64D"),
            hex!("E48C1A79 06765348 6533401B 25D8D93D 174DE469 5DD2125C 0D2F9468 CC41387E 3C1D8D90 3E950903 2A1FEBF7 92C74D18");

        bign_gek_4: U384, BashHash384,
            hex!("04E1315F 05B86B66 2D809209 D6104DE8 D25DB189 FBCE4BFF E6F6CBDE 84C96024 302D154E F8A7EEF0 B6FD2927 89C3272D"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74"),
            hex!("D06EFBC1 6FD6C088 0CBFC6A4 E3D65AB1 01FA8282 6934190F AABEBFBF FEDE93B2 2B85EA72 A7FB3147 A133A5A8 FEBD8320"),
            hex!("76BF95EA F9876FD9 8619501F 2120D8F7 8DCE2AFB C2E37353 B57B576E 24D821B2 6A078978 F6C3648A 51E67B60 DE40BCE7");

        bign_gek_5: U512, BashHash512,
            hex!("BEC09635 3EF4568A A417622A 95F2B563 33BF3A02 040B3137 2FD5737D E0F1A2BA 6090C1D1 A27155D8 711FFE5B 31027847 1B0B97CF 1B8FE821 C50205E5 D24AB9B8"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 27AAEE8F 8837F39C 962A7D21 D84B63FE D5E9B891 8DB5AB9D 91E1F014 4D7A028D"),
            hex!("2A66C87C 189C12E2 55239406 123BDEDB F19955EA F0808B2A D705E249 220845E2 0F4786FB 6765D0B5 C48984B1 B16556EF 19EA8192 B985E423 3D9C0950 8D6339E7"),
            hex!("B1CAB7FE 937559E2 074BD6CB A402F39D 55F94B6C B1073939 6B63AF93 88306A96 89428B71 A57CC827 6F9608E8 EBB597F3 5CC03B72 90AD2B80 A40CF7E3 642A38E8");

        bign_gek_6: U512, BashHash512,
            hex!("A90188D4 EAA8D5B3 1FD54F3E 02E10FEB F1577A14 642D7C88 B9951F3B 957C006C 567A20BD 7635B9FF 02C3045E DDD84553 D484DE44 9CFC054C 5A96C8CD 5CEA0E33"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 27AAEE8F 8837F39C 962A7D21 D84B63FE D5E9B891 8DB5AB9D 91E1F014 4D7A028D"),
            hex!("07ABBF85 80E7E5A3 21E9B940 F667AE20 9E2952CE F557978A E743DB08 6BAB4885 B708233C 3F5541DF 8AAFC361 1482FDE4 98E58B33 79A6622D AC2664C9 C118A162"),
            hex!("47F9F579 98B359FE 1EF1E693 D5ADF97E 208314C0 ED013235 101E6EDA 7675BABD 125F4D99 93B4A810 9B4A9832 21DF6A42 E7CCA9F4 15A45810 84B1F203 5FD80376");
    }

    /// BIGN P-256 curve order `q` (big-endian), shared by the generation lifecycle tests.
    const TEST_Q: [u8; 32] =
        hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC");

    /// Two distinct reduced-mod-`q` message digests, used as alternating contexts.
    const H_A: [u8; 32] =
        hex!("ABEF9725 D4C5A835 97A367D1 4494CC25 42F20F65 9DDFECC9 61A3EC55 0CBA8C75");
    const H_B: [u8; 32] =
        hex!("9D02EE44 6FB6A29F E5C982D4 B13AF9D3 E90861BC 4CEF27CF 306BFB0B 174A154A");

    /// Two distinct pieces of associated data, used as alternating contexts.
    const DATA_1: [u8; 4] = hex!("DEAD BEEF");
    const DATA_2: [u8; 4] = hex!("CAFE F00D");

    /// First fixed-vector secret key (`bign_gek_1`).
    const X: [u8; 32] =
        hex!("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269");

    /// Produce the next candidate `k` from `kgen` as an owned byte array.
    fn next_k(kgen: &mut KGenerator<'_, BeltBlock, U256>) -> [u8; 32] {
        let mut k = [0u8; 32];
        kgen.fill_next_k(&mut k);
        k
    }

    #[test]
    fn first_generation_starts_at_zero_and_retries_stay_in_it() {
        let q = U256::from_be_slice(&TEST_Q);
        let mut kgen = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_A, &DATA_1, &q);

        assert_eq!(kgen.generation(), 0);

        // A retry after an unsuitable `k` (simulated by simply asking again) must keep evolving
        // the same generation rather than opening a new one, and every candidate must differ.
        let k1 = next_k(&mut kgen);
        let k2 = next_k(&mut kgen);
        let k3 = next_k(&mut kgen);

        assert_eq!(kgen.generation(), 0);
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
        assert_ne!(k1, k3);
    }

    #[test]
    fn accept_context_starts_a_new_generation_and_resets_state() {
        let q = U256::from_be_slice(&TEST_Q);
        let mut kgen = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_A, &DATA_1, &q);

        // Drain several candidates so the belt-wbl state has drifted far from its initial value.
        let stale: [[u8; 32]; 3] = [next_k(&mut kgen), next_k(&mut kgen), next_k(&mut kgen)];
        assert_eq!(kgen.generation(), 0);

        // Accepting a changed context opens generation 1.
        kgen.accept_context::<BeltHash>(&X, &H_B, &DATA_2);
        assert_eq!(kgen.generation(), 1);

        // The first candidate of the new generation must match a freshly constructed generator
        // for the same context, proving the old belt-wbl state was fully reset.
        let mut fresh = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_B, &DATA_2, &q);
        assert_eq!(next_k(&mut kgen), next_k(&mut fresh));

        // And it must not replay any candidate emitted by the previous generation.
        let first = next_k(&mut kgen);
        assert!(stale.iter().all(|old| *old != first));
    }

    #[test]
    fn alternating_contexts_produce_distinct_k_and_deterministic_generations() {
        let q = U256::from_be_slice(&TEST_Q);
        let mut kgen = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_A, &DATA_1, &q);

        // Reference generators constructed directly for each context.
        let mut ref_a = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_A, &DATA_1, &q);
        let mut ref_b = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_B, &DATA_2, &q);

        // A → B → A → B, interleaved with retries inside each generation.
        let k_a1 = next_k(&mut kgen);
        let k_a1_retry = next_k(&mut kgen);
        kgen.accept_context::<BeltHash>(&X, &H_B, &DATA_2);
        assert_eq!(kgen.generation(), 1);
        let k_b1 = next_k(&mut kgen);
        let k_b1_retry = next_k(&mut kgen);

        kgen.accept_context::<BeltHash>(&X, &H_A, &DATA_1);
        assert_eq!(kgen.generation(), 2);
        let k_a2 = next_k(&mut kgen);
        let k_a2_retry = next_k(&mut kgen);

        kgen.accept_context::<BeltHash>(&X, &H_B, &DATA_2);
        assert_eq!(kgen.generation(), 3);
        let k_b2 = next_k(&mut kgen);

        // Every acceptance restarts the generation from the same initial belt-wbl state, so a
        // re-accepted context replays its own sequence from the beginning...
        assert_eq!(k_a1, next_k(&mut ref_a));
        assert_eq!(k_a2, k_a1);
        assert_eq!(k_a2_retry, k_a1_retry);
        assert_eq!(k_b1, next_k(&mut ref_b));
        assert_eq!(k_b2, k_b1);

        // ...while the two contexts never share candidates or in-generation retry sequences.
        assert_ne!(k_a1, k_b1);
        assert_ne!(k_a1_retry, k_b1_retry);
        assert_ne!(k_a1, k_a1_retry);
        assert_ne!(k_b1, k_b1_retry);
    }

    #[test]
    fn changed_associated_data_alone_starts_a_new_generation() {
        let q = U256::from_be_slice(&TEST_Q);
        let mut kgen = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_A, &DATA_1, &q);
        let with_data_1 = next_k(&mut kgen);

        // Same key and digest, only the associated data changes: a new generation must still be
        // derived, i.e. the generator must not keep emitting candidates for the old `data`.
        kgen.accept_context::<BeltHash>(&X, &H_A, &DATA_2);
        assert_eq!(kgen.generation(), 1);
        let with_data_2 = next_k(&mut kgen);
        assert_ne!(with_data_1, with_data_2);

        // A directly constructed generator with the new associated data agrees.
        let mut fresh = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_A, &DATA_2, &q);
        assert_eq!(with_data_2, next_k(&mut fresh));
    }

    #[test]
    fn empty_context_round_trip_restores_the_original_generation() {
        let q = U256::from_be_slice(&TEST_Q);
        let mut kgen = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_A, &[], &q);

        // The empty-context fixed vector still holds (first candidate of generation 0).
        assert_eq!(
            next_k(&mut kgen),
            hex!("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E")
        );

        // Drift into another context, then accept the original empty context again.
        kgen.accept_context::<BeltHash>(&X, &H_B, &DATA_2);
        assert_eq!(kgen.generation(), 1);
        let _ = next_k(&mut kgen);

        kgen.accept_context::<BeltHash>(&X, &H_A, &[]);
        assert_eq!(kgen.generation(), 2);

        // The re-accepted empty context reproduces the exact fixed vector from generation 0.
        assert_eq!(
            next_k(&mut kgen),
            hex!("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E")
        );

        // Re-accepting the very same context is also a well-defined new generation with a reset.
        kgen.accept_context::<BeltHash>(&X, &H_A, &[]);
        assert_eq!(kgen.generation(), 3);
        assert_eq!(
            next_k(&mut kgen),
            hex!("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E")
        );
    }

    #[test]
    fn failure_recovery_keeps_generation_until_context_changes() {
        let q = U256::from_be_slice(&TEST_Q);
        let mut kgen = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_A, &DATA_1, &q);

        // Simulate a signer rejecting the first two candidates (e.g. zero `r`) and retrying:
        // recovery stays inside the generation in progress.
        let rejected_1 = next_k(&mut kgen);
        let rejected_2 = next_k(&mut kgen);
        let accepted = next_k(&mut kgen);
        assert_eq!(kgen.generation(), 0);
        assert_ne!(rejected_1, accepted);
        assert_ne!(rejected_2, accepted);

        // A brand-new signing attempt with a different context gets a clean generation whose
        // first candidate matches a generator that never saw the failed attempt.
        kgen.accept_context::<BeltHash>(&X, &H_B, &DATA_2);
        let mut fresh = KGenerator::<BeltBlock, U256>::new::<BeltHash>(&X, &H_B, &DATA_2, &q);
        assert_eq!(next_k(&mut kgen), next_k(&mut fresh));
    }

}
