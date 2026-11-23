use core::marker::PhantomData;

use hybrid_array::Array;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{Error, XmssResult};
use crate::params::{XMSS_OID_LEN, XmssOid, XmssParameter, XmssParams};
use crate::state;
use crate::utils::bytes_to_ull;
use crate::xmss_commons;
use crate::xmss_core;

/// Parses the OID and initializes params from the first bytes of a key.
/// Tries XMSS OIDs first, then falls back to XMSSMT.
fn parse_oid_and_params(bytes: &[u8]) -> XmssResult<(XmssOid, XmssParams)> {
    if bytes.len() < XMSS_OID_LEN {
        return Err(Error::InvalidOid(0));
    }
    let mut raw_oid: u32 = 0;
    for i in 0..XMSS_OID_LEN {
        raw_oid |= (bytes[XMSS_OID_LEN - i - 1] as u32) << (i * 8);
    }
    let oid = XmssOid::try_from(raw_oid).or_else(|_| XmssOid::from_xmssmt_raw_oid(raw_oid))?;
    let mut params = XmssParams::default();
    oid.initialize(&mut params)?;
    Ok((oid, params))
}

/// Builds an identity for the public part of a signing key.
///
/// The identity deliberately excludes the leaf index and secret seeds: all
/// copies of the same key share it, so a stale copy can be compared against the
/// state already observed for the live key.
fn key_identity(params: &XmssParams, sk_without_oid: &[u8]) -> Vec<u8> {
    let n = params.n as usize;
    let idx_bytes = params.index_bytes as usize;
    let root_start = idx_bytes + 2 * n;

    let mut identity = Vec::with_capacity(16 + 2 * n);
    identity.extend_from_slice(&params.func.to_be_bytes());
    identity.extend_from_slice(&params.n.to_be_bytes());
    identity.extend_from_slice(&params.full_height.to_be_bytes());
    identity.extend_from_slice(&params.d.to_be_bytes());
    // [idx || SK_SEED || SK_PRF || root || PUB_SEED]
    identity.extend_from_slice(&sk_without_oid[root_start..root_start + 2 * n]);
    identity
}

// ---------------------------------------------------------------------------
// SigningKey<P>
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of a signing key's state.
///
/// The snapshot can be logged by callers that need evidence of which leaf was
/// reserved and which public key the reservation belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningState {
    /// Next leaf index encoded in the signing key.
    pub index: u64,
    /// Next-leaf index already committed for this key.
    pub committed_index: u64,
    /// Whether the key has no leaves left for signing.
    pub exhausted: bool,
    /// Digest of the public identity (parameter set, root, and public seed).
    pub key_digest: [u8; 32],
}

/// An XMSS signing key (secret key).
#[derive(Clone)]
pub struct SigningKey<P: XmssParameter> {
    bytes: Array<u8, P::SkLen>,
    params: XmssParams,
    _marker: PhantomData<P>,
}

impl<P: XmssParameter> core::fmt::Debug for SigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("parameter_set", &P::NAME)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl<P: XmssParameter> Drop for SigningKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<P: XmssParameter> Zeroize for SigningKey<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: XmssParameter> AsRef<[u8]> for SigningKey<P> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<P: XmssParameter> TryFrom<&[u8]> for SigningKey<P> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (oid, params) = parse_oid_and_params(value)?;
        let expected_oid = P::oid();
        if oid != expected_oid {
            return Err(Error::InvalidOid(oid.raw_oid()));
        }
        if value.len() != P::SK_LEN {
            return Err(Error::InvalidKeyLength {
                expected: P::SK_LEN,
                got: value.len(),
            });
        }
        let bytes = Array::try_from(value).map_err(|_| Error::InvalidKeyLength {
            expected: P::SK_LEN,
            got: value.len(),
        })?;
        let sk_without_oid = &bytes[XMSS_OID_LEN..];
        let index_bytes = params.index_bytes as usize;
        let index = bytes_to_ull(&sk_without_oid[..index_bytes]);
        let identity = key_identity(&params, sk_without_oid);
        // A key file is only as fresh as the last index this process has seen
        // for the same public identity.
        if let Some(committed) = state::committed_index(&identity) {
            if index < committed {
                return Err(Error::KeyStateRollback { index, committed });
            }
        }
        state::advance(&identity, index);
        Ok(Self {
            bytes,
            params,
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<Vec<u8>> for SigningKey<P> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        SigningKey::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<&Vec<u8>> for SigningKey<P> {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        SigningKey::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<Box<[u8]>> for SigningKey<P> {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        SigningKey::<P>::try_from(value.as_ref())
    }
}

#[cfg(test)]
impl<P: XmssParameter> PartialEq for SigningKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

#[cfg(test)]
impl<P: XmssParameter> Eq for SigningKey<P> {}

#[cfg(test)]
impl<P: XmssParameter> core::hash::Hash for SigningKey<P> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes[..].hash(state);
    }
}

#[cfg(feature = "serde")]
impl<P: XmssParameter> serdect::serde::Serialize for SigningKey<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: XmssParameter> serdect::serde::Deserialize<'de> for SigningKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl<P: XmssParameter> SigningKey<P> {
    pub(crate) fn new(bytes: Array<u8, P::SkLen>, params: XmssParams) -> Self {
        Self {
            bytes,
            params,
            _marker: PhantomData,
        }
    }

    /// Returns the next leaf index encoded in this signing key.
    pub fn index(&self) -> u64 {
        let index_bytes = self.params.index_bytes as usize;
        bytes_to_ull(&self.bytes[XMSS_OID_LEN..XMSS_OID_LEN + index_bytes])
    }

    /// Returns the next leaf index encoded in this signing key.
    ///
    /// This is an alias for [`Self::index`].
    pub fn leaf_index(&self) -> u64 {
        self.index()
    }

    /// Returns the number of one-time signatures still available.
    pub fn remaining_signatures(&self) -> u64 {
        let index = self.index();
        let max_index = self.params.max_index();
        if index > max_index {
            0
        } else {
            max_index.saturating_sub(index).saturating_add(1)
        }
    }

    /// Returns `true` once the key has no leaves left for signing.
    pub fn is_exhausted(&self) -> bool {
        self.index() > self.params.max_index()
    }

    /// Returns a stable digest of the public identity of this key.
    ///
    /// The digest covers the parameter set, Merkle root, and public seed, but
    /// not the secret seeds or the current leaf index.
    pub fn key_digest(&self) -> [u8; 32] {
        let digest = Sha256::digest(self.identity());
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..]);
        out
    }

    /// Returns a snapshot of the current signing state.
    pub fn state(&self) -> SigningState {
        let index = self.index();
        let identity = self.identity();
        SigningState {
            index,
            committed_index: state::committed_index(&identity).unwrap_or(index),
            exhausted: index > self.params.max_index(),
            key_digest: self.key_digest(),
        }
    }

    fn identity(&self) -> Vec<u8> {
        key_identity(&self.params, &self.bytes[XMSS_OID_LEN..])
    }

    fn check_state(&self) -> XmssResult<()> {
        let identity = self.identity();
        let index = self.index();
        if let Some(committed) = state::committed_index(&identity) {
            if index < committed {
                return Err(Error::KeyStateRollback { index, committed });
            }
        }
        Ok(())
    }

    fn commit_state(&self) {
        state::advance(&self.identity(), self.index());
    }

    fn sign_bytes(&mut self, m: &[u8]) -> XmssResult<Vec<u8>> {
        // Freeze the current leaf index before entering the core signer.  The
        // core advances the encoded index before it performs any fallible
        // cryptographic work, so a failed attempt consumes the leaf rather than
        // making it available to a retry.
        self.check_state()?;
        let result =
            xmss_core::xmssmt_core_sign(&self.params, &mut self.bytes[XMSS_OID_LEN..], m);
        self.commit_state();
        result
    }

    /// Signs a message. Returns the signature followed by the message and updates
    /// the internal state (one-time key index is advanced).
    pub fn sign(&mut self, m: &[u8]) -> XmssResult<Signature<P>> {
        let bytes = self.sign_bytes(m)?;
        Ok(Signature {
            bytes,
            _marker: PhantomData,
        })
    }

    /// Signs a message, returning only the detached signature (without the message appended).
    pub fn sign_detached(&mut self, m: &[u8]) -> XmssResult<DetachedSignature<P>> {
        let mut sm = self.sign_bytes(m)?;
        let sig_bytes = sm.len() - m.len();
        sm.truncate(sig_bytes);
        Ok(DetachedSignature {
            bytes: sm.into_boxed_slice(),
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> signature::SignerMut<DetachedSignature<P>> for SigningKey<P> {
    fn try_sign(&mut self, msg: &[u8]) -> Result<DetachedSignature<P>, signature::Error> {
        self.sign_detached(msg).map_err(|_| signature::Error::new())
    }
}

impl<P: XmssParameter> signature::Keypair for SigningKey<P> {
    type VerifyingKey = VerifyingKey<P>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey::from(self)
    }
}

// ---------------------------------------------------------------------------
// VerifyingKey<P>
// ---------------------------------------------------------------------------

/// An XMSS verifying key (public key).
#[derive(Clone, Debug)]
pub struct VerifyingKey<P: XmssParameter> {
    bytes: Array<u8, P::VkLen>,
    params: XmssParams,
    _marker: PhantomData<P>,
}

impl<P: XmssParameter> AsRef<[u8]> for VerifyingKey<P> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<P: XmssParameter> TryFrom<&[u8]> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (oid, params) = parse_oid_and_params(value)?;
        let expected_oid = P::oid();
        if oid != expected_oid {
            return Err(Error::InvalidOid(oid.raw_oid()));
        }
        if value.len() != P::VK_LEN {
            return Err(Error::InvalidKeyLength {
                expected: P::VK_LEN,
                got: value.len(),
            });
        }
        let bytes = Array::try_from(value).map_err(|_| Error::InvalidKeyLength {
            expected: P::VK_LEN,
            got: value.len(),
        })?;
        Ok(Self {
            bytes,
            params,
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<Vec<u8>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        VerifyingKey::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<&Vec<u8>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        VerifyingKey::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<Box<[u8]>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        VerifyingKey::<P>::try_from(value.as_ref())
    }
}

impl<P: XmssParameter> PartialEq for VerifyingKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

impl<P: XmssParameter> Eq for VerifyingKey<P> {}

impl<P: XmssParameter> core::hash::Hash for VerifyingKey<P> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes[..].hash(state);
    }
}

#[cfg(feature = "serde")]
impl<P: XmssParameter> serdect::serde::Serialize for VerifyingKey<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: XmssParameter> serdect::serde::Deserialize<'de> for VerifyingKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl<P: XmssParameter> VerifyingKey<P> {
    pub(crate) fn new(bytes: Array<u8, P::VkLen>, params: XmssParams) -> Self {
        Self {
            bytes,
            params,
            _marker: PhantomData,
        }
    }

    /// Verifies a given message signature pair.
    /// Returns the verified message on success.
    pub fn verify(&self, signature: &Signature<P>) -> XmssResult<Vec<u8>> {
        let mut m = Vec::new();
        xmss_commons::xmssmt_core_sign_open(
            &self.params,
            &mut m,
            &signature.bytes,
            &self.bytes[XMSS_OID_LEN..],
        )?;
        Ok(m)
    }

    /// Verifies a detached signature against the provided message.
    pub fn verify_detached(&self, signature: &DetachedSignature<P>, m: &[u8]) -> XmssResult<()> {
        if signature.index() > self.params.max_index() {
            return Err(Error::VerificationFailed);
        }
        let mut sm = Vec::with_capacity(signature.bytes.len() + m.len());
        sm.extend_from_slice(&signature.bytes);
        sm.extend_from_slice(m);
        let mut msg = Vec::new();
        xmss_commons::xmssmt_core_sign_open(
            &self.params,
            &mut msg,
            &sm,
            &self.bytes[XMSS_OID_LEN..],
        )?;
        Ok(())
    }
}

impl<P: XmssParameter> From<&SigningKey<P>> for VerifyingKey<P> {
    fn from(sk: &SigningKey<P>) -> Self {
        let n = sk.params.n as usize;
        let idx_bytes = sk.params.index_bytes as usize;

        // sk after OID: [idx || SK_SEED || SK_PRF || root || PUB_SEED]
        let root_start = XMSS_OID_LEN + idx_bytes + 2 * n;

        // pk: [OID || root || PUB_SEED]
        let mut pk = Array::<u8, P::VkLen>::default();
        pk[..XMSS_OID_LEN].copy_from_slice(&sk.bytes[..XMSS_OID_LEN]);
        pk[XMSS_OID_LEN..].copy_from_slice(&sk.bytes[root_start..root_start + 2 * n]);

        VerifyingKey {
            bytes: pk,
            params: sk.params,
            _marker: PhantomData,
        }
    }
}

impl<P: XmssParameter> signature::Verifier<DetachedSignature<P>> for VerifyingKey<P> {
    fn verify(&self, msg: &[u8], signature: &DetachedSignature<P>) -> Result<(), signature::Error> {
        self.verify_detached(signature, msg)
            .map_err(|_| signature::Error::new())
    }
}

// ---------------------------------------------------------------------------
// Signature<P>
// ---------------------------------------------------------------------------

/// An XMSS signature (signature + message, variable length).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature<P: XmssParameter> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

impl<P: XmssParameter> AsRef<[u8]> for Signature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: XmssParameter> Signature<P> {
    /// Returns the leaf index encoded in this signature.
    pub fn index(&self) -> u64 {
        let params = P::xmss_params();
        let index_bytes = params.index_bytes as usize;
        if self.bytes.len() < index_bytes {
            return u64::MAX;
        }
        bytes_to_ull(&self.bytes[..index_bytes])
    }

    /// Returns the leaf index encoded in this signature.
    ///
    /// This is an alias for [`Self::index`].
    pub fn leaf_index(&self) -> u64 {
        self.index()
    }
}

impl<P: XmssParameter> TryFrom<&[u8]> for Signature<P> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Signature {
            bytes: value.to_vec(),
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<Vec<u8>> for Signature<P> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Signature {
            bytes: value,
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<&Vec<u8>> for Signature<P> {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Signature::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<Box<[u8]>> for Signature<P> {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Signature::<P>::try_from(value.as_ref())
    }
}

impl<P: XmssParameter> From<Signature<P>> for Vec<u8> {
    fn from(sig: Signature<P>) -> Vec<u8> {
        sig.bytes
    }
}

#[cfg(feature = "serde")]
impl<P: XmssParameter> serdect::serde::Serialize for Signature<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: XmssParameter> serdect::serde::Deserialize<'de> for Signature<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl<P: XmssParameter> signature::SignatureEncoding for Signature<P> {
    type Repr = Vec<u8>;
}

// ---------------------------------------------------------------------------
// DetachedSignature<P>
// ---------------------------------------------------------------------------

/// A fixed-size detached XMSS signature (without appended message).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DetachedSignature<P: XmssParameter> {
    bytes: Box<[u8]>,
    _marker: PhantomData<P>,
}

impl<P: XmssParameter> AsRef<[u8]> for DetachedSignature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: XmssParameter> DetachedSignature<P> {
    /// Returns the leaf index encoded in this detached signature.
    pub fn index(&self) -> u64 {
        let params = P::xmss_params();
        let index_bytes = params.index_bytes as usize;
        bytes_to_ull(&self.bytes[..index_bytes])
    }

    /// Returns the leaf index encoded in this detached signature.
    ///
    /// This is an alias for [`Self::index`].
    pub fn leaf_index(&self) -> u64 {
        self.index()
    }
}

impl<P: XmssParameter> TryFrom<&[u8]> for DetachedSignature<P> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != P::SIG_LEN {
            return Err(Error::InvalidSignatureLength {
                expected: P::SIG_LEN,
                got: value.len(),
            });
        }
        Ok(DetachedSignature {
            bytes: value.into(),
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<Vec<u8>> for DetachedSignature<P> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != P::SIG_LEN {
            return Err(Error::InvalidSignatureLength {
                expected: P::SIG_LEN,
                got: value.len(),
            });
        }
        Ok(DetachedSignature {
            bytes: value.into_boxed_slice(),
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<&Vec<u8>> for DetachedSignature<P> {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        DetachedSignature::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<Box<[u8]>> for DetachedSignature<P> {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        if value.len() != P::SIG_LEN {
            return Err(Error::InvalidSignatureLength {
                expected: P::SIG_LEN,
                got: value.len(),
            });
        }
        Ok(DetachedSignature {
            bytes: value,
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> From<DetachedSignature<P>> for Vec<u8> {
    fn from(sig: DetachedSignature<P>) -> Vec<u8> {
        sig.bytes.into_vec()
    }
}

impl<P: XmssParameter> From<DetachedSignature<P>> for Box<[u8]> {
    fn from(sig: DetachedSignature<P>) -> Box<[u8]> {
        sig.bytes
    }
}

#[cfg(feature = "serde")]
impl<P: XmssParameter> serdect::serde::Serialize for DetachedSignature<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: XmssParameter> serdect::serde::Deserialize<'de> for DetachedSignature<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl<P: XmssParameter> signature::SignatureEncoding for DetachedSignature<P> {
    type Repr = Box<[u8]>;
}

// ---------------------------------------------------------------------------
// KeyPair<P>
// ---------------------------------------------------------------------------

/// An XMSS key pair containing both signing and verifying keys.
#[derive(Clone, Debug)]
pub struct KeyPair<P: XmssParameter> {
    signing_key: SigningKey<P>,
    verifying_key: VerifyingKey<P>,
}

impl<P: XmssParameter> KeyPair<P> {
    #[cfg(feature = "pkcs8")]
    pub(crate) fn new(signing_key: SigningKey<P>, verifying_key: VerifyingKey<P>) -> Self {
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Generates a random key pair for the parameter set `P`.
    pub fn generate<R: rand::CryptoRng>(rng: &mut R) -> XmssResult<Self> {
        let oid = P::oid();
        let (params, mut pk, mut sk) = oid.init_keypair_buffers(None)?;
        xmss_core::xmssmt_core_keypair(
            &params,
            &mut pk[XMSS_OID_LEN..],
            &mut sk[XMSS_OID_LEN..],
            rng,
        )?;
        let pk_array = Array::<u8, P::VkLen>::try_from(pk.as_slice()).map_err(|_| {
            Error::InvalidKeyLength {
                expected: P::VK_LEN,
                got: pk.len(),
            }
        })?;
        let sk_array = Array::<u8, P::SkLen>::try_from(sk.as_slice()).map_err(|_| {
            Error::InvalidKeyLength {
                expected: P::SK_LEN,
                got: sk.len(),
            }
        })?;
        Ok(Self {
            verifying_key: VerifyingKey::new(pk_array, params),
            signing_key: SigningKey::new(sk_array, params),
        })
    }

    /// Generates a key pair from a deterministic seed.
    /// Seed must be `P::SEED_LEN` bytes (3*n).
    pub fn from_seed(seed: &[u8]) -> XmssResult<Self> {
        let oid = P::oid();
        let (params, mut pk, mut sk) = oid.init_keypair_buffers(Some(seed))?;
        xmss_core::xmssmt_core_seed_keypair(
            &params,
            &mut pk[XMSS_OID_LEN..],
            &mut sk[XMSS_OID_LEN..],
            seed,
        )?;
        let pk_array = Array::<u8, P::VkLen>::try_from(pk.as_slice()).map_err(|_| {
            Error::InvalidKeyLength {
                expected: P::VK_LEN,
                got: pk.len(),
            }
        })?;
        let sk_array = Array::<u8, P::SkLen>::try_from(sk.as_slice()).map_err(|_| {
            Error::InvalidKeyLength {
                expected: P::SK_LEN,
                got: sk.len(),
            }
        })?;
        // Deterministic derivation remains available for inspecting the public
        // key.  If this seed was already advanced, signing with the derived key
        // is rejected by the per-identity state ledger.
        Ok(Self {
            verifying_key: VerifyingKey::new(pk_array, params),
            signing_key: SigningKey::new(sk_array, params),
        })
    }

    /// Returns a mutable reference to the signing key.
    pub fn signing_key(&mut self) -> &mut SigningKey<P> {
        &mut self.signing_key
    }

    /// Returns a reference to the verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }

    /// Returns a shared reference to the signing key (non-mut).
    #[cfg(any(feature = "pkcs8", test))]
    pub(crate) fn signing_key_ref(&self) -> &SigningKey<P> {
        &self.signing_key
    }
}
