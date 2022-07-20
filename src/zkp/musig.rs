use core::fmt;
///! This module implements high-level Rust bindings for a Schnorr-based
///! multi-signature scheme called MuSig2 (https://eprint.iacr.org/2020/1261).
///! It is compatible with bip-schnorr.
///!
///! The module also supports adaptor signatures as described in
///! https://github.com/ElementsProject/scriptless-scripts/pull/24
///!
///! The documentation in this include file is for reference and may not be sufficient
///! for users to begin using the library. A full description of the C API usage can be found
///! in [C-musig.md](secp256k1-sys/depend/secp256k1/src/modules/musig/musig.md), and Rust API
///! usage can be found in [Rust-musig.md](USAGE.md).
use {core, std};

use ffi::{self, CPtr};
use secp256k1::Parity;
use ZERO_TWEAK;
use {schnorr, KeyPair, XOnlyPublicKey};
use {Message, PublicKey, Secp256k1, SecretKey, Tweak};
use {Signing, Verification};

///  Data structure containing auxiliary data generated in `pubkey_agg` and
///  required for `session_*_init`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigKeyAggCache(ffi::MusigKeyaggCache, XOnlyPublicKey);

impl CPtr for MusigKeyAggCache {
    type Target = ffi::MusigKeyaggCache;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigKeyAggCache {
    /// Create a new [`MusigKeyAggCache`] by supplying a list of PublicKeys used in the session
    ///
    /// Computes a combined public key and the hash of the given public keys.
    ///
    /// Different orders of `pubkeys` result in different `agg_pk`s.
    ///
    /// The pubkeys can be sorted lexicographically before combining with which
    /// ensures the same resulting `agg_pk` for the same multiset of pubkeys.
    /// This is useful to do before aggregating pubkeys, such that the order of pubkeys
    /// does not affect the combined public key.
    ///
    /// # Returns
    ///
    ///  A pair ([`MusigKeyAggCache`], [`XOnlyPublicKey`]) where the first element is the `key_agg_cache`.
    /// This can be used to [`MusigKeyAggCache::nonce_gen`] and [`MusigKeyAggCache::nonce_process`]. The second
    /// element is the resultant Musig aggregated public key.
    ///
    /// #Args:
    ///
    /// * `secp` - Secp256k1 context object initialized for verification
    /// * `pubkeys` - Input array of public keys to combine. The order is important; a
    /// different order will result in a different combined public key
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, KeyPair, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// let _agg_pk = key_agg_cache.agg_pk();
    /// # }
    /// ```
    pub fn new<C: Verification>(secp: &Secp256k1<C>, pubkeys: &[XOnlyPublicKey]) -> Self {
        let cx = *secp.ctx();
        let xonly_ptrs = pubkeys.iter().map(|k| k.as_ptr()).collect::<Vec<_>>();
        let mut key_agg_cache = ffi::MusigKeyaggCache::new();

        unsafe {
            let mut agg_pk = XOnlyPublicKey::from(ffi::XOnlyPublicKey::new());
            if ffi::secp256k1_musig_pubkey_agg(
                cx,
                // FIXME: passing null pointer to ScratchSpace uses less efficient algorithm
                // Need scratch_space_{create,destroy} exposed in public C API to safely handle
                // memory
                core::ptr::null_mut(),
                agg_pk.as_mut_ptr(),
                &mut key_agg_cache,
                xonly_ptrs.as_ptr() as *const *const _,
                xonly_ptrs.len(),
            ) == 0
            {
                // Returns 0 only if the keys are malformed that never happens in safe rust type system.
                unreachable!("Invalid XOnlyPublicKey in input pubkeys")
            } else {
                MusigKeyAggCache(key_agg_cache, agg_pk)
            }
        }
    }

    /// Obtains the aggregate public key for this [`MusigKeyAggCache`]
    pub fn agg_pk(&self) -> XOnlyPublicKey {
        self.1
    }

    /// Apply ordinary "EC" tweaking to a public key in a [`MusigKeyAggCache`] by
    /// adding the generator multiplied with `tweak32` to it. Returns the tweaked [`PublicKey`].
    /// This is useful for deriving child keys from an aggregate public key via BIP32.
    ///
    /// This function is required if you want to _sign_ for a tweaked aggregate key.
    /// On the other hand, if you are only computing a public key, but not intending
    /// to create a signature for it, use [`secp256k1::PublicKey::add_exp_assign`]
    /// instead.
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for verification
    /// * `tweak`: tweak of type [`SecretKey`] with which to tweak the aggregated key
    ///
    /// # Errors:
    ///
    /// If resulting public key would be invalid (only when the tweak is the negation of the corresponding
    /// secret key). For uniformly random 32-byte arrays(for example, in BIP 32 derivation) the chance of
    /// being invalid is negligible (around 1 in 2^128).
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, KeyPair, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let mut key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    ///
    /// let tweak = SecretKey::from_slice(&[2; 32]).unwrap();
    /// let _tweaked_key = key_agg_cache.pubkey_ec_tweak_add(&secp, tweak).unwrap();
    /// # }
    /// ```
    pub fn pubkey_ec_tweak_add<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: SecretKey,
    ) -> Result<PublicKey, MusigTweakErr> {
        let cx = *secp.ctx();
        unsafe {
            let mut out = PublicKey::from(ffi::PublicKey::new());
            if ffi::secp256k1_musig_pubkey_ec_tweak_add(
                cx,
                out.as_mut_ptr(),
                self.as_mut_ptr(),
                tweak.as_ptr(),
            ) == 0
            {
                Err(MusigTweakErr::InvalidTweak)
            } else {
                Ok(out)
            }
        }
    }

    /// Apply "x-only" tweaking to a public key in a [`MusigKeyAggCache`] by
    /// adding the generator multiplied with `tweak32` to it. Returns the tweaked [`XOnlyPublicKey`].
    /// This is useful in creating taproot outputs.
    ///
    /// This function is required if you want to _sign_ for a tweaked aggregate key.
    /// On the other hand, if you are only computing a public key, but not intending
    /// to create a signature for it, you can just use [`XOnlyPublicKey::tweak_add_assign`]
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for verification
    /// * `tweak`: tweak of type [`SecretKey`] with which to tweak the aggregated key
    ///
    /// # Errors:
    ///
    /// If resulting public key would be invalid (only when the tweak is the negation of the corresponding
    /// secret key). For uniformly random 32-byte arrays(for example, in BIP341 taproot tweaks) the chance of
    /// being invalid is negligible (around 1 in 2^128)
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, KeyPair, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let mut key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    ///
    /// let tweak = SecretKey::from_slice(&[2; 32]).unwrap();
    /// let _x_only_key_tweaked = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak).unwrap();
    /// # }
    /// ```
    pub fn pubkey_xonly_tweak_add<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: SecretKey,
    ) -> Result<XOnlyPublicKey, MusigTweakErr> {
        let cx = *secp.ctx();
        unsafe {
            let mut out = XOnlyPublicKey::from(ffi::XOnlyPublicKey::new());
            if ffi::secp256k1_musig_pubkey_xonly_tweak_add(
                cx,
                out.as_mut_ptr(),
                self.as_mut_ptr(),
                tweak.as_ptr(),
            ) == 0
            {
                Err(MusigTweakErr::InvalidTweak)
            } else {
                Ok(out)
            }
        }
    }

    /// Starts a signing session by generating a nonce
    ///
    /// This function outputs a secret nonce that will be required for signing and a
    /// corresponding public nonce that is intended to be sent to other signers.
    ///
    /// MuSig differs from regular Schnorr signing in that implementers _must_ take
    /// special care to not reuse a nonce. If you cannot provide a `sec_key`, `session_id`
    /// UNIFORMLY RANDOM AND KEPT SECRET (even from other signers).
    /// Refer to libsecp256k1-zkp documentation for additional considerations.
    ///
    /// Musig2 nonces can be precomputed without knowing the aggregate public key, the message to sign.
    /// However, for maximal mis-use resistance, this API requires user to have already
    /// have [`SecretKey`], [`Message`] and [`MusigKeyAggCache`]. See the `new_nonce_pair` method
    /// that allows generating [`MusigSecNonce`] and [`MusigPubNonce`] with only the `session_id` field.
    ///
    /// Remember that nonce reuse will immediately leak the secret key!
    ///
    /// # Returns:
    ///
    /// A pair of ([`MusigSecNonce`], [`MusigPubNonce`]) that can be later used signing and aggregation
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `session_id`: Uniform random identifier for this session. This _must_ never be re-used.
    /// If this is not sampled uniformly at random, this can leak the private key
    /// * `sec_key`: [`SecretKey`] that we will use to sign to a create partial signature.
    /// * `msg`: [`Message`] that will be signed later on.
    /// * `extra_rand`: Additional randomness for mis-use resistance
    ///
    /// /// # Errors:
    ///
    /// * `ZeroSession`: if the `session_id` is supplied is all zeros.
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigKeyAggCache, XOnlyPublicKey, Secp256k1, SecretKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let mut session_id = [0; 32];
    /// thread_rng().fill_bytes(&mut session_id);
    ///
    /// // Generate the nonce for party with `keypair1`.
    /// let sec_key = SecretKey::from_keypair(&keypair1);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    ///
    /// // Provide the current time for mis-use resistance
    /// let extra_rand : Option<[u8; 32]> = None;
    /// let (_sec_nonce, _pub_nonce) = key_agg_cache.nonce_gen(&secp, session_id, sec_key, msg, None)
    ///     .expect("non zero session id");
    /// # }
    /// ```
    pub fn nonce_gen<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        session_id: [u8; 32],
        sec_key: SecretKey,
        msg: Message,
        extra_rand: Option<[u8; 32]>,
    ) -> Result<(MusigSecNonce, MusigPubNonce), MusigNonceGenError> {
        new_musig_nonce_pair(
            secp,
            session_id,
            Some(&self),
            Some(sec_key),
            Some(msg),
            extra_rand,
        )
    }

    /// Get a const pointer to the inner MusigKeyAggCache
    pub fn as_ptr(&self) -> *const ffi::MusigKeyaggCache {
        &self.0
    }

    /// Get a mut pointer to the inner MusigKeyAggCache
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigKeyaggCache {
        &mut self.0
    }
}

/// Musig tweaking related errors.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum MusigTweakErr {
    /// Invalid tweak (tweak is the negation of the corresponding secret key).
    InvalidTweak,
}

#[cfg(feature = "std")]
impl std::error::Error for MusigTweakErr {}

impl fmt::Display for MusigTweakErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            MusigTweakErr::InvalidTweak => write!(
                f,
                "Invalid Tweak: This only happens when
                tweak is negation of secret key"
            ),
        }
    }
}

/// Musig tweaking related errors.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum MusigNonceGenError {
    /// Invalid tweak (tweak is the negation of the corresponding secret key).
    ZeroSession,
}

#[cfg(feature = "std")]
impl std::error::Error for MusigNonceGenError {}

impl fmt::Display for MusigNonceGenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            MusigNonceGenError::ZeroSession => write!(f, "Supplied a zero session id"),
        }
    }
}
/// Starts a signing session by generating a nonce. Use [`MusigKeyAggCache::nonce_gen`] whenever
/// possible. This API provides full flexibility in providing
///
/// This function outputs a secret nonce that will be required for signing and a
/// corresponding public nonce that is intended to be sent to other signers.
///
/// MuSig differs from regular Schnorr signing in that implementers _must_ take
/// special care to not reuse a nonce. If you cannot provide a `sec_key`, `session_id`
/// UNIFORMLY RANDOM AND KEPT SECRET (even from other signers). Refer to libsecp256k1-zkp
/// documentation for additional considerations.
///
/// Musig2 nonces can be precomputed without knowing the aggregate public key, the message to sign.
///
///
/// # Arguments:
///
/// * `secp` : [`Secp256k1`] context object initialized for signing
/// * `session_id`: Uniform random identifier for this session. This _must_ never be re-used.
/// If this is not sampled uniformly at random, this can leak the private key
/// * `sec_key`: Optional [`SecretKey`] that we will use to sign to a create partial signature. Provide this
/// for maximal mis-use resistance.
/// * `msg`: Optional [`Message`] that will be signed later on. Provide this for maximal misuse resistance.
/// * `extra_rand`: Additional randomness for mis-use resistance. Provide this for maximal misuse resistance
///
/// Remember that nonce reuse will immediately leak the secret key!
///
/// # Errors:
///
/// * `ZeroSession`: if the `session_id` is supplied is all zeros.
///
/// Example:
///
/// ```rust
/// # # [cfg(any(test, feature = "rand-std"))] {
/// # use secp256k1_zkp::rand::{thread_rng, RngCore};
/// # use secp256k1_zkp::{Message, KeyPair, MusigKeyAggCache, XOnlyPublicKey, Secp256k1, SecretKey, new_musig_nonce_pair};
/// let secp = Secp256k1::new();
/// // The session id must be sampled at random. Read documentation for more details.
/// let mut session_id = [0; 32];
/// thread_rng().fill_bytes(&mut session_id);
///
/// // Supply extra auxillary randomness to prevent misuse(for example, time of day)
/// let extra_rand : Option<[u8; 32]> = None;
///
/// let (_sec_nonce, _pub_nonce) = new_musig_nonce_pair(&secp, session_id, None, None, None, None)
///     .expect("non zero session id");
/// # }
/// ```
pub fn new_musig_nonce_pair<C: Signing>(
    secp: &Secp256k1<C>,
    session_id: [u8; 32],
    key_agg_cache: Option<&MusigKeyAggCache>,
    sec_key: Option<SecretKey>,
    msg: Option<Message>,
    extra_rand: Option<[u8; 32]>,
) -> Result<(MusigSecNonce, MusigPubNonce), MusigNonceGenError> {
    let cx = *secp.ctx();
    let extra_ptr = extra_rand
        .as_ref()
        .map(|e| e.as_ptr())
        .unwrap_or(core::ptr::null());
    let sk_ptr = sec_key
        .as_ref()
        .map(|e| e.as_ptr())
        .unwrap_or(core::ptr::null());
    let msg_ptr = msg
        .as_ref()
        .map(|ref e| e.as_ptr())
        .unwrap_or(core::ptr::null());
    let cache_ptr = key_agg_cache
        .map(|e| e.as_ptr())
        .unwrap_or(core::ptr::null());
    unsafe {
        let mut sec_nonce = MusigSecNonce(ffi::MusigSecNonce::new());
        let mut pub_nonce = MusigPubNonce(ffi::MusigPubNonce::new());
        if ffi::secp256k1_musig_nonce_gen(
            cx,
            sec_nonce.as_mut_ptr(),
            pub_nonce.as_mut_ptr(),
            (&session_id).as_ref().as_ptr(),
            sk_ptr,
            msg_ptr,
            cache_ptr,
            extra_ptr,
        ) == 0
        {
            // Rust type system guarantees that
            // - input secret key is valid
            // - msg is 32 bytes
            // - Key agg cache is valid
            // - extra input is 32 bytes
            // This can only happen when the session id is all zeros
            Err(MusigNonceGenError::ZeroSession)
        } else {
            Ok((sec_nonce, pub_nonce))
        }
    }
}

/// Opaque data structure that holds a partial MuSig signature.
///
/// Serialized and parsed with [`MusigPartialSignature::serialize`] and
/// [`MusigPartialSignature::from_slice`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigPartialSignature(ffi::MusigPartialSignature);

impl CPtr for MusigPartialSignature {
    type Target = ffi::MusigPartialSignature;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigPartialSignature {
    /// Serialize a MuSigPartialSignature or adaptor signature
    ///
    /// # Returns
    ///
    /// 32-byte array when the signature could be serialized
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigAggNonce, MusigKeyAggCache, MusigSession, XOnlyPublicKey, Secp256k1, SecretKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let mut session_id = [0; 32];
    /// thread_rng().fill_bytes(&mut session_id);
    ///
    /// // Generate the nonce for party with `keypair1`.
    /// let sec_key1 = SecretKey::from_keypair(&keypair1);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id, sec_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    ///  // Generate the nonce for party with `keypair2`.
    /// let sec_key2 = SecretKey::from_keypair(&keypair2);
    /// let (_sec_nonce, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id, sec_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    ///     None,
    /// );
    ///
    /// let partial_sig = session.partial_sign(
    ///     &secp,
    ///     &mut sec_nonce1,
    ///     &keypair1,
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// let _ser_sig = partial_sig.serialize();
    /// # }
    /// ```
    pub fn serialize(&self) -> [u8; 32] {
        let mut data = [0; 32];
        unsafe {
            if ffi::secp256k1_musig_partial_sig_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Only fails if args are null pointer which is possible in safe rust
                unreachable!("Serialization cannot fail")
            } else {
                data
            }
        }
    }

    /// Deserialize a MusigPartialSignature from bytes.
    ///
    /// # Errors:
    ///
    /// - ArgLenMismatch: If the signature is not 32 bytes
    /// - MalformedArg: If the signature is 32 bytes, but out of curve order
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{
    /// #   Message, MusigAggNonce, MusigPartialSignature, MusigKeyAggCache, MusigSession, Secp256k1, SecretKey, XOnlyPublicKey, KeyPair
    /// # };
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let mut session_id = [0; 32];
    /// thread_rng().fill_bytes(&mut session_id);
    ///
    /// // Generate the nonce for party with `keypair1`.
    /// let sec_key1 = SecretKey::from_keypair(&keypair1);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id, sec_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    ///  // Generate the nonce for party with `keypair2`.
    /// let sec_key2 = SecretKey::from_keypair(&keypair2);
    /// let (_sec_nonce, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id, sec_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    ///     None,
    /// );
    ///
    /// let partial_sig = session.partial_sign(
    ///     &secp,
    ///     &mut sec_nonce1,
    ///     &keypair1,
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// let ser_sig = partial_sig.serialize();
    /// let _parsed_sig = MusigPartialSignature::from_slice(&ser_sig).unwrap();
    /// # }
    /// ```
    pub fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        let mut part_sig = MusigPartialSignature(ffi::MusigPartialSignature::new());
        if data.len() != 32 {
            return Err(ParseError::ArgLenMismatch {
                expected: 32,
                got: data.len(),
            });
        }
        unsafe {
            if ffi::secp256k1_musig_partial_sig_parse(
                ffi::secp256k1_context_no_precomp,
                part_sig.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(ParseError::MalformedArg)
            } else {
                Ok(part_sig)
            }
        }
    }

    /// Get a const pointer to the inner MusigPartialSignature
    pub fn as_ptr(&self) -> *const ffi::MusigPartialSignature {
        &self.0
    }

    /// Get a mut pointer to the inner MusigPartialSignature
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigPartialSignature {
        &mut self.0
    }
}

/// Musig partial signature parsing errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum ParseError {
    /// Length mismatch
    ArgLenMismatch {
        /// Expected size.
        expected: usize,
        /// Actual size.
        got: usize,
    },
    /// Parse Argument is malformed. This might occur if the point is on the secp order,
    /// or if the secp scalar is outside of group order
    MalformedArg,
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            ParseError::ArgLenMismatch { expected, got } => {
                write!(f, "Argument must be {} bytes, got {}", expected, got)
            }
            ParseError::MalformedArg => write!(f, "Malformed parse argument"),
        }
    }
}

/// Creates a signature from a pre-signature(not to be confused with [`MusigPartialSignature`])
/// and an adaptor.
///
/// # Arguments:
///
/// * `pre_sig` : [`schnorr::Signature`] to which the adaptor is to be added
/// * `sec_adaptor` : Secret adaptor of [`Tweak`] type to add to pre signature
/// * `nonce_parity`: The [`Parity`] obtained by [`MusigSession::nonce_parity`] for the session
/// used to compute `pre_sig`.
///
/// # Returns:
///
/// The [`schnorr::Signature`] with the adaptor applied.
///
/// Example:
///
/// ```rust
/// # # [cfg(any(test, feature = "rand-std"))] {
/// # use secp256k1_zkp::rand::{thread_rng, RngCore};
/// # use secp256k1_zkp::{adapt, schnorr, Tweak, Message, MusigAggNonce, MusigKeyAggCache, MusigSession, XOnlyPublicKey, Secp256k1, SecretKey, PublicKey, KeyPair};
/// let secp = Secp256k1::new();
/// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
/// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
/// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
/// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
///
/// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
/// let agg_pk = key_agg_cache.agg_pk();
/// // The session id must be sampled at random. Read documentation for more details.
/// let mut session_id = [0; 32];
/// thread_rng().fill_bytes(&mut session_id);
///
/// // Generate the nonce for party with `keypair1`.
/// let sec_key1 = SecretKey::from_keypair(&keypair1);
/// let msg = Message::from_slice(&[3; 32]).unwrap();
/// let mut extra_rand = [0u8; 32];
/// thread_rng().fill_bytes(&mut extra_rand);
/// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id, sec_key1, msg, None)
///     .expect("non zero session id");
///
///  // Generate the nonce for party with `keypair2`.
/// let sec_key2 = SecretKey::from_keypair(&keypair2);
/// let mut extra_rand = [0u8; 32];
/// thread_rng().fill_bytes(&mut extra_rand);
/// let (mut sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id, sec_key2, msg, None)
///     .expect("non zero session id");
///
/// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
///
/// // Tweak with a secret adaptor
/// let mut adapt_bytes = [0; 32];
/// thread_rng().fill_bytes(&mut adapt_bytes);
/// let adapt_sec = SecretKey::from_slice(&adapt_bytes).unwrap();
/// let adapt_pub = PublicKey::from_secret_key(&secp, &adapt_sec);
/// let adapt_sec = Tweak::from_slice(adapt_sec.as_ref()).unwrap();
///
/// let session = MusigSession::new(
///     &secp,
///     &key_agg_cache,
///     aggnonce,
///     msg,
///     Some(adapt_pub), // adaptor here
/// );
///
/// let partial_sig1 = session.partial_sign(
///     &secp,
///     &mut sec_nonce1,
///     &keypair1,
///     &key_agg_cache,
/// ).unwrap();
///
/// // Other party creates the other partial signature
/// let partial_sig2 = session.partial_sign(
///     &secp,
///     &mut sec_nonce2,
///     &keypair2,
///     &key_agg_cache,
/// ).unwrap();
///
/// let nonce_parity = session.nonce_parity();
/// let pre_sig = session.partial_sig_agg(&[partial_sig1, partial_sig2]);
///
/// // Note that without the adaptor, the aggregated signature will fail verification
///
/// assert!(secp.verify_schnorr(&pre_sig, &msg, &agg_pk).is_err());
/// // Get the final schnorr signature
/// let schnorr_sig = adapt(pre_sig, adapt_sec, nonce_parity);
/// assert!(secp.verify_schnorr(&schnorr_sig, &msg, &agg_pk).is_ok());
/// # }
/// ```
pub fn adapt(
    pre_sig: schnorr::Signature,
    sec_adaptor: Tweak,
    nonce_parity: Parity,
) -> schnorr::Signature {
    unsafe {
        let mut sig = pre_sig;
        if ffi::secp256k1_musig_adapt(
            ffi::secp256k1_context_no_precomp,
            sig.as_mut_ptr(),
            pre_sig.as_ptr(),
            sec_adaptor.as_ptr(),
            nonce_parity.to_i32(),
        ) == 0
        {
            // Only fails when the arguments are invalid which is not possible in safe rust
            unreachable!("Arguments must be valid and well-typed")
        } else {
            schnorr::Signature::from_slice(sig.as_ref())
                .expect("Adapted signatures from pre-sig must be valid schnorr signatures")
        }
    }
}

/// Extracts a secret adaptor from a MuSig, given all parties' partial
/// signatures. This function will not fail unless given grossly invalid data; if it
/// is merely given signatures that do not verify, the returned value will be
/// nonsense. It is therefore important that all data be verified at earlier steps of
/// any protocol that uses this function.
///
/// # Arguments:
///
/// * `sig`: the [`schnorr::Signature`] with the adaptor applied.
/// * `pre_sig` : Secret adaptor of [`SecretKey`] type to add to pre signature
/// corresponding to `sig`. This is the aggregation of all [`MusigPartialSignature`] without
/// the adaptor
/// * `nonce_parity`: The [`Parity`] obtained by [`MusigSession::nonce_parity`] for the session
/// used to compute `pre_sig64`.
///
/// # Returns:
///
/// The adaptor secret of [`Tweak`]. The [`Tweak`] type is like [`SecretKey`], but also
/// allows for representing the zero value.
///
/// Example:
///
/// ```rust
/// # # [cfg(any(test, feature = "rand-std"))] {
/// # use secp256k1_zkp::rand::{thread_rng, RngCore};
/// # use secp256k1_zkp::{adapt, extract_adaptor};
/// # use secp256k1_zkp::{Message, KeyPair, PublicKey, MusigAggNonce, MusigKeyAggCache, MusigSession, XOnlyPublicKey, Secp256k1, SecretKey, Tweak};
/// let secp = Secp256k1::new();
/// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
/// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
/// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
/// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
///
/// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
/// // The session id must be sampled at random. Read documentation for more details.
/// let mut session_id = [0; 32];
/// thread_rng().fill_bytes(&mut session_id);
///
/// // Generate the nonce for party with `keypair1`.
/// let sec_key1 = SecretKey::from_keypair(&keypair1);
/// let msg = Message::from_slice(&[3; 32]).unwrap();
/// let mut extra_rand = [0u8; 32];
/// thread_rng().fill_bytes(&mut extra_rand);
/// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id, sec_key1, msg, None)
///     .expect("non zero session id");
///
///  // Generate the nonce for party with `keypair2`.
/// let sec_key2 = SecretKey::from_keypair(&keypair2);
/// let mut extra_rand = [0u8; 32];
/// thread_rng().fill_bytes(&mut extra_rand);
/// let (mut sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id, sec_key2, msg, None)
///     .expect("non zero session id");
///
/// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
///
/// // Tweak with a secret adaptor
/// let mut adapt_bytes = [0; 32];
/// thread_rng().fill_bytes(&mut adapt_bytes);
/// let adapt_sec = SecretKey::from_slice(&adapt_bytes).unwrap();
/// let adapt_pub = PublicKey::from_secret_key(&secp, &adapt_sec);
/// let adapt_sec = Tweak::from_slice(adapt_sec.as_ref()).unwrap();
///
/// let session = MusigSession::new(
///     &secp,
///     &key_agg_cache,
///     aggnonce,
///     msg,
///     Some(adapt_pub), // adaptor here
/// );
///
/// let partial_sig1 = session.partial_sign(
///     &secp,
///     &mut sec_nonce1,
///     &keypair1,
///     &key_agg_cache,
/// ).unwrap();
///
/// // Other party creates the other partial signature
/// let partial_sig2 = session.partial_sign(
///     &secp,
///     &mut sec_nonce2,
///     &keypair2,
///     &key_agg_cache,
/// ).unwrap();
///
/// let nonce_parity = session.nonce_parity();
/// let pre_sig = session.partial_sig_agg(&[partial_sig1, partial_sig2]);
///
/// let schnorr_sig = adapt(pre_sig, adapt_sec, nonce_parity);
/// let extracted_sec = extract_adaptor(
///     schnorr_sig,
///     pre_sig,
///     nonce_parity,
/// );
/// assert_eq!(extracted_sec, adapt_sec);
/// # }
/// ```
pub fn extract_adaptor(
    sig: schnorr::Signature,
    pre_sig: schnorr::Signature,
    nonce_parity: Parity,
) -> Tweak {
    unsafe {
        let mut secret = ZERO_TWEAK;
        if ffi::secp256k1_musig_extract_adaptor(
            ffi::secp256k1_context_no_precomp,
            secret.as_mut_ptr(),
            sig.as_ptr(),
            pre_sig.as_ptr(),
            nonce_parity.to_i32(),
        ) == 0
        {
            // Only fails when the arguments are invalid which is not possible in safe rust
            unreachable!("Arguments must be valid and well-typed")
        } else {
            secret
        }
    }
}

/// This structure MUST NOT be copied or
/// read or written to it directly. A signer who is online throughout the whole
/// process and can keep this structure in memory can use the provided API
/// functions for a safe standard workflow. See
/// https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/ for
/// more details about the risks associated with serializing or deserializing
/// this structure. There are no serialization and parsing functions (yet).
///
/// Note this deliberately does not implement `Copy` or `Clone`. After creation, the only
/// use of this nonce is [`MusigSession::partial_sign`] API that takes a mutable reference
/// and overwrites this nonce with zero.
///
/// A signer who is online throughout the whole process and can keep this
/// structure in memory can use the provided API functions for a safe standard
/// workflow. See
/// https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/ for
/// more details about the risks associated with serializing or deserializing
/// this structure.
///
/// Signers that pre-computes and saves these nonces are not yet supported. Users
/// who want to serialize this must use unsafe rust to do so.
#[derive(Debug, Eq, PartialEq)]
pub struct MusigSecNonce(ffi::MusigSecNonce);

impl CPtr for MusigSecNonce {
    type Target = ffi::MusigSecNonce;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigSecNonce {
    /// Get a const pointer to the inner MusigKeyAggCache
    pub fn as_ptr(&self) -> *const ffi::MusigSecNonce {
        &self.0
    }

    /// Get a mut pointer to the inner MusigKeyAggCache
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigSecNonce {
        &mut self.0
    }
}

/// Opaque data structure that holds a MuSig public nonce.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigPubNonce(ffi::MusigPubNonce);

impl CPtr for MusigPubNonce {
    type Target = ffi::MusigPubNonce;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigPubNonce {
    /// Serialize a MusigPubNonce
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigKeyAggCache, MusigPubNonce, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = XOnlyPublicKey::from_keypair(&keypair);
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key]);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let session_id = [2; 32];
    /// let (mut secnonce, pubnonce) = key_agg_cache.nonce_gen(&secp, session_id, sec_key, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let _pubnonce_ser = pubnonce.serialize();
    /// # }
    /// ```
    pub fn serialize(&self) -> [u8; ffi::MUSIG_PUBNONCE_LEN] {
        let mut data = [0; ffi::MUSIG_PUBNONCE_LEN];
        unsafe {
            if ffi::secp256k1_musig_pubnonce_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Only fails when the arguments are invalid which is not possible in safe rust
                unreachable!("Arguments must be valid and well-typed")
            } else {
                data
            }
        }
    }

    /// Deserialize a MusigPubNonce from a portable byte representation
    ///
    /// # Errors:
    ///
    /// - ArgLenMismatch: If the [`MusigPubNonce`] is not 132 bytes
    /// - MalformedArg: If the [`MusigPubNonce`] is 132 bytes, but out of curve order
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigKeyAggCache, MusigPubNonce, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = XOnlyPublicKey::from_keypair(&keypair);
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key]);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let session_id = [2; 32];
    /// let (mut secnonce, pubnonce) = key_agg_cache.nonce_gen(&secp, session_id, sec_key, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let pubnonce_ser = pubnonce.serialize();
    /// let parsed_pubnonce = MusigPubNonce::from_slice(&pubnonce_ser).unwrap();
    /// assert_eq!(parsed_pubnonce, pubnonce);
    /// # }
    /// ```
    pub fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        let mut pubnonce = MusigPubNonce(ffi::MusigPubNonce::new());
        if data.len() != ffi::MUSIG_PUBNONCE_LEN {
            return Err(ParseError::ArgLenMismatch {
                expected: ffi::MUSIG_PUBNONCE_LEN,
                got: data.len(),
            });
        }
        unsafe {
            if ffi::secp256k1_musig_pubnonce_parse(
                ffi::secp256k1_context_no_precomp,
                pubnonce.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(ParseError::MalformedArg)
            } else {
                Ok(pubnonce)
            }
        }
    }

    /// Get a const pointer to the inner MusigPubNonce
    pub fn as_ptr(&self) -> *const ffi::MusigPubNonce {
        &self.0
    }

    /// Get a mut pointer to the inner MusigPubNonce
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigPubNonce {
        &mut self.0
    }
}

/// Opaque data structure that holds a MuSig aggregated nonce.
///
/// There are no serialization and parsing functions (yet).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigAggNonce(ffi::MusigAggNonce);

impl CPtr for MusigAggNonce {
    type Target = ffi::MusigAggNonce;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigAggNonce {
    /// Combine received public nonces into a single aggregated nonce
    ///
    /// This is useful to reduce the communication between signers, because instead
    /// of everyone sending nonces to everyone else, there can be one party
    /// receiving all nonces, combining the nonces with this function and then
    /// sending only the combined nonce back to the signers. The pubnonces argument
    /// of [MusigKeyAggCache::nonce_process] then simply becomes an array whose sole
    /// element is this combined nonce.
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigAggNonce, MusigKeyAggCache, MusigPubNonce, MusigSession, Secp256k1, SecretKey, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let mut session_id = [0; 32];
    /// thread_rng().fill_bytes(&mut session_id);
    ///
    /// // Generate the nonce for party with `keypair1`.
    /// let sec_key1 = SecretKey::from_keypair(&keypair1);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id, sec_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    ///  // Generate the nonce for party with `keypair2`.
    /// let sec_key2 = SecretKey::from_keypair(&keypair2);
    /// let (_sec_nonce, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id, sec_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    /// # }
    /// ```
    pub fn new<C: Signing>(secp: &Secp256k1<C>, nonces: &[MusigPubNonce]) -> Self {
        let mut aggnonce = MusigAggNonce(ffi::MusigAggNonce::new());
        let nonce_ptrs = nonces.iter().map(|n| n.as_ptr()).collect::<Vec<_>>();
        unsafe {
            if ffi::secp256k1_musig_nonce_agg(
                *secp.ctx(),
                aggnonce.as_mut_ptr(),
                nonce_ptrs.as_ptr(),
                nonce_ptrs.len(),
            ) == 0
            {
                // This can only crash if the individual nonces are invalid which is not possible is rust.
                // Note that even if aggregate nonce is point at infinity, the musig spec sets it as `G`
                unreachable!("Public key nonces are well-formed and valid in rust typesystem")
            } else {
                aggnonce
            }
        }
    }

    /// Serialize a MusigAggNonce
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigAggNonce, MusigKeyAggCache, MusigPubNonce, MusigSession, Secp256k1, SecretKey, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = XOnlyPublicKey::from_keypair(&keypair);
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key]);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    ///
    /// let session_id = [2; 32];
    /// let (mut secnonce, pubnonce) = key_agg_cache.nonce_gen(&secp, session_id, sec_key, msg, None)
    ///     .expect("non zero session id");
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]);
    ///
    /// let _aggnonce_ser = aggnonce.serialize();
    /// # }
    /// ```
    pub fn serialize(&self) -> [u8; ffi::MUSIG_AGGNONCE_LEN] {
        let mut data = [0; ffi::MUSIG_AGGNONCE_LEN];
        unsafe {
            if ffi::secp256k1_musig_aggnonce_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Only fails when the arguments are invalid which is not possible in safe rust
                unreachable!("Arguments must be valid and well-typed")
            } else {
                data
            }
        }
    }

    /// Deserialize a MusigAggNonce from byte slice
    ///
    /// # Errors:
    ///
    /// - ArgLenMismatch: If the slice is not 132 bytes
    /// - MalformedArg: If the byte slice is 132 bytes, but the [`MusigAggNonce`] is invalid
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigAggNonce, MusigKeyAggCache, Secp256k1, SecretKey, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = XOnlyPublicKey::from_keypair(&keypair);
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key]);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    ///
    /// let session_id = [2; 32];
    /// let (mut secnonce, pubnonce) = key_agg_cache.nonce_gen(&secp, session_id, sec_key, msg, None)
    ///     .expect("non zero session id");
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]);
    ///
    /// let aggnonce_ser = aggnonce.serialize();
    /// let parsed_aggnonce = MusigAggNonce::from_slice(&aggnonce_ser).unwrap();
    /// assert_eq!(parsed_aggnonce, aggnonce);
    /// # }
    /// ```
    pub fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != ffi::MUSIG_AGGNONCE_LEN {
            return Err(ParseError::ArgLenMismatch {
                expected: ffi::MUSIG_AGGNONCE_LEN,
                got: data.len(),
            });
        }
        let mut aggnonce = MusigAggNonce(ffi::MusigAggNonce::new());
        unsafe {
            if ffi::secp256k1_musig_aggnonce_parse(
                ffi::secp256k1_context_no_precomp,
                aggnonce.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(ParseError::MalformedArg)
            } else {
                Ok(aggnonce)
            }
        }
    }

    /// Get a const pointer to the inner MusigAggNonce
    pub fn as_ptr(&self) -> *const ffi::MusigAggNonce {
        &self.0
    }

    /// Get a mut pointer to the inner MusigAggNonce
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigAggNonce {
        &mut self.0
    }
}

/// Musig session data structure containing the
/// secret and public nonce used in a multi-signature signing session
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigSession(ffi::MusigSession);

impl CPtr for MusigSession {
    type Target = ffi::MusigSession;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigSession {
    /// Takes the public nonces of all signers and computes a session that is
    /// required for signing and verification of partial signatures.
    ///
    /// If the adaptor argument is [`Option::Some`], then the output of
    /// partial signature aggregation will be a pre-signature which is not a valid Schnorr
    /// signature. In order to create a valid signature, the pre-signature and the
    /// secret adaptor must be provided to `musig_adapt`.
    ///
    /// # Returns:
    ///
    /// A [`MusigSession`] that can be later used for signing.
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `key_agg_cache`: [`MusigKeyAggCache`] to be used for this session
    /// * `agg_nonce`: [`MusigAggNonce`], the aggregate nonce
    /// * `msg`: [`Message`] that will be signed later on.
    /// * `adaptor`: The adaptor of type [`PublicKey`] if this is signing session is a part of
    /// an adaptor signature protocol.
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigAggNonce, MusigKeyAggCache, MusigSession, XOnlyPublicKey, Secp256k1, SecretKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// let agg_pk = key_agg_cache.agg_pk();
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let mut session_id = [0; 32];
    /// thread_rng().fill_bytes(&mut session_id);
    ///
    /// // Generate the nonce for party with `keypair1`.
    /// let sec_key1 = SecretKey::from_keypair(&keypair1);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id, sec_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    ///  // Generate the nonce for party with `keypair2`.
    /// let sec_key2 = SecretKey::from_keypair(&keypair2);
    /// let (mut sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id, sec_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    ///     None, // adaptor here
    /// );
    /// # }
    /// ```
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        key_agg_cache: &MusigKeyAggCache,
        agg_nonce: MusigAggNonce,
        msg: Message,
        adaptor: Option<PublicKey>,
    ) -> Self {
        let mut session = MusigSession(ffi::MusigSession::new());
        let adaptor_ptr = match adaptor {
            Some(a) => a.as_ptr(),
            None => core::ptr::null(),
        };
        unsafe {
            if ffi::secp256k1_musig_nonce_process(
                *secp.ctx(),
                session.as_mut_ptr(),
                agg_nonce.as_ptr(),
                msg.as_ptr(),
                key_agg_cache.as_ptr(),
                adaptor_ptr,
            ) == 0
            {
                // Only fails on cryptographically unreachable codes or if the args are invalid.
                // None of which can occur in safe rust.
                unreachable!("Impossible to construct invalid arguments in safe rust.
                    Also reaches here if R1 + R2*b == point at infinity, but only occurs with 1/1^128 probability")
            } else {
                session
            }
        }
    }

    /// Produces a partial signature for a given key pair and secret nonce.
    ///
    /// Remember that nonce reuse will immediately leak the secret key!
    ///
    /// # Returns:
    ///
    /// A [`MusigPartialSignature`] that can be later be aggregated into a [`schnorr::Signature`]
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `sec_nonce`: [`MusigSecNonce`] to be used for this session that has never
    /// been used before. For mis-use resistance, this API takes a mutable reference
    /// to `sec_nonce` and sets it to zero even if the partial signing fails.
    /// * `key_pair`: The [`KeyPair`] to sign the message
    /// * `key_agg_cache`: [`MusigKeyAggCache`] containing the aggregate pubkey used in
    /// the creation of this session
    ///
    /// # Errors:
    ///
    /// - If the provided [`MusigSecNonce`] has already been used for signing
    ///
    /// # Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigAggNonce, MusigKeyAggCache, MusigSession, Secp256k1, SecretKey, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let mut session_id = [0; 32];
    /// thread_rng().fill_bytes(&mut session_id);
    ///
    /// // Generate the nonce for party with `keypair1`.
    /// let sec_key1 = SecretKey::from_keypair(&keypair1);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id, sec_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    ///  // Generate the nonce for party with `keypair2`.
    /// let sec_key2 = SecretKey::from_keypair(&keypair2);
    /// let (mut sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id, sec_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    ///     None, // adaptor here
    /// );
    ///
    /// let _partial_sig = session.partial_sign(
    ///     &secp,
    ///     &mut sec_nonce1,
    ///     &keypair1,
    ///     &key_agg_cache,
    /// ).unwrap();
    /// # }
    /// ```
    pub fn partial_sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        secnonce: &mut MusigSecNonce,
        keypair: &KeyPair,
        key_agg_cache: &MusigKeyAggCache,
    ) -> Result<MusigPartialSignature, MusigSignError> {
        unsafe {
            let mut partial_sig = MusigPartialSignature(ffi::MusigPartialSignature::new());
            if ffi::secp256k1_musig_partial_sign(
                *secp.ctx(),
                partial_sig.as_mut_ptr(),
                secnonce.as_mut_ptr(),
                keypair.as_ptr(),
                key_agg_cache.as_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Since the arguments in rust are always session_valid, the only reason
                // this will fail if the nonce was reused.
                Err(MusigSignError::NonceReuse)
            } else {
                Ok(partial_sig)
            }
        }
    }

    /// Checks that an individual partial signature verifies
    ///
    /// This function is essential when using protocols with adaptor signatures.
    /// However, it is not essential for regular MuSig's, in the sense that if any
    /// partial signatures does not verify, the full signature will also not verify, so the
    /// problem will be caught. But this function allows determining the specific party
    /// who produced an invalid signature, so that signing can be restarted without them.
    ///
    /// # Returns:
    ///
    /// true if the partial signature successfully verifies, otherwise returns false
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `key_agg_cache`: [`MusigKeyAggCache`] containing the aggregate pubkey used in
    /// the creation of this session
    /// * `partial_sig`: [`MusigPartialSignature`] sent by the signer associated with
    /// the given `pub_nonce` and `pubkey`
    /// * `pub_nonce`: The [`MusigPubNonce`] of the signer associated with the `partial_sig`
    /// and `pub_key`
    /// * `pub_key`: The [`XOnlyPublicKey`] of the signer associated with the given
    /// `partial_sig` and `pub_nonce`
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigAggNonce, MusigKeyAggCache, MusigSession, Secp256k1, SecretKey, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let mut session_id = [0; 32];
    /// thread_rng().fill_bytes(&mut session_id);
    ///
    /// // Generate the nonce for party with `keypair1`.
    /// let sec_key1 = SecretKey::from_keypair(&keypair1);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id, sec_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    ///  // Generate the nonce for party with `keypair2`.
    /// let sec_key2 = SecretKey::from_keypair(&keypair2);
    /// let (mut sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id, sec_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    ///     None, // adaptor here
    /// );
    ///
    /// let partial_sig1 = session.partial_sign(
    ///     &secp,
    ///     &mut sec_nonce1,
    ///     &keypair1,
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// assert!(session.partial_verify(
    ///     &secp,
    ///     &key_agg_cache,
    ///     partial_sig1,
    ///     pub_nonce1,
    ///     pub_key1,
    /// ));
    /// # }
    /// ```
    pub fn partial_verify<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        key_agg_cache: &MusigKeyAggCache,
        partial_sig: MusigPartialSignature,
        pub_nonce: MusigPubNonce,
        pub_key: XOnlyPublicKey,
    ) -> bool {
        let cx = *secp.ctx();
        unsafe {
            ffi::secp256k1_musig_partial_sig_verify(
                cx,
                partial_sig.as_ptr(),
                pub_nonce.as_ptr(),
                pub_key.as_ptr(),
                key_agg_cache.as_ptr(),
                self.as_ptr(),
            ) == 1
        }
    }

    /// Aggregate partial signatures for this session into a single [`schnorr::Signature`]
    ///
    /// # Returns:
    ///
    /// A single [`schnorr::Signature`]. Note that this does *NOT* mean that the signature verifies with respect to the
    /// aggregate public key.
    ///
    /// # Arguments:
    ///
    /// * `partial_sigs`: Array of [`MusigPartialSignature`] to be aggregated
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigAggNonce, MusigKeyAggCache, MusigSession, Secp256k1, SecretKey, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let keypair1 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key1 = XOnlyPublicKey::from_keypair(&keypair1);
    /// let keypair2 = KeyPair::new(&secp, &mut thread_rng());
    /// let pub_key2 = XOnlyPublicKey::from_keypair(&keypair2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// let agg_pk = key_agg_cache.agg_pk();
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let mut session_id = [0; 32];
    /// thread_rng().fill_bytes(&mut session_id);
    ///
    /// // Generate the nonce for party with `keypair1`.
    /// let sec_key1 = SecretKey::from_keypair(&keypair1);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id, sec_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    ///  // Generate the nonce for party with `keypair2`.
    /// let sec_key2 = SecretKey::from_keypair(&keypair2);
    /// let (mut sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id, sec_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    ///
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    ///     None,
    /// );
    ///
    /// let partial_sig1 = session.partial_sign(
    ///     &secp,
    ///     &mut sec_nonce1,
    ///     &keypair1,
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// // Other party creates the other partial signature
    /// let partial_sig2 = session.partial_sign(
    ///     &secp,
    ///     &mut sec_nonce2,
    ///     &keypair2,
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// let nonce_parity = session.nonce_parity();
    /// let schnorr_sig = session.partial_sig_agg(&[partial_sig1, partial_sig2]);
    ///
    /// // Get the final schnorr signature
    /// assert!(secp.verify_schnorr(&schnorr_sig, &msg, &agg_pk).is_ok())
    /// # }
    /// ```
    pub fn partial_sig_agg(&self, partial_sigs: &[MusigPartialSignature]) -> schnorr::Signature {
        let part_sigs = partial_sigs.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
        let mut sig = [0u8; 64];
        unsafe {
            if ffi::secp256k1_musig_partial_sig_agg(
                ffi::secp256k1_context_no_precomp,
                sig.as_mut_ptr(),
                self.as_ptr(),
                part_sigs.as_ptr(),
                part_sigs.len(),
            ) == 0
            {
                // All arguments are well-typed partial signatures
                unreachable!("Impossible to construct invalid(not well-typed) partial signatures")
            } else {
                // Resulting signature must be well-typed. Does not mean that will be succeed verification
                schnorr::Signature::from_slice(&sig)
                    .expect("Resulting signature must be well-typed")
            }
        }
    }

    /// Extracts the nonce_parity bit from a session
    ///
    /// This is used for adaptor signatures
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{Message, KeyPair, MusigAggNonce, MusigKeyAggCache, MusigSession, Secp256k1, SecretKey, XOnlyPublicKey};
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = XOnlyPublicKey::from_keypair(&keypair);
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key]);
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let session_id = [1; 32];
    /// let (mut secnonce, pubnonce) = key_agg_cache.nonce_gen(&secp, session_id, sec_key, msg, None)
    ///     .expect("non zero session id");
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]);
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    ///     None,
    /// );
    ///
    /// let _parity = session.nonce_parity();
    /// # }
    /// ```
    pub fn nonce_parity(&self) -> Parity {
        let mut parity = 0i32;
        unsafe {
            if ffi::secp256k1_musig_nonce_parity(
                ffi::secp256k1_context_no_precomp,
                &mut parity,
                self.as_ptr(),
            ) == 0
            {
                unreachable!("Well-typed and valid arguments to the function")
            } else {
                Parity::from_i32(parity).expect("Parity guaranteed to be binary")
            }
        }
    }

    /// Get a const pointer to the inner MusigSession
    pub fn as_ptr(&self) -> *const ffi::MusigSession {
        &self.0
    }

    /// Get a mut pointer to the inner MusigSession
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigSession {
        &mut self.0
    }
}

/// Musig tweaking related errors.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum MusigSignError {
    /// Musig nonce re-used.
    /// When creating a partial signature, nonce is cleared and set to all zeros.
    /// This error is caused when we create a partial signature with zero nonce.
    // Note: Because of the current borrowing rules around nonce, this should be impossible.
    // Maybe, we can just unwrap this and not have error at all?
    NonceReuse,
}

#[cfg(feature = "std")]
impl std::error::Error for MusigSignError {}

impl fmt::Display for MusigSignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            MusigSignError::NonceReuse => write!(f, "Musig signing nonce re-used"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate serde_json;

    use self::serde_json::Value;
    use crate::from_hex;
    use rand::{thread_rng, RngCore};

    use secp256k1::schnorr::Signature;
    use {KeyPair, XOnlyPublicKey};

    use core::str::FromStr;
    use std::fs::File;
    use std::io::prelude::*;
    use std::path::Path;

    // Notice 1
    //
    // The current secp256k1-zkp implementaion from Elements Project does not
    // support variable length messages as described in issue #155 (see below).
    // Therefore, this test suite will include, for the time being, a filter_155
    // variable which will indicate whether to skip tests that include messages
    // whose length does not equal 32 bytes.
    //
    // https://github.com/ElementsProject/secp256k1-zkp/issues/155

    // Notice 2
    //
    // The current secp256k1-zkp implementaion from Elements Project does not
    // support handling nonce generation in a manner conformant with the current
    // spec. Therefore, nonce aggregation tests will need to be ignored for now.
    // See the tracking issue below.
    //
    // https://github.com/ElementsProject/secp256k1-zkp/pull/192

    // Notice 3
    //
    // This library currently uses G in place of 0 (zero). This has implications
    // for, among other things, nonce aggregation. This test suite features
    // various contortions to make up for this including: swapping out 0 and G
    // when necessary and swapping out the expected signature with a different
    // signature in sign_verify_vectors.json.

    fn swap_out_g(input: &str) -> String {
        // This musig implementation uses g for zero. So, we need to back out
        // instances of g from our results and replace them with zero when
        // necessary.
        input.replace(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "000000000000000000000000000000000000000000000000000000000000000000",
        )
    }

    fn swap_in_g(input: &str) -> String {
        input.replace(
            "000000000000000000000000000000000000000000000000000000000000000000",
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        )
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut result = String::from("");
        for (i, elem) in bytes.iter().enumerate() {
            let foo = format!("{:02X}", elem);
            result.push_str(&foo);
        }
        result
    }

    fn open_json(name: &str) -> Value {
        let path = Path::new("src").join("zkp").join("test_vectors");
        let path = path.join(name);

        let display = path.display();

        let mut file = match File::open(&path) {
            Err(why) => panic!("couldn't open {}: {}", display, why),
            Ok(file) => file,
        };

        let mut s = String::new();
        file.read_to_string(&mut s).unwrap();

        serde_json::from_str(s.as_str()).unwrap()
    }

    fn from_hex_32(hex: &str) -> Result<[u8; 32], ()> {
        let mut buf = [0u8; 32];
        from_hex(hex, &mut buf)?;
        Ok(buf)
    }

    fn from_hex_132(hex: &str) -> Result<[u8; 132], ()> {
        let mut buf = [0u8; 132];
        from_hex(hex, &mut buf)?;
        Ok(buf)
    }

    fn from_hex_all_32(list: Vec<&str>) -> Result<Vec<[u8; 32]>, ()> {
        let mut result = vec![];
        for entry in list.iter() {
            let entry = from_hex_32(entry)?;
            result.push(entry);
        }
        Ok(result)
    }

    fn from_hex_all_132(list: Vec<&str>) -> Result<Vec<[u8; 132]>, ()> {
        let mut result = vec![];
        for entry in list.iter() {
            let entry = from_hex_132(entry)?;
            result.push(entry);
        }
        Ok(result)
    }

    fn bytes_to_pubkeys(
        list: Vec<[u8; 32]>,
    ) -> Result<Vec<XOnlyPublicKey>, Box<dyn std::error::Error>> {
        let mut result = vec![];
        for entry in list.iter() {
            let pk = XOnlyPublicKey::from_slice(entry)?;
            result.push(pk)
        }
        Ok(result)
    }

    #[test]
    fn test_key_agg_vectors() {
        let secp = Secp256k1::new();

        let test_data = open_json("key_agg_vectors.json");
        let test_elements = test_data.as_object().unwrap();

        let mut x: Vec<[u8; 32]> = vec![];
        let mut t: Vec<[u8; 32]> = vec![];
        let mut valid_test_cases: Vec<Value> = vec![];
        let mut error_test_cases = vec![];

        // Unpack and exhaust the json test file.
        for (elem, value) in test_elements.iter() {
            match elem.as_str() {
                "pubkeys" => {
                    let pubkeys: Vec<&str> = value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                    x = from_hex_all_32(pubkeys).unwrap();
                }
                "tweaks" => {
                    let tweaks: Vec<&str> = value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                    t = from_hex_all_32(tweaks).unwrap();
                }
                "valid_test_cases" => {
                    valid_test_cases = value.as_array().unwrap().to_vec();
                }
                "error_test_cases" => error_test_cases = value.as_array().unwrap().to_vec(),
                unexpected => {
                    panic!("Encountered unexpected test element: {}", unexpected)
                }
            }
        }

        for test_case in valid_test_cases.iter() {
            let key_indices = test_case["key_indices"].as_array().unwrap();
            let mut pub_keys: Vec<XOnlyPublicKey> = vec![];
            for key_index in key_indices {
                let index = key_index.as_u64().unwrap() as usize;
                let key = x[index];
                let key = XOnlyPublicKey::from_slice(&key).unwrap();
                pub_keys.push(key);
            }

            let cache = MusigKeyAggCache::new(&secp, &pub_keys);
            let agg_pk = cache.agg_pk();

            let expected = test_case["expected"].as_str().unwrap();
            let expected = XOnlyPublicKey::from_str(expected).unwrap();

            assert_eq!(agg_pk, expected);
        }

        for test_case in error_test_cases.iter() {
            let error_type = test_case["error"]["type"].as_str().unwrap();
            match error_type {
                "invalid_contribution" => {
                    let key_indices = test_case["key_indices"].as_array().unwrap();
                    let bad_signer = test_case["error"]["signer"].as_u64().unwrap() as usize;
                    for (signer, key) in key_indices.iter().enumerate() {
                        let index = key.as_u64().unwrap() as usize;
                        let key = x[index];
                        let result = XOnlyPublicKey::from_slice(&key);
                        match result {
                            Ok(_) => {
                                assert_ne!(signer, bad_signer);
                            }
                            Err(err) => {
                                assert_eq!(signer, bad_signer);
                                assert_eq!(format!("{:?}", err), "InvalidPublicKey".to_string());
                            }
                        }
                    }
                }
                "value" => {
                    let key_indices = test_case["key_indices"].as_array().unwrap();
                    let mut pub_keys: Vec<XOnlyPublicKey> = vec![];
                    for key_index in key_indices {
                        let index = key_index.as_u64().unwrap() as usize;
                        let key = x[index];
                        let key = XOnlyPublicKey::from_slice(&key).unwrap();
                        pub_keys.push(key);
                    }

                    let mut cache = MusigKeyAggCache::new(&secp, &pub_keys);

                    let is_xonly = test_case["is_xonly"].as_array().unwrap()[0]
                        .as_bool()
                        .unwrap();

                    let tweak_indices = test_case["tweak_indices"].as_array().unwrap();
                    let tweak_index = tweak_indices[0].as_u64().unwrap() as usize;
                    let tweak = t[tweak_index];
                    let tweak = SecretKey::from_slice(&tweak);
                    match tweak {
                        Ok(tweak) => {
                            let tweak_error = if is_xonly {
                                cache.pubkey_xonly_tweak_add(&secp, tweak).err().unwrap()
                            } else {
                                cache.pubkey_ec_tweak_add(&secp, tweak).err().unwrap()
                            };
                            assert_eq!(format!("{:?}", tweak_error), "InvalidTweak".to_string());
                        }
                        Err(err) => {
                            assert_eq!(format!("{:?}", err), "InvalidSecretKey".to_string());
                        }
                    }
                }
                _ => panic!("Invalid error type."),
            }
        }
    }

    #[test]
    fn test_nonce_gen_vectors() {
        // Test fails... Waiting on variable length messages
        // https://github.com/ElementsProject/secp256k1-zkp/issues/155
        //
        // Test fails .. Waiting on musig nonce generation update
        // https://github.com/ElementsProject/secp256k1-zkp/pull/192

        let secp = Secp256k1::new();

        let test_data = open_json("nonce_gen_vectors.json");
        let test_elements = test_data.as_object().unwrap();

        let mut test_cases: Vec<Value> = vec![];

        // Unpack and exhaust the json test file.
        for (elem, value) in test_elements.iter() {
            match elem.as_str() {
                "test_cases" => test_cases = value.as_array().unwrap().to_vec(),
                unexpected => {
                    panic!("Unexpected test element: {}", unexpected)
                }
            }
        }

        for test_case in test_cases {
            let rand_ = test_case["rand_"].as_str();
            let sk = test_case["sk"].as_str();
            let aggpk = test_case["aggpk"].as_str();
            let msg = test_case["msg"].as_str();
            let extra_in = test_case["extra_in"].as_str();
            let expected = test_case["expected"].as_str();

            let rand_ = rand_.unwrap();
            let session_id = from_hex_32(rand_).unwrap();

            let sec_key = if let Some(sk) = sk {
                Some(SecretKey::from_str(sk).unwrap())
            } else {
                None
            };

            let key_agg_cache: MusigKeyAggCache;
            let key_agg_cache = if let Some(aggpk) = aggpk {
                let pk = XOnlyPublicKey::from_str(&aggpk).unwrap();
                key_agg_cache = MusigKeyAggCache::new(&secp, &[pk]);
                Some(&key_agg_cache)
            } else {
                None
            };

            let msg = if let Some(msg) = msg {
                // Parse &str as bytes
                let mut left = char::from_u32(0).unwrap();
                let mut right: char;
                let mut bytes: Vec<u8> = vec![];
                for (i, c) in msg.chars().into_iter().enumerate() {
                    if i % 2 == 0 {
                        left = c;
                    } else {
                        right = c;
                        let byte = format!("{}{}", left, right);
                        let byte = u8::from_str_radix(&byte, 16).unwrap();
                        bytes.push(byte);
                    }
                }
                let msg = Message::from_slice(&bytes).unwrap();
                Some(msg)
            } else {
                None
            };

            let extra_rand = if let Some(extra_rand) = extra_in {
                let extra_rand = from_hex_32(extra_rand).unwrap();
                Some(extra_rand)
            } else {
                None
            };

            let (sn, _) =
                new_musig_nonce_pair(&secp, session_id, key_agg_cache, sec_key, msg, extra_rand)
                    .unwrap();

            // TODO: Turn these into asserts after #155 and #192 get fixed.
            println!("ex: {}", expected.unwrap());
            println!("sn: {}", format!("{:?}", sn.0).to_uppercase());
        }
    }

    #[test]
    fn test_nonce_agg_vectors() {
        let secp = Secp256k1::new();

        let test_data = open_json("nonce_agg_vectors.json");
        let test_elements = test_data.as_object().unwrap();

        let mut pnonces: Vec<&str> = vec![];
        let mut valid_test_cases: Vec<Value> = vec![];
        let mut error_test_cases: Vec<Value> = vec![];

        // Unpack and exhaust the json test file.
        for (elem, value) in test_elements.iter() {
            match elem.as_str() {
                "pnonces" => {
                    pnonces = value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                }
                "valid_test_cases" => {
                    valid_test_cases = value.as_array().unwrap().to_vec();
                }
                "error_test_cases" => {
                    error_test_cases = value.as_array().unwrap().to_vec();
                }
                unexpected => panic!("Unexpected element: {}", unexpected),
            }
        }

        for test_case in valid_test_cases {
            let expected = test_case["expected"].as_str().unwrap();
            let expected = from_hex_132(expected).unwrap();

            let mut nonces: Vec<MusigPubNonce> = vec![];

            let pnonce_indices: Vec<usize> = test_case["pnonce_indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect();

            for index in pnonce_indices {
                let pnonce = from_hex_132(pnonces[index]).unwrap();
                let pnonce = MusigPubNonce::from_slice(&pnonce).unwrap();
                nonces.push(pnonce);
            }

            let result: [u8; 132] = MusigAggNonce::new(&secp, &nonces).serialize();
            let result = &to_hex(&result);
            // we swap out g because a test case with the following comment:
            // "Sum of second points encoded in the nonces is point at infinity
            // which is serialized as 33 zero bytes"
            let result = swap_out_g(result).to_uppercase();

            let mut agg_nonce = [0u8; 132];
            from_hex(&result, &mut agg_nonce).unwrap();

            assert_eq!(agg_nonce, expected);
        }

        for test_case in error_test_cases.iter() {
            let error_type = test_case["error"]["type"].as_str().unwrap();
            match error_type {
                "invalid_contribution" => {
                    let key_indices = test_case["pnonce_indices"].as_array().unwrap();
                    let bad_signer = test_case["error"]["signer"].as_u64().unwrap() as usize;
                    for (signer, key) in key_indices.iter().enumerate() {
                        let index = key.as_u64().unwrap() as usize;
                        let pnonce = from_hex_132(pnonces[index]).unwrap();
                        let result = MusigPubNonce::from_slice(&pnonce);

                        match result {
                            Ok(_) => {
                                assert_ne!(signer, bad_signer);
                            }
                            Err(err) => {
                                assert_eq!(signer, bad_signer);
                                assert_eq!(format!("{:?}", err), "MalformedArg".to_string());
                            }
                        }
                    }
                }
                unexpected => panic!("Unexpected error type: {}", unexpected),
            }
        }
    }

    #[test]
    fn better_test_sign_verify_vectors() {
        let secp = Secp256k1::new();

        let test_data = open_json("sign_verify_vectors.json");
        let test_elements = test_data.as_object().unwrap();

        let mut sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let mut x: Vec<&str> = vec![];
        let mut secnonce = "";
        let mut pnonces: Vec<&str> = vec![];
        let mut aggnonces: Vec<&str> = vec![];
        let mut msgs: Vec<&str> = vec![];
        let mut valid_test_cases: Vec<Value> = vec![];
        let mut sign_error_test_cases: Vec<Value> = vec![];
        let mut verify_fail_test_cases: Vec<Value> = vec![];
        let mut verify_error_test_cases: Vec<Value> = vec![];

        // Unpack and exhaust json test file.
        for (elem, value) in test_elements.iter() {
            match elem.as_str() {
                "sk" => {
                    sk = SecretKey::from_str(value.as_str().unwrap()).unwrap();
                }
                "pubkeys" => {
                    x = value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                }
                "secnonce" => secnonce = value.as_str().unwrap(),
                "pnonces" => {
                    pnonces = value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                }
                "aggnonces" => {
                    aggnonces = value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                }
                "msgs" => {
                    msgs = value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                }
                "valid_test_cases" => valid_test_cases = value.as_array().unwrap().to_vec(),
                "sign_error_test_cases" => {
                    sign_error_test_cases = value.as_array().unwrap().to_vec();
                }
                "verify_fail_test_cases" => {
                    verify_fail_test_cases = value.as_array().unwrap().to_vec();
                }
                "verify_error_test_cases" => {
                    verify_error_test_cases = value.as_array().unwrap().to_vec();
                }
                unexpected => {
                    panic!("Encountered unexpected test element: {}", unexpected);
                }
            }
        }

        // The public key corresponding to sk is at index 0
        let keypair = KeyPair::from_secret_key(&secp, sk);
        assert_eq!(
            keypair.public_key(),
            XOnlyPublicKey::from_str(x[0]).unwrap()
        );

        // The public nonce corresponding to secnonce is at index 0
        let k1 = &secnonce[0..64];
        let k2 = &secnonce[64..];
        let pn1_as_pk = &pnonces[0][2..66];
        let pn2_as_pk = &pnonces[0][66..];
        let kp1 = KeyPair::from_seckey_str(&secp, k1).unwrap();
        let kp2 = KeyPair::from_seckey_str(&secp, k2).unwrap();
        let pk1 = XOnlyPublicKey::from_keypair(&kp1);
        let pk2 = PublicKey::from_keypair(&kp2);
        let pn1_as_pk = XOnlyPublicKey::from_str(pn1_as_pk).unwrap();
        let pn2_as_pk = PublicKey::from_str(pn2_as_pk).unwrap();
        assert_eq!(pk1, pn1_as_pk);
        assert_eq!(pk2, pn2_as_pk);

        // The aggregate of the first three elements of pnonce is at index 0
        let pn0 = MusigPubNonce::from_slice(&from_hex_132(pnonces[0]).unwrap()).unwrap();
        let pn1 = MusigPubNonce::from_slice(&from_hex_132(pnonces[1]).unwrap()).unwrap();
        let pn2 = MusigPubNonce::from_slice(&from_hex_132(pnonces[2]).unwrap()).unwrap();
        let aggnonce = MusigAggNonce::new(&secp, &[pn0, pn1, pn2]);
        let json_aggnonce =
            MusigAggNonce::from_slice(&from_hex_132(aggnonces[0]).unwrap()).unwrap();
        assert_eq!(aggnonce, json_aggnonce);

        for valid_test_case in valid_test_cases.iter() {
            let key_indices = valid_test_case["key_indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect::<Vec<usize>>();
            let nonce_indices = valid_test_case["nonce_indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect::<Vec<usize>>();
            let aggnonce_index = valid_test_case["aggnonce_index"].as_u64().unwrap() as usize;
            let msg_index = valid_test_case["msg_index"].as_u64().unwrap() as usize;
            let signer_index = valid_test_case["signer_index"].as_u64().unwrap() as usize;
            let expected = valid_test_case["expected"].as_str().unwrap();

            let mut pubkeys: Vec<XOnlyPublicKey> = vec![];
            for key_index in key_indices {
                let pk = XOnlyPublicKey::from_str(x[key_index]).unwrap();
                pubkeys.push(pk);
            }

            let key_agg_cache = MusigKeyAggCache::new(&secp, &pubkeys);

            let expected_agg_nonce = aggnonces[aggnonce_index];
            let expected_agg_nonce = swap_in_g(expected_agg_nonce);
            let expected_agg_nonce = from_hex_132(&expected_agg_nonce).unwrap();

            let expected_agg_nonce = MusigAggNonce::from_slice(&expected_agg_nonce).unwrap();

            let mut nonces: Vec<MusigPubNonce> = vec![];
            for nonce_index in nonce_indices {
                let nonce = MusigPubNonce::from_slice(&from_hex_132(pnonces[nonce_index]).unwrap())
                    .unwrap();
                nonces.push(nonce);
            }
            let agg_nonce = MusigAggNonce::new(&secp, &nonces);
            assert_eq!(agg_nonce, expected_agg_nonce);

            let msg = msgs[msg_index];

            let filter_155 = msg.len() == 64;
            if filter_155 {
                let msg = Message::from_slice(&from_hex_32(msg).unwrap()).unwrap();
                let session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);

                // This secnonce is non-standard and invented for this rust test
                // suite. The sign_verify_vectors.json file needed a new secnonce
                // because this rust library will not allow instantiating a secnonce
                // from bytes.
                let secnonce_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key()]);
                let (mut secnonce, _) = secnonce_cache
                    .nonce_gen(&secp, [0u8; 32], sk, msg, None)
                    .unwrap();

                println!("aggnonce: {:?}", aggnonce);

                let result = session
                    .partial_sign(&secp, &mut secnonce, &keypair, &key_agg_cache)
                    .unwrap();

                println!("expected: {:?}", expected);
                let expected =
                    MusigPartialSignature::from_slice(&from_hex_32(expected).unwrap()).unwrap();

                assert_eq!(result, expected);
            }
        }
    }

    #[test]
    fn test_sign_verify_vectors() {
        let secp = Secp256k1::new();

        let x = from_hex_all_32(vec![
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        ])
        .unwrap();
        let x = bytes_to_pubkeys(x).unwrap();

        // The public nonce corresponding to our generated sec_nonce is at index 0
        let pnonce = from_hex_all_132(vec![
            &("03bd300b42bfe2c60db4c1d426bace4f33ab6cf6200b0417c42ee2406a4079302d".to_owned()
                + "02e24782231413acd9c61dfd44a4c8513bec402f5d2e3fe5b8a2155d29ade50b68"),
            &("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".to_owned()
                + "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            &("032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE93".to_owned()
                + "03E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046"),
            &("02bd300b42bfe2c60db4c1d426bace4f33ab6cf6200b0417c42ee2406a4079302d".to_owned()
                + "03e24782231413acd9c61dfd44a4c8513bec402f5d2e3fe5b8a2155d29ade50b68"),
        ])
        .unwrap();
        let pnonce_0 = MusigPubNonce::from_slice(&pnonce[0]).unwrap();
        let pnonce_1 = MusigPubNonce::from_slice(&pnonce[1]).unwrap();
        let pnonce_2 = MusigPubNonce::from_slice(&pnonce[2]).unwrap();
        let pnonce_3 = MusigPubNonce::from_slice(&pnonce[3]).unwrap();

        let expected_agg_nonce = from_hex_all_132(vec![
            &("0301f336146ccd7ef94758595c663c2ce1e1dea257eba8286e252bb505be62da0e".to_owned()
                + "023ae13b74626218863efbf7382822718b5c373712cbe39f1107a9de1c47537e51"),
        ])
        .unwrap();
        let expected_agg_nonce = MusigAggNonce::from_slice(&expected_agg_nonce[0]).unwrap();
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0, pnonce_1, pnonce_2]);
        assert_eq!(agg_nonce, expected_agg_nonce);

        let sec_key = from_hex_all_32(vec![
            "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671",
        ])
        .unwrap();
        let sec_key = SecretKey::from_slice(&sec_key[0]).unwrap();

        let keypair = KeyPair::from_secret_key(&secp, sec_key);

        let msg = from_hex_all_32(vec![
            "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
        ])
        .unwrap();
        let msg = Message::from_slice(&msg[0]).unwrap();

        // Signatures
        let expected = from_hex_all_32(vec![
            "6f5034545e7cf0ae5850247eb92972c2c4bad035e8dcaad73ce99788760323fc",
            "e70863d9f0748822c540da29ccc88951f2d26b591bfe8a17838d5f1dea5a7d2c",
            "bfff7afe818cc37920bb9f140ebb20a5cfebc9bb9bf14bd88f8ccdc3894ccb68",
            "8fd1606427ff7f2db3ddeace01d6bfb84f60d8428f9559ec6ae89ac8368eed53",
        ])
        .unwrap();

        // Vector 1
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key(), x[0], x[1]]);

        let secnonce_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key()]);
        let (mut secnonce, _) = secnonce_cache
            .nonce_gen(&secp, [0u8; 32], sec_key, msg, None)
            .unwrap();

        let session_ctx = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);

        let vector_1_sig = session_ctx
            .partial_sign(&secp, &mut secnonce, &keypair, &key_agg_cache)
            .unwrap()
            .serialize();
        assert_eq!(vector_1_sig, expected[0]);

        // Vector 2
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[x[0], keypair.public_key(), x[1]]);

        let secnonce_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key()]);
        let (mut secnonce, _) = secnonce_cache
            .nonce_gen(&secp, [0u8; 32], sec_key, msg, None)
            .unwrap();

        let session_ctx = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);

        let vector_2_sig = session_ctx
            .partial_sign(&secp, &mut secnonce, &keypair, &key_agg_cache)
            .unwrap()
            .serialize();

        assert_eq!(vector_2_sig, expected[1]);

        // Vector 3
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[x[0], x[1], keypair.public_key()]);

        let secnonce_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key()]);
        let (mut secnonce, _) = secnonce_cache
            .nonce_gen(&secp, [0u8; 32], sec_key, msg, None)
            .unwrap();

        let session_ctx = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);

        let vector_3_sig = session_ctx
            .partial_sign(&secp, &mut secnonce, &keypair, &key_agg_cache)
            .unwrap()
            .serialize();
        assert_eq!(vector_3_sig, expected[2]);

        // Vector 4: Both halves of aggregate nonce correspond to point at infinity
        // secp256k1-zkp nonce aggregation returns G as infinity.
        let g_is_infinity = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let g_is_infinity = from_hex_all_132(vec![g_is_infinity]).unwrap();
        let g_is_infinity = MusigAggNonce::from_slice(&g_is_infinity[0]).unwrap();
        let inf_aggnonce = MusigAggNonce::new(&secp, &[pnonce_0, pnonce_3]);
        assert_eq!(inf_aggnonce, g_is_infinity);

        let key_agg_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key(), x[0]]);

        let secnonce_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key()]);
        let (mut secnonce, _) = secnonce_cache
            .nonce_gen(&secp, [0u8; 32], sec_key, msg, None)
            .unwrap();
        println!("Sec nonce: {:?}", secnonce);
        let session_ctx = MusigSession::new(&secp, &key_agg_cache, inf_aggnonce, msg, None);

        let vector_4_sig = session_ctx
            .partial_sign(&secp, &mut secnonce, &keypair, &key_agg_cache)
            .unwrap()
            .serialize();
        let mut foo = format!("{:02x?}", vector_4_sig);
        foo.retain(|c| "0123456789abcdefABCDEF".contains(c));
        println!("foo: {}", foo);
        assert_eq!(vector_4_sig, expected[3]);

        // Vector 5: Signer 2 provided an invalid public key
        // Skipping Vector 5 becasue we have already tested invalid public keys in fn test_errors().

        // Vector 6: Aggregate nonce is invalid due wrong tag, 0x04, in the first half.
        let invalid_agg = from_hex_all_132(vec![
            &("048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61".to_owned()
                + "037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"),
        ])
        .unwrap();
        let invalid_agg = MusigAggNonce::from_slice(&invalid_agg[0]).err().unwrap();
        assert_eq!(format!("{}", invalid_agg), "Malformed parse argument");

        // Vector 7: Aggregate nonce is invalid because the second half does not
        // correspond to an X coordinate
        let invalid_agg = from_hex_all_132(vec![
            &("028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61".to_owned()
                + "020000000000000000000000000000000000000000000000000000000000000009"),
        ])
        .unwrap();
        let invalid_agg = MusigAggNonce::from_slice(&invalid_agg[0]).err().unwrap();
        assert_eq!(format!("{}", invalid_agg), "Malformed parse argument");

        // Vector 8: Vector 8: Aggregate nonce is invalid because second half
        // exceeds field size
        let invalid_agg = from_hex_all_132(vec![
            &("028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61".to_owned()
                + "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"),
        ])
        .unwrap();
        let invalid_agg = MusigAggNonce::from_slice(&invalid_agg[0]).err().unwrap();
        assert_eq!(format!("{}", invalid_agg), "Malformed parse argument");

        // Verification test vectors
        // Vector 9
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key(), x[0], x[1]]);
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0, pnonce_1, pnonce_2]);
        let session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);
        let partial_sig = MusigPartialSignature::from_slice(&expected[0]).unwrap();
        // Agg nonce of the signer.
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0]);
        // Pub nonce of the signer.
        let pub_nonce = MusigPubNonce::from_slice(&agg_nonce.serialize()).unwrap();
        assert!(session.partial_verify(
            &secp,
            &key_agg_cache,
            partial_sig,
            pub_nonce,
            keypair.public_key(),
        ));
        //assert partial_sig_verify(expected[0], [pnonce[0], pnonce[1], pnonce[2]], [pk, X[0], X[1]], [], [], msg, 0)

        // Vector 10
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[x[0], keypair.public_key(), x[1]]);
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_1, pnonce_0, pnonce_2]);
        let session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);
        let partial_sig = MusigPartialSignature::from_slice(&expected[1]).unwrap();
        // Agg nonce of the signer.
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0]);
        // Pub nonce of the signer.
        let pub_nonce = MusigPubNonce::from_slice(&agg_nonce.serialize()).unwrap();
        assert!(session.partial_verify(
            &secp,
            &key_agg_cache,
            partial_sig,
            pub_nonce,
            keypair.public_key(),
        ));
        //assert partial_sig_verify(expected[1], [pnonce[1], pnonce[0], pnonce[2]], [X[0], pk, X[1]], [], [], msg, 1)

        // Vector 11
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[x[0], x[1], keypair.public_key()]);
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_1, pnonce_2, pnonce_0]);
        let session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);
        let partial_sig = MusigPartialSignature::from_slice(&expected[2]).unwrap();
        // Agg nonce of the signer.
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0]);
        // Pub nonce of the signer.
        let pub_nonce = MusigPubNonce::from_slice(&agg_nonce.serialize()).unwrap();
        assert!(session.partial_verify(
            &secp,
            &key_agg_cache,
            partial_sig,
            pub_nonce,
            keypair.public_key(),
        ));
        //assert partial_sig_verify(expected[2], [pnonce[1], pnonce[2], pnonce[0]], [X[0], X[1], pk], [], [], msg, 2)

        // Vector 12: Both halves of aggregate nonce correspond to point at infinity
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0, pnonce_3]);
        assert_eq!(agg_nonce, inf_aggnonce);
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key(), x[0]]);
        let session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);
        let partial_sig = MusigPartialSignature::from_slice(&expected[3]).unwrap();
        // Agg nonce of the signer.
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0]);
        // Pub nonce of the signer.
        let pub_nonce = MusigPubNonce::from_slice(&agg_nonce.serialize()).unwrap();
        assert!(session.partial_verify(
            &secp,
            &key_agg_cache,
            partial_sig,
            pub_nonce,
            keypair.public_key(),
        ));
        // assert partial_sig_verify(expected[3], [pnonce[0], pnonce[3]], [pk, X[0]], [], [], msg, 0)

        // Vector 13: Wrong signature (which is equal to the negation of valid signature expected[0])
        // TODO: Learn to generate this wrong signature.
        let wrong_sig = from_hex_all_32(vec![
            "97AC833ADCB1AFA42EBF9E0725616F3C9A0D5B614F6FE283CEAAA37A8FFAF406",
        ])
        .unwrap();
        let goodsig = expected[0];
        let foo = Signature::from_slice(&goodsig).unwrap();
        let wrong_sig = MusigPartialSignature::from_slice(&wrong_sig[0]).unwrap();
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key(), x[0], x[1]]);
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0, pnonce_1, pnonce_2, pnonce_3]);
        let pub_nonce = MusigPubNonce::from_slice(&agg_nonce.serialize()).unwrap();
        let session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);
        assert!(!session.partial_verify(
            &secp,
            &key_agg_cache,
            wrong_sig,
            pub_nonce,
            keypair.public_key(),
        ));
        //  assert not partial_sig_verify(wrong_sig, pnonce, [pk, X[0], X[1]], [], [], msg, 0)

        // Vector 14: Wrong signer
        // TODO: The python version of this seems to test with pnonce_3 which it probably shouldn't??
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key(), x[0], x[1]]);
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0, pnonce_1, pnonce_2]);
        let session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);
        let partial_sig = MusigPartialSignature::from_slice(&expected[0]).unwrap();
        // Agg nonce of the signer.
        let pub_nonce = MusigAggNonce::new(&secp, &[pnonce_0]);
        // Pub nonce of the signer.
        let pub_nonce = MusigPubNonce::from_slice(&pub_nonce.serialize()).unwrap();
        assert!(session.partial_verify(
            &secp,
            &key_agg_cache,
            partial_sig,
            pub_nonce,
            keypair.public_key(),
        ));
        let key_agg_cache = MusigKeyAggCache::new(&secp, &[keypair.public_key(), x[0], x[1]]);
        let agg_nonce = MusigAggNonce::new(&secp, &[pnonce_0, pnonce_1, pnonce_2]);
        let session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg, None);
        let partial_sig = MusigPartialSignature::from_slice(&expected[0]).unwrap();
        // Agg nonce of the signer.
        let pub_nonce = MusigAggNonce::new(&secp, &[pnonce_0]);
        // Pub nonce of the signer.
        let pub_nonce = MusigPubNonce::from_slice(&pub_nonce.serialize()).unwrap();
        assert!(!session.partial_verify(&secp, &key_agg_cache, partial_sig, pub_nonce, x[0],));
        // assert not partial_sig_verify(expected[0], pnonce, [pk, X[0], X[1]], [], [], msg, 1)

        // Vector 15: Signature exceeds group size
        let wrong_sig = from_hex_all_32(vec![
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        ])
        .unwrap();
        let wrong_sig = MusigPartialSignature::from_slice(&wrong_sig[0])
            .err()
            .unwrap();
        assert_eq!(format!("{}", wrong_sig), "Malformed parse argument");

        // Vector 16: Invalid pubnonce
        // There are too many bytes in the public nonce. That's why it fails. No need to test in rust.
        // let invalid_pubnonce = from_hex_all_32(vec![
        //     "020000000000000000000000000000000000000000000000000000000000000009",
        // ])
        // .unwrap();

        // Vector 17: Invalid public key
        // Skipping Vector 17 becasue we have already tested invalid public keys in fn test_errors()
    }

    #[test]
    fn test_key_agg_cache() {
        let secp = Secp256k1::new();
        let mut sec_bytes = [0; 32];
        thread_rng().fill_bytes(&mut sec_bytes);
        let sec_key = SecretKey::from_slice(&sec_bytes).unwrap();
        let keypair = KeyPair::from_secret_key(&secp, sec_key);
        let pub_key = XOnlyPublicKey::from_keypair(&keypair);

        let _key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key, pub_key]);
    }

    #[test]
    fn test_nonce_parsing() {
        let secp = Secp256k1::new();
        let sec_bytes = [1; 32];
        let sec_key = SecretKey::from_slice(&sec_bytes).unwrap();
        let keypair = KeyPair::from_secret_key(&secp, sec_key);
        let pub_key = XOnlyPublicKey::from_keypair(&keypair);

        let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key, pub_key]);
        let msg = Message::from_slice(&[3; 32]).unwrap();
        let session_id = [2; 32];
        let sec_key = SecretKey::from_slice(&[4; 32]).unwrap();
        let (_secnonce, pubnonce) = key_agg_cache
            .nonce_gen(&secp, session_id, sec_key, msg, None)
            .expect("non zero session id");
        let pubnonce_ser = pubnonce.serialize();
        let parsed_pubnonce = MusigPubNonce::from_slice(&pubnonce_ser).unwrap();

        assert_eq!(parsed_pubnonce, pubnonce);
    }
}
