//! # FN-DSA-PADDED-512 Rust Wrapper
//! 
//! A Rust wrapper for the FN-DSA-PADDED-512 (Falcon-padded-512) 
//! post-quantum cryptographic signature scheme.
//!
//! ## Features
//! - Key generation from random or seed
//! - Public key recovery from secret key
//! - Digital signature creation and verification (detached and attached modes)
//! - Safe Rust API with proper error handling
//! - Secure seed handling (seeds are cleared after use)
//!
//! ## Example
//! ```rust
//! use fn_dsa_padded_512::{Keypair, sign_detached, verify_detached};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate keypair
//! let keypair = Keypair::generate()?;
//!
//! // Sign message (detached)
//! let message = b"Hello, post-quantum world!";
//! let signature = sign_detached(message, &keypair.secret_key)?;
//!
//! // Verify signature
//! let is_valid = verify_detached(&signature, message, &keypair.public_key)?;
//! assert!(is_valid);
//!
//! // Generate from seed (seed will be cleared after use)
//! let mut seed = [0x42u8; 48];
//! let keypair_from_seed = Keypair::from_seed(&mut seed)?;
//! // seed is now zeroed out for security
//!
//! // Recover public key from secret key
//! let recovered_pk = keypair_from_seed.secret_key.recover_public_key()?;
//! assert_eq!(recovered_pk.0, keypair_from_seed.public_key.0);
//! # Ok(())
//! # }
//! ```

use std::os::raw::{c_int, c_uchar};

/// FN-DSA-PADDED-512 algorithm constants
pub mod constants {
    pub const PUBLIC_KEY_BYTES: usize = 897;
    pub const SECRET_KEY_BYTES: usize = 1281;
    pub const SIGNATURE_BYTES: usize = 666;
    pub const SEED_BYTES: usize = 48;
}

/// Error types for FN-DSA-PADDED-512 operations
#[derive(Debug, Clone, PartialEq)]
pub enum FnDsaError {
    KeyGeneration,
    PublicKeyRecovery,
    Signing,
    Verification,
    InvalidSignature,
    InvalidInput,
}

impl std::fmt::Display for FnDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FnDsaError::KeyGeneration => write!(f, "Key generation failed"),
            FnDsaError::PublicKeyRecovery => write!(f, "Public key recovery failed"),
            FnDsaError::Signing => write!(f, "Signing failed"),
            FnDsaError::Verification => write!(f, "Verification failed"),
            FnDsaError::InvalidSignature => write!(f, "Invalid signature"),
            FnDsaError::InvalidInput => write!(f, "Invalid input"),
        }
    }
}

impl std::error::Error for FnDsaError {}

pub type Result<T> = std::result::Result<T, FnDsaError>;

/// Public key (897 bytes)
#[derive(Clone)]
pub struct PublicKey(pub [u8; constants::PUBLIC_KEY_BYTES]);

/// Secret key (1281 bytes)
#[derive(Clone)]
pub struct SecretKey(pub [u8; constants::SECRET_KEY_BYTES]);

/// Digital signature (up to 666 bytes)
#[derive(Clone)]
pub struct Signature {
    pub data: Vec<u8>,
}

/// Keypair containing public and secret keys
#[derive(Clone)]
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

// FFI declarations
extern "C" {
    fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(
        pk: *mut c_uchar,
        sk: *mut c_uchar,
    ) -> c_int;

    fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair_from_fseed(
        pk: *mut c_uchar,
        sk: *mut c_uchar,
        seed: *mut c_uchar,
    ) -> c_int;

    fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_pubkey_from_privkey(
        pk: *mut c_uchar,
        sk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
        sig: *mut c_uchar,
        siglen: *mut libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        sk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
        sig: *const c_uchar,
        siglen: libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        pk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign(
        sm: *mut c_uchar,
        smlen: *mut libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        sk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_open(
        m: *mut c_uchar,
        mlen: *mut libc::size_t,
        sm: *const c_uchar,
        smlen: libc::size_t,
        pk: *const c_uchar,
    ) -> c_int;
}

impl Keypair {
    /// Generate a new keypair using system randomness
    pub fn generate() -> Result<Self> {
        let mut pk = [0u8; constants::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; constants::SECRET_KEY_BYTES];

        let result = unsafe {
            PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        };

        if result != 0 {
            return Err(FnDsaError::KeyGeneration);
        }

        Ok(Keypair {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    /// Generate keypair from a 48-byte seed (deterministic)
    /// 
    /// **Security Note**: The seed will be cleared (zeroed) after use for security reasons.
    /// This is done by the underlying C implementation to prevent seed reuse.
    /// 
    /// # Arguments
    /// * `seed` - A mutable reference to a 48-byte seed that will be cleared after use
    /// 
    /// # Example
    /// ```rust
    /// # use fn_dsa_padded_512::{Keypair, constants};
    /// let mut seed = [0x42u8; constants::SEED_BYTES];
    /// let keypair = Keypair::from_seed(&mut seed)?;
    /// // seed is now [0u8; 48] - cleared for security
    /// # Ok::<(), fn_dsa_padded_512::FnDsaError>(())
    /// ```
    pub fn from_seed(seed: &mut [u8; constants::SEED_BYTES]) -> Result<Self> {
        let mut pk = [0u8; constants::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; constants::SECRET_KEY_BYTES];

        let result = unsafe {
            PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair_from_fseed(
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
                seed.as_mut_ptr(),
            )
        };

        if result != 0 {
            return Err(FnDsaError::KeyGeneration);
        }

        Ok(Keypair {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }
}

impl SecretKey {
    /// Recover the public key from this secret key
    /// 
    /// # Example
    /// ```rust
    /// # use fn_dsa_padded_512::Keypair;
    /// let keypair = Keypair::generate()?;
    /// let recovered_pk = keypair.secret_key.recover_public_key()?;
    /// assert_eq!(recovered_pk.0, keypair.public_key.0);
    /// # Ok::<(), fn_dsa_padded_512::FnDsaError>(())
    /// ```
    pub fn recover_public_key(&self) -> Result<PublicKey> {
        let mut pk = [0u8; constants::PUBLIC_KEY_BYTES];

        let result = unsafe {
            PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_pubkey_from_privkey(
                pk.as_mut_ptr(),
                self.0.as_ptr(),
            )
        };

        if result != 0 {
            return Err(FnDsaError::PublicKeyRecovery);
        }

        Ok(PublicKey(pk))
    }
}

/// Sign a message with the secret key (detached signature)
pub fn sign_detached(message: &[u8], secret_key: &SecretKey) -> Result<Signature> {
    let mut sig = vec![0u8; constants::SIGNATURE_BYTES];
    let mut siglen = constants::SIGNATURE_BYTES;

    let result = unsafe {
        PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
            sig.as_mut_ptr(),
            &mut siglen,
            message.as_ptr(),
            message.len(),
            secret_key.0.as_ptr(),
        )
    };

    if result != 0 {
        return Err(FnDsaError::Signing);
    }

    sig.truncate(siglen);
    Ok(Signature { data: sig })
}

/// Verify a detached signature
pub fn verify_detached(signature: &Signature, message: &[u8], public_key: &PublicKey) -> Result<bool> {
    let result = unsafe {
        PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
            signature.data.as_ptr(),
            signature.data.len(),
            message.as_ptr(),
            message.len(),
            public_key.0.as_ptr(),
        )
    };

    Ok(result == 0)
}

/// Sign a message with the secret key (attached signature)
/// Returns a signed message containing both the signature and the original message
pub fn sign_attached(message: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>> {
    let mut sm = vec![0u8; message.len() + constants::SIGNATURE_BYTES];
    let mut smlen = sm.len();

    let result = unsafe {
        PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign(
            sm.as_mut_ptr(),
            &mut smlen,
            message.as_ptr(),
            message.len(),
            secret_key.0.as_ptr(),
        )
    };

    if result != 0 {
        return Err(FnDsaError::Signing);
    }

    sm.truncate(smlen);
    Ok(sm)
}

/// Verify and extract message from an attached signature
/// Returns the original message if verification succeeds
pub fn verify_attached(signed_message: &[u8], public_key: &PublicKey) -> Result<Vec<u8>> {
    let mut m = vec![0u8; signed_message.len()];
    let mut mlen = m.len();

    let result = unsafe {
        PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_open(
            m.as_mut_ptr(),
            &mut mlen,
            signed_message.as_ptr(),
            signed_message.len(),
            public_key.0.as_ptr(),
        )
    };

    if result != 0 {
        return Err(FnDsaError::InvalidSignature);
    }

    m.truncate(mlen);
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Keypair::generate().unwrap();
        assert_eq!(keypair.public_key.0.len(), constants::PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret_key.0.len(), constants::SECRET_KEY_BYTES);
    }

    #[test]
    fn test_public_key_recovery() {
        let keypair = Keypair::generate().unwrap();
        let recovered_pk = keypair.secret_key.recover_public_key().unwrap();
        assert_eq!(recovered_pk.0, keypair.public_key.0);
    }

    #[test]
    fn test_detached_sign_and_verify() {
        let keypair = Keypair::generate().unwrap();
        let message = b"Hello, FN-DSA-PADDED-512!";
        
        let signature = sign_detached(message, &keypair.secret_key).unwrap();
        let is_valid = verify_detached(&signature, message, &keypair.public_key).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_attached_sign_and_verify() {
        let keypair = Keypair::generate().unwrap();
        let message = b"Hello, Falcon-padded-512!";
        
        let signed_message = sign_attached(message, &keypair.secret_key).unwrap();
        let recovered_message = verify_attached(&signed_message, &keypair.public_key).unwrap();
        
        assert_eq!(recovered_message, message);
    }

    #[test]
    fn test_deterministic_keygen() {
        let seed = [42u8; constants::SEED_BYTES];
        let mut seed1 = seed;
        let mut seed2 = seed;
        
        let keypair1 = Keypair::from_seed(&mut seed1).unwrap();
        let keypair2 = Keypair::from_seed(&mut seed2).unwrap();
        
        assert_eq!(keypair1.public_key.0, keypair2.public_key.0);
        assert_eq!(keypair1.secret_key.0, keypair2.secret_key.0);
        
        // Both seeds should be cleared
        assert_eq!(seed1, [0u8; constants::SEED_BYTES]);
        assert_eq!(seed2, [0u8; constants::SEED_BYTES]);
    }

    #[test]
    fn test_seed_clearing() {
        let original_seed = [0x42u8; constants::SEED_BYTES];
        let mut seed = original_seed;
        
        let _keypair = Keypair::from_seed(&mut seed).unwrap();
        
        // Seed should be cleared after use
        assert_ne!(seed, original_seed);
        assert_eq!(seed, [0u8; constants::SEED_BYTES]);
    }

    #[test]
    fn test_invalid_signature() {
        let keypair = Keypair::generate().unwrap();
        let message = b"Valid message";
        let wrong_message = b"Wrong message";
        
        let signature = sign_detached(message, &keypair.secret_key).unwrap();
        let is_valid = verify_detached(&signature, wrong_message, &keypair.public_key).unwrap();
        
        assert!(!is_valid);
    }

    #[test]
    fn test_comprehensive() {
        // Test full workflow with key recovery
        let mut seed = [0x99u8; constants::SEED_BYTES];
        let keypair = Keypair::from_seed(&mut seed).unwrap();
        
        // Verify key recovery works
        let recovered_pk = keypair.secret_key.recover_public_key().unwrap();
        assert_eq!(recovered_pk.0, keypair.public_key.0);
        
        // Test both signature modes
        let message = b"Comprehensive test message";
        
        // Detached mode
        let detached_sig = sign_detached(message, &keypair.secret_key).unwrap();
        assert!(verify_detached(&detached_sig, message, &keypair.public_key).unwrap());
        
        // Attached mode
        let attached_sig = sign_attached(message, &keypair.secret_key).unwrap();
        let recovered_msg = verify_attached(&attached_sig, &keypair.public_key).unwrap();
        assert_eq!(recovered_msg, message);
        
        // Verify seed was cleared
        assert_eq!(seed, [0u8; constants::SEED_BYTES]);
    }
}