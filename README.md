# FN-DSA-PADDED-512 Rust Library

Rust wrapper for the FN-DSA-PADDED-512 (Falcon-padded-512) post-quantum cryptographic signature scheme.

## Overview

FN-DSA-PADDED-512 is a post-quantum digital signature algorithm based on lattice cryptography, designed to be secure against quantum computer attacks. This library provides a safe Rust interface with proper error handling and memory management.

### Algorithm Parameters

| Parameter | Size (bytes) |
|-----------|--------------|
| Public Key | 897 |
| Secret Key | 1,281 |
| Signature | = 666 |
| Seed | 48 |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
fn-dsa-padded-512 = "0.1.0"
```

### Prerequisites

- Rust 1.70.0+
- C compiler (GCC/Clang)
- Required C source files in `src/` directories

## Quick Start

```rust
use fn_dsa_padded_512::{Keypair, sign_detached, verify_detached};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keypair
    let keypair = Keypair::generate()?;

    // Sign message
    let message = b"Hello, post-quantum world!";
    let signature = sign_detached(message, &keypair.secret_key)?;

    // Verify signature
    let is_valid = verify_detached(&signature, message, &keypair.public_key)?;
    assert!(is_valid);

    Ok(())
}
```

## API Reference

### Types

```rust
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

pub struct PublicKey(pub [u8; 897]);
pub struct SecretKey(pub [u8; 1281]);
pub struct Signature { pub data: Vec<u8> }

pub enum FnDsaError {
    KeyGeneration,
    PublicKeyRecovery,
    Signing,
    Verification,
    InvalidSignature,
    InvalidInput,
}
```

### Key Generation

#### Random Generation
```rust
let keypair = Keypair::generate()?;
```

#### Deterministic from Seed
```rust
let mut seed = [0x42u8; 48];
let keypair = Keypair::from_seed(&mut seed)?;
// seed is now zeroed for security
```

#### Public Key Recovery
```rust
let recovered_pk = keypair.secret_key.recover_public_key()?;
```

### Signing and Verification

#### Detached Signatures
```rust
// Sign
let signature = sign_detached(message, &secret_key)?;

// Verify
let is_valid = verify_detached(&signature, message, &public_key)?;
```

#### Attached Signatures
```rust
// Sign (message + signature in one blob)
let signed_message = sign_attached(message, &secret_key)?;

// Verify and extract original message
let original_message = verify_attached(&signed_message, &public_key)?;
```

## Usage Examples

### Basic Workflow
```rust
use fn_dsa_padded_512::*;

let keypair = Keypair::generate()?;
let message = b"Important document";

// Detached signature
let sig = sign_detached(message, &keypair.secret_key)?;
assert!(verify_detached(&sig, message, &keypair.public_key)?);

// Attached signature  
let signed = sign_attached(message, &keypair.secret_key)?;
let recovered = verify_attached(&signed, &keypair.public_key)?;
assert_eq!(recovered, message);
```

### Deterministic Keys
```rust
let seed = [0x01, 0x23, /* ... */, 0xff]; // 48 bytes
let mut seed_copy = seed;
let keypair = Keypair::from_seed(&mut seed_copy)?;
// seed_copy is now [0u8; 48] - cleared for security
```

### Key Serialization
```rust
use std::fs;

let keypair = Keypair::generate()?;

// Save keys
fs::write("public.key", &keypair.public_key.0)?;
fs::write("secret.key", &keypair.secret_key.0)?;

// Load keys
let pub_data: [u8; 897] = fs::read("public.key")?.try_into().unwrap();
let sec_data: [u8; 1281] = fs::read("secret.key")?.try_into().unwrap();
let loaded_keypair = Keypair {
    public_key: PublicKey(pub_data),
    secret_key: SecretKey(sec_data),
};
```

## Security Features

- **Post-quantum security**: Resistant to quantum attacks
- **Seed clearing**: Seeds are automatically zeroed after key generation
- **Memory safety**: Safe Rust API with proper error handling
- **Public key recovery**: Derive public key from secret key when needed

## Performance

- Typical performance on modern x86_64:
- Signing rate: 247.1 sigs/sec
- Verification rate: 18753.2 verifs/sec
- Large message (100KB): 5.051417ms


## Testing

```bash
cargo test                    # Run all tests
cargo test --release         # Faster execution
cargo test test_comprehensive # Run full workflow test
```

## Constants

```rust
pub mod constants {
    pub const PUBLIC_KEY_BYTES: usize = 897;
    pub const SECRET_KEY_BYTES: usize = 1281;
    pub const SIGNATURE_BYTES: usize = 666;
    pub const SEED_BYTES: usize = 48;
}
```

## Error Handling

```rust
match keypair_result {
    Ok(keypair) => { /* use keypair */ },
    Err(FnDsaError::KeyGeneration) => { /* handle key gen failure */ },
    Err(FnDsaError::InvalidSignature) => { /* invalid signature */ },
    Err(e) => eprintln!("Error: {}", e),
}
```

## Security Considerations

- **Store secret keys securely** - never log or transmit them
- **Use strong entropy** for random key generation
- **Verify signatures** before trusting signed data
- **Seeds are cleared** automatically after use
- **Rotate keys regularly** for long-term applications

## Building from Source

```bash
git clone <repository>
cd fn-dsa-padded-512
cargo build --release
```

Requires C source files in `src/common/` and `src/fndsapadded512/` as specified in `build.rs`.

---

For more examples and advanced usage, see the documentation and test files.