use fn_dsa_padded_512::{
    constants, Keypair, sign_detached, verify_detached, 
    sign_attached, verify_attached, FnDsaError
};
use std::collections::HashSet;

/// Compact test results tracking
#[derive(Debug, Default)]
struct TestResults {
    passed: usize,
    failed: usize,
}

impl TestResults {
    fn test(&mut self, name: &str, condition: bool) {
        let symbol = if condition { "✓" } else { "✗" };
        println!("{} {}", symbol, name);
        if condition { self.passed += 1; } else { self.failed += 1; }
    }
    
    fn summary(&self) {
        let total = self.passed + self.failed;
        if total == 0 { println!("No tests run!"); return; }
        
        println!("\n=== RESULTS: {}/{} passed ({:.1}%) ===", 
                 self.passed, total, (self.passed as f64 / total as f64) * 100.0);
        if self.failed == 0 {
            println!("🎉 ALL TESTS PASSED!");
        } else {
            println!("⚠️  {} tests failed", self.failed);
        }
    }
}

fn print_hex_short(label: &str, data: &[u8], len: usize) {
    print!("{}: ", label);
    for byte in data.iter().take(len) {
        print!("{:02x}", byte);
    }
    if data.len() > len { print!("... ({} bytes)", data.len()); }
    println!();
}

fn is_all_zeros(data: &[u8]) -> bool {
    data.iter().all(|&x| x == 0)
}

/// Test both signature modes with given keypair
fn test_signatures(keypair: &Keypair, name: &str, results: &mut TestResults) -> Result<(), FnDsaError> {
    println!("\n--- Testing {} ---", name);
    let msg = b"FN-DSA-PADDED-512 test message";
    
    // Detached signatures
    let det_sig = sign_detached(msg, &keypair.secret_key)?;
    print_hex_short("Detached sig", &det_sig.data, 16);
    results.test(&format!("{} - detached sign", name), !det_sig.data.is_empty());
    results.test(&format!("{} - detached size", name), det_sig.data.len() == constants::SIGNATURE_BYTES);
    
    let det_valid = verify_detached(&det_sig, msg, &keypair.public_key)?;
    results.test(&format!("{} - detached verify", name), det_valid);
    
    // Test wrong message
    let mut wrong_msg = msg.to_vec();
    wrong_msg[0] ^= 0x01;
    let det_invalid = verify_detached(&det_sig, &wrong_msg, &keypair.public_key)?;
    results.test(&format!("{} - detached invalid reject", name), !det_invalid);
    
    // Attached signatures
    let att_sig = sign_attached(msg, &keypair.secret_key)?;
    print_hex_short("Attached sig", &att_sig, 16);
    results.test(&format!("{} - attached sign", name), att_sig.len() > msg.len());
    results.test(&format!("{} - attached size", name), att_sig.len() == msg.len() + constants::SIGNATURE_BYTES);
    
    let recovered_msg = verify_attached(&att_sig, &keypair.public_key)?;
    results.test(&format!("{} - attached verify", name), recovered_msg == msg);
    
    // Test corrupted attached signature
    let mut corrupt_att = att_sig.clone();
    if !corrupt_att.is_empty() { corrupt_att[0] ^= 0x01; }
    let att_corrupt_result = verify_attached(&corrupt_att, &keypair.public_key);
    results.test(&format!("{} - attached corrupt reject", name), 
                matches!(att_corrupt_result, Err(FnDsaError::InvalidSignature)));
    
    Ok(())
}

/// Enhanced malleability and attack resistance tests
fn test_signature_attacks(keypair: &Keypair, results: &mut TestResults) -> Result<(), FnDsaError> {
    println!("\n=== SIGNATURE ATTACK RESISTANCE ===");
    let msg = b"Attack resistance test message";
    let sig = sign_detached(msg, &keypair.secret_key)?;
    
    // Test 1: Systematic bit-flip attacks
    let mut bit_flip_success = 0;
    let test_positions = [0, 1, sig.data.len()/4, sig.data.len()/2, sig.data.len()-2, sig.data.len()-1]
        .iter().filter(|&&pos| pos < sig.data.len()).cloned().collect::<Vec<_>>();
    
    for &pos in &test_positions {  // Changed: iterate over references
        for bit in 0..8 {
            let mut modified_sig = sig.clone();
            modified_sig.data[pos] ^= 1 << bit;
            
            let is_rejected = match verify_detached(&modified_sig, msg, &keypair.public_key) {
                Ok(valid) => !valid,
                Err(_) => true,
            };
            
            if is_rejected { bit_flip_success += 1; }
        }
    }
    
    let total_bit_tests = test_positions.len() * 8;
    let bit_flip_rate = if total_bit_tests > 0 { bit_flip_success as f64 / total_bit_tests as f64 } else { 0.0 };
    results.test("bit-flip attack resistance (>95%)", bit_flip_rate > 0.95);
    println!("  Bit-flip rejection rate: {:.1}%", bit_flip_rate * 100.0);
    
    // Test 2: Length-based attacks (division by zero protection)
    let original_len = sig.data.len();
    if original_len == 0 {
        results.test("non-empty signature", false);
        return Ok(());
    }
    
    let truncation_points = [
        1, 
        std::cmp::max(1, original_len / 8),
        std::cmp::max(1, original_len / 4), 
        std::cmp::max(1, original_len / 2),
        original_len.saturating_sub(1)
    ];
    let mut truncation_success = 0;
    
    for &trunc_len in &truncation_points {
        if trunc_len < original_len && trunc_len > 0 {
            let mut trunc_sig = sig.clone();
            trunc_sig.data.truncate(trunc_len);
            
            let is_rejected = match verify_detached(&trunc_sig, msg, &keypair.public_key) {
                Ok(valid) => !valid,
                Err(_) => true,
            };
            
            if is_rejected { truncation_success += 1; }
        }
    }
    
    results.test("truncation attack resistance", truncation_success >= 4); // At least 4/5 should fail
    
    // Test 3: Extension attacks
    for extra_bytes in [1, 16, 100] {
        let mut extended_sig = sig.clone();
        for i in 0..extra_bytes {
            extended_sig.data.push((i ^ 0xAA) as u8); // Pseudo-random pattern
        }
        
        let is_rejected = match verify_detached(&extended_sig, msg, &keypair.public_key) {
            Ok(valid) => !valid,
            Err(_) => true,
        };
        
        results.test(&format!("extension attack (+{} bytes)", extra_bytes), is_rejected);
    }
    
    // Test 4: Pattern-based attacks
    let patterns = [
        vec![0x00; 50], // All zeros
        vec![0xFF; 50], // All ones
        (0..50).map(|i| i as u8).collect::<Vec<_>>(), // Sequential
        (0..50).map(|i| (i * 17) as u8).collect::<Vec<_>>(), // Pseudo-random
    ];
    
    for (i, pattern) in patterns.iter().enumerate() {
        let mut pattern_sig = sig.clone();
        pattern_sig.data.extend_from_slice(pattern);
        
        let is_rejected = match verify_detached(&pattern_sig, msg, &keypair.public_key) {
            Ok(valid) => !valid,
            Err(_) => true,
        };
        results.test(&format!("pattern attack {}", i), is_rejected);
    }
    
    // Test 5: Empty and minimal signatures
    let empty_sig = fn_dsa_padded_512::Signature { data: vec![] };
    let empty_rejected = match verify_detached(&empty_sig, msg, &keypair.public_key) {
        Ok(valid) => !valid,
        Err(_) => true,
    };
    results.test("empty signature rejection", empty_rejected);
    
    let minimal_sig = fn_dsa_padded_512::Signature { data: vec![0x42] };
    let minimal_rejected = match verify_detached(&minimal_sig, msg, &keypair.public_key) {
        Ok(valid) => !valid,
        Err(_) => true,
    };
    results.test("minimal signature rejection", minimal_rejected);
    
    Ok(())
}

/// Test signature properties and consistency
fn test_signature_properties(keypair: &Keypair, results: &mut TestResults) -> Result<(), FnDsaError> {
    println!("\n=== SIGNATURE PROPERTIES ===");
    let msg = b"Signature properties test";
    
    // Generate multiple signatures
    let mut signatures = Vec::new();
    for _ in 0..20 {
        let sig = sign_detached(msg, &keypair.secret_key)?;
        signatures.push(sig);
    }
    
    // Validate all signatures
    let mut all_valid = true;
    for sig in &signatures {
        if !verify_detached(sig, msg, &keypair.public_key)? {
            all_valid = false;
            break;
        }
    }
    results.test("multiple signatures all valid", all_valid);
    
    // Check signature lengths
    let first_len = signatures[0].data.len();
    let consistent_length = signatures.iter().all(|s| s.data.len() == first_len);
    results.test("consistent signature length", consistent_length);
    results.test("correct signature length", first_len == constants::SIGNATURE_BYTES);
    
    // Check uniqueness (for probabilistic schemes)
    let mut unique_sigs = HashSet::new();
    for sig in &signatures {
        unique_sigs.insert(sig.data.clone());
    }
    
    let uniqueness_ratio = if signatures.is_empty() { 0.0 } else { unique_sigs.len() as f64 / signatures.len() as f64 };
    results.test("signature uniqueness", uniqueness_ratio >= 0.5);
    println!("  Signature uniqueness: {:.1}%", uniqueness_ratio * 100.0);
    
    // Test signature entropy (basic check)
    if !signatures.is_empty() {
        let sig_data = &signatures[0].data;
        let zero_bytes = sig_data.iter().filter(|&&b| b == 0).count();
        let entropy_check = zero_bytes < sig_data.len() / 2; // Less than 50% zeros
        results.test("signature entropy check", entropy_check);
    }
    
    Ok(())
}

/// Test edge cases and boundary conditions
fn test_edge_cases(results: &mut TestResults) -> Result<(), FnDsaError> {
    println!("\n=== EDGE CASES ===");
    
    // Test with various message sizes including critical boundaries
    let test_sizes = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 1000];
    let keypair = Keypair::generate()?;
    
    for &size in &test_sizes {
        let msg = vec![((size + 0xAA) % 256) as u8; size]; // Avoid all-zeros
        
        let det_sig = sign_detached(&msg, &keypair.secret_key)?;
        let det_valid = verify_detached(&det_sig, &msg, &keypair.public_key)?;
        
        let att_sig = sign_attached(&msg, &keypair.secret_key)?;
        let recovered = verify_attached(&att_sig, &keypair.public_key)?;
        let att_valid = recovered == msg;
        
        results.test(&format!("message size {} bytes", size), det_valid && att_valid);
    }
    
    // Test extreme seed values with additional patterns
    let extreme_seeds = [
        [0x00; constants::SEED_BYTES], // All zeros
        [0xFF; constants::SEED_BYTES], // All ones
        {
            let mut seed = [0; constants::SEED_BYTES];
            seed[0] = 0x80; // High bit set
            seed
        },
        {
            let mut seed = [0xFF; constants::SEED_BYTES];
            seed[constants::SEED_BYTES-1] = 0x7F; // Clear high bit in last byte
            seed
        },
        {
            let mut seed = [0; constants::SEED_BYTES];
            for i in 0..constants::SEED_BYTES {
                seed[i] = (i % 256) as u8; // Sequential pattern
            }
            seed
        },
        {
            let mut seed = [0; constants::SEED_BYTES];
            for i in 0..constants::SEED_BYTES {
                seed[i] = ((i * 17 + 42) % 256) as u8; // Pseudo-random pattern
            }
            seed
        },
    ];
    
    for (i, &seed) in extreme_seeds.iter().enumerate() {
        let mut seed_copy = seed;
        let kp = Keypair::from_seed(&mut seed_copy)?;
        
        // Verify key sizes
        results.test(&format!("extreme seed {} - PK size", i), kp.public_key.0.len() == constants::PUBLIC_KEY_BYTES);
        results.test(&format!("extreme seed {} - SK size", i), kp.secret_key.0.len() == constants::SECRET_KEY_BYTES);
        
        let test_msg = b"Extreme seed test";
        let sig = sign_detached(test_msg, &kp.secret_key)?;
        let valid = verify_detached(&sig, test_msg, &kp.public_key)?;
        
        results.test(&format!("extreme seed {} functionality", i), valid);
        results.test(&format!("extreme seed {} cleared", i), is_all_zeros(&seed_copy));
    }
    
    Ok(())
}

/// Test cross-key security
fn test_cross_key_security(results: &mut TestResults) -> Result<(), FnDsaError> {
    println!("\n=== CROSS-KEY SECURITY ===");
    
    // Generate keypairs with different methods
    let kp_random1 = Keypair::generate()?;
    let kp_random2 = Keypair::generate()?;
    
    let mut seed1 = [0x11; constants::SEED_BYTES];
    let mut seed2 = [0x22; constants::SEED_BYTES];
    let kp_seed1 = Keypair::from_seed(&mut seed1)?;
    let kp_seed2 = Keypair::from_seed(&mut seed2)?;
    
    let keypairs = [&kp_random1, &kp_random2, &kp_seed1, &kp_seed2];
    let msg = b"Cross-key security test";
    
    // Test cross-verification
    let mut cross_key_secure = true;
    let mut tests_performed = 0;
    
    for (i, &kp_signer) in keypairs.iter().enumerate() {
        let sig = sign_detached(msg, &kp_signer.secret_key)?;
        
        for (j, &kp_verifier) in keypairs.iter().enumerate() {
            if i != j {
                let verify_result = verify_detached(&sig, msg, &kp_verifier.public_key)?;
                if verify_result {
                    cross_key_secure = false;
                    println!("  SECURITY BREACH: Key {} sig verified with key {}", i, j);
                }
                tests_performed += 1;
            }
        }
    }
    
    results.test("cross-key security", cross_key_secure);
    println!("  Cross-key tests: {}", tests_performed);
    
    // Test key uniqueness
    let mut unique_pks = HashSet::new();
    let mut unique_sks = HashSet::new();
    
    for kp in &keypairs {
        unique_pks.insert(kp.public_key.0.clone());
        unique_sks.insert(kp.secret_key.0.clone());
    }
    
    results.test("unique public keys", unique_pks.len() == keypairs.len());
    results.test("unique secret keys", unique_sks.len() == keypairs.len());
    
    Ok(())
}

/// Performance testing with safety checks
fn test_performance_stress(results: &mut TestResults) -> Result<(), FnDsaError> {
    println!("\n=== PERFORMANCE & STRESS ===");
    
    let keypair = Keypair::generate()?;
    let msg = b"Performance test";
    
    // Signing performance
    let sign_start = std::time::Instant::now();
    let mut signatures = Vec::new();
    
    for i in 0..50 {
        let sig_start = std::time::Instant::now();
        let sig = sign_detached(msg, &keypair.secret_key)?;
        let sig_time = sig_start.elapsed();
        
        if sig_time.as_secs() > 1 {
            println!("  Warning: Slow signature #{}: {:?}", i, sig_time);
        }
        
        signatures.push(sig);
    }
    
    let total_sign_time = sign_start.elapsed();
    let sign_rate = if total_sign_time.as_secs_f64() > 0.0 { 50.0 / total_sign_time.as_secs_f64() } else { f64::INFINITY };
    println!("  Signing rate: {:.1} sigs/sec", sign_rate);
    results.test("signing performance", sign_rate > 5.0);
    
    // Verification performance  
    let verify_start = std::time::Instant::now();
    let mut all_verified = true;
    
    for (i, sig) in signatures.iter().enumerate() {
        let ver_start = std::time::Instant::now();
        let valid = verify_detached(sig, msg, &keypair.public_key)?;
        let ver_time = ver_start.elapsed();
        
        if !valid {
            all_verified = false;
            println!("  Signature #{} verification failed", i);
        }
        
        if ver_time.as_secs() > 1 {
            println!("  Warning: Slow verification #{}: {:?}", i, ver_time);
        }
    }
    
    let total_verify_time = verify_start.elapsed();
    let verify_rate = if total_verify_time.as_secs_f64() > 0.0 { 50.0 / total_verify_time.as_secs_f64() } else { f64::INFINITY };
    println!("  Verification rate: {:.1} verifs/sec", verify_rate);
    
    results.test("all signatures verified", all_verified);
    results.test("verification performance", verify_rate > 5.0);
    
    // Memory stress - large message
    let large_msg = vec![0x42; 100_000]; // 100KB (reduced for CI)
    let large_start = std::time::Instant::now();
    let large_sig = sign_detached(&large_msg, &keypair.secret_key)?;
    let large_valid = verify_detached(&large_sig, &large_msg, &keypair.public_key)?;
    let large_duration = large_start.elapsed();
    
    println!("  Large message (100KB): {:?}", large_duration);
    results.test("large message handling", large_valid);
    results.test("large message performance", large_duration.as_secs() < 5);
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut results = TestResults::default();
    
    println!("FN-DSA-PADDED-512 Enhanced Comprehensive Test Suite v2");
    println!("Constants: PK={}, SK={}, SIG={}, SEED={}", 
             constants::PUBLIC_KEY_BYTES, constants::SECRET_KEY_BYTES,
             constants::SIGNATURE_BYTES, constants::SEED_BYTES);
    
    // Validate constants
    results.test("reasonable public key size", constants::PUBLIC_KEY_BYTES == 897);
    results.test("reasonable secret key size", constants::SECRET_KEY_BYTES == 1281);
    results.test("reasonable signature size", constants::SIGNATURE_BYTES == 666);
    results.test("reasonable seed size", constants::SEED_BYTES == 48);
    
    // Test 1: Basic functionality
    println!("\n=== BASIC FUNCTIONALITY ===");
    let random_keypair = Keypair::generate()?;
    results.test("random keypair generation", true);
    results.test("public key size", random_keypair.public_key.0.len() == constants::PUBLIC_KEY_BYTES);
    results.test("secret key size", random_keypair.secret_key.0.len() == constants::SECRET_KEY_BYTES);
    
    print_hex_short("Random PK", &random_keypair.public_key.0, 32);
    print_hex_short("Random SK", &random_keypair.secret_key.0, 32);
    
    test_signatures(&random_keypair, "random keys", &mut results)?;
    
    // Test 2: Public key recovery
    println!("\n=== PUBLIC KEY RECOVERY ===");
    let recovered_pk = random_keypair.secret_key.recover_public_key()?;
    results.test("public key recovery", recovered_pk.0 == random_keypair.public_key.0);
    
    // Test 3: Deterministic generation
    println!("\n=== DETERMINISTIC GENERATION ===");
    let seed = [0x42u8; constants::SEED_BYTES];
    let mut seed1 = seed;
    let mut seed2 = seed;
    
    let keypair1 = Keypair::from_seed(&mut seed1)?;
    let keypair2 = Keypair::from_seed(&mut seed2)?;
    
    results.test("seed1 cleared", is_all_zeros(&seed1));
    results.test("seed2 cleared", is_all_zeros(&seed2));
    results.test("deterministic PK", keypair1.public_key.0 == keypair2.public_key.0);
    results.test("deterministic SK", keypair1.secret_key.0 == keypair2.secret_key.0);
    
    test_signatures(&keypair1, "seeded keys", &mut results)?;
    
    // Test 4: Cross-verification
    let test_msg = b"Cross-verification test";
    let sig_from_kp1 = sign_detached(test_msg, &keypair1.secret_key)?;
    let cross_verify = verify_detached(&sig_from_kp1, test_msg, &keypair2.public_key)?;
    results.test("cross-verification identical keys", cross_verify);
    
    // Test 5: Message type coverage
    println!("\n=== MESSAGE TYPES ===");
    let messages = [
        (&b""[..], "empty"),
        (b"x", "single byte"),
        (b"Hello, World!", "ascii text"),
        (&vec![0u8; 100][..], "zeros"),
        (&vec![255u8; 100][..], "ones"),
        (b"\x00\x01\x02\xFF\xFE\xFD", "binary"),
        (&(0..256).map(|i| i as u8).collect::<Vec<_>>()[..], "sequential"),
    ];
    
    for (msg, desc) in &messages {
        let sig = sign_detached(msg, &random_keypair.secret_key)?;
        let valid = verify_detached(&sig, msg, &random_keypair.public_key)?;
        results.test(&format!("msg type: {}", desc), valid);
    }
    
    // Advanced security tests
    test_signature_attacks(&random_keypair, &mut results)?;
    test_signature_properties(&random_keypair, &mut results)?;
    test_edge_cases(&mut results)?;
    test_cross_key_security(&mut results)?;
    test_performance_stress(&mut results)?;
    
    // Test seed uniqueness
    println!("\n=== SEED UNIQUENESS ===");
    let seeds = [[0xAA; constants::SEED_BYTES], [0xBB; constants::SEED_BYTES], [0xCC; constants::SEED_BYTES]];
    let mut keypairs = Vec::new();
    
    for (i, seed) in seeds.iter().enumerate() {
        let mut seed_copy = *seed;
        let kp = Keypair::from_seed(&mut seed_copy)?;
        keypairs.push(kp);
        results.test(&format!("seed {} cleared", i), is_all_zeros(&seed_copy));
    }
    
    // Verify all keys are different
    for i in 0..keypairs.len() {
        for j in i+1..keypairs.len() {
            let keys_different = keypairs[i].public_key.0 != keypairs[j].public_key.0;
            results.test(&format!("keys {}-{} different", i, j), keys_different);
        }
    }
    
    // Final summary
    results.summary();
    
    if results.failed > 0 {
        eprintln!("\n❌ {} test(s) failed - review implementation!", results.failed);
        std::process::exit(1);
    }
    
    println!("\n✅ FN-DSA-PADDED-512 implementation passed all {} tests!", results.passed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_validity() {
        assert_eq!(constants::PUBLIC_KEY_BYTES, 897);
        assert_eq!(constants::SECRET_KEY_BYTES, 1281);
        assert_eq!(constants::SIGNATURE_BYTES, 666);
        assert_eq!(constants::SEED_BYTES, 48);
    }

    #[test]
    fn test_basic_operations() {
        let keypair = Keypair::generate().unwrap();
        let msg = b"test message";
        
        // Test detached
        let det_sig = sign_detached(msg, &keypair.secret_key).unwrap();
        assert_eq!(det_sig.data.len(), constants::SIGNATURE_BYTES);
        assert!(verify_detached(&det_sig, msg, &keypair.public_key).unwrap());
        
        // Test attached
        let att_sig = sign_attached(msg, &keypair.secret_key).unwrap();
        assert_eq!(att_sig.len(), msg.len() + constants::SIGNATURE_BYTES);
        let recovered = verify_attached(&att_sig, &keypair.public_key).unwrap();
        assert_eq!(recovered, msg);
    }
    
    #[test]
    fn test_attack_resistance() {
        let keypair = Keypair::generate().unwrap();
        let msg = b"Attack test message";
        let sig = sign_detached(msg, &keypair.secret_key).unwrap();
        
        // Bit flip attack
        if !sig.data.is_empty() {
            let mut modified = sig.clone();
            modified.data[0] ^= 0x01;
            let result = verify_detached(&modified, msg, &keypair.public_key).unwrap_or(true);
            assert!(!result, "Modified signature should be rejected");
        }
        
        // Length attack
        if sig.data.len() > 10 {
            let mut truncated = sig.clone();
            truncated.data.truncate(sig.data.len() / 2);
            let result = verify_detached(&truncated, msg, &keypair.public_key);
            assert!(result.is_err() || !result.unwrap(), "Truncated signature should be rejected");
        }
    }

    #[test]
    fn test_comprehensive_suite() {
        main().expect("Comprehensive test suite should pass");
    }
}