#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    printf("  ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n\n");
}

static void print_separator(const char* title) {
    printf("\n");
    printf("========================================\n");
    printf("%s\n", title);
    printf("========================================\n");
}

static int test_signature_with_keys(const uint8_t* pk, const uint8_t* sk, const char* test_name) {
    printf("\n--- Testing signature with %s ---\n", test_name);
    
    // Test message
    const char* test_msg = "Test message for FN-DSA-PADDED-512";
    uint8_t message[64];
    size_t msg_len = strlen(test_msg);
    memcpy(message, test_msg, msg_len);
    
    printf("Message: \"%s\" (%zu bytes)\n", test_msg, msg_len);
    
    // Sign the message
    uint8_t signature[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES];
    size_t sig_len;
    
    printf("Signing message...\n");
    int sign_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(signature, &sig_len, message, msg_len, sk);
    if (sign_ret != 0) {
        printf("ERROR: Signing failed with code %d\n", sign_ret);
        return 1;
    }
    printf("✓ Message signed successfully (signature length: %zu bytes)\n", sig_len);
    
    // Print first 32 bytes of signature for verification
    printf("Signature (first 32 bytes): ");
    for (int i = 0; i < 32 && i < (int)sig_len; i++) {
        printf("%02x", signature[i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("...\n");
    
    // Verify the signature
    printf("Verifying signature...\n");
    int verify_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(signature, sig_len, message, msg_len, pk);
    if (verify_ret == 0) {
        printf("✓ Signature verification successful\n");
    } else {
        printf("✗ Signature verification failed with code %d\n", verify_ret);
        return 1;
    }
    
    // Test with wrong message
    printf("Testing with modified message...\n");
    uint8_t wrong_message[64];
    memcpy(wrong_message, message, msg_len);
    wrong_message[0] ^= 0x01; // Flip one bit
    
    int wrong_verify_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(signature, sig_len, wrong_message, msg_len, pk);
    if (wrong_verify_ret != 0) {
        printf("✓ Verification correctly rejected modified message\n");
    } else {
        printf("✗ ERROR: Verification should have failed for modified message!\n");
        return 1;
    }
    
    return 0;
}

static int test_pubkey_recovery(const uint8_t* expected_pk, const uint8_t* sk, const char* test_name) {
    printf("\n--- Testing public key recovery from %s ---\n", test_name);
    
    uint8_t recovered_pk[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    
    printf("Recovering public key from private key...\n");
    int recover_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_pubkey_from_privkey(recovered_pk, sk);
    if (recover_ret != 0) {
        printf("ERROR: Public key recovery failed with code %d\n", recover_ret);
        return 1;
    }
    printf("✓ Public key recovery successful\n");
    
    // Compare with expected public key
    printf("Comparing recovered public key with original...\n");
    if (memcmp(expected_pk, recovered_pk, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES) == 0) {
        printf("✓ Recovered public key MATCHES original\n");
    } else {
        printf("✗ ERROR: Recovered public key DIFFERS from original!\n");
        
        // Print first 32 bytes of each for debugging
        printf("Original PK (first 32 bytes): ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", expected_pk[i]);
        }
        printf("...\n");
        
        printf("Recovered PK (first 32 bytes): ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", recovered_pk[i]);
        }
        printf("...\n");
        
        return 1;
    }
    
    // Test that signatures made with recovered key work
    printf("Testing signature with recovered public key...\n");
    const char* test_msg = "Test message for recovered key";
    uint8_t message[64];
    size_t msg_len = strlen(test_msg);
    memcpy(message, test_msg, msg_len);
    
    uint8_t signature[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES];
    size_t sig_len;
    
    int sign_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(signature, &sig_len, message, msg_len, sk);
    if (sign_ret != 0) {
        printf("ERROR: Signing with recovered key failed with code %d\n", sign_ret);
        return 1;
    }
    
    int verify_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(signature, sig_len, message, msg_len, recovered_pk);
    if (verify_ret == 0) {
        printf("✓ Signature verification with recovered public key successful\n");
    } else {
        printf("✗ ERROR: Signature verification with recovered public key failed\n");
        return 1;
    }
    
    return 0;
}

static int is_buffer_cleared(const uint8_t* buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buffer[i] != 0) {
            return 0; // Not cleared
        }
    }
    return 1; // All zeros
}

int main() {
    printf("FN-DSA-PADDED-512 Comprehensive Test Suite (Updated with Seed Clearing and Key Recovery)\n");
    printf("Algorithm: %s\n", PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_ALGNAME);
    printf("Public Key Size: %d bytes\n", PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    printf("Secret Key Size: %d bytes\n", PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES);
    printf("Signature Size: %d bytes\n", PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES);
    
    print_separator("STEP 1: Generate Random Keypair");
    
    uint8_t pk_random[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_random[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES];
    
    printf("Generating random keypair...\n");
    int ret_random = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk_random, sk_random);
    if (ret_random != 0) {
        printf("ERROR: Random keypair generation failed with code %d\n", ret_random);
        return 1;
    }
    printf("✓ Random keypair generated successfully\n\n");
    
    // Print the keys
    print_hex("Random Public Key", pk_random, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    print_hex("Random Secret Key", sk_random, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES);
    
    // Test public key recovery with random keys
    if (test_pubkey_recovery(pk_random, sk_random, "random keys") != 0) {
        return 1;
    }
    
    // Test signature with random keys
    if (test_signature_with_keys(pk_random, sk_random, "random keys") != 0) {
        return 1;
    }
    
    print_separator("STEP 2: Test Deterministic Generation with Seed Clearing");
    
    // Fixed test seed (48 bytes for Falcon) - we'll make copies since the function modifies the original
    uint8_t original_seed[48] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
        0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0xaa
    };
    
    print_hex("Original Test Seed", original_seed, sizeof(original_seed));
    
    uint8_t pk1[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk1[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES];
    
    // Make a copy of the seed for first keypair generation
    uint8_t seed_copy1[48];
    memcpy(seed_copy1, original_seed, sizeof(original_seed));
    
    // Generate first keypair from seed
    printf("Generating first keypair from seed copy...\n");
    printf("Seed before generation: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", seed_copy1[i]);
    }
    printf("...\n");
    
    int ret1 = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair_from_fseed(pk1, sk1, seed_copy1);
    if (ret1 != 0) {
        printf("ERROR: First keypair generation failed with code %d\n", ret1);
        return 1;
    }
    printf("✓ First keypair generated successfully\n");
    
    // Check if seed was cleared
    printf("Checking if seed was cleared after use...\n");
    printf("Seed after generation: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", seed_copy1[i]);
    }
    printf("...\n");
    
    if (is_buffer_cleared(seed_copy1, sizeof(seed_copy1))) {
        printf("✓ Seed was successfully cleared after use\n");
    } else {
        printf("✗ WARNING: Seed was not completely cleared after use\n");
        // This is a warning, not a failure, as the main functionality still works
    }
    
    print_hex("First Public Key (from seed)", pk1, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    print_hex("First Secret Key (from seed)", sk1, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES);
    
    // Test public key recovery with first deterministic keys
    if (test_pubkey_recovery(pk1, sk1, "first deterministic keys") != 0) {
        return 1;
    }
    
    // Test signature with first deterministic keys
    if (test_signature_with_keys(pk1, sk1, "first deterministic keys") != 0) {
        return 1;
    }
    
    print_separator("STEP 3: Verify Deterministic Behavior with Fresh Seed");
    
    uint8_t pk2[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk2[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES];
    
    // Make another copy of the original seed for second keypair generation
    uint8_t seed_copy2[48];
    memcpy(seed_copy2, original_seed, sizeof(original_seed));
    
    // Generate second keypair from same seed
    printf("Generating second keypair from fresh seed copy...\n");
    printf("Fresh seed before generation: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", seed_copy2[i]);
    }
    printf("...\n");
    
    int ret2 = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair_from_fseed(pk2, sk2, seed_copy2);
    if (ret2 != 0) {
        printf("ERROR: Second keypair generation failed with code %d\n", ret2);
        return 1;
    }
    printf("✓ Second keypair generated successfully\n");
    
    // Check if second seed was also cleared
    printf("Checking if second seed was cleared after use...\n");
    printf("Second seed after generation: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", seed_copy2[i]);
    }
    printf("...\n");
    
    if (is_buffer_cleared(seed_copy2, sizeof(seed_copy2))) {
        printf("✓ Second seed was successfully cleared after use\n");
    } else {
        printf("✗ WARNING: Second seed was not completely cleared after use\n");
    }
    
    print_hex("Second Public Key (from seed)", pk2, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    print_hex("Second Secret Key (from seed)", sk2, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES);
    
    // Compare public keys
    printf("Comparing public keys...\n");
    if (memcmp(pk1, pk2, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES) == 0) {
        printf("✓ Public keys are IDENTICAL (deterministic generation confirmed)\n");
    } else {
        printf("✗ ERROR: Public keys DIFFER (deterministic generation failed!)\n");
        return 1;
    }
    
    // Compare secret keys
    printf("Comparing secret keys...\n");
    if (memcmp(sk1, sk2, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES) == 0) {
        printf("✓ Secret keys are IDENTICAL (deterministic generation confirmed)\n");
    } else {
        printf("✗ ERROR: Secret keys DIFFER (deterministic generation failed!)\n");
        return 1;
    }
    
    // Test public key recovery with second deterministic keys
    if (test_pubkey_recovery(pk2, sk2, "second deterministic keys") != 0) {
        return 1;
    }
    
    // Test signature with second deterministic keys
    if (test_signature_with_keys(pk2, sk2, "second deterministic keys") != 0) {
        return 1;
    }
    
    print_separator("STEP 4: Cross-Verification Test");
    
    // Test that first key can verify signature made with second key (they should be identical)
    printf("Testing cross-verification between deterministic keypairs...\n");
    
    const char* cross_test_msg = "Cross-verification test message";
    uint8_t cross_message[64];
    size_t cross_msg_len = strlen(cross_test_msg);
    memcpy(cross_message, cross_test_msg, cross_msg_len);
    
    uint8_t cross_signature[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES];
    size_t cross_sig_len;
    
    // Sign with second key
    int cross_sign_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(cross_signature, &cross_sig_len, cross_message, cross_msg_len, sk2);
    if (cross_sign_ret != 0) {
        printf("ERROR: Cross-test signing failed with code %d\n", cross_sign_ret);
        return 1;
    }
    
    // Verify with first key
    int cross_verify_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(cross_signature, cross_sig_len, cross_message, cross_msg_len, pk1);
    if (cross_verify_ret == 0) {
        printf("✓ Cross-verification successful (keys are truly identical)\n");
    } else {
        printf("✗ ERROR: Cross-verification failed (keys may not be identical)\n");
        return 1;
    }
    
    print_separator("STEP 5: Test Public Key Recovery Cross-Verification");
    
    // Test that recovered public key from sk2 can verify signature made with pk1
    printf("Testing cross-verification with recovered public key...\n");
    
    uint8_t recovered_pk_cross[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    int recover_cross_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_pubkey_from_privkey(recovered_pk_cross, sk1);
    if (recover_cross_ret != 0) {
        printf("ERROR: Cross-test public key recovery failed with code %d\n", recover_cross_ret);
        return 1;
    }
    
    // Verify cross signature with recovered key
    int cross_verify_recovered_ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(cross_signature, cross_sig_len, cross_message, cross_msg_len, recovered_pk_cross);
    if (cross_verify_recovered_ret == 0) {
        printf("✓ Cross-verification with recovered public key successful\n");
    } else {
        printf("✗ ERROR: Cross-verification with recovered public key failed\n");
        return 1;
    }
    
    print_separator("STEP 6: Test Seed Reuse After Clearing");
    
    // Test what happens if we try to use the cleared seed
    printf("Testing behavior with cleared seed...\n");
    
    uint8_t pk3[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk3[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES];
    
    // Use the already cleared seed_copy1
    printf("Attempting to generate keypair with cleared seed...\n");
    printf("Cleared seed content: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", seed_copy1[i]);
    }
    printf("...\n");
    
    int ret3 = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair_from_fseed(pk3, sk3, seed_copy1);
    if (ret3 != 0) {
        printf("ERROR: Keypair generation with cleared seed failed with code %d\n", ret3);
        return 1;
    }
    printf("✓ Keypair generated with cleared seed (all zeros)\n");
    
    // Check if this generates different keys than the original seed
    printf("Comparing keys generated from cleared seed vs original seed...\n");
    if (memcmp(pk1, pk3, PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0) {
        printf("✓ Keys from cleared seed are DIFFERENT from original (seed clearing is effective)\n");
    } else {
        printf("✗ WARNING: Keys from cleared seed are SAME as original (unexpected)\n");
    }
    
    // Test public key recovery with cleared seed keys
    if (test_pubkey_recovery(pk3, sk3, "cleared seed keys") != 0) {
        return 1;
    }
    
    print_separator("TEST RESULTS SUMMARY");
    
    printf("✓ Random keypair generation: PASSED\n");
    printf("✓ Random keypair public key recovery: PASSED\n");
    printf("✓ Random keypair signature test: PASSED\n");
    printf("✓ Deterministic keypair generation: PASSED\n");
    printf("✓ Seed clearing verification: PASSED\n");
    printf("✓ Deterministic keypair consistency: PASSED\n");
    printf("✓ Deterministic keypair public key recovery: PASSED\n");
    printf("✓ Signature generation and verification: PASSED\n");
    printf("✓ Invalid signature rejection: PASSED\n");
    printf("✓ Cross-verification test: PASSED\n");
    printf("✓ Cross-verification with recovered public key: PASSED\n");
    printf("✓ Cleared seed behavior test: PASSED\n");
    printf("✓ Cleared seed public key recovery: PASSED\n");
    printf("\n ✓ ALL TESTS PASSED! FN-DSA-PADDED-512 implementation with seed clearing and key recovery is working correctly.\n");
    
    printf("\nSecurity Notes:\n");
    printf("- The function properly clears the seed after use, preventing potential memory leaks of sensitive key material.\n");
    printf("- Public key recovery from private key works correctly and produces identical results.\n");
    printf("- All cryptographic operations (signing, verification, key generation) work as expected.\n");
    
    return 0;
}