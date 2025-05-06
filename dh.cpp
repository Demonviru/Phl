#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>

// Function to derive a key using SHA256
std::vector<unsigned char> deriveKey(const unsigned char* sharedSecret, size_t sharedSecretLen) {
    std::vector<unsigned char> derivedKey(SHA256_DIGEST_LENGTH);
    SHA256(sharedSecret, sharedSecretLen, derivedKey.data());
    return derivedKey;
}

// Generate an EC key pair
EVP_PKEY* generateKeyPair() {
    EVP_PKEY_CTX* paramCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY* params = NULL;
    EVP_PKEY_paramgen_init(paramCtx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, NID_X9_62_prime256v1);
    EVP_PKEY_paramgen(paramCtx, &params);

    EVP_PKEY_CTX* keyCtx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY* keyPair = NULL;
    EVP_PKEY_keygen_init(keyCtx);
    EVP_PKEY_keygen(keyCtx, &keyPair);

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(keyCtx);
    EVP_PKEY_CTX_free(paramCtx);

    return keyPair;
}

// Compute a shared secret
std::vector<unsigned char> computeSharedSecret(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peerPublicKey);

    size_t secretLen = 0;
    EVP_PKEY_derive(ctx, NULL, &secretLen);
    std::vector<unsigned char> sharedSecret(secretLen);
    EVP_PKEY_derive(ctx, sharedSecret.data(), &secretLen);

    EVP_PKEY_CTX_free(ctx);
    return sharedSecret;
}

// Key rotation mechanism
void rotateKey(EVP_PKEY*& keyPair) {
    EVP_PKEY_free(keyPair);
    keyPair = generateKeyPair();
}

// Print a key in hex format
void printKey(const std::vector<unsigned char>& key, const std::string& label) {
    std::cout << label << ": ";
    for (const auto& byte : key) {
        printf("%02x", byte);
    }
    std::cout << std::endl;
}

int main() {
    // Generate key pairs for two parties (Alice and Bob)
    EVP_PKEY* aliceKeyPair = generateKeyPair();
    EVP_PKEY* bobKeyPair = generateKeyPair();

    // Extract public keys
    EVP_PKEY* alicePublicKey = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(alicePublicKey, aliceKeyPair);

    EVP_PKEY* bobPublicKey = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(bobPublicKey, bobKeyPair);

    // Compute shared secrets
    auto aliceSharedSecret = computeSharedSecret(aliceKeyPair, bobPublicKey);
    auto bobSharedSecret = computeSharedSecret(bobKeyPair, alicePublicKey);

    // Derive keys using SHA256
    auto aliceDerivedKey = deriveKey(aliceSharedSecret.data(), aliceSharedSecret.size());
    auto bobDerivedKey = deriveKey(bobSharedSecret.data(), bobSharedSecret.size());

    // Print the derived keys
    printKey(aliceDerivedKey, "Alice's Derived Key");
    printKey(bobDerivedKey, "Bob's Derived Key");

    // Verify that both parties derived the same key
    if (aliceDerivedKey == bobDerivedKey) {
        std::cout << "Key agreement successful. The keys match!" << std::endl;
    } else {
        std::cout << "Key agreement failed. The keys do not match!" << std::endl;
    }

    // Rotate keys
    rotateKey(aliceKeyPair);
    rotateKey(bobKeyPair);

    // Cleanup
    EVP_PKEY_free(aliceKeyPair);
    EVP_PKEY_free(bobKeyPair);
    EVP_PKEY_free(alicePublicKey);
    EVP_PKEY_free(bobPublicKey);

    return 0;
}
