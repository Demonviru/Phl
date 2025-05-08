#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <fstream>

// Function to derive a key using SHA256
std::vector<unsigned char> deriveKey(const unsigned char* sharedSecret, size_t sharedSecretLen) {
    std::vector<unsigned char> derivedKey(SHA256_DIGEST_LENGTH);
    SHA256(sharedSecret, sharedSecretLen, derivedKey.data());
    return derivedKey;
}

std::vector<unsigned char> xordeobfucate(const std::vector<unsigned char>& obfuscatedData, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> decryptedData(obfuscatedData.size());
    for (size_t i = 0; i < obfuscatedData.size(); ++i) {
        decryptedData[i] = obfuscatedData[i] ^ key[i % key.size()];
    }
    return decryptedData;
}

// Verify the message signature using RSA-2048
bool verysignature(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature, EVP_PKEY* publicKey) {
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkeyCtx = NULL;

    EVP_DigestVerifyInit(mdCtx, &pkeyCtx, EVP_sha256(), NULL, publicKey);
    EVP_DigestVerifyUpdate(mdCtx, message.data(), message.size());
    int result = EVP_DigestVerifyFinal(mdCtx, signature.data(), signature.size());

    EVP_MD_CTX_free(mdCtx);

    return (result == 1); // 1 indicates successful verification
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

// Encrypt data using AES-256-GCM
std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    RAND_bytes(iv.data(), iv.size());

    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertextLen = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertextLen += len;

    ciphertext.resize(ciphertextLen);
    ciphertext.insert(ciphertext.end(), iv.begin(), iv.end()); // Append IV
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// Decrypt data using AES-256-GCM
std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> iv(ciphertext.end() - AES_BLOCK_SIZE, ciphertext.end());
    std::vector<unsigned char> plaintext(ciphertext.size() - AES_BLOCK_SIZE);

    int len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size() - AES_BLOCK_SIZE);
    int plaintextLen = len;

    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintextLen += len;

    plaintext.resize(plaintextLen);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

// Sign data using RSA-2048
std::vector<unsigned char> signMessage(const std::vector<unsigned char>& message, EVP_PKEY* privateKey) {
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkeyCtx = NULL;
    std::vector<unsigned char> signature(EVP_PKEY_size(privateKey));

    size_t sigLen = 0;
    EVP_DigestSignInit(mdCtx, &pkeyCtx, EVP_sha256(), NULL, privateKey);
    EVP_DigestSignUpdate(mdCtx, message.data(), message.size());
    EVP_DigestSignFinal(mdCtx, signature.data(), &sigLen);

    signature.resize(sigLen);
    EVP_MD_CTX_free(mdCtx);

    return signature;
}

// XOR-based Transport Obfuscation
std::vector<unsigned char> xorObfuscate(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> obfuscated(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        obfuscated[i] = data[i] ^ key[i % key.size()];
    }
    return obfuscated;
}

// Main Function
int main() {
    // Generate key pairs for two parties (Alice and Bob)
    EVP_PKEY* aliceKeyPair = generateKeyPair();
    EVP_PKEY* bobKeyPair = generateKeyPair();

    // Compute shared secrets
    auto aliceSharedSecret = computeSharedSecret(aliceKeyPair, bobKeyPair);
    auto bobSharedSecret = computeSharedSecret(bobKeyPair, aliceKeyPair);

    // Derive session keys
    auto aliceDerivedKey = deriveKey(aliceSharedSecret.data(), aliceSharedSecret.size());
    auto bobDerivedKey = deriveKey(bobSharedSecret.data(), bobSharedSecret.size());

    // Example message
    std::string message = "Hello, secure world!";
    std::vector<unsigned char> plaintext(message.begin(), message.end());

    // Encrypt the message
    auto ciphertext = encrypt(plaintext, aliceDerivedKey);

    // Decrypt the message
    auto decryptedText = decrypt(ciphertext, bobDerivedKey);

    // Display results
    std::cout << "Original Message: " << message << std::endl;
    std::cout << "Decrypted Message: " << std::string(decryptedText.begin(), decryptedText.end()) << std::endl;

    // Cleanup
    EVP_PKEY_free(aliceKeyPair);
    EVP_PKEY_free(bobKeyPair);

    return 0;
}
