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

// Funkce pro rotaci klíče
std::vector<unsigned char> rotateSessionKey(const std::vector<unsigned char>& sharedSecret, size_t iteration) {
    // Derivace nového klíče pomocí SHA-256 a čísla iterace pro FS
    std::vector<unsigned char> key(32);
    std::vector<unsigned char> iterData = sharedSecret;
    iterData.push_back((iteration >> 24) & 0xFF);  // Add iteration number to ensure uniqueness
    iterData.push_back((iteration >> 16) & 0xFF);
    iterData.push_back((iteration >> 8) & 0xFF);
    iterData.push_back(iteration & 0xFF);
    
    SHA256(iterData.data(), iterData.size(), key.data());
    
    return key;
}

// Funkce pro generování sdíleného tajemství mezi uživateli
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

// Encrypt data using AES-256-GCM with Auth Tag
std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    RAND_bytes(iv.data(), iv.size());

    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());
    
    // Encrypt the plaintext
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertextLen = len;

    // Finalize encryption and get the authentication tag
    unsigned char authTag[AES_BLOCK_SIZE];
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertextLen += len;
    
    // Get the authentication tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_BLOCK_SIZE, authTag);
    
    // Append the IV and Auth Tag to the ciphertext
    ciphertext.resize(ciphertextLen + AES_BLOCK_SIZE * 2);  // Space for IV + AuthTag
    std::copy(iv.begin(), iv.end(), ciphertext.end() - (AES_BLOCK_SIZE * 2)); // IV at the end
    std::copy(authTag, authTag + AES_BLOCK_SIZE, ciphertext.end() - AES_BLOCK_SIZE); // Auth tag at the end

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// Decrypt data using AES-256-GCM with Auth Tag
std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    // Extract IV and Auth Tag from the ciphertext
    std::vector<unsigned char> iv(ciphertext.end() - (AES_BLOCK_SIZE * 2), ciphertext.end() - AES_BLOCK_SIZE);
    std::vector<unsigned char> authTag(ciphertext.end() - AES_BLOCK_SIZE, ciphertext.end());
    
    std::vector<unsigned char> plaintext(ciphertext.size() - AES_BLOCK_SIZE * 2);

    int len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size() - AES_BLOCK_SIZE * 2);
    int plaintextLen = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_BLOCK_SIZE, authTag.data());
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintextLen += len;

    // If the tag is invalid, the decryption fails
    if (ret > 0) {
        plaintext.resize(plaintextLen);
    } else {
        plaintext.clear(); // Decryption failed, data integrity compromised
    }

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

