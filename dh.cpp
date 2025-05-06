#include <openssl/evp.h>
#include <openssl/bn.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <openssl/dh.h>  // Add this line

void print_hex(const std::vector<unsigned char>& buffer) {
    for (unsigned char byte : buffer)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    std::cout << std::dec << std::endl;
}

// RFC 3526 MODP Group 15 Prime and Generator
const char* MODP15_PRIME_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE65381FFFFFFFFFFFFFFFF";

int main() {
    // Create DH parameters (MODP Group 15)
    BIGNUM* p = nullptr;
    BN_hex2bn(&p, MODP15_PRIME_HEX);
    BIGNUM* g = BN_new();
    BN_set_word(g, 2);

    // Create DH params and wrap in EVP_PKEY
    EVP_PKEY* params = nullptr;
    {
        DH* dh = DH_new();
        DH_set0_pqg(dh, p, nullptr, g);
        params = EVP_PKEY_new();
        EVP_PKEY_assign_DH(params, dh);
    }

    // Generate Alice's key
    EVP_PKEY_CTX* alice_ctx = EVP_PKEY_CTX_new(params, nullptr);
    EVP_PKEY* alice_key = nullptr;
    EVP_PKEY_keygen_init(alice_ctx);
    EVP_PKEY_keygen(alice_ctx, &alice_key);
    EVP_PKEY_CTX_free(alice_ctx);

    // Generate Bob's key
    EVP_PKEY_CTX* bob_ctx = EVP_PKEY_CTX_new(params, nullptr);
    EVP_PKEY* bob_key = nullptr;
    EVP_PKEY_keygen_init(bob_ctx);
    EVP_PKEY_keygen(bob_ctx, &bob_key);
    EVP_PKEY_CTX_free(bob_ctx);

    // Derive Alice's secret using Bob's public key
    EVP_PKEY_CTX* derive_ctx1 = EVP_PKEY_CTX_new(alice_key, nullptr);
    EVP_PKEY_derive_init(derive_ctx1);
    EVP_PKEY_derive_set_peer(derive_ctx1, bob_key);
    size_t secret_len;
    EVP_PKEY_derive(derive_ctx1, nullptr, &secret_len);
    std::vector<unsigned char> alice_secret(secret_len);
    EVP_PKEY_derive(derive_ctx1, alice_secret.data(), &secret_len);
    EVP_PKEY_CTX_free(derive_ctx1);

    // Derive Bob's secret using Alice's public key
    EVP_PKEY_CTX* derive_ctx2 = EVP_PKEY_CTX_new(bob_key, nullptr);
    EVP_PKEY_derive_init(derive_ctx2);
    EVP_PKEY_derive_set_peer(derive_ctx2, alice_key);
    std::vector<unsigned char> bob_secret(secret_len);
    EVP_PKEY_derive(derive_ctx2, bob_secret.data(), &secret_len);
    EVP_PKEY_CTX_free(derive_ctx2);

    // Compare secrets
    bool match = (alice_secret == bob_secret);
    std::cout << "Shared secret match: " << (match ? "YES" : "NO") << std::endl;

    std::cout << "Alice's Secret: "; print_hex(alice_secret);
    std::cout << "Bob's Secret  : "; print_hex(bob_secret);
    std::cout << "Secret Length (bytes): " << secret_len << std::endl;

    // Clean up
    EVP_PKEY_free(alice_key);
    EVP_PKEY_free(bob_key);
    EVP_PKEY_free(params);

    return 0;
}
