#include <iostream>
#include <string>
#include <set>
#include <ctime>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

class SecureChat {
private:
    RSA* server_rsa_key;
    RSA* client_rsa_key;
    BIGNUM* dh_prime;
    BIGNUM* dh_generator;
    std::set<std::pair<std::string, int>> nonce_cache;

    void clear_sensitive_data() {
        RSA_free(server_rsa_key);
        RSA_free(client_rsa_key);
        BN_free(dh_prime);
        BN_free(dh_generator);
    }

    void initialize_rsa_keys() {
        server_rsa_key = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        client_rsa_key = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    }

    void initialize_diffie_hellman() {
        dh_prime = BN_new();
        dh_generator = BN_new();
        BN_hex2bn(&dh_prime,
            "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48"
            "198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51"
            "F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB"
            "2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A69581105190"
            "7E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9"
            "DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9"
            "FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B"
            "2454BF6F4FADF034B10403119CD8E3B92FCC5B");
        BN_set_word(dh_generator, 2);
    }

public:
    SecureChat() {
        initialize_rsa_keys();
        initialize_diffie_hellman();
    }

    ~SecureChat() {
        clear_sensitive_data();
    }

    // Getter functions to access private keys
    RSA* get_server_rsa_key() const {
        return server_rsa_key;
    }

    RSA* get_client_rsa_key() const {
        return client_rsa_key;
    }

    // Function for generating Diffie-Hellman keypair
    std::pair<BIGNUM*, BIGNUM*> generate_dh_keypair() {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* private_key = BN_new();
        BIGNUM* public_key = BN_new();

        BN_rand_range(private_key, dh_prime);
        BN_mod_exp(public_key, dh_generator, private_key, dh_prime, ctx);

        BN_CTX_free(ctx);
        return {private_key, public_key};
    }

    // Compute shared key for Diffie-Hellman
    std::vector<unsigned char> compute_shared_key(BIGNUM* private_key, BIGNUM* other_public_key) {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* shared_key_bn = BN_new();
        BN_mod_exp(shared_key_bn, other_public_key, private_key, dh_prime, ctx);

        std::vector<unsigned char> shared_key(BN_num_bytes(shared_key_bn));
        BN_bn2bin(shared_key_bn, shared_key.data());

        BN_free(shared_key_bn);
        BN_CTX_free(ctx);
        return shared_key;
    }

    // RSA Encryption
    std::vector<unsigned char> rsa_encrypt(const std::vector<unsigned char>& data, RSA* public_key) {
        std::vector<unsigned char> encrypted(RSA_size(public_key));
        int len = RSA_public_encrypt(
            data.size(), data.data(), encrypted.data(), public_key, RSA_PKCS1_OAEP_PADDING);
        encrypted.resize(len);
        return encrypted;
    }

    // RSA Decryption
    std::vector<unsigned char> rsa_decrypt(const std::vector<unsigned char>& encrypted_data, RSA* private_key) {
        std::vector<unsigned char> decrypted(RSA_size(private_key));
        int len = RSA_private_decrypt(
            encrypted_data.size(), encrypted_data.data(), decrypted.data(), private_key, RSA_PKCS1_OAEP_PADDING);
        decrypted.resize(len);
        return decrypted;
    }

    // HMAC Compute
    std::vector<unsigned char> hmac_compute(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
        unsigned char* hmac_result = HMAC(
            EVP_sha256(), key.data(), key.size(), data.data(), data.size(), nullptr, nullptr);
        return std::vector<unsigned char>(hmac_result, hmac_result + SHA256_DIGEST_LENGTH);
    }

    // HMAC Verify
    bool hmac_verify(const std::vector<unsigned char>& data, const std::vector<unsigned char>& hmac, const std::vector<unsigned char>& key) {
        auto computed_hmac = hmac_compute(data, key);
        return hmac == computed_hmac;
    }

    // Proof of Work
    std::pair<int, std::string> proof_of_work(int difficulty = 4) {
        std::string prefix(difficulty, '0');
        int nonce = 0;
        while (true) {
            std::string candidate = std::to_string(nonce);
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(candidate.c_str()), candidate.size(), hash);

            std::string hash_hex;
            for (unsigned char c : hash) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", c);
                hash_hex += buf;
            }

            if (hash_hex.substr(0, difficulty) == prefix) {
                return {nonce, hash_hex};
            }
            nonce++;
        }
    }

    // Replay Protection Check
    bool check_replay(const std::string& msg_id, int seq_no, int time_window = 300) {
        int current_time = static_cast<int>(std::time(nullptr));
        auto key = std::make_pair(msg_id, seq_no);

        if (nonce_cache.find(key) != nonce_cache.end() || (current_time - std::stoi(msg_id)) > time_window) {
            return false; // Replay or expired
        }

        nonce_cache.insert(key);
        return true;
    }
};

int main() {
    SecureChat secure_chat;

    // Simulate key exchange
    auto [private_key_a, public_key_a] = secure_chat.generate_dh_keypair();
    auto [private_key_b, public_key_b] = secure_chat.generate_dh_keypair();

    auto shared_key_a = secure_chat.compute_shared_key(private_key_a, public_key_b);
    auto shared_key_b = secure_chat.compute_shared_key(private_key_b, public_key_a);

    if (shared_key_a == shared_key_b) {
        std::cout << "Shared keys match!\n";
    } else {
        std::cout << "Shared keys do not match!\n";
    }

    // Example of RSA encryption/decryption using the getter functions
    std::string message = "Secure message!";
    auto encrypted_message = secure_chat.rsa_encrypt(
        std::vector<unsigned char>(message.begin(), message.end()), secure_chat.get_server_rsa_key());
    auto decrypted_message = secure_chat.rsa_decrypt(encrypted_message, secure_chat.get_server_rsa_key());

    std::cout << "Original: " << message << "\nDecrypted: " << std::string(decrypted_message.begin(), decrypted_message.end()) << "\n";

    // Example of HMAC
    auto hmac_value = secure_chat.hmac_compute(
        std::vector<unsigned char>(message.begin(), message.end()), shared_key_a);
    if (secure_chat.hmac_verify(
            std::vector<unsigned char>(message.begin(), message.end()), hmac_value, shared_key_a)) {
        std::cout << "HMAC verification successful!\n";
    } else {
        std::cout << "HMAC verification failed!\n";
    }

    // Proof of Work
    auto [nonce, hash_result] = secure_chat.proof_of_work();
    std::cout << "Proof of Work completed: Nonce=" << nonce << ", Hash=" << hash_result << "\n";

    // Replay protection
    std::string msg_id = std::to_string(std::time(nullptr));
    int seq_no = 1;

    if (secure_chat.check_replay(msg_id, seq_no)) {
        std::cout << "Replay protection passed!\n";
    } else {
        std::cout << "Replay detected!\n";
    }

    return 0;
}
