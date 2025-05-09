#ifndef CRYPTO_LIBRARY_HPP
#define CRYPTO_LIBRARY_HPP

#include <iostream>
#include <vector>
#include <string>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// Constants for Diffie-Hellman
const std::string DH_PRIME_HEX = "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B";
const int DH_GENERATOR = 2;

// Utility Functions
std::vector<uint8_t> getRandomBytes(size_t length);

// RSA Key Pair Generation
std::pair<std::string, std::string> generateRSAKeyPair();

// Diffie-Hellman Key Exchange
std::vector<uint8_t> diffieHellmanKeyExchange();

// AES Encryption (GCM for messages and CTR for voice calls)
std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>> aesEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::string& mode = "GCM");
std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag = {}, const std::string& mode = "GCM");

// Authorization Key Generation
std::vector<uint8_t> generateAuthKey();

#endif // CRYPTO_LIBRARY_HPP
