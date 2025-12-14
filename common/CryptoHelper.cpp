#include "CryptoHelper.hpp"
#include <cstring>
#include <stdexcept>
#include <random>

extern "C" {
    uint32_t random32(void) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<uint32_t> dis;
        return dis(gen);
    }
    
    void random_buffer(uint8_t *buf, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = static_cast<uint8_t>(random32() & 0xFF);
        }
    }

    #include "ecdsa.h"
    #include "secp256k1.h"
    #include "sha2.h"
}

const ecdsa_curve *get_curve() {
    return &secp256k1;
}

std::vector<uint8_t> CryptoHelper::sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    sha256_Raw(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> CryptoHelper::sign(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& privKey) {
    if (hash.size() != 32) throw std::invalid_argument("Hash must be 32 bytes");
    
    std::vector<uint8_t> signature(64); 
    uint8_t pby; 

    int res = ecdsa_sign_digest(
        get_curve(),
        privKey.data(),
        hash.data(),
        signature.data(),
        &pby,
        NULL
    );

    if (res != 0) throw std::runtime_error("Signing failed");
    return signature;
}

bool CryptoHelper::verify(const std::vector<uint8_t>& pubKey, const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature) {
    if (hash.size() != 32 || signature.size() != 64) return false;

    int res = ecdsa_verify_digest(
        get_curve(),
        pubKey.data(),
        signature.data(),
        hash.data()
    );

    return (res == 0); 
}

std::vector<uint8_t> CryptoHelper::generateRandom32() {
    std::vector<uint8_t> rnd(32);
    random_buffer(rnd.data(), 32);
    return rnd;
}