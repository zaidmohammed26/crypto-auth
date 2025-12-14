#pragma once
#include <vector>
#include <cstdint>

class CryptoHelper {
public:
    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

    static std::vector<uint8_t> sign(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& privKey);

    static bool verify(const std::vector<uint8_t>& pubKey, const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature);
    
    static std::vector<uint8_t> generateRandom32();
};