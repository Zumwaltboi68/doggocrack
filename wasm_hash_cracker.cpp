/*
 * Ultra-Fast Hash Cracker - WebAssembly Compatible
 * Compile with: emcc -O3 -s WASM=1 -s EXPORTED_FUNCTIONS="['_ultraCrack','_hashSHA256','_hashMD5','_getHashRate']" hash_cracker.cpp -o hash_cracker.js
 */

#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define EXPORT EMSCRIPTEN_KEEPALIVE extern "C"
#else
#define EXPORT
#include <iostream>
#include <chrono>
#endif

// Inline helper for better performance
#define INLINE inline __attribute__((always_inline))

// Rotate operations
INLINE uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

INLINE uint32_t rotl(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// SHA-256 Constants
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 Implementation
class SHA256 {
private:
    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t bitlen;
    uint32_t datalen;

    INLINE uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    INLINE uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    INLINE uint32_t sig0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    INLINE uint32_t sig1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    INLINE uint32_t gamma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    INLINE uint32_t gamma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void transform() {
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, h, t1, t2;

        // Prepare message schedule
        for (int i = 0; i < 16; i++) {
            w[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) |
                   (buffer[i * 4 + 2] << 8) | (buffer[i * 4 + 3]);
        }

        for (int i = 16; i < 64; i++) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }

        // Initialize working variables
        a = state[0]; b = state[1]; c = state[2]; d = state[3];
        e = state[4]; f = state[5]; g = state[6]; h = state[7];

        // Main loop
        for (int i = 0; i < 64; i++) {
            t1 = h + sig1(e) + ch(e, f, g) + K256[i] + w[i];
            t2 = sig0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        // Update state
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

public:
    SHA256() { init(); }

    void init() {
        datalen = 0;
        bitlen = 0;
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
    }

    void update(const uint8_t data[], size_t len) {
        for (size_t i = 0; i < len; i++) {
            buffer[datalen++] = data[i];
            if (datalen == 64) {
                transform();
                bitlen += 512;
                datalen = 0;
            }
        }
    }

    void final(uint8_t hash[32]) {
        uint32_t i = datalen;

        // Padding
        if (datalen < 56) {
            buffer[i++] = 0x80;
            while (i < 56) buffer[i++] = 0x00;
        } else {
            buffer[i++] = 0x80;
            while (i < 64) buffer[i++] = 0x00;
            transform();
            memset(buffer, 0, 56);
        }

        // Append length
        bitlen += datalen * 8;
        buffer[63] = bitlen;
        buffer[62] = bitlen >> 8;
        buffer[61] = bitlen >> 16;
        buffer[60] = bitlen >> 24;
        buffer[59] = bitlen >> 32;
        buffer[58] = bitlen >> 40;
        buffer[57] = bitlen >> 48;
        buffer[56] = bitlen >> 56;
        transform();

        // Output hash
        for (i = 0; i < 4; i++) {
            hash[i]      = (state[0] >> (24 - i * 8)) & 0xff;
            hash[i + 4]  = (state[1] >> (24 - i * 8)) & 0xff;
            hash[i + 8]  = (state[2] >> (24 - i * 8)) & 0xff;
            hash[i + 12] = (state[3] >> (24 - i * 8)) & 0xff;
            hash[i + 16] = (state[4] >> (24 - i * 8)) & 0xff;
            hash[i + 20] = (state[5] >> (24 - i * 8)) & 0xff;
            hash[i + 24] = (state[6] >> (24 - i * 8)) & 0xff;
            hash[i + 28] = (state[7] >> (24 - i * 8)) & 0xff;
        }
    }

    void hash(const char* str, size_t len, uint8_t out[32]) {
        init();
        update((const uint8_t*)str, len);
        final(out);
    }
};

// MD5 Implementation
class MD5 {
private:
    static const uint32_t S[64];
    static const uint32_t T[64];

    INLINE uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (~x & z);
    }

    INLINE uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
        return (x & z) | (y & ~z);
    }

    INLINE uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }

    INLINE uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
        return y ^ (x | ~z);
    }

public:
    void hash(const char* str, size_t len, uint8_t out[16]) {
        uint32_t h[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
        
        // Simplified for short strings
        uint8_t padded[64] = {0};
        memcpy(padded, str, len);
        padded[len] = 0x80;
        
        uint64_t bitLen = len * 8;
        memcpy(padded + 56, &bitLen, 8);
        
        uint32_t* w = (uint32_t*)padded;
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        
        // Round 1
        for (int i = 0; i < 16; i++) {
            uint32_t temp = a + F(b, c, d) + w[i] + T[i];
            a = d; d = c; c = b; b += rotl(temp, S[i]);
        }
        
        // Round 2
        for (int i = 16; i < 32; i++) {
            int g = (5 * i + 1) % 16;
            uint32_t temp = a + G(b, c, d) + w[g] + T[i];
            a = d; d = c; c = b; b += rotl(temp, S[i]);
        }
        
        // Round 3
        for (int i = 32; i < 48; i++) {
            int g = (3 * i + 5) % 16;
            uint32_t temp = a + H(b, c, d) + w[g] + T[i];
            a = d; d = c; c = b; b += rotl(temp, S[i]);
        }
        
        // Round 4
        for (int i = 48; i < 64; i++) {
            int g = (7 * i) % 16;
            uint32_t temp = a + I(b, c, d) + w[g] + T[i];
            a = d; d = c; c = b; b += rotl(temp, S[i]);
        }
        
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        memcpy(out, h, 16);
    }
};

const uint32_t MD5::S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

const uint32_t MD5::T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// Hash Cracker Engine
class HashCracker {
private:
    std::atomic<bool> running;
    std::atomic<bool> found;
    std::atomic<uint64_t> totalHashes;
    std::string result;

public:
    HashCracker() : running(false), found(false), totalHashes(0) {}

    void indexToString(uint64_t index, int length, const char* charset, int charsetLen, char* out) {
        for (int i = length - 1; i >= 0; i--) {
            out[i] = charset[index % charsetLen];
            index /= charsetLen;
        }
        out[length] = '\0';
    }

    void hexToBytes(const char* hex, uint8_t* bytes, int len) {
        for (int i = 0; i < len; i++) {
            char byte[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
            bytes[i] = (uint8_t)strtol(byte, nullptr, 16);
        }
    }

    bool compareHash(const uint8_t* h1, const uint8_t* h2, int len) {
        return memcmp(h1, h2, len) == 0;
    }

    void crackWorker(const char* targetHashHex, const char* charset, int length, 
                     uint64_t start, uint64_t end, int algorithm) {
        uint8_t targetHash[32];
        uint8_t candidateHash[32];
        char candidate[32];
        
        int hashLen = (algorithm == 0) ? 32 : 16;
        hexToBytes(targetHashHex, targetHash, hashLen);
        
        int charsetLen = strlen(charset);
        SHA256 sha256;
        MD5 md5;
        
        for (uint64_t i = start; i < end && running.load() && !found.load(); i++) {
            indexToString(i, length, charset, charsetLen, candidate);
            
            if (algorithm == 0) {
                sha256.hash(candidate, length, candidateHash);
            } else {
                md5.hash(candidate, length, candidateHash);
            }
            
            totalHashes++;
            
            if (compareHash(candidateHash, targetHash, hashLen)) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    result = candidate;
                    running.store(false);
                    return;
                }
            }
        }
    }

    std::string crack(const char* hash, const char* charset, int maxLen, int algorithm) {
        if (running.load()) return "";
        
        running.store(true);
        found.store(false);
        totalHashes.store(0);
        result.clear();
        
        int numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
        
        for (int len = 1; len <= maxLen && running.load() && !found.load(); len++) {
            uint64_t total = 1;
            int charsetLen = strlen(charset);
            for (int i = 0; i < len; i++) {
                total *= charsetLen;
            }
            
            uint64_t perThread = total / numThreads;
            std::vector<std::thread> threads;
            
            for (int t = 0; t < numThreads; t++) {
                uint64_t start = t * perThread;
                uint64_t end = (t == numThreads - 1) ? total : (t + 1) * perThread;
                
                threads.emplace_back(&HashCracker::crackWorker, this, 
                                   hash, charset, len, start, end, algorithm);
            }
            
            for (auto& thread : threads) {
                thread.join();
            }
            
            if (found.load()) break;
        }
        
        running.store(false);
        return result;
    }

    void stop() { running.store(false); }
    uint64_t getHashes() const { return totalHashes.load(); }
    bool isRunning() const { return running.load(); }
};

// Global instance
static HashCracker cracker;

// WebAssembly Exports
EXPORT const char* ultraCrack(const char* hash, const char* charset, int maxLength, int algorithm) {
    static std::string result;
    result = cracker.crack(hash, charset, maxLength, algorithm);
    return result.empty() ? nullptr : result.c_str();
}

EXPORT uint64_t getHashRate() {
    return cracker.getHashes();
}

EXPORT void stopCracking() {
    cracker.stop();
}

EXPORT int isRunning() {
    return cracker.isRunning() ? 1 : 0;
}

EXPORT const char* hashSHA256(const char* input) {
    static std::string result;
    SHA256 hasher;
    uint8_t hash[32];
    
    hasher.hash(input, strlen(input), hash);
    
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    }
    
    result = ss.str();
    return result.c_str();
}

EXPORT const char* hashMD5(const char* input) {
    static std::string result;
    MD5 hasher;
    uint8_t hash[16];
    
    hasher.hash(input, strlen(input), hash);
    
    std::stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    }
    
    result = ss.str();
    return result.c_str();
}

// Native test program
#ifndef __EMSCRIPTEN__
int main() {
    std::cout << "=== Ultra-Fast Hash Cracker ===" << std::endl;
    
    const char* test = "test";
    const char* hash = hashSHA256(test);
    
    std::cout << "Test: '" << test << "' -> " << hash << std::endl;
    std::cout << "Cracking..." << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    const char* result = ultraCrack(hash, "abcdefghijklmnopqrstuvwxyz", 6, 0);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (result) {
        std::cout << "Found: " << result << std::endl;
        std::cout << "Time: " << ms << "ms" << std::endl;
        std::cout << "Rate: " << (getHashRate() * 1000 / ms) << " H/s" << std::endl;
    }
    
    return 0;
}
#endif
