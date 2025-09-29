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
// Portable rotate helpers (works on all compilers)
static __forceinline uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}
static __forceinline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

// Detect AVX2 availability for native builds (WASM doesn't have AVX2)
#if defined(__AVX2__) && !defined(__EMSCRIPTEN__)
  #define HAVE_AVX2 1
#else
  #define HAVE_AVX2 0
#endif

// -------------------- SHA-256 constants --------------------
alignas(32) static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

alignas(32) static const uint32_t SHA256_H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// -------------------- UltraFastSHA256 --------------------
class UltraFastSHA256 {
private:
    alignas(32) uint32_t state[8];
    alignas(64) uint8_t buffer[64];
    uint64_t bitlen;
    uint32_t datalen;

    // portable rotate-right wrapper
    __forceinline uint32_t rotr(uint32_t x, uint32_t n) const {
        return rotr32(x, (unsigned)n);
    }

    // SHA helper functions
    __forceinline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) const {
        return (x & y) ^ (~x & z);
    }

    __forceinline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) const {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    __forceinline uint32_t ep0(uint32_t x) const {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    __forceinline uint32_t ep1(uint32_t x) const {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    __forceinline uint32_t sig0(uint32_t x) const {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    __forceinline uint32_t sig1(uint32_t x) const {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void transform() {
        alignas(32) uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, h, t1, t2;

        // Prepare message schedule
        for (int i = 0; i < 16; i++) {
            uint32_t word;
            std::memcpy(&word, buffer + i * 4, 4);
            w[i] = __builtin_bswap32(word);
        }

        // Message schedule extension (unrolled in steps of 4 for speed)
        for (int i = 16; i < 64; i += 4) {
            w[i]   = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];
            w[i+1] = sig1(w[i-1]) + w[i-6] + sig0(w[i-14]) + w[i-15];
            w[i+2] = sig1(w[i])   + w[i-5] + sig0(w[i-13]) + w[i-14];
            w[i+3] = sig1(w[i+1]) + w[i-4] + sig0(w[i-12]) + w[i-13];
        }

        // Initialize working variables
        a = state[0]; b = state[1]; c = state[2]; d = state[3];
        e = state[4]; f = state[5]; g = state[6]; h = state[7];

        // Compression loop (fully unrolled in groups of 8)
        for (int i = 0; i < 64; i += 8) {
            t1 = h + ep1(e) + ch(e, f, g) + SHA256_K[i] + w[i];
            t2 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

            t1 = h + ep1(e) + ch(e, f, g) + SHA256_K[i+1] + w[i+1];
            t2 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

            t1 = h + ep1(e) + ch(e, f, g) + SHA256_K[i+2] + w[i+2];
            t2 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

            t1 = h + ep1(e) + ch(e, f, g) + SHA256_K[i+3] + w[i+3];
            t2 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

            t1 = h + ep1(e) + ch(e, f, g) + SHA256_K[i+4] + w[i+4];
            t2 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

            t1 = h + ep1(e) + ch(e, f, g) + SHA256_K[i+5] + w[i+5];
            t2 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

            t1 = h + ep1(e) + ch(e, f, g) + SHA256_K[i+6] + w[i+6];
            t2 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

            t1 = h + ep1(e) + ch(e, f, g) + SHA256_K[i+7] + w[i+7];
            t2 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }

        // Update state
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

public:
    UltraFastSHA256() { init(); }

    void init() {
        datalen = 0;
        bitlen = 0;
        std::memcpy(state, SHA256_H, sizeof(SHA256_H));
        std::memset(buffer, 0, sizeof(buffer));
    }

    void update(const uint8_t data[], size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[datalen++] = data[i];
            if (datalen == 64) {
                transform();
                bitlen += 512;
                datalen = 0;
            }
        }
    }

    void final(uint8_t hash[]) {
        uint32_t i = datalen;

        // Pad message
        if (datalen < 56) {
            buffer[i++] = 0x80;
            while (i < 56) buffer[i++] = 0x00;
        } else {
            buffer[i++] = 0x80;
            while (i < 64) buffer[i++] = 0x00;
            transform();
            std::memset(buffer, 0, 56);
        }

        // Append length
        bitlen += datalen * 8;
        buffer[63] = static_cast<uint8_t>(bitlen);
        buffer[62] = static_cast<uint8_t>(bitlen >> 8);
        buffer[61] = static_cast<uint8_t>(bitlen >> 16);
        buffer[60] = static_cast<uint8_t>(bitlen >> 24);
        buffer[59] = static_cast<uint8_t>(bitlen >> 32);
        buffer[58] = static_cast<uint8_t>(bitlen >> 40);
        buffer[57] = static_cast<uint8_t>(bitlen >> 48);
        buffer[56] = static_cast<uint8_t>(bitlen >> 56);
        transform();

        // Convert to bytes
        for (i = 0; i < 4; ++i) {
            hash[i]      = (state[0] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 4]  = (state[1] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 8]  = (state[2] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 12] = (state[3] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 16] = (state[4] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 20] = (state[5] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 24] = (state[6] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 28] = (state[7] >> (24 - i * 8)) & 0x000000ff;
        }
    }

    // Optimized single-shot hash for short strings
    __forceinline void hashShortString(const char* str, size_t len, uint8_t hash[32]) {
        init();
        update(reinterpret_cast<const uint8_t*>(str), len);
        final(hash);
    }
};

// -------------------- UltraFastMD5 --------------------
class UltraFastMD5 {
private:
    static const uint32_t S[64];
    static const uint32_t K[64];

    __forceinline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
    __forceinline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
    __forceinline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
    __forceinline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

public:
    __forceinline uint32_t rotl(uint32_t x, uint32_t n) {
        return rotl32(x, (unsigned)n);
    }

    void hashShortString(const char* str, size_t len, uint8_t hash[16]) {
        uint32_t h[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};

        // For very short strings, use optimized path
        alignas(16) uint8_t padded[64];
        std::memset(padded, 0, 64);
        std::memcpy(padded, str, len);
        padded[len] = 0x80;

        // Append length (little-endian for MD5)
        uint64_t bitLen = static_cast<uint64_t>(len) * 8ULL;
        std::memcpy(padded + 56, &bitLen, 8);

        // Process block
        uint32_t* w = reinterpret_cast<uint32_t*>(padded);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];

        // Unrolled MD5 rounds (four phases)
        for (int i = 0; i < 16; i += 4) {
            uint32_t temp;
            temp = a + F(b, c, d) + w[i] + K[i]; a = d; d = c; c = b; b += rotl(temp, S[i]);
            temp = a + F(b, c, d) + w[i+1] + K[i+1]; a = d; d = c; c = b; b += rotl(temp, S[i+1]);
            temp = a + F(b, c, d) + w[i+2] + K[i+2]; a = d; d = c; c = b; b += rotl(temp, S[i+2]);
            temp = a + F(b, c, d) + w[i+3] + K[i+3]; a = d; d = c; c = b; b += rotl(temp, S[i+3]);
        }

        for (int i = 16; i < 32; i += 4) {
            uint32_t temp;
            int g = (5*i + 1) % 16;
            temp = a + G(b, c, d) + w[g] + K[i]; a = d; d = c; c = b; b += rotl(temp, S[i]);
            g = (5*(i+1) + 1) % 16;
            temp = a + G(b, c, d) + w[g] + K[i+1]; a = d; d = c; c = b; b += rotl(temp, S[i+1]);
            g = (5*(i+2) + 1) % 16;
            temp = a + G(b, c, d) + w[g] + K[i+2]; a = d; d = c; c = b; b += rotl(temp, S[i+2]);
            g = (5*(i+3) + 1) % 16;
            temp = a + G(b, c, d) + w[g] + K[i+3]; a = d; d = c; c = b; b += rotl(temp, S[i+3]);
        }

        for (int i = 32; i < 48; i += 4) {
            uint32_t temp;
            int g = (3*i + 5) % 16;
            temp = a + H(b, c, d) + w[g] + K[i]; a = d; d = c; c = b; b += rotl(temp, S[i]);
            g = (3*(i+1) + 5) % 16;
            temp = a + H(b, c, d) + w[g] + K[i+1]; a = d; d = c; c = b; b += rotl(temp, S[i+1]);
            g = (3*(i+2) + 5) % 16;
            temp = a + H(b, c, d) + w[g] + K[i+2]; a = d; d = c; c = b; b += rotl(temp, S[i+2]);
            g = (3*(i+3) + 5) % 16;
            temp = a + H(b, c, d) + w[g] + K[i+3]; a = d; d = c; c = b; b += rotl(temp, S[i+3]);
        }

        for (int i = 48; i < 64; i += 4) {
            uint32_t temp;
            int g = (7*i) % 16;
            temp = a + I(b, c, d) + w[g] + K[i]; a = d; d = c; c = b; b += rotl(temp, S[i]);
            g = (7*(i+1)) % 16;
            temp = a + I(b, c, d) + w[g] + K[i+1]; a = d; d = c; c = b; b += rotl(temp, S[i+1]);
            g = (7*(i+2)) % 16;
            temp = a + I(b, c, d) + w[g] + K[i+2]; a = d; d = c; c = b; b += rotl(temp, S[i+2]);
            g = (7*(i+3)) % 16;
            temp = a + I(b, c, d) + w[g] + K[i+3]; a = d; d = c; c = b; b += rotl(temp, S[i+3]);
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        std::memcpy(hash, h, 16);
    }
};

// MD5 constants
const uint32_t UltraFastMD5::S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

const uint32_t UltraFastMD5::K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// -------------------- High-performance parallel hash cracker --------------------
class HyperSpeedCracker {
private:
    std::atomic<bool> running;
    std::atomic<bool> found;
    std::atomic<uint64_t> totalHashes;
    std::string foundPassword;
    std::string targetHash;
    std::string charset;
    int maxLength;
    int numThreads;

    UltraFastSHA256 sha256Engine;
    UltraFastMD5 md5Engine;

public:
    HyperSpeedCracker() : running(false), found(false), totalHashes(0) {
        unsigned conc = std::thread::hardware_concurrency();
        numThreads = static_cast<int>(conc ? conc : 1u);
    }

    // Optimized candidate generation using bit manipulation
    __forceinline void indexToCandidate(uint64_t index, int length, const char* charsetArr, int charsetSize, char* output) {
        for (int i = length - 1; i >= 0; i--) {
            output[i] = charsetArr[index % charsetSize];
            index /= charsetSize;
        }
        output[length] = '\0';
    }

    // SIMD-optimized hash comparison (guarded)
    __forceinline bool compareHashes(const uint8_t* hash1, const uint8_t* hash2, int len) {
#if HAVE_AVX2
        if (len == 32) { // SHA-256
            __m256i v1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(hash1));
            __m256i v2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(hash2));
            __m256i cmp = _mm256_cmpeq_epi8(v1, v2);
            return _mm256_movemask_epi8(cmp) == 0xFFFFFFFF;
        }
#endif
        return std::memcmp(hash1, hash2, len) == 0;
    }

    // Hex string to bytes conversion
    void hexToBytes(const std::string& hex, uint8_t* bytes) {
        size_t len = hex.length();
        for (size_t i = 0; i < len && i + 1 < len; i += 2) {
            bytes[i/2] = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        }
    }

    // Multi-threaded brute force worker
    void bruteForceWorker(int threadId, int algorithm, const std::string& target,
                         const std::string& charsetStr, int length, uint64_t start, uint64_t end) {

        alignas(32) uint8_t candidateHash[32];
        alignas(32) uint8_t targetBytes[32];
        char candidate[64];

        int hashLen = (algorithm == 0) ? 32 : 16; // SHA-256 : MD5
        std::memset(targetBytes, 0, 32);
        hexToBytes(target, targetBytes);

        const int batchSize = 100000;
        uint64_t localHashes = 0;

        const char* charsetArr = charsetStr.c_str();
        int charsetSize = static_cast<int>(charsetStr.length());

        for (uint64_t i = start; i < end && running.load() && !found.load(); i += batchSize) {
            uint64_t batchEnd = std::min(i + batchSize, end);

            for (uint64_t j = i; j < batchEnd && running.load() && !found.load(); j++) {
                indexToCandidate(j, length, charsetArr, charsetSize, candidate);

                if (algorithm == 0) {
                    sha256Engine.hashShortString(candidate, length, candidateHash);
                } else {
                    md5Engine.hashShortString(candidate, length, candidateHash);
                }

                localHashes++;

                if (compareHashes(candidateHash, targetBytes, hashLen)) {
                    bool expected = false;
                    if (found.compare_exchange_strong(expected, true)) {
                        foundPassword = candidate;
                        running.store(false);
                        return;
                    }
                }
            }

            totalHashes.fetch_add(localHashes);
            localHashes = 0;
        }

        totalHashes.fetch_add(localHashes);
    }

    std::string crack(const std::string& hash, const std::string& charset, int maxLen, int algorithm = 0) {
        if (running.load()) return "Already running";

        running.store(true);
        found.store(false);
        totalHashes.store(0);
        foundPassword.clear();

        auto startTime = std::chrono::high_resolution_clock::now();

        for (int length = 1; length <= maxLen && running.load() && !found.load(); length++) {
            uint64_t totalCombinations = 1;
            for (int i = 0; i < length; i++) {
                totalCombinations *= static_cast<uint64_t>(charset.length());
                if (totalCombinations == 0) break;
            }

            if (totalCombinations == 0) break;

            uint64_t combinationsPerThread = totalCombinations / static_cast<uint64_t>(numThreads);
            std::vector<std::thread> workers;

            for (int t = 0; t < numThreads; t++) {
                uint64_t start = static_cast<uint64_t>(t) * combinationsPerThread;
                uint64_t end = (t == numThreads - 1) ? totalCombinations : (static_cast<uint64_t>(t + 1) * combinationsPerThread);

                workers.emplace_back(&HyperSpeedCracker::bruteForceWorker, this,
                                      t, algorithm, hash, charset, length, start, end);
            }

            for (auto& worker : workers) {
                worker.join();
            }

            if (found.load()) break;
        }

        running.store(false);

        auto endTime = std::chrono::high_resolution_clock::now();
        (void)std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime); // unused currently

        if (found.load()) {
            return foundPassword;
        }

        return "";
    }

    uint64_t getHashRate() const {
        return totalHashes.load();
    }

    void stop() {
        running.store(false);
    }

    bool isRunning() const {
        return running.load();
    }
};

// Global cracker instance
static HyperSpeedCracker cracker;

// WebAssembly / C exports
EXPORT const char* ultraCrack(const char* hash, const char* charset, int maxLength, int algorithm) {
    static std::string result;
    result = cracker.crack(std::string(hash), std::string(charset), maxLength, algorithm);
    return result.empty() ? nullptr : result.c_str();
}

EXPORT uint64_t getHashRate() {
    return cracker.getHashRate();
}

EXPORT void stopCracking() {
    cracker.stop();
}

EXPORT int isRunning() {
    return cracker.isRunning() ? 1 : 0;
}

EXPORT const char* hashSHA256(const char* input) {
    static std::string result;
    UltraFastSHA256 hasher;
    alignas(32) uint8_t hash[32];

    hasher.hashShortString(input, std::strlen(input), hash);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        ss << std::setw(2) << static_cast<int>(hash[i]);
    }

    result = ss.str();
    return result.c_str();
}

EXPORT const char* hashMD5(const char* input) {
    static std::string result;
    UltraFastMD5 hasher;
    alignas(16) uint8_t hash[16];

    hasher.hashShortString(input, std::strlen(input), hash);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; i++) {
        ss << std::setw(2) << static_cast<int>(hash[i]);
    }

    result = ss.str();
    return result.c_str();
}
