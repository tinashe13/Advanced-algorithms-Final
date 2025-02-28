#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstdint>

using namespace std;

class SHA256 {
private:
    static const uint32_t ROUND_CONSTANTS[64];
    uint32_t hashValues[8];
    uint64_t messageLength;
    vector<uint8_t> messageBlock;

    static uint32_t rotateRight(uint32_t value, uint32_t bits) {
        return (value >> bits) | (value << (32 - bits));
    }

    static uint32_t choose(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static uint32_t sigma0(uint32_t value) {
        return rotateRight(value, 7) ^ rotateRight(value, 18) ^ (value >> 3);
    }

    static uint32_t sigma1(uint32_t value) {
        return rotateRight(value, 17) ^ rotateRight(value, 19) ^ (value >> 10);
    }

    static uint32_t upperSigma0(uint32_t value) {
        return rotateRight(value, 2) ^ rotateRight(value, 13) ^ rotateRight(value, 22);
    }

    static uint32_t upperSigma1(uint32_t value) {
        return rotateRight(value, 6) ^ rotateRight(value, 11) ^ rotateRight(value, 25);
    }

    void processBlock() {
        uint32_t messageSchedule[64];
        uint32_t workingHash[8];
        uint32_t tempHash1, tempHash2;

        // Copy current hash values to working variables
        for (int i = 0; i < 8; ++i) {
            workingHash[i] = hashValues[i];
        }

        // Prepare message schedule
        for (int i = 0; i < 16; ++i) {
            messageSchedule[i] = (messageBlock[i * 4] << 24) |
                                (messageBlock[i * 4 + 1] << 16) |
                                (messageBlock[i * 4 + 2] << 8) |
                                (messageBlock[i * 4 + 3]);
        }

        // Extend message schedule
        for (int round = 16; round < 64; ++round) {
            messageSchedule[round] = sigma1(messageSchedule[round - 2]) +
                                   messageSchedule[round - 7] +
                                   sigma0(messageSchedule[round - 15]) +
                                   messageSchedule[round - 16];
        }

        // Main compression loop
        for (int round = 0; round < 64; ++round) {
            tempHash1 = workingHash[7] +
                       upperSigma1(workingHash[4]) +
                       choose(workingHash[4], workingHash[5], workingHash[6]) +
                       ROUND_CONSTANTS[round] +
                       messageSchedule[round];

            tempHash2 = upperSigma0(workingHash[0]) +
                       majority(workingHash[0], workingHash[1], workingHash[2]);

            // Rotate working variables
            workingHash[7] = workingHash[6];
            workingHash[6] = workingHash[5];
            workingHash[5] = workingHash[4];
            workingHash[4] = workingHash[3] + tempHash1;
            workingHash[3] = workingHash[2];
            workingHash[2] = workingHash[1];
            workingHash[1] = workingHash[0];
            workingHash[0] = tempHash1 + tempHash2;
        }

        // Update hash values
        for (int i = 0; i < 8; ++i) {
            hashValues[i] += workingHash[i];
        }
    }

public:
    SHA256() : messageLength(0) {
        // Initialize hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
        hashValues[0] = 0x6a09e667;
        hashValues[1] = 0xbb67ae85;
        hashValues[2] = 0x3c6ef372;
        hashValues[3] = 0xa54ff53a;
        hashValues[4] = 0x510e527f;
        hashValues[5] = 0x9b05688c;
        hashValues[6] = 0x1f83d9ab;
        hashValues[7] = 0x5be0cd19;
        messageBlock.reserve(64);  // Reserve space for one block
    }

    void updateHash(const uint8_t* data, size_t dataLength) {
        for (size_t i = 0; i < dataLength; ++i) {
            messageBlock.push_back(data[i]);
            if (messageBlock.size() == 64) {
                processBlock();
                messageLength += 512;  // 512 bits = 64 bytes
                messageBlock.clear();
            }
        }
    }

    void updateHash(const string& data) {
        updateHash(reinterpret_cast<const uint8_t*>(data.c_str()), data.length());
    }

    string finalize() {
        size_t originalBlockSize = messageBlock.size();
        size_t paddingLength = (originalBlockSize < 56) ?
                             (56 - originalBlockSize) :
                             (120 - originalBlockSize);

        // Add padding
        messageBlock.push_back(0x80);  // Append 1 followed by zeros
        paddingLength--;

        while (paddingLength > 0) {
            messageBlock.push_back(0x00);
            paddingLength--;
        }

        // Add message length
        messageLength += messageBlock.size() * 8;
        for (int i = 7; i >= 0; --i) {
            messageBlock.push_back(static_cast<uint8_t>((messageLength >> (i * 8)) & 0xFF));
        }

        processBlock();

        // Convert final hash to hexadecimal string
        stringstream hashString;
        for (int i = 0; i < 8; ++i) {
            hashString << hex << setw(8) << setfill('0') << hashValues[i];
        }
        return hashString.str();
    }

    static string calculateHash(const string& input) {
        SHA256 hasher;
        hasher.updateHash(input);
        return hasher.finalize();
    }
};

// Initialize round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
const uint32_t SHA256::ROUND_CONSTANTS[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


int main() {

    ifstream inputFile("test.txt", ios::binary);
    if (!inputFile) {
        cerr << "Failed to open input file." << endl;
        return 1;
    }

    SHA256 hashCalculator;
    vector<char> fileBuffer(4096);  // 4KB buffer for file reading

    while (inputFile.read(fileBuffer.data(), fileBuffer.size())) {
        hashCalculator.updateHash(reinterpret_cast<uint8_t*>(fileBuffer.data()),inputFile.gcount());
    }

    // Handle any remaining data
    if (inputFile.gcount() > 0) {
        hashCalculator.updateHash(reinterpret_cast<uint8_t*>(fileBuffer.data()),inputFile.gcount());
    }

    if (inputFile.bad()) {
        cerr << "Error occurred while reading the file." << endl;
        return 1;
    }

    string finalHash = hashCalculator.finalize();
    cout << "SHA-256 Hash: " << finalHash << endl;
    return 0;
}