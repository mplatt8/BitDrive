#include "Encrypt.h"

std::pair<std::string, std::string> readIn(const std::string keyFile, const std::string encFile) { //filename has the key need to take in file to be encrypted as well

    std::ifstream inFile(keyFile);
    
    if (!inFile) {
        std::cerr << "Failed to open file" << std::endl;
    }

    std::string key((std::istreambuf_iterator<char>(inFile)), 
    (std::istreambuf_iterator<char>()));

    inFile.close();

    std::ifstream inFile2(encFile);
    
    if (!inFile2) {
        std::cerr << "Failed to open file" << std::endl;
    }

    std::string enc((std::istreambuf_iterator<char>(inFile2)), 
    (std::istreambuf_iterator<char>()));

    inFile2.close();

    return std::make_pair(static_cast<std::string> (key), static_cast<std::string> (enc));
}

std::string encrypt(const std::string & key, const std::string & enc, const std::string & mode) {

    std::vector<unsigned char> vec;
    decodeBase58Check(key.c_str(), vec);
    std::string hex = EncodeHex(vec);
    if (!hex.empty()) {
        hex.erase(hex.begin());
        hex.erase(hex.begin());
    }
    
    return hashing(hex, enc, mode);
}


std::string hashing(const std::string & hex, const std::string & enc, const std::string & mode) {

    size_t encSize = enc.size();

    const unsigned char * hexPointer = reinterpret_cast<const unsigned char*> (hex.c_str());
    unsigned char hash512[SHA512_DIGEST_LENGTH] = {0};

    std::string result;
    

    if (mode == "decrypt") {
        encSize = encSize / 8;
    }

    result.reserve(encSize + 32);

    while (result.size() < encSize){

        SHA512(hexPointer, hex.size(), hash512);
        unsigned char * start = hash512;
        unsigned char * mid = hash512 + 32;
        unsigned char * end = hash512 + 64;
        std::string left(start, mid);
        for (size_t i = 0; i < left.size(); ++i) {
            result += left[i];
        }
        std::string right(mid, end);
        hexPointer = reinterpret_cast<const unsigned char*> (right.c_str());
    }
    
    while (result.size() != encSize) {
        auto it = result.end() - 1;
        result.erase(it);
        it--;
    }
    std::string binEnc;
    if (mode == "decrypt") {
        binEnc = enc;
    }
    else {
        binEnc = plainTextToBinary(enc);
    }
    std::string binResult = toBinary(result);

    std::string check = "1000000010100011000111011011011000100101011110011001111101011110011000110110101101011010000110101010100000110100101011101110001100010000000110110001000100010011110100001111101111101110100001111101100111010100100010001110110110100110001011010110011011000011101000000100100001000001100110001000110011010111010111110100001000000111011101111000100111010011101110110001110010001011110101011101111111010101";

    if (binResult == check) {
        std::cerr << "CHECK";
    }
    
    return xorStrings(binEnc, binResult);
}

std::string xorStrings(const std::string & a, const std::string & b) {

    if (a.size() != b.size()) {
        std::cerr << "ERROR" << std::flush;
        exit(1);
    }

    std::string encrypted;
    
    for (size_t i = 0; i < a.size(); ++i) {
        encrypted.push_back((a[i] == '1') ^ (b[i] == '1') ? '1' : '0');
    }

    return encrypted;
}

std::string hexToBinary(const std::string& hex) {
    std::string binary;
    for (char hexChar : hex) {
        std::bitset<4> b(std::stoi(std::string(1, hexChar), nullptr, 16));
        binary += b.to_string();
    }
    return binary;
}

bool decodeBase58(const char* psz, std::vector<unsigned char>& vec) {

    const char* pszBase58 = 
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    while (*psz && isspace(*psz)) psz++;

    int zeroes = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    
    std::vector<unsigned char> bignum;
    while (*psz && !isspace(*psz)) {
        
        const char* ch = strchr(pszBase58, *psz);

        if (ch == NULL) return false;
        
        int carry = ch - pszBase58;

        for (std::vector<unsigned char>::reverse_iterator it = bignum.rbegin(); 
        it != bignum.rend(); it++) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        bignum.insert(bignum.begin(), carry);
        psz++;
    }
    
    while (isspace(*psz))
        psz++;
    if (*psz != 0) return false;

    std::vector<unsigned char>::iterator it = bignum.begin() + zeroes;
    
    while (it != bignum.end() && *it == 0)
        it++;
    vec.assign(it, bignum.end());
    return true;
}

bool decodeBase58Check(const std::string& str, std::vector<unsigned char>& vec) {
    if (!decodeBase58(str.c_str(), vec)) return false;

    if (!ChecksumIsValid(vec)) return false;

    vec.resize(vec.size() - 4);

    return true;
}

bool ChecksumIsValid(const std::vector<unsigned char>& vec) {
    if (vec.size() < 4) return false;

    unsigned char hash1[SHA256_DIGEST_LENGTH] = {0};
    unsigned char hash2[SHA256_DIGEST_LENGTH] = {0};
    
    SHA256(vec.data(), vec.size() - 4, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    return std::memcmp(hash2, &vec[vec.size() - 4], 4) == 0;
}

std::string EncodeHex(const std::vector<unsigned char>& vec) {
    std::string hex;
    for(auto ch : vec)
    {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", ch);
        hex += buf;
    }
    return hex;
}

std::string binaryToPlainText(const std::string& binary) {
    std::string plainText;
    for (std::size_t i = 0; i < binary.length(); i += 8) {
        std::string byte = binary.substr(i, 8);
        char c = static_cast<char>(std::bitset<8>(byte).to_ulong());
        plainText.push_back(c);
    }
    return plainText;
}

std::string toBinary(const std::string& data) {
    std::stringstream ss;
    for (char c : data) {
        ss << std::bitset<8>(static_cast<unsigned char>(c));
    }
    return ss.str();
}

std::string plainTextToBinary(const std::string& plainText) {
    std::string binary;
    for (char c : plainText) {
        binary += std::bitset<8>(c).to_string();
    }
    return binary;
}