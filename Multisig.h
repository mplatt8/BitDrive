#ifndef MULTISIG_H
#define MULTISIG_H

#include <iostream>
#include <fstream>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <iterator>
#include <bitset>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <bitcoin/system.hpp>
#include <wally.hpp>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <openssl/ec.h>
#include <cstdint>



void createMulti();
std::string stringToHex(const std::string &input);

class PublicKeyGenerator {

    private: 
    std::vector<uint32_t> currentCustomPath;

    public:
    std::vector<std::string> generatePub(const std::string& phrase, const size_t& signers, const uint32_t* initialCustomPath = nullptr, const size_t initialCustomPathLen = 0);

};

#endif // MULTISIG_H