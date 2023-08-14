#ifndef ENCRYPT_H
#define ENCRYPT_H

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


struct Utxo {
    std::string address;
    std::string txid;
    int32_t vout;
    double amount;

    Utxo() : address(), txid(), vout(), amount() {}

    Utxo(const std::string & address, const std::string& txid, int32_t vout, double amount) 
    : address(address), txid(txid), vout(vout), amount(amount) {}

};

std::pair<std::string, std::string> readIn(const std::string keyFile, const std::string encFile);
std::string encrypt(const std::string & key, const std::string & enc, const std::string & mode);
std::string hashing(const std::string& hex, const std::string & enc, const std::string & mode);
bool ChecksumIsValid(const std::vector<unsigned char>& vec);
std::string EncodeHex(const std::vector<unsigned char>& vec);
bool decodeBase58(const char* psz, std::vector<unsigned char>& vec);
std::string binaryToPlainText(const std::string& binary);
std::string hexToBinary(const std::string& hex);
std::string xorStrings(const std::string & a, const std::string & b);
bool decodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet);
std::string toBinary(const std::string& data);
std::string plainTextToBinary(const std::string& plainText);
std::string binaryToHex(const std::string& binary);
nlohmann::json sendRPC(const std::string& method, const nlohmann::json& params);
size_t callback(const char* in, size_t size, size_t num, std::string* out);
std::string createTransaction(const std::string & encryptedHex);
std::string getOP_RETURN(const std::string & txid);

#endif // ENCRYPT_H