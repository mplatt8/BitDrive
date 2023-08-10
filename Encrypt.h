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