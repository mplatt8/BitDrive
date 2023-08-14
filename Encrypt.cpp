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
        encSize = encSize / 2;
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
        binEnc = hexToBinary(enc);
    }
    else {
        binEnc = plainTextToBinary(enc);
    }
    std::string binResult = toBinary(result);

    return xorStrings(binEnc, binResult);
}

std::string xorStrings(const std::string & a, const std::string & b) {

    if (a.size() != b.size()) {
        std::cerr << "ERROR" << std::flush;
        exit(1);
    }

    std::string encrypted = "";
    encrypted.clear();
    
    for (size_t i = 0; i < a.size(); ++i) {
        encrypted.push_back(((a[i] == '1') ^ (b[i] == '1')) ? '1' : '0');

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

std::string binaryToHex(const std::string& binary) {
    if (binary.size() % 8 != 0) {
        throw std::runtime_error("The binary string length must be a multiple of 8");
    }

    std::stringstream ss;
    for (size_t i = 0; i < binary.size(); i += 8) {
        std::bitset<8> bin(binary.substr(i, 8));
        unsigned n = bin.to_ulong();
        ss << std::setw(2) << std::setfill('0') << std::hex << n;
    }
    return ss.str();
}


size_t callback(const char* in, size_t size, size_t num, std::string* out) {
    const size_t totalBytes(size * num);
    out->append(in, totalBytes);
    return totalBytes;
}

nlohmann::json sendRPC(const std::string& method, const nlohmann::json& params) {
    const std::string rpcUser = "mplatt8";
    const std::string rpcPass = "6d61726320706c617474";
    const std::string rpcURL = "http://127.0.0.1:18443/";

    CURL* curl = curl_easy_init();

    if (!curl) {
        throw std::runtime_error("Failed to initialize curl");
    }

    curl_easy_setopt(curl, CURLOPT_URL, rpcURL.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERNAME, rpcUser.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, rpcPass.c_str());

    nlohmann::json payload;
    payload["jsonrpc"] = "1.0";
    payload["id"] = "curl";
    payload["method"] = method;
    payload["params"] = params;

    std::string payloadStr = payload.dump();
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadStr.c_str());

    std::string responseString;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Curl request failed: " + std::string(curl_easy_strerror(res)));
    }

    curl_easy_cleanup(curl);

    nlohmann::json response = nlohmann::json::parse(responseString);

    if (response.contains("error") && !response["error"].is_null()) {
        throw std::runtime_error("RPC error received in response.");
    }

    return response;
}
std::string createTransaction(const std::string & encryptedHex) {
    nlohmann::json params = nlohmann::json::array();
    nlohmann::json list = sendRPC("listunspent", params);

    std::vector<Utxo> Utxos;

    for (const auto & utxo : list["result"]) {
        Utxo u;
        u.address = utxo["address"];
        u.txid =       utxo["txid"];
        u.vout =       utxo["vout"];
        u.amount =   utxo["amount"];
        Utxos.push_back(u);
    }
    size_t counter = 0;
    std::cout << "Pick a utxo to spend: " << std::endl;
    for (const auto & u : Utxos) {
        std::cout << counter << ") " << "address: " << u.address << " txid: " 
        << u.txid << " vout: " << u.vout << " amount: " << u.amount << std::endl;
        counter++;
    }
    size_t choice;
    std::cin >> choice;
    while (choice < 0 || choice > Utxos.size() - 1) {
        std::cerr << "Invalid choice. Choose a number from list" << std::endl;
        std::cin >> choice;
    }

    auto & ref = Utxos[choice];

    nlohmann::json in = nlohmann::json::array({
        {
            {"txid", ref.txid},
            {"vout", ref.vout}
        }
    });

    nlohmann::json out = {
        {"data", encryptedHex},
        {ref.address, ref.amount - .01}
    };

    nlohmann::json txParams = nlohmann::json::array({in, out});
    nlohmann::json rawTx = sendRPC("createrawtransaction", txParams);
    std::string hexRawTx = rawTx["result"].get<std::string>();

    nlohmann::json signParams = nlohmann::json::array({hexRawTx});
    nlohmann::json signedTx = sendRPC("signrawtransactionwithwallet", signParams);
    std::string hexSignedTx = signedTx["result"]["hex"].get<std::string>();

    nlohmann::json sendParams = nlohmann::json::array({hexSignedTx});
    nlohmann::json txid = sendRPC("sendrawtransaction", sendParams);

    return txid["result"].get<std::string>();
}

std::string getOP_RETURN(const std::string & txid) {
    std::string OP = "";
    nlohmann::json txParams = nlohmann::json::array({txid, true});
    nlohmann::json txDetails = sendRPC("getrawtransaction", txParams);

    for (const auto & vout : txDetails["result"]["vout"]) {
        if (vout["scriptPubKey"]["type"] == "nulldata") {
            OP = vout["scriptPubKey"]["asm"];
            OP.erase(0,10);
            break;
        }
    }
    if (OP == "") {
        std::cerr << "Failed to find OP_RETURN" << std::endl;
        exit(1);
    }
    return OP;
}