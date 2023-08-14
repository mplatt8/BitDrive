#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include "Encrypt.h"

bool handleFileOperation(const std::string& mode, const std::string& keyFile, const std::string& encFile, const std::string& outputFilename) {
    auto content = readIn(keyFile, encFile);

    if (mode == "decrypt") {
        content.second = getOP_RETURN(content.second);
    }

    std::string operationResult = encrypt(content.first, content.second, mode);
    std::string store = (mode == "encrypt") ? createTransaction(binaryToHex(operationResult)) : binaryToPlainText(operationResult);

    std::ofstream outFile(outputFilename, std::ios::binary);
    if (!outFile) {
        std::cerr << "Failed to create output file" << std::endl;
        return false;
    }
    outFile.write(store.data(), store.size());
    outFile.close();

    std::cout << "Operation result saved to: " << outputFilename << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 4 || (argv[1] != std::string("encrypt") && argv[1] != std::string("decrypt"))) {
        std::cerr << "Error" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string outputFilename = (mode == "encrypt") ? "encrypted.txt" : "decrypted.txt";

    return handleFileOperation(mode, argv[2], argv[3], outputFilename) ? 0 : 1;
}


