#include <iostream>
#include <fstream>
#include <ostream>
#include <string>
#include <openssl/evp.h>
#include "Encrypt.h"


bool handleFileOperation(const std::string& mode, const std::string& keyFile, const std::string& encFile, const std::string& outputFilename) {
    // Read the files
    std::pair<std::string, std::string> content = readIn(keyFile, encFile);

    // Encrypt or decrypt as needed
    std::string operationResult = encrypt(content.first, content.second, mode);
    if (mode == "decrypt") {
        operationResult = binaryToPlainText(operationResult);
    }

    // Create and write to the output file
    std::ofstream outFile(outputFilename, std::ios::binary);
    if (!outFile) {
        std::cerr << "Failed to create output file" << std::endl;
        return false;
    }
    outFile.write(operationResult.c_str(), operationResult.size());
    outFile.close();

    std::cout << "Operation result saved to: " << outputFilename << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Error" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string keyFile = argv[2];
    std::string encFile = argv[3];

    // Define the output file name based on the mode
    std::string outputFilename = (mode == "encrypt") ? "encrypted.txt" : "decrypted.txt";

    if (mode != "encrypt" && mode != "decrypt") {
        std::cerr << "Invalid operation mode, choose 'encrypt' or 'decrypt'" << std::endl;
        return 1;
    }

    if (!handleFileOperation(mode, keyFile, encFile, outputFilename)) {
        return 1;
    }

    return 0;
}


