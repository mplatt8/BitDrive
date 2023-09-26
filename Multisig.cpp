#include "Multisig.h"
#include "Encrypt.h"

void createMulti() {

}

std::vector<std::string> PublicKeyGenerator::generatePub(const std::string& phrase, const size_t& signers, const uint32_t* customPath, const size_t customPathLen) {
    std::vector<std::string> pubKeys;
    unsigned char seed[BIP39_SEED_LEN_512];
    size_t written;
    uint32_t defaultPath[] = {0 | BIP32_FLAG_KEY_PRIVATE, 0 | BIP32_FLAG_KEY_PRIVATE}; // Default to m/0/0
    bool continueGen = true;

    if (bip39_mnemonic_to_seed(phrase.c_str(), "", seed, sizeof(seed), &written) != WALLY_OK) {
        std::cerr << "Failed to convert mnemonic to seed" << std::endl;
        return {};
    }

    ext_key masterKey;
    if (bip32_key_from_seed(seed, written, BIP32_VER_TEST_PRIVATE, 0, &masterKey) != WALLY_OK) {
        std::cerr << "Failed to derive master key" << std::endl;
        return {};
    }

    if (signers == 0 && customPath) {
        currentCustomPath.assign(customPath, customPath + customPathLen);
    }

    size_t loopSize = (signers == 0) ? 1 : signers;
    for (size_t i = 0; i < loopSize; ++i) {
        uint32_t modifiedPath[2]; // Create a copy of the path
        if (signers != 0) {
            defaultPath[1] = i;
        }

        const uint32_t* path = (signers == 0 && !currentCustomPath.empty()) ? currentCustomPath.data() : defaultPath;
        size_t pathLen = (signers == 0 && !currentCustomPath.empty()) ? currentCustomPath.size() : 2;

        ext_key derivedKey;
        if (bip32_key_from_parent_path(&masterKey, path, pathLen, BIP32_FLAG_KEY_PRIVATE, &derivedKey) != WALLY_OK) {
            std::cerr << "Failed to derive key" << std::endl;
            return {};
        }

        unsigned char* pubKeyBytes = derivedKey.pub_key;
        std::string hexStr;
        for (size_t j = 0; j < 33; ++j) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", pubKeyBytes[j]);
            hexStr.append(buf);
        }
        pubKeys.push_back(hexStr);

        // Increment the last number in the copied path
        if (signers == 0) {
            modifiedPath[1]++; // Increment the last element of the copied path
            currentCustomPath.assign(modifiedPath, modifiedPath + 2); // Update the current custom path
        }

        if (signers == 0) {
            std::cout << "Generate next address in path? Y/N" << std::endl;
            char choice;
            std::cin >> choice;
            if (choice != 'Y' && choice != 'N') {
                std::cerr << "Invalid Input - No Further Address Generated" << std::endl;
            }
            else if (choice == 'Y') {
                loopSize++;
            }
            else {
                continue;
            }
        }
    }
    if (signers == 0 && !currentCustomPath.empty()) {
        // For GUI: When the user toggles forward, you could update currentCustomPath
        // For example: currentCustomPath.push_back(nextIndex | BIP32_FLAG_KEY_PRIVATE);
    }

    return pubKeys;
}



