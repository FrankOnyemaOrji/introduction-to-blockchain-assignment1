#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#define MAX_DATA_SIZE 256

// Define the structure of a block
struct Block {
    int index;
    time_t timestamp;
    char data[MAX_DATA_SIZE];
    unsigned char previous_hash[32];
    unsigned char hash[32];
};

// Function to hash the block data
void hash_block(struct Block* block) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned int hash_len;

    // Concatenate block details (index, timestamp, data, and previous hash)
    char buffer[512];
    sprintf(buffer, "%d%ld%s", block->index, block->timestamp, block->data);
    
    // Initialize hash and update with buffer and previous hash
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, buffer, strlen(buffer));
    EVP_DigestUpdate(mdctx, block->previous_hash, sizeof(block->previous_hash));

    // Finalize the hash and store it
    EVP_DigestFinal_ex(mdctx, block->hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
}

// Function to create a new block
struct Block create_block(int index, const char* data, const unsigned char previous_hash[32]) {
    struct Block new_block;
    new_block.index = index;
    new_block.timestamp = time(NULL);
    strncpy(new_block.data, data, MAX_DATA_SIZE);

    // Ensure previous_hash is fully populated (if genesis, it'll be all 0's)
    memset(new_block.previous_hash, 0, 32);
    if (previous_hash != NULL) {
        memcpy(new_block.previous_hash, previous_hash, 32);
    }

    hash_block(&new_block);  // Calculate the block's hash
    return new_block;
}

// Function to validate the blockchain
int validate_blockchain(struct Block blockchain[], int chain_length) {
    for (int i = 1; i < chain_length; i++) {
        struct Block previous_block = blockchain[i - 1];
        struct Block current_block = blockchain[i];
        
        // Validate current block's previous hash
        if (memcmp(previous_block.hash, current_block.previous_hash, 32) != 0) {
            return 0;  // Blockchain is invalid
        }

        // Store original hash for comparison
        unsigned char recalculated_hash[32];
        memcpy(recalculated_hash, current_block.hash, 32);

        // Recompute the current block's hash
        hash_block(&current_block);

        // Compare recalculated hash with stored hash
        if (memcmp(current_block.hash, recalculated_hash, 32) != 0) {
            return 0;  // Blockchain is invalid
        }
    }
    return 1;  // Blockchain is valid
}

int main() {
    // Create a simple blockchain with 3 blocks
    struct Block blockchain[3];

    // Genesis block (index 0, no previous hash, initialized with zeros)
    unsigned char genesis_hash[32] = {0};  // Initialized to 0 for the genesis block
    blockchain[0] = create_block(0, "Genesis Block", genesis_hash);

    // Block 1
    blockchain[1] = create_block(1, "Second Block", blockchain[0].hash);

    // Block 2
    blockchain[2] = create_block(2, "Third Block", blockchain[1].hash);

    // Validate the blockchain
    if (validate_blockchain(blockchain, 3)) {
        printf("Blockchain is valid!\n");
    } else {
        printf("Blockchain is invalid!\n");
    }

    return 0;
}
