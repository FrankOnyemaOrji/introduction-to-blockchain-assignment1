#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

/**
 * EVP - EVP function from OpenSSL are used to create,
 * hash context(EVP_MD_ETX), to feed data sn finalize -
 * hash computation.
 * The SHA-256 algorithm takes the input string, processes 
 * it in chunks, and outputs a 32-byte hash.
 * The hash is printed in hexadecimal format for easier readability.
 * Testing: The program tests the SHA-256 hashing by computing the 
 * hash for the string "Blockchain Cryptography"
 */
void sha256_hash_string(unsigned char hash[], char outputBuffer[65])
{
	int i;
	for (i = 0; i < 32; i++) {
		sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
}

void compute_sha256(const char* input) 
{
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_sha256();
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;

	EVP_DigestInit_ex(mdctx, md, NULL);

	EVP_DigestUpdate(mdctx, input, strlen(input));

	EVP_DigestFinal_ex(mdctx, hash, &hash_len);

	EVP_MD_CTX_free(mdctx);

	char outputBuffer[65];

	sha256_hash_string(hash, outputBuffer);

	printf("SHA-256 hash of \"%s\": %s\n", input, outputBuffer);
}

int main ()
{
	const char* input = "Blockchain Cryptography";

	compute_sha256(input);


	return (0);
}

