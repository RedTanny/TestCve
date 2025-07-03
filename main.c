#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <curl/curl.h>

#define HASH_HEX_SIZE (SHA256_DIGEST_LENGTH * 2 + 1)

void sha256_hash(const char *input, char *output_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(hash, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }
    output_hex[HASH_HEX_SIZE - 1] = '\0';
}

int send_hash_to_server(const char *url, const char *hash) {
    CURL *curl;
    CURLcode res;
    int success = 0;
    char postfields[256];
    snprintf(postfields, sizeof(postfields), "save=%s", hash);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            success = 1;
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return success;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <key> <server_url>\n", argv[0]);
        return 1;
    }
    const char *key = argv[1];
    const char *server_url = argv[2];
    char hash_hex[HASH_HEX_SIZE];
    sha256_hash(key, hash_hex);
    printf("SHA256 hash: %s\n", hash_hex);
    if (send_hash_to_server(server_url, hash_hex)) {
        printf("Hash sent successfully!\n");
    } else {
        printf("Failed to send hash.\n");
    }
    return 0;
} 