#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/encryption.h"
#include "../src/file_ops.h"
#include "../src/kdf.h"
#include "../src/sha512.h"
#include "../src/utils.h"

static void test_sanitize_username(void) {
    char out[USERNAME_MAX_LEN];
    assert(sanitize_username("alice", out, sizeof(out)) == 0);
    assert(strcmp(out, "alice") == 0);
    assert(sanitize_username("bob smith", out, sizeof(out)) == 0);
    assert(strcmp(out, "bob_smith") == 0);
    assert(sanitize_username("bad$name", out, sizeof(out)) == -1);
}

static void test_is_strong_password(void) {
    assert(is_strong_password("Weakpass1") == 0);
    assert(is_strong_password("Str0ng!Password") == 1);
}

static void test_sha512_known_vector(void) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    const char *input = "abc";
    const char expected_hex[] =
        "ddaf35a193617abacc417349ae204131"
        "12e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f";
    sha512_compute((const unsigned char *)input, strlen(input), hash);
    char hex[SHA512_DIGEST_LENGTH * 2 + 1];
    bytes_to_hex(hash, sizeof(hash), hex);
    assert(strcmp(hex, expected_hex) == 0);
}

static void test_pbkdf2_vector(void) {
    const char *password = "password";
    const unsigned char salt[] = {'s', 'a', 'l', 't'};
    unsigned char output[64];
    const char expected_hex[] =
        "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
        "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce";

    assert(pbkdf2_sha512((const unsigned char *)password, strlen(password),
                         salt, sizeof(salt), 1, output, sizeof(output)) == 0);
    char hex[sizeof(output) * 2 + 1];
    bytes_to_hex(output, sizeof(output), hex);
    assert(strcmp(hex, expected_hex) == 0);
}

static void test_bytes_to_hex_roundtrip(void) {
    unsigned char bytes[] = {0x00, 0xff, 0x10, 0x20};
    char hex[sizeof(bytes) * 2 + 1];
    unsigned char roundtrip[sizeof(bytes)];
    bytes_to_hex(bytes, sizeof(bytes), hex);
    size_t converted = hex_to_bytes(hex, roundtrip, sizeof(roundtrip));
    assert(converted == sizeof(bytes));
    assert(memcmp(bytes, roundtrip, sizeof(bytes)) == 0);
}

static void test_file_operations(void) {
    const char *username = "testuser";
    const char *message = "hello world";
    const char *encrypted = "abcd";

    assert(write_plain_message(username, message) == 0);

    char filename[256];
    snprintf(filename, sizeof(filename), "%s.txt", username);
    FILE *fp = fopen(filename, "r");
    assert(fp != NULL);
    char buffer[64];
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\r\n")] = '\0';
    }
    fclose(fp);
    assert(strncmp(buffer, message, strlen(message)) == 0);

    assert(replace_with_encrypted(username, encrypted) == 0);
    fp = fopen(filename, "r");
    assert(fp != NULL);
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\r\n")] = '\0';
    }
    fclose(fp);
    assert(strcmp(buffer, encrypted) == 0);

    unlink(filename);
}

static void test_encryption_length(void) {
    const char *message = "integration-test-message";
    const char *password = "Str0ng!Password";
    unsigned char salt[64];
    for (size_t i = 0; i < sizeof(salt); i++) {
        salt[i] = (unsigned char)i;
    }
    char encrypted[513];
    assert(derive_key_and_encrypt(message, password, salt, sizeof(salt),
                                  encrypted, sizeof(encrypted)) == 0);
    assert(strlen(encrypted) == 512);
}

static void integration_workflow(void) {
    const char *username = "workflow";
    const char *message = "end to end";
    const char *password = "Str0ng!Password";
    unsigned char salt[64];
    memset(salt, 0x42, sizeof(salt));

    assert(write_plain_message(username, message) == 0);

    char encrypted[513];
    assert(derive_key_and_encrypt(message, password, salt, sizeof(salt),
                                  encrypted, sizeof(encrypted)) == 0);

    assert(replace_with_encrypted(username, encrypted) == 0);

    char filename[256];
    snprintf(filename, sizeof(filename), "%s.txt", username);
    FILE *fp = fopen(filename, "r");
    assert(fp != NULL);
    char buffer[520];
    fgets(buffer, sizeof(buffer), fp);
    fclose(fp);
    size_t len = strcspn(buffer, "\r\n");
    buffer[len] = '\0';
    assert(strcmp(buffer, encrypted) == 0);

    unlink(filename);
}

int main(void) {
    test_sanitize_username();
    test_is_strong_password();
    test_sha512_known_vector();
    test_pbkdf2_vector();
    test_bytes_to_hex_roundtrip();
    test_file_operations();
    test_encryption_length();
    integration_workflow();
    printf("All tests passed.\n");
    return 0;
}
