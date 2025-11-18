#include <stdio.h>
#include <string.h>

#include "encryption.h"
#include "file_ops.h"
#include "input.h"
#include "qrng.h"
#include "utils.h"

#define SALT_LEN 64
#define ENCRYPTED_HEX_LEN (256 * 2 + 1)

int main(void) {
    char username[USERNAME_MAX_LEN];
    char message[MESSAGE_MAX_LEN];
    char password[PASSWORD_MAX_LEN];
    unsigned char salt[SALT_LEN];
    char encrypted_hex[ENCRYPTED_HEX_LEN];

    if (prompt_username(username, sizeof(username)) != 0) {
        fprintf(stderr, "Failed to read username.\n");
        return 1;
    }

    if (prompt_message(message, sizeof(message)) != 0) {
        fprintf(stderr, "Failed to read message.\n");
        return 1;
    }

    if (prompt_password(password, sizeof(password)) != 0) {
        fprintf(stderr, "Failed to read password.\n");
        return 1;
    }

    if (qrng_fetch_bytes(salt, sizeof(salt)) != 0) {
        fprintf(stderr, "Failed to retrieve quantum salt.\n");
        secure_zero(password, sizeof(password));
        return 1;
    }

    if (write_plain_message(username, message) != 0) {
        fprintf(stderr, "Failed to write initial message file.\n");
        secure_zero(password, sizeof(password));
        secure_zero(salt, sizeof(salt));
        return 1;
    }

    if (derive_key_and_encrypt(message, password, salt, sizeof(salt),
                               encrypted_hex, sizeof(encrypted_hex)) != 0) {
        fprintf(stderr, "Encryption failed.\n");
        secure_zero(password, sizeof(password));
        secure_zero(salt, sizeof(salt));
        return 1;
    }

    if (replace_with_encrypted(username, encrypted_hex) != 0) {
        fprintf(stderr, "Failed to update file with encrypted content.\n");
        secure_zero(password, sizeof(password));
        secure_zero(salt, sizeof(salt));
        secure_zero(encrypted_hex, sizeof(encrypted_hex));
        return 1;
    }

    printf("Encryption complete. Encrypted data stored in %s.txt\n", username);

    secure_zero(password, sizeof(password));
    secure_zero(salt, sizeof(salt));
    secure_zero(encrypted_hex, sizeof(encrypted_hex));

    return 0;
}
