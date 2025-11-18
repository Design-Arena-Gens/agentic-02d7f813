#include "input.h"

#include <stdio.h>
#include <string.h>

#include "qrng.h"
#include "utils.h"

static void trim_newline(char *str) {
    if (!str) {
        return;
    }
    size_t len = strlen(str);
    if (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        if (len > 1 && str[len - 2] == '\r') {
            str[len - 2] = '\0';
        }
    }
}

int prompt_username(char *username, int max_len) {
    if (!username || max_len <= 0) {
        return -1;
    }

    char buffer[USERNAME_MAX_LEN * 2];
    while (1) {
        printf("Enter your name (alphanumeric, '-', '_'): ");
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            return -1;
        }
        trim_newline(buffer);
        if (sanitize_username(buffer, username, (size_t)max_len) == 0) {
            return 0;
        }
        printf("Invalid username. Please try again.\n");
    }
}

int prompt_message(char *message, int max_len) {
    if (!message || max_len <= 0) {
        return -1;
    }

    printf("Enter a short message to encrypt: ");
    if (!fgets(message, max_len, stdin)) {
        return -1;
    }
    trim_newline(message);
    if (message[0] == '\0') {
        printf("Message cannot be empty.\n");
        return prompt_message(message, max_len);
    }
    return 0;
}

static int prompt_password_option(void) {
    char input[8];
    while (1) {
        printf("Choose password option:\n");
        printf("  1) Enter a password\n");
        printf("  2) Generate a quantum password\n");
        printf("Selection (1 or 2): ");
        if (!fgets(input, sizeof(input), stdin)) {
            return -1;
        }
        if (input[0] == '1') {
            return 1;
        }
        if (input[0] == '2') {
            return 2;
        }
        printf("Invalid selection. Please choose 1 or 2.\n");
    }
}

int prompt_password(char *password, int max_len) {
    if (!password || max_len <= 0) {
        return -1;
    }

    int option = prompt_password_option();
    if (option == -1) {
        return -1;
    }

    if (option == 1) {
        char buffer[PASSWORD_MAX_LEN * 2];
        while (1) {
            printf("Enter a strong password (>=12 chars, include upper, lower, digit, special): ");
            if (!fgets(buffer, sizeof(buffer), stdin)) {
                return -1;
            }
            trim_newline(buffer);
            if (strlen(buffer) >= (size_t)max_len) {
                printf("Password too long (max %d characters).\n", max_len - 1);
                continue;
            }
            if (is_strong_password(buffer)) {
                strncpy(password, buffer, (size_t)max_len);
                password[max_len - 1] = '\0';
                secure_zero(buffer, sizeof(buffer));
                return 0;
            }
            printf("Password does not meet complexity requirements.\n");
        }
    }

    if (option == 2) {
        size_t generated_len = 20;
        if ((int)generated_len >= max_len) {
            generated_len = (size_t)(max_len - 1);
        }
        if (qrng_generate_password(password, generated_len) != 0) {
            printf("Failed to generate password from QRNG.\n");
            return -1;
        }
        printf("Generated quantum password: %s\n", password);
        return 0;
    }

    return -1;
}
