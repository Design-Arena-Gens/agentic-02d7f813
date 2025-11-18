#include "utils.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

int sanitize_username(const char *input, char *output, size_t max_len) {
    if (!input || !output || max_len == 0) {
        return -1;
    }

    size_t idx = 0;
    for (; input[idx] != '\0' && idx < max_len - 1; idx++) {
        char ch = input[idx];
        if (isalnum((unsigned char)ch) || ch == '-' || ch == '_') {
            output[idx] = ch;
        } else if (isspace((unsigned char)ch)) {
            output[idx] = '_';
        } else {
            return -1;
        }
    }

    output[idx] = '\0';
    return idx > 0 ? 0 : -1;
}

int is_strong_password(const char *password) {
    if (!password) {
        return 0;
    }

    size_t len = strlen(password);
    if (len < 12 || len > PASSWORD_MAX_LEN - 1) {
        return 0;
    }

    int has_upper = 0;
    int has_lower = 0;
    int has_digit = 0;
    int has_special = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)password[i];
        if (isupper(ch)) {
            has_upper = 1;
        } else if (islower(ch)) {
            has_lower = 1;
        } else if (isdigit(ch)) {
            has_digit = 1;
        } else if (ispunct(ch) || ch == ' ') {
            has_special = 1;
        }
    }

    return has_upper && has_lower && has_digit && has_special;
}

void secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

void bytes_to_hex(const unsigned char *bytes, size_t len, char *out_hex) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2] = hex_chars[(bytes[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = hex_chars[bytes[i] & 0xF];
    }
    out_hex[len * 2] = '\0';
}

size_t hex_to_bytes(const char *hex, unsigned char *out_bytes, size_t max_bytes) {
    if (!hex || !out_bytes) {
        return 0;
    }

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return 0;
    }

    size_t bytes_len = hex_len / 2;
    if (bytes_len > max_bytes) {
        bytes_len = max_bytes;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int value = 0;
        if (sscanf(&hex[i * 2], "%2x", &value) != 1) {
            return 0;
        }
        out_bytes[i] = (unsigned char)value;
    }

    return bytes_len;
}
