#include "qrng.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

static int fallback_random(unsigned char *buffer, size_t len) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        return -1;
    }
    size_t read = fread(buffer, 1, len, urandom);
    fclose(urandom);
    return read == len ? 0 : -1;
}

static int parse_hex16_json(const char *json, unsigned char *buffer, size_t len) {
    size_t needed = len;
    const char *data_pos = strstr(json, "\"data\"");
    if (!data_pos) {
        return -1;
    }

    const char *p = strchr(data_pos, '[');
    if (!p) {
        return -1;
    }
    p++;

    size_t written = 0;
    while (*p && written < needed) {
        if (*p == '"') {
            char hex_digits[5] = {0};
            p++;
            for (int i = 0; i < 4 && p[i] && p[i] != '"'; i++) {
                hex_digits[i] = p[i];
            }
            if (strlen(hex_digits) != 4) {
                return -1;
            }

            unsigned int value = 0;
            if (sscanf(hex_digits, "%4x", &value) != 1) {
                return -1;
            }

            if (written < needed) {
                buffer[written++] = (unsigned char)((value >> 8) & 0xFF);
            }
            if (written < needed) {
                buffer[written++] = (unsigned char)(value & 0xFF);
            }

            p = strchr(p, '"');
            if (!p) {
                break;
            }
        }
        p++;
    }

    return written >= needed ? 0 : -1;
}

int qrng_fetch_bytes(unsigned char *buffer, size_t len) {
    if (!buffer || len == 0) {
        return -1;
    }

    size_t required_pairs = (len + 1) / 2;
    if (required_pairs == 0) {
        required_pairs = 1;
    }
    if (required_pairs > 1024) {
        required_pairs = 1024;
    }

    char cmd[256];
    int ret = snprintf(cmd, sizeof(cmd),
                       "curl -fsSL \"https://qrng.anu.edu.au/API/jsonI.php?length=%zu&type=hex16\"",
                       required_pairs);
    if (ret <= 0 || (size_t)ret >= sizeof(cmd)) {
        return fallback_random(buffer, len);
    }

    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        return fallback_random(buffer, len);
    }

    char response[16384];
    size_t total_read = fread(response, 1, sizeof(response) - 1, pipe);
    pclose(pipe);

    if (total_read == 0) {
        return fallback_random(buffer, len);
    }
    response[total_read] = '\0';

    if (parse_hex16_json(response, buffer, len) != 0) {
        return fallback_random(buffer, len);
    }

    return 0;
}

int qrng_generate_password(char *password, size_t len) {
    if (!password || len < 12) {
        return -1;
    }

    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*()-_=+[]{}:;,.?/|";
    const size_t charset_len = sizeof(charset) - 1;

    unsigned char random_buf[512];
    if (len > sizeof(random_buf)) {
        return -1;
    }

    for (int attempt = 0; attempt < 5; attempt++) {
        if (qrng_fetch_bytes(random_buf, len) != 0) {
            if (fallback_random(random_buf, len) != 0) {
                return -1;
            }
        }

        for (size_t i = 0; i < len; i++) {
            password[i] = charset[random_buf[i] % charset_len];
        }
        password[len] = '\0';

        if (is_strong_password(password)) {
            secure_zero(random_buf, sizeof(random_buf));
            return 0;
        }
    }

    secure_zero(random_buf, sizeof(random_buf));
    return -1;
}
