#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

#define USERNAME_MAX_LEN 64
#define MESSAGE_MAX_LEN 1024
#define PASSWORD_MAX_LEN 256

int sanitize_username(const char *input, char *output, size_t max_len);
int is_strong_password(const char *password);
void secure_zero(void *ptr, size_t len);
void bytes_to_hex(const unsigned char *bytes, size_t len, char *out_hex);
size_t hex_to_bytes(const char *hex, unsigned char *out_bytes, size_t max_bytes);

#endif /* UTILS_H */
