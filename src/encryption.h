#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stddef.h>

int derive_key_and_encrypt(const char *message,
                           const char *password,
                           const unsigned char *salt,
                           size_t salt_len,
                           char *out_hex,
                           size_t out_hex_len);

#endif /* ENCRYPTION_H */
