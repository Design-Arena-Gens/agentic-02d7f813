#ifndef KDF_H
#define KDF_H

#include <stddef.h>

int pbkdf2_sha512(const unsigned char *password, size_t password_len,
                  const unsigned char *salt, size_t salt_len,
                  unsigned int iterations,
                  unsigned char *output, size_t output_len);

#endif /* KDF_H */
