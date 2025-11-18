#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>

#include "sha512.h"

void hmac_sha512(const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t data_len,
                 unsigned char out[SHA512_DIGEST_LENGTH]);

#endif /* HMAC_H */
