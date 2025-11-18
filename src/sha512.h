#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_LENGTH 64

typedef struct {
    uint64_t state[8];
    uint64_t bitlen[2];
    unsigned char buffer[SHA512_BLOCK_SIZE];
    size_t buffer_len;
} sha512_ctx;

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const unsigned char *data, size_t len);
void sha512_final(sha512_ctx *ctx, unsigned char hash[SHA512_DIGEST_LENGTH]);
void sha512_compute(const unsigned char *data, size_t len, unsigned char hash[SHA512_DIGEST_LENGTH]);

#endif /* SHA512_H */
