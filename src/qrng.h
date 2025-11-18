#ifndef QRNG_H
#define QRNG_H

#include <stddef.h>

int qrng_fetch_bytes(unsigned char *buffer, size_t len);
int qrng_generate_password(char *password, size_t len);

#endif /* QRNG_H */
