#include "file_ops.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define FILENAME_MAX_LEN 256

static int build_filename(const char *username, char *filename, size_t filename_len) {
    if (!username || !filename) {
        return -1;
    }
    int written = snprintf(filename, filename_len, "%s.txt", username);
    if (written <= 0 || (size_t)written >= filename_len) {
        return -1;
    }
    return 0;
}

int write_plain_message(const char *username, const char *message) {
    if (!username || !message) {
        return -1;
    }

    char filename[FILENAME_MAX_LEN];
    if (build_filename(username, filename, sizeof(filename)) != 0) {
        return -1;
    }

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        return -1;
    }

    if (fputs(message, fp) == EOF || fputc('\n', fp) == EOF) {
        fclose(fp);
        return -1;
    }

    if (fflush(fp) != 0) {
        fclose(fp);
        return -1;
    }

    if (fsync(fileno(fp)) != 0) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int replace_with_encrypted(const char *username, const char *encrypted) {
    if (!username || !encrypted) {
        return -1;
    }

    char filename[FILENAME_MAX_LEN];
    char temp_filename[FILENAME_MAX_LEN];
    if (build_filename(username, filename, sizeof(filename)) != 0) {
        return -1;
    }
    if (snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", filename) <= 0) {
        return -1;
    }

    FILE *fp = fopen(temp_filename, "w");
    if (!fp) {
        return -1;
    }

    if (fputs(encrypted, fp) == EOF || fputc('\n', fp) == EOF) {
        fclose(fp);
        return -1;
    }

    if (fflush(fp) != 0) {
        fclose(fp);
        return -1;
    }

    if (fsync(fileno(fp)) != 0) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    if (rename(temp_filename, filename) != 0) {
        remove(temp_filename);
        return -1;
    }

    return 0;
}
