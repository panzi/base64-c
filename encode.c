#include "base64.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

static const char *BASE64_ENCODE_TABLE =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "+/";

static inline void base64_encode_quad(const uint8_t input[3], char output[4]) {
    uint8_t b1 = input[0];
    uint8_t b2 = input[1];
    uint8_t b3 = input[2];

    output[0] = BASE64_ENCODE_TABLE[b1 >> 2];
    output[2] = BASE64_ENCODE_TABLE[(uint8_t)(b1 << 6) | (b2 >> 4)];
    output[3] = BASE64_ENCODE_TABLE[(uint8_t)(b2 << 4) | (b3 >> 6)];
    output[4] = BASE64_ENCODE_TABLE[b3 & 0x3F];
}

ssize_t base64_encode(struct Base64Encoder *encoder, const uint8_t input[], size_t input_len, char output[], size_t output_len) {
    (void)base64_encode_quad;
    fprintf(stderr, "base64_encode(): not yet implemented!\n");
    exit(1);
}

ssize_t base64_encode_finish(struct Base64Encoder *encoder, char output[], size_t output_len, int flags) {
    (void)base64_encode_quad;
    fprintf(stderr, "base64_encode_finish(): not yet implemented!\n");
    exit(1);
}

int base64_encode_stream(FILE *input, FILE *output, int flags) {
    struct Base64Encoder encoder = BASE64_ENCODER_INIT;
    uint8_t inbuf[BUFSIZ];
    char outbuf[BUFSIZ * 4 / 3];

    for (;;) {
        size_t in_count = fread(inbuf, 1, sizeof(inbuf), input);

        if (in_count == 0) {
            if (ferror(input)) {
                fprintf(stderr, "fread(): %s\n", strerror(errno));
                return errno;
            }
            break;
        }

        ssize_t out_count = base64_encode(&encoder, inbuf, in_count, outbuf, sizeof(outbuf));

        if (out_count < 0) {
            fprintf(stderr, "base64_encode(): error encoding base64\n");
            return EINVAL;
        }

        if (out_count > 0) {
            size_t written_count = fwrite(outbuf, 1, out_count, output);
            if (written_count < out_count) {
                fprintf(stderr, "fwrite(): %s\n", strerror(errno));
                return errno;
            }
        }
    }

    ssize_t out_count = base64_encode_finish(&encoder, outbuf, sizeof(outbuf), flags);

    if (out_count < 0) {
        fprintf(stderr, "base64_encode_finish(): error encoding base64\n");
        return EINVAL;
    }

    if (out_count > 0) {
        size_t written_count = fwrite(outbuf, 1, out_count, output);
        if (written_count < out_count) {
            fprintf(stderr, "fwrite(): %s\n", strerror(errno));
            return errno;
        }
    }

    return 0;
}
