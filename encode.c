#include "base64.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

static const char *BASE64_ENCODE_TABLE =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "+/";

static const char *URLSAFE_BASE64_ENCODE_TABLE =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "-_";

static inline void base64_encode_quad(const uint8_t input[3], char output[4], const char *table) {
    uint8_t b1 = input[0];
    uint8_t b2 = input[1];
    uint8_t b3 = input[2];

    output[0] = table[b1 >> 2];
    output[1] = table[((b1 << 4) & 0x3F) | (b2 >> 4)];
    output[2] = table[((b2 << 2) & 0x3F) | (b3 >> 6)];
    output[3] = table[b3 & 0x3F];
}

ssize_t base64_encode(struct Base64Encoder *encoder, const uint8_t input[], size_t input_len, char output[], size_t output_len) {
    size_t buf_size = encoder->buf_size;
    assert(buf_size <= 3);

    if (input_len > (((size_t)SSIZE_MAX - 2) / 4) - buf_size || ((input_len + buf_size) * 4 + 2) / 3 > (size_t)SSIZE_MAX) {
        fprintf(stderr, "input_len too big: %zu > %zu\n", input_len, (size_t)SSIZE_MAX);
        return -1;
    }

    size_t input_index = 0;
    ssize_t output_index = 0;

    uint8_t *buf = encoder->buf;
    const char *table = encoder->flags & BASE64_DIALECT_URLSAFE ? URLSAFE_BASE64_ENCODE_TABLE : BASE64_ENCODE_TABLE;

    if (buf_size > 0) {
        size_t rem = 3 - buf_size;
        size_t read_count = rem < input_len ? rem : input_len;
        memcpy(buf + buf_size, input, read_count);
        buf_size += read_count;
        if (buf_size != 3) {
            encoder->buf_size = buf_size;
            return 0;
        }

        if (output_len < 4) {
            fprintf(stderr, "output buffer too small\n");
            return -1;
        }

        base64_encode_quad(buf, output, table);
        output_index += 4;
        input_index = read_count;
    }

    size_t trunc_input_len = input_len - (input_len - input_index) % 3;

    if (trunc_input_len / 3 > (output_len - output_index) / 4) {
        fprintf(stderr, "output buffer too small\n");
        return -1;
    }

    for (; input_index < trunc_input_len; input_index += 3) {
        base64_encode_quad(input + input_index, output + output_index, table);
        output_index += 4;
    }

    if (trunc_input_len < input_len) {
        size_t rem = input_len - trunc_input_len;
        memcpy(buf, input + trunc_input_len, rem);
        encoder->buf_size = rem;
    } else {
        encoder->buf_size = 0;
    }

    return output_index;
}

ssize_t base64_encode_finish(struct Base64Encoder *encoder, char output[], size_t output_len) {
    size_t buf_size = encoder->buf_size;

    if (buf_size == 0) {
        return 0;
    }

    const uint8_t *buf = encoder->buf;

    uint8_t b1 = buf[0];
    uint8_t b2 = buf[1];
    uint8_t b3 = buf[2];

    unsigned int flags = encoder->flags;
    const char *table = flags & BASE64_DIALECT_URLSAFE ? URLSAFE_BASE64_ENCODE_TABLE : BASE64_ENCODE_TABLE;

    if (flags & BASE64_SKIP_PADDING) {
        size_t b64_size = (buf_size * 4 + 2) / 3;

        if (b64_size > output_len) {
            fprintf(stderr, "output buffer too small\n");
            return -1;
        }

        output[0] = table[b1 >> 2];
        if (buf_size > 1) {
            output[1] = table[((b1 << 4) & 0x3F) | (b2 >> 4)];

            if (buf_size > 2) {
                output[2] = table[((b2 << 2) & 0x3F) | (b3 >> 6)];
                output[3] = table[b3 & 0x3F];
            } else {
                output[2] = table[(b2 << 2) & 0x3F];
            }
        } else {
            output[1] = table[(b1 << 4) & 0x3F];
        }

        encoder->buf_size = 0;

        return b64_size;
    }

    if (4 > output_len) {
        fprintf(stderr, "output buffer too small\n");
        return -1;
    }

    output[0] = table[b1 >> 2];
    if (buf_size > 1) {
        output[1] = table[((b1 << 4) & 0x3F) | (b2 >> 4)];

        if (buf_size > 2) {
            output[2] = table[((b2 << 2) & 0x3F) | (b3 >> 6)];
            output[3] = table[b3 & 0x3F];
        } else {
            output[2] = table[(b2 << 2) & 0x3F];
            output[3] = '=';
        }
    } else {
        output[1] = table[(b1 << 4) & 0x3F];
        output[2] = '=';
        output[3] = '=';
    }

    encoder->buf_size = 0;

    return 4;
}

int base64_encode_stream(FILE *input, FILE *output, unsigned int flags) {
    struct Base64Encoder encoder = BASE64_ENCODER_INIT(flags);
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

    ssize_t out_count = base64_encode_finish(&encoder, outbuf, sizeof(outbuf));

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
