#include "base64.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>

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

ssize_t base64_encode(const uint8_t input[], size_t input_len, char output[], size_t output_len, int flags) {
    struct Base64Encoder encoder = BASE64_ENCODER_INIT(flags);

    ssize_t count1 = base64_encode_chunk(&encoder, input, input_len, output, output_len);

    if (count1 < 0) {
        return count1;
    }

    ssize_t count2 = base64_encode_finish(&encoder, output, output_len);

    if (count2 < 0) {
        return count2;
    }

    return count1 + count2;
}

ssize_t base64_encode_chunk(struct Base64Encoder *encoder, const uint8_t input[], size_t input_len, char output[], size_t output_len) {
    size_t buf_size = encoder->buf_size;
    assert(buf_size <= 3);

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
            if (output_len > 0) {
                output[0] = '\0';
            }
            return 0;
        }

        if (output_len < 4) {
            BASE64_DEBUGF("output buffer too small: %zu < 4", output_len);
            return BASE64_ERROR_BUFFER_SIZE;
        }

        base64_encode_quad(buf, output, table);
        output_index += 4;
        input_index = read_count;
    }

    size_t trunc_input_len = input_len - (input_len - input_index) % 3;
    size_t trunc_input_rem = trunc_input_len - input_index;

    if (trunc_input_rem > (SIZE_MAX - 2) / 4) {
        BASE64_DEBUGF("output buffer size calculation overflow: %zu > %zu", trunc_input_rem, (SIZE_MAX - 2) / 4);
        return BASE64_ERROR_BUFFER_SIZE;
    }

    if ((trunc_input_rem * 4 + 2) / 3 > (output_len - output_index)) {
        BASE64_DEBUGF("output buffer too small: %zu > %zu", (trunc_input_rem * 4 + 2) / 3, (output_len - output_index));
        return BASE64_ERROR_BUFFER_SIZE;
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

    if (output_len > output_index) {
        output[output_index] = '\0';
    }

    return output_index;
}

ssize_t base64_encode_finish(struct Base64Encoder *encoder, char output[], size_t output_len) {
    size_t buf_size = encoder->buf_size;

    if (buf_size == 0) {
        if (output_len > 0) {
            output[0] = '\0';
        }
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
            BASE64_DEBUGF("output buffer too small: %zu > %zu", b64_size, output_len);
            return BASE64_ERROR_BUFFER_SIZE;
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

        if (b64_size < output_len) {
            output[b64_size] = '\0';
        }

        return b64_size;
    }

    if (4 > output_len) {
        BASE64_DEBUGF("output buffer too small: 4 > %zu", output_len);
        return BASE64_ERROR_BUFFER_SIZE;
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

    if (4 < output_len) {
        output[4] = '\0';
    }

    encoder->buf_size = 0;

    return 4;
}

int base64_encode_stream(FILE *input, FILE *output, unsigned int flags) {
    struct Base64Encoder encoder = BASE64_ENCODER_INIT(flags);
    uint8_t inbuf[BASE64_BUFSIZ];
    char outbuf[(BASE64_BUFSIZ * 4 + 2) / 3 + 4 + 1];

    for (;;) {
        size_t in_count = fread(inbuf, 1, sizeof(inbuf), input);

        if (in_count == 0) {
            if (ferror(input)) {
                BASE64_DEBUGF("fread(): %s", strerror(errno));
                return BASE64_ERROR_IO;
            }
            break;
        }

        ssize_t out_count = base64_encode_chunk(&encoder, inbuf, in_count, outbuf, sizeof(outbuf));

        if (out_count < 0) {
            BASE64_DEBUGF("base64_encode(): %s", base64_error_message(out_count));
            return out_count;
        }

        if (out_count > 0) {
            size_t written_count = fwrite(outbuf, 1, out_count, output);
            if (written_count < out_count) {
                BASE64_DEBUGF("fwrite(): %s", strerror(errno));
                return BASE64_ERROR_IO;
            }
        }
    }

    ssize_t out_count = base64_encode_finish(&encoder, outbuf, sizeof(outbuf));

    if (out_count < 0) {
        BASE64_DEBUGF("base64_encode_finish(): %s", base64_error_message(out_count));
        return out_count;
    }

    if (out_count > 0) {
        size_t written_count = fwrite(outbuf, 1, out_count, output);
        if (written_count < out_count) {
            BASE64_DEBUGF("fwrite(): %s", strerror(errno));
            return BASE64_ERROR_IO;
        }
    }

    return 0;
}

int base64_encode_fd(int infd, int outfd, unsigned int flags) {
    struct Base64Encoder encoder = BASE64_ENCODER_INIT(flags);
    uint8_t inbuf[BASE64_BUFSIZ];
    char outbuf[(BASE64_BUFSIZ * 4 + 2) / 3 + 4 + 1];

    for (;;) {
        ssize_t in_count = read(infd, inbuf, sizeof(inbuf));

        if (in_count == 0) {
            break;
        } else if (in_count < 0) {
            int errnum = errno;
            if (errnum == EINTR) {
                continue;
            }
            BASE64_DEBUGF("read(): %s", strerror(errnum));
            return BASE64_ERROR_IO;
        }

        ssize_t out_count = base64_encode_chunk(&encoder, inbuf, in_count, outbuf, sizeof(outbuf));

        if (out_count < 0) {
            BASE64_DEBUGF("base64_encode(): %s", base64_error_message(out_count));
            return out_count;
        }

        int errnum = base64_write_all(outfd, outbuf, out_count);
        if (errnum != 0) {
            return errnum;
        }
    }

    ssize_t out_count = base64_encode_finish(&encoder, outbuf, sizeof(outbuf));

    if (out_count < 0) {
        BASE64_DEBUGF("base64_encode_finish(): %s", base64_error_message(out_count));
        return out_count;
    }

    return base64_write_all(outfd, outbuf, out_count);
}

char *base64_encode_str(const uint8_t input[], size_t input_len, int flags) {
    size_t buf_size = BASE64_ENCODE_OUTBUF_SIZE(input_len);
    char *buf = malloc(buf_size);
    if (buf == NULL) {
        return NULL;
    }

    struct Base64Encoder encoder = BASE64_ENCODER_INIT(flags);

    ssize_t count1 = base64_encode_chunk(&encoder, input, input_len, buf, buf_size);

    if (count1 < 0) {
        BASE64_DEBUGF("base64_encode(): %s", base64_error_message(count1));
        errno = EINVAL;
        return NULL;
    }

    ssize_t count2 = base64_encode_finish(&encoder, buf + count1, buf_size - count1);

    if (count2 < 0) {
        BASE64_DEBUGF("base64_encode_finish(): %s", base64_error_message(count2));
        errno = EINVAL;
        return NULL;
    }

    size_t actual_size = count1 + count2 + 1;
    assert(actual_size <= buf_size);

    if (actual_size < buf_size) {
        char *new_buf = realloc(buf, actual_size);
        if (new_buf != NULL) {
            buf = new_buf;
        }
    }

    return buf;
}
