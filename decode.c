#include "base64.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#define BASE64_CHAR_ERROR   ((unsigned int)0x100)
#define BASE64_CHAR_PADDING ((unsigned int)0x200)

static const uint16_t BASE64_DECODE_TABLE[256] = {
    [ 0 ... 255 ] = BASE64_CHAR_ERROR,
    [ 'A' ] =  0, [ 'a' ] = 26, [ '0' ] = 52,
    [ 'B' ] =  1, [ 'b' ] = 27, [ '1' ] = 53,
    [ 'C' ] =  2, [ 'c' ] = 28, [ '2' ] = 54,
    [ 'D' ] =  3, [ 'd' ] = 29, [ '3' ] = 55,
    [ 'E' ] =  4, [ 'e' ] = 30, [ '4' ] = 56,
    [ 'F' ] =  5, [ 'f' ] = 31, [ '5' ] = 57,
    [ 'G' ] =  6, [ 'g' ] = 32, [ '6' ] = 58,
    [ 'H' ] =  7, [ 'h' ] = 33, [ '7' ] = 59,
    [ 'I' ] =  8, [ 'i' ] = 34, [ '8' ] = 60,
    [ 'J' ] =  9, [ 'j' ] = 35, [ '9' ] = 61,
    [ 'K' ] = 10, [ 'k' ] = 36, [ '+' ] = 62,
    [ 'L' ] = 11, [ 'l' ] = 37, [ '/' ] = 63,
    [ 'M' ] = 12, [ 'm' ] = 38, [ '=' ] = BASE64_CHAR_PADDING,
    [ 'N' ] = 13, [ 'n' ] = 39,
    [ 'O' ] = 14, [ 'o' ] = 40,
    [ 'P' ] = 15, [ 'p' ] = 41,
    [ 'Q' ] = 16, [ 'q' ] = 42,
    [ 'R' ] = 17, [ 'r' ] = 43,
    [ 'S' ] = 18, [ 's' ] = 44,
    [ 'T' ] = 19, [ 't' ] = 45,
    [ 'U' ] = 20, [ 'u' ] = 46,
    [ 'V' ] = 21, [ 'v' ] = 47,
    [ 'W' ] = 22, [ 'w' ] = 48,
    [ 'X' ] = 23, [ 'x' ] = 49,
    [ 'Y' ] = 24, [ 'y' ] = 50,
    [ 'Z' ] = 25, [ 'z' ] = 51,
};

#define BASE64_DECODE_CHAR(C) (BASE64_DECODE_TABLE[(C)])
#define BASE64_DECODE_CHAR_ALT(C) ( \
    (C) >= 'A' && (C) <= 'Z' ? (uint_fast16_t)(C) - 'A' : \
    (C) >= 'a' && (C) <= 'z' ? 26 + (uint_fast16_t)(C) - 'a' : \
    (C) >= '0' && (C) <= '9' ? 52 + (uint_fast16_t)(C) - '0' : \
    (C) == '+' ? 62 : \
    (C) == '/' ? 63 : \
    (C) == '=' ? BASE64_CHAR_PADDING : \
    BASE64_CHAR_ERROR \
)

static inline int base64_decode_quad(const char input[4], uint8_t output[3]) {
    uint_fast16_t c1 = input[0];
    uint_fast16_t c2 = input[1];
    uint_fast16_t c3 = input[2];
    uint_fast16_t c4 = input[3];

    c1 = BASE64_DECODE_CHAR(c1);
    c2 = BASE64_DECODE_CHAR(c2);
    c3 = BASE64_DECODE_CHAR(c3);
    c4 = BASE64_DECODE_CHAR(c4);

    if (((c1 | c2 | c3 | c4) & BASE64_CHAR_ERROR) | ((c1 | c2) & BASE64_CHAR_PADDING)) {
        fprintf(stderr, "illegal input: \"%c%c%c%c\"\n", input[0], input[1], input[2], input[3]);
        fprintf(stderr, "                %c%c%c%c\n",
            c1 == BASE64_CHAR_ERROR ? '^' : ' ',
            c2 == BASE64_CHAR_ERROR ? '^' : ' ',
            c3 == BASE64_CHAR_ERROR ? '^' : ' ',
            c4 == BASE64_CHAR_ERROR ? '^' : ' ');
        return -1;
    }

    if (~(c4 & BASE64_CHAR_PADDING) & (c3 & BASE64_CHAR_PADDING)) {
        fprintf(stderr, "illegal input (padding): \"%c%c%c%c\"\n", input[0], input[1], input[2], input[3]);
        return -1;
    }

    uint8_t b1 = c1;
    uint8_t b2 = c2;
    uint8_t b3 = c3;
    uint8_t b4 = c4;

    output[0] = (uint8_t)(b1 << 2) | (b2 >> 4);
    output[1] = (uint8_t)(b2 << 4) | (b3 >> 2);
    output[2] = (uint8_t)(b3 << 6) | b4;

    return 3 - (c3 >> 9) - (c4 >> 9);
}

ssize_t base64_decode(struct Base64Decoder *decoder, const char *input, size_t input_len, uint8_t output[], size_t output_len) {
    if (input_len > (size_t)SSIZE_MAX) {
        fprintf(stderr, "input_len too big: %zu > %zu\n", input_len, (size_t)SSIZE_MAX);
        return -1;
    }

    size_t input_index = 0;
    ssize_t output_index = 0;

    size_t buf_size = decoder->buf_size;
    char *buf = decoder->buf;

    if (buf_size > 0) {
        assert(buf_size < 4);

        size_t rem = 4 - buf_size;
        size_t read_count = rem < input_len ? rem : input_len;
        memcpy(buf + buf_size, input, read_count);
        buf_size += read_count;
        if (buf_size != 4) {
            decoder->buf_size = buf_size;
            return 0;
        }

        if (output_len < 3) {
            fprintf(stderr, "output buffer too small\n");
            return -1;
        }

        int out_count = base64_decode_quad(buf, output);
        if (out_count < 0) {
            return -1;
        }
        output_index = (ssize_t)out_count;
        input_index = read_count;
    }

    size_t trunc_input_len = input_len - (input_len - input_index) % 4;

    if (trunc_input_len / 4 * 3 > (output_len - output_index)) {
        fprintf(stderr, "output buffer too small\n");
        return -1;
    }

    for (; input_index < trunc_input_len; input_index += 4) {
        int out_count = base64_decode_quad(input + input_index, output + output_index);
        if (out_count < 0) {
            return -1;
        }
        output_index += (ssize_t)out_count;
    }

    if (trunc_input_len < input_len) {
        size_t rem = input_len - trunc_input_len;
        memcpy(buf, input + trunc_input_len, rem);
        decoder->buf_size = rem;
    } else {
        decoder->buf_size = 0;
    }

    return output_index;
}

ssize_t base64_decode_finish(struct Base64Decoder *decoder, uint8_t output[], size_t output_len, int flags) {
    size_t buf_size = decoder->buf_size;

    if (buf_size == 0) {
        return 0;
    }

    if (!(flags & BASE64_ALLOW_TRUNCATE)) {
        fprintf(stderr, "missing padding!\n");
        return -1;
    }

    char *buf = decoder->buf;
    memset(buf + buf_size, 'A', 4 - buf_size);

    if (output_len < buf_size) {
        // XXX: not exact
        fprintf(stderr, "output buffer too small\n");
        return -1;
    }

    return base64_decode_quad(buf, output);
}

int base64_decode_stream(FILE *input, FILE *output, int flags) {
    struct Base64Decoder decoder = BASE64_DECODER_INIT;
    char inbuf[BUFSIZ];
    uint8_t outbuf[BUFSIZ];

    for (;;) {
        size_t in_count = fread(inbuf, 1, sizeof(inbuf), input);

        if (in_count == 0) {
            if (ferror(input)) {
                fprintf(stderr, "fread(): %s\n", strerror(errno));
                return errno;
            }
            break;
        }

        ssize_t out_count = base64_decode(&decoder, inbuf, in_count, outbuf, sizeof(outbuf));

        if (out_count < 0) {
            fprintf(stderr, "base64_decode(): error parsing base64\n");
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

    ssize_t out_count = base64_decode_finish(&decoder, outbuf, sizeof(outbuf), flags);

    if (out_count < 0) {
        fprintf(stderr, "base64_decode_finish(): error parsing base64\n");
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
