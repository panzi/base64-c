#include "base64.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#define BASE64_CHAR_ERROR   ((uint16_t)0x100)
#define BASE64_CHAR_PADDING ((uint16_t)0x200)

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

static const uint16_t URLSAFE_BASE64_DECODE_TABLE[256] = {
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
    [ 'K' ] = 10, [ 'k' ] = 36, [ '-' ] = 62,
    [ 'L' ] = 11, [ 'l' ] = 37, [ '_' ] = 63,
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

static inline int base64_decode_quad(const char input[4], uint8_t output[3], const uint16_t *table) {
    uint_fast16_t c1 = input[0];
    uint_fast16_t c2 = input[1];
    uint_fast16_t c3 = input[2];
    uint_fast16_t c4 = input[3];

    c1 = table[c1];
    c2 = table[c2];
    c3 = table[c3];
    c4 = table[c4];

    if (((c1 | c2 | c3 | c4) & BASE64_CHAR_ERROR) | ((c1 | c2) & BASE64_CHAR_PADDING)) {
        BASE64_DEBUGF("illegal input: \"%c%c%c%c\"",
            input[0], input[1], input[2], input[3]);

        BASE64_DEBUGF("                %c%c%c%c",
            c1 == BASE64_CHAR_ERROR ? '^' : ' ',
            c2 == BASE64_CHAR_ERROR ? '^' : ' ',
            c3 == BASE64_CHAR_ERROR ? '^' : ' ',
            c4 == BASE64_CHAR_ERROR ? '^' : ' ');

        return BASE64_ERROR_SYNTAX;
    }

    if (~(c4 & BASE64_CHAR_PADDING) & (c3 & BASE64_CHAR_PADDING)) {
        BASE64_DEBUGF("illegal input (padding): \"%c%c%c%c\"",
            input[0], input[1], input[2], input[3]);
        return BASE64_ERROR_SYNTAX;
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

ssize_t base64_decode(const char *input, size_t input_len, uint8_t output[], size_t output_len, int flags) {
    struct Base64Decoder decoder = BASE64_DECODER_INIT(flags);

    ssize_t count1 = base64_decode_chunk(&decoder, input, input_len, output, output_len);

    if (count1 < 0) {
        return count1;
    }

    ssize_t count2 = base64_decode_finish(&decoder, output + count1, output_len - count1);

    if (count2 < 0) {
        return count2;
    }

    return count1 + count2;
}

ssize_t base64_decode_chunk(struct Base64Decoder *decoder, const char *input, size_t input_len, uint8_t output[], size_t output_len) {
    size_t buf_size = decoder->buf_size;
    assert(buf_size <= 4);

    size_t input_index = 0;
    ssize_t output_index = 0;

    char *buf = decoder->buf;
    const uint16_t *table = decoder->flags & BASE64_DIALECT_URLSAFE ?
        URLSAFE_BASE64_DECODE_TABLE : BASE64_DECODE_TABLE;

    if (buf_size > 0) {
        size_t rem = 4 - buf_size;
        size_t read_count = rem < input_len ? rem : input_len;
        memcpy(buf + buf_size, input, read_count);
        buf_size += read_count;
        if (buf_size != 4) {
            decoder->buf_size = buf_size;
            return 0;
        }

        if (output_len < 3) {
            BASE64_DEBUGF("output buffer too small: %zu < 3", output_len);
            return BASE64_ERROR_BUFFER_SIZE;
        }

        int out_count = base64_decode_quad(buf, output, table);
        if (out_count < 0) {
            return out_count;
        }
        output_index = (ssize_t)out_count;
        input_index = read_count;
    }

    size_t trunc_input_len = input_len - (input_len - input_index) % 4;
    size_t trunc_input_rem = trunc_input_len - input_index;

    if (trunc_input_rem > (SIZE_MAX - 3) / 3) {
        BASE64_DEBUGF("output buffer size calculation overflow: %zu > %zu", trunc_input_rem, (SIZE_MAX - 3) / 3);
        return BASE64_ERROR_BUFFER_SIZE;
    }

    if ((trunc_input_rem * 3 + 3) / 4 > (output_len - output_index)) {
        BASE64_DEBUGF("output buffer too small: %zu > %zu", (trunc_input_rem * 3 + 3) / 4, (output_len - output_index));
        return BASE64_ERROR_BUFFER_SIZE;
    }

    for (; input_index < trunc_input_len; input_index += 4) {
        int out_count = base64_decode_quad(input + input_index, output + output_index, table);
        if (out_count < 0) {
            return out_count;
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

ssize_t base64_decode_finish(struct Base64Decoder *decoder, uint8_t output[], size_t output_len) {
    size_t buf_size = decoder->buf_size;

    if (buf_size == 0) {
        return 0;
    }

    if (!(decoder->flags & BASE64_ALLOW_TRUNCATE)) {
        BASE64_DEBUGF("missing padding! (buf_size=%zu, buf={0x%02x, 0x%02x, 0x%02x, 0x%02x})",
            buf_size,
            (unsigned int)decoder->buf[0],
            (unsigned int)decoder->buf[1],
            (unsigned int)decoder->buf[2],
            (unsigned int)decoder->buf[3]);
        return BASE64_ERROR_SYNTAX;
    }

    char *buf = decoder->buf;
    memset(buf + buf_size, '=', 4 - buf_size);

    if (output_len < ((buf_size * 3) / 4)) {
        BASE64_DEBUGF("output buffer too small: %zu < %zu", output_len, ((buf_size * 3) / 4));
        return BASE64_ERROR_BUFFER_SIZE;
    }

    const uint16_t *table = decoder->flags & BASE64_DIALECT_URLSAFE ?
        URLSAFE_BASE64_DECODE_TABLE : BASE64_DECODE_TABLE;
    int out_count = base64_decode_quad(buf, output, table);

    if (out_count >= 0) {
        decoder->buf_size = 0;
    }

    return out_count;
}

int base64_decode_stream(FILE *input, FILE *output, unsigned int flags) {
    struct Base64Decoder decoder = BASE64_DECODER_INIT(flags & ~BASE64_ALLOW_WHITESPACE);
    char inbuf[(16 * 1024 * 4 + 2) / 3];
    uint8_t outbuf[16 * 1024 + 3];
    unsigned int allow_ws = flags & BASE64_ALLOW_WHITESPACE;

    for (;;) {
        size_t in_count = fread(inbuf, 1, sizeof(inbuf), input);

        if (in_count == 0) {
            if (ferror(input)) {
                BASE64_DEBUGF("fread(): %s", strerror(errno));
                return BASE64_ERROR_IO;
            }
            break;
        }

        if (allow_ws) {
            in_count = base64_strip_whitespace(inbuf, in_count);
        }
        ssize_t out_count = base64_decode_chunk(&decoder, inbuf, in_count, outbuf, sizeof(outbuf));

        if (out_count < 0) {
            BASE64_DEBUGF("base64_decode(): %s", base64_error_message(out_count));
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

    ssize_t out_count = base64_decode_finish(&decoder, outbuf, sizeof(outbuf));

    if (out_count < 0) {
        BASE64_DEBUGF("base64_decode_finish(): %s", base64_error_message(out_count));
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
