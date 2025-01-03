#ifndef BASE64_H
#define BASE64_H
#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined _WIN32 || defined _WIN64 || defined __CYGWIN__
#   ifdef WIN_EXPORT
#       ifdef __GNUC__
#           define BASE64_EXPORT __attribute__ ((dllexport))
#       else
#           define BASE64_EXPORT __declspec(dllexport)
#       endif
#   else
#       ifdef __GNUC__
#           define BASE64_EXPORT __attribute__ ((dllimport))
#       else
#           define BASE64_EXPORT __declspec(dllimport)
#       endif
#   endif
#   define BASE64_PRIVATE
#else
#   if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)
#       define BASE64_EXPORT  __attribute__ ((visibility ("default")))
#       define BASE64_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define BASE64_EXPORT
#       define BASE64_PRIVATE
#   endif
#endif

#define BASE64_ERROR_SYNTAX      -1
#define BASE64_ERROR_BUFFER_SIZE -2
#define BASE64_ERROR_IO          -3

BASE64_EXPORT const char *base64_error_message(int error_code);
BASE64_EXPORT size_t base64_strip_whitespace(char buffer[], size_t size);

// Flags
#define BASE64_ALLOW_TRUNCATE   1
#define BASE64_ALLOW_WHITESPACE 2
#define BASE64_DIALECT_URLSAFE  4

struct Base64Decoder {
    char buf[4];
    unsigned int buf_size;
    unsigned int flags;
};

#define BASE64_DECODER_INIT(FLAGS) { .buf = { 0, 0, 0, 0 }, .buf_size = 0, .flags = (FLAGS) }

#define BASE64_NUM_CHARS(NBYTES) (((NBYTES) * 4 + 2) / 3)
#define BASE64_NUM_BYTES(NCHARS) (((NCHARS) * 3 + 3) / 4)

#define BASE64_DECODE_OUTBUF_SIZE(NCHARS) (BASE64_NUM_BYTES(NCHARS) + 3)
#define BASE64_ENCODE_OUTBUF_SIZE(NBYTES) (BASE64_NUM_CHARS(NBYTES) + 5)

BASE64_EXPORT ssize_t base64_decode(const char *input, size_t input_len, uint8_t output[], size_t output_len, int flags);
BASE64_EXPORT ssize_t base64_decode_chunk(struct Base64Decoder *decoder, const char *input, size_t input_len, uint8_t output[], size_t output_len);
BASE64_EXPORT ssize_t base64_decode_finish(struct Base64Decoder *decoder, uint8_t output[], size_t output_len);

BASE64_EXPORT int base64_decode_stream(FILE *input, FILE *output, unsigned int flags);

#define BASE64_SKIP_PADDING BASE64_ALLOW_TRUNCATE

struct Base64Encoder {
    uint8_t buf[3];
    unsigned int buf_size;
    unsigned int flags;
};

#define BASE64_ENCODER_INIT(FLAGS) { .buf = { 0, 0, 0 }, .buf_size = 0, .flags = (FLAGS) }

BASE64_EXPORT ssize_t base64_encode(const uint8_t input[], size_t input_len, char output[], size_t output_len, int flags);
BASE64_EXPORT ssize_t base64_encode_chunk(struct Base64Encoder *encoder, const uint8_t input[], size_t input_len, char output[], size_t output_len);
BASE64_EXPORT ssize_t base64_encode_finish(struct Base64Encoder *encoder, char output[], size_t output_len);
BASE64_EXPORT char   *base64_encode_str(const uint8_t input[], size_t input_len, int flags);

BASE64_EXPORT int base64_encode_stream(FILE *input, FILE *output, unsigned int flags);

#ifdef NDEBUG
#   define BASE64_DEBUGF(FMT, ...)
#else
#   define BASE64_DEBUGF(FMT, ...) fprintf(stderr, "%s:%u: " FMT "\n", __FILE__, __LINE__ __VA_OPT__(,) __VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

#endif
