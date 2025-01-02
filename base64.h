#ifndef BASE64_H
#define BASE64_H
#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BASE64_DIALECT_URLSAFE 2

#define BASE64_ALLOW_TRUNCATE 1

struct Base64Decoder {
    char buf[4];
    unsigned int buf_size;
    unsigned int flags;
};

#define BASE64_DECODER_INIT(FLAGS) { .buf = { 0, 0, 0, 0 }, .buf_size = 0, .flags = (FLAGS) }

ssize_t base64_decode(struct Base64Decoder *decoder, const char *input, size_t input_len, uint8_t output[], size_t output_len);
ssize_t base64_decode_finish(struct Base64Decoder *decoder, uint8_t output[], size_t output_len);

int base64_decode_stream(FILE *input, FILE *output, unsigned int flags);

#define BASE64_SKIP_PADDING BASE64_ALLOW_TRUNCATE

struct Base64Encoder {
    uint8_t buf[3];
    unsigned int buf_size;
    unsigned int flags;
};

#define BASE64_ENCODER_INIT(FLAGS) { .buf = { 0, 0, 0 }, .buf_size = 0, .flags = (FLAGS) }

ssize_t base64_encode(struct Base64Encoder *encoder, const uint8_t input[], size_t input_len, char output[], size_t output_len);
ssize_t base64_encode_finish(struct Base64Encoder *encoder, char output[], size_t output_len);

int base64_encode_stream(FILE *input, FILE *output, unsigned int flags);

#ifdef __cplusplus
}
#endif

#endif
