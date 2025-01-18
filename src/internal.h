#ifndef BASE64_INTERNAL_H
#define BASE64_INTERNAL_H
#pragma once

#include "base64.h"

#ifdef __cplusplus
extern "C" {
#endif

// 2 MiB
#define BASE64_BUFSIZ (2 * 1024 * 1024)

// + 1 so % 3 == 0
#define BASE64_ENCODE_INBUF_LEN  (BASE64_BUFSIZ + 1)
// enough space for encoding BASE64_ENCODE_INBUF_LEN plus potentially buffered data plus '\0'
#define BASE64_ENCODE_OUTBUF_LEN ((BASE64_ENCODE_INBUF_LEN * 4 + 2) / 3 + 4 + 1)

// + 1 so % 4 == 0
#define BASE64_DECODE_INBUF_LEN  (((BASE64_BUFSIZ * 4 + 2) / 3) + 1)
// enough space for decoding BASE64_DECODE_INBUF_LEN plus potentially buffered data
#define BASE64_DECODE_OUTBUF_LEN ((BASE64_DECODE_INBUF_LEN * 3 + 3) / 4 + 3)

BASE64_PRIVATE int base64_write_all(int fd, const void *buf, size_t count);

#ifdef __cplusplus
}
#endif

#endif
