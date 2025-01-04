#ifndef BASE64_INTERNAL_H
#define BASE64_INTERNAL_H
#pragma once

#include "base64.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASE64_BUFSIZ (16 * 1024)

BASE64_PRIVATE int base64_write_all(int fd, const void *buf, size_t count);

#ifdef __cplusplus
}
#endif

#endif
