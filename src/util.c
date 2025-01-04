#include "base64.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

const char *base64_error_message(int error_code) {
    switch (error_code) {
        case BASE64_ERROR_SYNTAX:
            return "illegal base 64 syntax";

        case BASE64_ERROR_BUFFER_SIZE:
            return "output buffer too small";

        case BASE64_ERROR_IO:
        {
            int errnum = errno;
            return errnum == 0 ? "I/O error" : strerror(errnum);
        }

        default:
            return "illegal error code";
    }
}

#define IS_SPACE(C) (((C) >= '\t' && (C) <= '\r') || (C) == ' ')

size_t base64_strip_whitespace(char buffer[], size_t size) {
    size_t space_index = 0;
    for (; space_index < size; ++ space_index) {
        char ch = buffer[space_index];
        if (IS_SPACE(ch)) {
            break;
        }
    }

    size_t delete_count = 0;

    while (space_index < size) {
        size_t non_space_index = space_index + 1;
        for (; non_space_index < size; ++ non_space_index) {
            char ch = buffer[non_space_index];
            if (!IS_SPACE(ch)) {
                break;
            }
        }

        size_t next_space_index = non_space_index;
        for (; next_space_index < size; ++ next_space_index) {
            char ch = buffer[next_space_index];
            if (IS_SPACE(ch)) {
                break;
            }
        }

        size_t space_len = non_space_index - space_index;
        memmove(
            buffer + space_index - delete_count,
            buffer + non_space_index,
            next_space_index - non_space_index);

        delete_count += space_len;

        space_index = next_space_index;
    }

    return size - delete_count;
}

int base64_write_all(int fd, const void *buf, size_t count) {
    while (count > 0) {
        ssize_t written_count = write(fd, buf, count);
        if (written_count < 0) {
            int errnum = errno;
            if (errnum == EINTR) {
                continue;
            }
            BASE64_DEBUGF("write(): %s", strerror(errnum));
            return BASE64_ERROR_IO;
        }
        count -= written_count;
        buf += written_count;
    }
    return 0;
}
