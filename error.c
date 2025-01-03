#include "base64.h"

#include <errno.h>
#include <string.h>

const char *base64_error_message(int error_code) {
    switch (error_code) {
        case BASE64_ERROR_ILLEGAL_SYNTAX:
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
