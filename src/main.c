#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "base64.h"

static void usage(FILE *out, int argc, char *argv[]) {
    fprintf(out, "Usage: %s [OPTIONS] [--] [file...]\n", argc > 0 ? argv[0] : "base64");
}

static void help(int argc, char *argv[]) {
    usage(stdout, argc, argv);
    printf("\n");
    printf("OPTIONS:\n");
    printf("\n");
    printf("    -h          Print this help message.\n");
    printf("    -d          Decode Base 64.\n");
    printf("    -t          Allow truncated padding when decoding, don't emit padding when encoding.\n");
    printf("    -s          Allow white-space when decoding.\n");
    printf("    -u          Use URL-safe Base 64 (use '-' and '_' instead of '+' and '/').\n");
}

int main(int argc, char *argv[]) {
    bool encode = true;
    unsigned int flags = 0;

    int opt = -1;
    while ((opt = getopt(argc, argv, "hdtus")) != -1) {
        switch (opt) {
            case 'h':
                help(argc, argv);
                return 0;

            case 'd':
                encode = false;
                break;

            case 't':
                flags |= BASE64_ALLOW_TRUNCATE;
                break;

            case 'u':
                flags |= BASE64_DIALECT_URLSAFE;
                break;

            case 's':
                flags |= BASE64_ALLOW_WHITESPACE;
                break;

            default:
                usage(stderr, argc, argv);
                return 1;
        }
    }

    if (encode) {
        if (optind >= argc) {
            int errnum = base64_encode_stream(stdin, stdout, flags);
            if (errnum != 0) {
                fprintf(stderr, "Error encoding base64 from <stdin>: %s\n",
                    base64_error_message(errnum));
            }
        } else {
            for (int argind = optind; argind < argc; ++ argind) {
                const char *filename = argv[argind];
                FILE *fp = fopen(filename, "rb");
                if (fp == NULL) {
                    perror(filename);
                } else {
                    int errnum = base64_encode_stream(fp, stdout, flags);
                    if (errnum != 0) {
                        fprintf(stderr, "Error encoding base64 from %s: %s\n",
                            filename, base64_error_message(errnum));
                    }
                    fclose(fp);
                }
            }
        }
    } else {
        if (optind >= argc) {
            int errnum = base64_decode_stream(stdin, stdout, flags);
            if (errnum != 0) {
                fprintf(stderr, "Error parsing base64 from <stdin>: %s\n",
                    base64_error_message(errnum));
            }
        } else {
            for (int argind = optind; argind < argc; ++ argind) {
                const char *filename = argv[argind];
                FILE *fp = fopen(filename, "rb");
                if (fp == NULL) {
                    perror(filename);
                } else {
                    int errnum = base64_decode_stream(fp, stdout, flags);
                    if (errnum != 0) {
                        fprintf(stderr, "Error parsing base64 from %s: %s\n",
                            filename, base64_error_message(errnum));
                    }
                    fclose(fp);
                }
            }
        }
    }

    return 0;
}
