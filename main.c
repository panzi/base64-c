#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "base64.h"

void usage(FILE *out, int argc, char *argv[]) {
    fprintf(out, "Usage: %s [-d] [--] [file...]\n", argc > 0 ? argv[0] : "base64");
}

int main(int argc, char *argv[]) {
    bool encode = true;
    int flags = 0;

    int opt = -1;
    while ((opt = getopt(argc, argv, "dt")) != -1) {
        switch (opt) {
            case 'd':
                encode = false;
                break;

            case 't':
                flags |= BASE64_ALLOW_TRUNCATE;
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
                fprintf(stderr, "Error encoding base64 from <stdin>\n");
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
                        fprintf(stderr, "Error encoding base64 from: %s\n", filename);
                    }
                    fclose(fp);
                }
            }
        }
    } else {
        if (optind >= argc) {
            int errnum = base64_decode_stream(stdin, stdout, 0);
            if (errnum != 0) {
                fprintf(stderr, "Error parsing base64 from <stdin>\n");
            }
        } else {
            for (int argind = optind; argind < argc; ++ argind) {
                const char *filename = argv[argind];
                FILE *fp = fopen(filename, "rb");
                if (fp == NULL) {
                    perror(filename);
                } else {
                    int errnum = base64_decode_stream(fp, stdout, 0);
                    if (errnum != 0) {
                        fprintf(stderr, "Error parsing base64 from: %s\n", filename);
                    }
                    fclose(fp);
                }
            }
        }
    }

    return 0;
}
