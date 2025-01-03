#include <stdio.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>

#include "base64.h"

struct TestContext {
    jmp_buf env;
};

typedef void (*test_func_t)(struct TestContext*);

#define STR_(X) #X
#define STR(X) STR_(X)

#define _test_msg_fmt_(FMT, ...) FMT
#define _test_msg_fmt(DEFAULT, ...) _test_msg_fmt_(__VA_ARGS__ __VA_OPT__(,) DEFAULT)

#define _test_msg_args_(FMT, ...) __VA_OPT__(,) __VA_ARGS__
#define _test_msg_args(...) _test_msg_args_("" __VA_ARGS__)

#define test_assert(COND, ...) \
    if (!(COND)) { \
        fprintf(stderr, "%s:%u:%s: ASSERTION FAILED %s: " _test_msg_fmt("false" __VA_OPT__(,) __VA_ARGS__) "\n", __FILE__, __LINE__, __func__, STR(COND) _test_msg_args(__VA_ARGS__)); \
        longjmp(ctx->env, -1); \
    }

#define test_assert_eq(EXPECTED, ACTUAL, ...) \
    if ((EXPECTED) != (ACTUAL)) {\
        fprintf(stderr, "%s:%u:%s: ASSERTION FAILED %s: " _test_msg_fmt("not equals" __VA_OPT__(,) __VA_ARGS__) "\n", __FILE__, __LINE__, __func__, STR(EXPECTED == ACTUAL) _test_msg_args(__VA_ARGS__)); \
        longjmp(ctx->env, -1); \
    }

#define test_fail(FMT, ...) \
    fprintf(stderr, "%s:%u:%s: ASSERTION FAILED: " FMT "\n", __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__); \
    longjmp(ctx->env, -1); \

void test_decode_chunks(struct TestContext *ctx) {
    uint8_t outbuf[512];
    const char *chunks[] = {
        "A", "", "A==", "BBB", "=", "CC", "CC", NULL
    };
    const uint8_t expected[] = {
        0x00, 0x04, 0x10, 0x08, 0x20, 0x82,
    };

    struct Base64Decoder decoder = BASE64_DECODER_INIT(0);
    size_t outindex = 0;
    for (const char **chunk = chunks; *chunk; ++ chunk) {
        ssize_t count = base64_decode_chunk(&decoder, *chunk, strlen(*chunk), outbuf + outindex, sizeof(outbuf) - outindex);
        test_assert(count >= 0, "base64_decode_chunk(): %s", base64_error_message(count));
        outindex += (size_t)count;
    }

    ssize_t count = base64_decode_finish(&decoder, outbuf + outindex, sizeof(outbuf) - outindex);
    test_assert(count >= 0, "base64_decode_finish(): %s", base64_error_message(count));
    outindex += (size_t)count;

    test_assert_eq(sizeof(expected), outindex);
    test_assert(memcmp(outbuf, expected, sizeof(expected)) == 0);
}

struct ChunkData {
    const uint8_t *data;
    size_t size;
};

#define CHUNK_DATA(...) { .data = (uint8_t[]){ __VA_ARGS__ }, .size = sizeof((uint8_t[]){ __VA_ARGS__ }) }

void test_encode_chunks(struct TestContext *ctx) {
    const struct ChunkData chunks[] = {
        CHUNK_DATA(0x00, 0x01, 0xFF, 0x33),
        CHUNK_DATA(0x1E, 0x56, 0x0A),
        CHUNK_DATA(),
        CHUNK_DATA(0x7F),
        { .data = NULL, .size = 0 },
    };
    const char *expected = "AAH/Mx5WCn8=";
    char outbuf[512];

    struct Base64Encoder encoder = BASE64_ENCODER_INIT(0);
    size_t outindex = 0;
    for (const struct ChunkData *chunk = chunks; chunk->data != NULL; ++ chunk) {
        ssize_t count = base64_encode_chunk(&encoder, chunk->data, chunk->size, outbuf + outindex, sizeof(outbuf) - outindex);
        test_assert(count >= 0, "base64_encode_chunk(): %s", base64_error_message(count));
        outindex += (size_t)count;
    }

    ssize_t count = base64_encode_finish(&encoder, outbuf + outindex, sizeof(outbuf) - outindex);
    test_assert(count >= 0, "base64_encode_finish(): %s", base64_error_message(count));
    outindex += (size_t)count;

    test_assert_eq(strlen(expected), outindex);
    test_assert(strcmp(outbuf, expected) == 0);
}

void test_encode_str(struct TestContext *ctx) {
    const char *data = "Hello World!";
    char *b64 = base64_encode_str((const uint8_t*)data, strlen(data), 0);
    test_assert(b64 != NULL);
    test_assert(strcmp(b64, "SGVsbG8gV29ybGQh") == 0);
    free(b64);
}

const test_func_t tests[] = {
    test_decode_chunks,
    test_encode_chunks,
    test_encode_str,
    NULL,
};

int main(int argc, char *argv[]) {
    size_t test_count = 0;
    size_t error_count = 0;

    printf("Running C API tests...\n");
    for (const test_func_t *test_func = tests; *test_func; ++ test_func) {
        struct TestContext ctx;
        if (setjmp(ctx.env) == 0) {
            (*test_func)(&ctx);
        } else {
            ++ error_count;
        }
        ++ test_count;
    }

    printf("%zu tests, %zu successful, %zu failed\n", test_count, test_count - error_count, error_count);

    return error_count > 0 ? 1 : 0;
}
