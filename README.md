Base-64
=======

Base-64 implementation in C done just as an exercise.

This supports streaming in the sense that you can decode and encode Base-64 in
chunks, even if the chunks aren't at 3 bytes/4 Base-64 charcater boundaries.
You just need to make sure that your provided output buffer is big enough for
the decoded/encoded chunk.

API
---

The main functions in this library are the fllowing. All others are just helpers
built around them.

```C
ssize_t base64_decode_chunk(struct Base64Decoder *decoder, const char *input, size_t input_len, uint8_t output[], size_t output_len);
ssize_t base64_decode_finish(struct Base64Decoder *decoder, uint8_t output[], size_t output_len);

ssize_t base64_encode_chunk(struct Base64Encoder *encoder, const uint8_t input[], size_t input_len, char output[], size_t output_len);
ssize_t base64_encode_finish(struct Base64Encoder *encoder, char output[], size_t output_len);
```

### Example usage

Having this as two functions means you can decode/encode big input in chunks,
even if the chunks don't exactly cut the input into Base 64 units. Base 64
encodes 3 bytes into 4 ASCII characters, so when decoding you always need to
read 4 (non-white space) ASCII characters to decode a unit. When encoding you
need to always read 3 bytes to encode a full unit.

For decoding the output buffer needs to be big enough to hold the decoded input,
including potentially buffered bytes inside the decoder struct. See the
`BASE64_DECODE_OUTBUF_SIZE(NCHARS)` helper macro for the size calculation.

For encoding the output buffer needs to be big enough to hold the encoded input,
including potentially buffered bytes inside the encoder struct. See the
`BASE64_ENCODE_OUTBUF_SIZE(NBYTES)` helper macro for the size calculation.

You can re-use the encode/decoder structs for further encoding/decoding, you
just need to set `buf_size` to 0 (and you can change `flags` if you want to).

```C
struct Base64Decoder decoder = BASE64_DECODER_INIT(0);

ssize_t res = base64_decode_chunk(&decode, input, input_len, output, output_len);
if (res < 0) {
    fprintf(stderr, "Error: %s\n", base64_error_message(res));
    exit(1);
}

size_t decoded_size = res;

res = base64_decode_finish(&decode, output + decoded_size, output_len - decoded_size);
if (res < 0) {
    fprintf(stderr, "Error: %s\n", base64_error_message(res));
    exit(1);
}

decoded_size += res;
```

```C
struct Base64Encoder encoder = BASE64_ENCODER_INIT(0);

ssize_t res = base64_encode_chunk(&decode, input, input_len, output, output_len);
if (res < 0) {
    fprintf(stderr, "Error: %s\n", base64_error_message(res));
    exit(1);
}

size_t encoded_size = res;

res = base64_decode_finish(&decode, output + encoded_size, output_len - encoded_size);
if (res < 0) {
    fprintf(stderr, "Error: %s\n", base64_error_message(res));
    exit(1);
}

encoded_size += res;
```

See [`src/base64.h`](src/base64.h) for all provided functions and flags, and
[`src/main.c`](src/main.c) for more usage.

Build
-----

Compile static and shared library, and `base64` binary:

```bash
mkdir -p build/debug
make -j`nproc`
```

This generates these files:

```
build/debug/base64
build/debug/libbase64.a
build/debug/libbase64.so
```

Compile in release mode:

```bash
mkdir -p build/release
make -j`nproc` DEBUG=OFF
```

This generates these files:

```
build/release/base64
build/release/libbase64.a
build/release/libbase64.so
```

Run test:

```bash
make test
```
