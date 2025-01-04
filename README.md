Base-64
=======

Base-64 implementation in C done just as an exercise.

This supports streaming in the sense that you can decode and encode Base-64 in
chunks, even if the chunks aren't at 3 bytes/4 Base-64 charcater boundaries.
You just need to make sure that your provided output buffer is big enough for
the decoded/encoded chunk.

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
