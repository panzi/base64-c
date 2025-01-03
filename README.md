Base-64
=======

Base-64 implementation in C done just as an exercise.

This supports streaming in the sense that you can decode and encode Base-64 in
chunks, even if the chunks aren't at 3 bytes/4 Base-64 charcater boundaries.
You just need to make sure that your provided output buffer is big enough for
the decoded/encoded chunk.
