#!/usr/bin/bash

set -eo pipefail

export LANG=C

base64=${1:-./build/debug/base64}

error_count=0
test_count=0
for len in {0..256} 8192 9000; do
    b64=$(head -c "$len" /dev/urandom | base64 -w0)
    if ! cmp -s <(echo -n "$b64" | base64 -d) <(echo -n "$b64" | "$base64" -d); then
        echo "Failed to decode [length=$len]: $b64">&2
        echo "Decoded as (re-encoded using system base64): $(echo -n "$b64" | "$base64" -d | base64 -w0)">&2
        error_count=$((error_count+1))
    fi

    if ! cmp -s <(echo -n "$b64") <(echo -n "$b64" | base64 -d | "$base64"); then
        echo "Failed to encode [length=$len]: $b64">&2
        echo "Encoded as: $(echo -n "$b64" | base64 -d | "$base64")">&2
        error_count=$((error_count+1))
    fi

    test_count=$((test_count+2))
done

echo "$test_count tests, $((test_count-error_count)) successful, $error_count failed"

if [[ 0 -ne "$error_count" ]]; then
    exit 1
fi
