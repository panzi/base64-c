#!/usr/bin/bash

set -eo pipefail

export LANG=C

base64=${1:-./build/debug/base64}

error_count=0
test_count=0

function print_summary {
    echo
    echo "$test_count tests, $((test_count-error_count)) successful, $error_count failed"
}

trap print_summary EXIT

for len in {0..256} 8192 9000; do
    b64=$(head -c "$len" /dev/urandom | base64 -w0)
    if ! cmp -s <(echo -n "$b64" | base64 -d) <(echo -n "$b64" | "$base64" -d); then
        echo "Failed to decode [length=$len]: $b64">&2
        echo "Decoded as (re-encoded using system base64): $(echo -n "$b64" | "$base64" -d | base64 -w0)">&2
        echo >&2
        error_count=$((error_count+1))
    fi

    if ! cmp -s <(echo -n "$b64") <(echo -n "$b64" | base64 -d | "$base64"); then
        echo "Failed to encode [length=$len]: $b64">&2
        echo "Encoded as: $(echo -n "$b64" | base64 -d | "$base64")">&2
        echo >&2
        error_count=$((error_count+1))
    fi

    ub64=$(echo -n "$b64" | tr '+/' '-_' | sed s/=//g)
    if ! cmp -s <(echo -n "$b64" | base64 -d) <(echo -n "$ub64" | "$base64" -d -u -t); then
        echo "Failed to decode URL-safe [length=$len]: $ub64">&2
        echo "Decoded as (re-encoded using system base64): $(echo -n "$ub64" | "$base64" -d -u -t | base64 -w0)">&2
        echo >&2
        error_count=$((error_count+1))
    fi

    if ! cmp -s <(echo -n "$ub64") <(echo -n "$b64" | base64 -d | "$base64" -u -t); then
        echo "Failed to encode URL-safe [length=$len]: $ub64">&2
        echo "Encoded as: $(echo -n "$b64" | base64 -d | "$base64" -u -t)">&2
        echo >&2
        error_count=$((error_count+1))
    fi

    test_count=$((test_count+4))
done

if [[ 0 -ne "$error_count" ]]; then
    exit 1
fi
