#!/bin/sh
# 幂等地 apply BoringSSL patch：已 apply 则跳过，否则 apply
PATCH="$1"
if git apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "[boringssl-patch] already applied, skipping."
else
    git apply --ignore-whitespace "$PATCH"
    echo "[boringssl-patch] applied successfully."
fi
