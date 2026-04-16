#!/bin/sh
# Idempotently apply one or more BoringSSL patches.
# Usage: apply-boringssl.sh patch1.patch [patch2.patch ...]
for PATCH in "$@"; do
    if git apply --reverse --check "$PATCH" 2>/dev/null; then
        echo "[boringssl-patch] $(basename "$PATCH") already applied, skipping."
    else
        git apply --ignore-whitespace "$PATCH"
        echo "[boringssl-patch] $(basename "$PATCH") applied successfully."
    fi
done
