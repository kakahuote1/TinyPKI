#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
clang_format_package="clang-format==18.1.8"
fix=0

if [[ "${1:-}" == "--fix" ]]; then
    fix=1
fi

has_clang_format_18() {
    local version
    version="$("${@}" --version 2>/dev/null || true)"
    [[ "$version" == *"version 18."* ]]
}

resolve_clang_format() {
    if [[ -n "${CLANG_FORMAT:-}" ]]; then
        if has_clang_format_18 "$CLANG_FORMAT"; then
            printf '%s\n' "$CLANG_FORMAT"
            return 0
        fi
        echo "CLANG_FORMAT must point to clang-format 18.x." >&2
        return 1
    fi

    if command -v clang-format-18 >/dev/null 2>&1; then
        printf '%s\n' "clang-format-18"
        return 0
    fi

    if command -v clang-format >/dev/null 2>&1 &&
        has_clang_format_18 clang-format; then
        printf '%s\n' "clang-format"
        return 0
    fi

    if command -v uvx >/dev/null 2>&1; then
        printf '%s\n' "uvx --from ${clang_format_package} clang-format"
        return 0
    fi

    echo "clang-format 18.x was not found. Install clang-format-18 or uvx." >&2
    return 1
}

cd "$repo_root"
read -r -a clang_format <<<"$(resolve_clang_format)"

mapfile -d '' files < <(
    find include src tests -type f \( -name "*.h" -o -name "*.c" \) -print0 |
        sort -z
)

if [[ "${#files[@]}" -eq 0 ]]; then
    echo "No C headers or sources found."
    exit 0
fi

echo "Using $("${clang_format[@]}" --version)"

if [[ "$fix" -eq 1 ]]; then
    "${clang_format[@]}" -i -style=file "${files[@]}"
else
    "${clang_format[@]}" --dry-run -Werror -style=file "${files[@]}"
fi
