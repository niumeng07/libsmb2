#!/bin/bash
# macOS: compile the actual library with narrowing warnings treated as errors.
set -euo pipefail
cd "$(dirname "$0")/.."
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/libsmb2-integers.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
flags=(-DHAVE_CONFIG_H=1 '-D_U_=__attribute__((unused))'
       -Iinclude -Iinclude/apple -Iinclude/smb2 -Ilib -fno-modules
       -Werror=shorten-64-to-32 -g -fsanitize=address,undefined)
for source in lib/*.c; do
    xcrun clang "${flags[@]}" -c "$source" -o "$build_dir/$(basename "${source%.c}").o"
done
ar rcs "$build_dir/libsmb2.a" "$build_dir/"*.o
for test in integer-protocol-test integer-ntlm-test integer-dcerpc-test; do
    xcrun clang "${flags[@]}" "tests/$test.c" "$build_dir/libsmb2.a" -o "$build_dir/$test"
    "$build_dir/$test"
done
