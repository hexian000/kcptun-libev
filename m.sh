#!/bin/sh
cd "$(dirname "$0")"
GENERATOR="Unix Makefiles"
set -ex

case "$1" in
"x")
    # cross compiling, SYSROOT need to be set
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_PREFIX_PATH="${SYSROOT}" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/src/kcptun-libev"
    ;;
"xs")
    # cross compile statically linked executable
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_PREFIX_PATH="${SYSROOT}" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -DBUILD_STATIC=ON \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/src/kcptun-libev"
    ;;
"r")
    # rebuild release
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/src/kcptun-libev"
    ;;
"s")
    # rebuild statically linked executable
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DBUILD_STATIC=ON \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/src/kcptun-libev"
    ;;
"p")
    # rebuild for profiling
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    nice cmake --build "build"
    (cd "build/src" && objdump -drwS "kcptun-libev" >"kcptun-libev.S")
    ls -lh "build/src/kcptun-libev"
    ;;
"posix")
    # force POSIX APIs
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DTARGET_POSIX=1 \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/src/kcptun-libev"
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    nice cmake --build "build"
    (cd "build/src" && llvm-objdump -drwS "kcptun-libev" >"kcptun-libev.S")
    ls -lh "build/src/kcptun-libev"
    ;;
"msys2")
    # set SYSROOT for finding dependencies
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -DLINK_STATIC_LIBS=TRUE \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/src/kcptun-libev"
    ;;
"single")
    # rebuild as single file
    rm -rf "build" && mkdir -p "build/src"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    find contrib src -name '*.c' | while read -r FILE; do
        echo "#include \"${FILE}\""
    done | gcc -pipe -O2 -g -DNDEBUG -D_GNU_SOURCE -pedantic -Wall -Wextra -std=gnu11 \
        -Icontrib/csnippets -Icontrib -Isrc -include build/src/config.h \
        -o "build/src/kcptun-libev" -xc - -lev -lsodium -lm
    ;;
"c")
    # clean artifacts
    rm -rf "build" "compile_commands.json"
    ;;
*)
    # default to debug builds
    mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    ln -sf "build/compile_commands.json" "compile_commands.json"
    nice cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
esac
