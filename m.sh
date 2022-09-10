#!/bin/sh
cd "$(dirname "$0")"
set -ex

case "$1" in
"x")
    # cross compiling, environment vars need to be set
    rm -rf "xbuild" && mkdir "xbuild"
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "xbuild"
    cmake --build "xbuild" --parallel
    ls -lh "xbuild/src/kcptun-libev"
    ;;
"r")
    # release
    rm -rf "build" && mkdir "build"
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
"s")
    # rebuild statically linked executable with musl libc
    rm -rf "build" && mkdir "build"
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_C_COMPILER="musl-gcc" \
        -DCMAKE_EXE_LINKER_FLAGS="-static" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -DLINK_STATIC_LIBS=TRUE \
        -S "." -B "build"
    cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
"p")
    # rebuild for profiling/benchmarking
    rm -rf "build" && mkdir "build"
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    cmake --build "build" --parallel
    objdump -drwS "build/src/kcptun-libev" >"build/src/kcptun-libev.S"
    ls -lh "build/src/kcptun-libev"
    ;;
"clang")
    # rebuild with clang/lld
    rm -rf "build" && mkdir "build"
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        -S "." -B "build"
    cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
"c")
    # clean artifacts
    rm -rf build xbuild
    ;;
*)
    # default to debug builds
    # ln -sf build/compile_commands.json compile_commands.json
    mkdir -p "build"
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
esac
