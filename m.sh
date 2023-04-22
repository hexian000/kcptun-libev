#!/bin/sh
cd "$(dirname "$0")"
GENERATOR="Unix Makefiles"
set -ex

case "$1" in
"x")
    # cross compiling, SYSROOT need to be set
    rm -rf "xbuild" && mkdir "xbuild"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_PREFIX_PATH="${SYSROOT}" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -S "." -B "xbuild"
    nice cmake --build "xbuild" --parallel
    ls -lh "xbuild/src/kcptun-libev"
    ;;
"xs")
    # cross compile statically linked executable
    rm -rf "xbuild" && mkdir "xbuild"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXE_LINKER_FLAGS="-static" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_PREFIX_PATH="${SYSROOT}" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -DLINK_STATIC_LIBS=TRUE \
        -S "." -B "xbuild"
    nice cmake --build "xbuild" --parallel
    ls -lh "xbuild/src/kcptun-libev"
    ;;
"r")
    # rebuild release
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    nice cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
"s")
    # rebuild statically linked executable
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXE_LINKER_FLAGS="-static" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DLINK_STATIC_LIBS=TRUE \
        -S "." -B "build"
    nice cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
"p")
    # rebuild for profiling/benchmarking
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    nice cmake --build "build" --parallel
    (cd "build/src" && objdump -drwS "kcptun-libev" >"kcptun-libev.S")
    ls -lh "build/src/kcptun-libev"
    ;;
"posix")
    # force POSIX APIs
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DPOSIX=1 \
        -S "." -B "build"
    nice cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    nice cmake --build "build" --parallel
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
    nice cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
"c")
    # clean artifacts
    rm -rf "build" "xbuild" "compile_commands.json"
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
