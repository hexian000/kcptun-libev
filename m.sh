#!/bin/sh

set -ex

case "$1" in
"x")
    # cross compiling, environment vars need to be set
    rm -rf xbuild
    mkdir -p "xbuild" && cd "xbuild"
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_FIND_ROOT_PATH="${BUILDROOT}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    cmake --build . --parallel
    ;;
"r")
    rm -rf build
    mkdir -p build && cd build
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    cmake --build . --parallel
    ls -lh src/kcptun-libev
    ;;
"s")
    rm -rf build
    mkdir -p build && cd build
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="MinSizeRel" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    cmake --build . --parallel
    # cd src/tests && ctest
    ls -lh src/kcptun-libev
    ;;
"p")
    rm -rf build
    mkdir -p build && cd build
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    cmake --build . --parallel
    # cd src/tests && ctest
    ;;
"clang")
    rm -rf build
    mkdir -p build && cd build
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        ..
    cmake --build . --parallel
    # cd src/tests && ctest
    ls -lh src/kcptun-libev
    ;;
"c")
    rm -rf build xbuild
    ;;
*)
    # ln -sf build/compile_commands.json compile_commands.json
    mkdir -p build && cd build
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    cmake --build . --parallel
    # cd src/tests && ctest
    ;;
esac
