#!/bin/sh

set -ex

# ln -sf build/compile_commands.json compile_commands.json
rm -rf build
mkdir -p build && cd build
case "$1" in
"x")
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_FIND_ROOT_PATH="${STAGING_DIR}/target-mipsel_24kc_musl" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    ;;
"r")
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    ;;
*)
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    ;;
esac

cmake --build . --parallel
ls -lh src/kcptun-libev

# cd src/tests && ctest
