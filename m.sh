#!/bin/sh
# m.sh: in-tree build script for convenience
cd "$(dirname "$0")"
set -ex

case "$1" in
"c")
    # clean artifacts
    rm -rf build compile_commands.json
    ;;
"x")
    # cross compiling, environment vars need to be set
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSROOT="${SYSROOT}" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DCMAKE_SKIP_RPATH=ON \
        ..
    cmake --build .
    ls -lh bin/kcptun-libev
    ;;
"posix")
    # rebuild for strict POSIX compliance
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DFORCE_POSIX=ON \
        ..
    cp compile_commands.json ../
    cmake --build .
    ls -lh bin/kcptun-libev
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld --rtlib=compiler-rt" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build .
    (cd bin && llvm-objdump -drwS kcptun-libev >kcptun-libev.S)
    ls -lh bin/kcptun-libev
    ;;
"msys2")
    # rebuild with MSYS 2
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
        ..
    cmake --build .
    HOST="$(cc -dumpmachine)"
    zip -9j "kcptun-libev-win32.${HOST}.zip" \
        "/usr/bin/msys-2.0.dll" \
        "bin/kcptun-libev.exe"
    ls -lh "kcptun-libev-win32.${HOST}.zip"
    ;;
"ndk")
    # rebuild with Android NDK
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSTEM_NAME="Android" \
        -DCMAKE_SYSTEM_VERSION="${ANDROID_API_LEVEL}" \
        -DCMAKE_ANDROID_NDK="${ANDROID_NDK_ROOT}" \
        -DCMAKE_ANDROID_ARCH_ABI="${ABI_NAME}" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DLINK_STATIC_LIBS=ON \
        ..
    cmake --build .
    ls -lh bin/kcptun-libev
    ;;
"single")
    # rebuild as a single file
    rm -rf build && mkdir -p build/src
    (cd build && cmake -DCMAKE_BUILD_TYPE="Release" ..)
    find contrib src -name '*.c' | while read -r FILE; do
        echo "#include \"${FILE}\""
    done | gcc -pipe -O3 -s -DNDEBUG -D_GNU_SOURCE -pedantic -Wall -Wextra -std=c11 \
        -Icontrib/cjson -Icontrib/csnippets -Icontrib/kcp -Icontrib/libbloom -Isrc \
        -include build/src/config.h \
        -flto=auto -fno-fat-lto-objects -flto-partition=one \
        -fwhole-program \
        -fPIE -pie \
        -o build/bin/kcptun-libev -xc - -lev -lsodium -lm
    ls -lh build/bin/kcptun-libev
    ;;
"san")
    # rebuild with clang & sanitizers
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_C_COMPILER="clang" \
        -DENABLE_SANITIZERS=ON \
        ..
    cp compile_commands.json ../
    cmake --build .
    ls -lh bin/kcptun-libev
    ;;
"min")
    # rebuild for minimized size
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="MinSizeRel" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build .
    ls -lh bin/kcptun-libev
    ;;
"p")
    # rebuild for profiling
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build .
    (cd bin && objdump -drwS kcptun-libev >kcptun-libev.S)
    ls -lh bin/kcptun-libev
    ;;
"r")
    # rebuild for release
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        ..
    cp compile_commands.json ../
    cmake --build .
    ls -lh bin/kcptun-libev
    ;;
"d")
    # rebuild for debug
    if command -v clang-format >/dev/null; then
        find src -type f -regex '.*\.[hc]' -exec clang-format -i {} +
    fi
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DENABLE_SANITIZERS=ON \
        ..
    cp compile_commands.json ../
    cmake --build .
    ls -lh bin/kcptun-libev
    ;;
*)
    cd build
    cmake --build .
    ls -lh bin/kcptun-libev
    ;;
esac
