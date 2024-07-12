#!/bin/sh
cd "$(dirname "$0")"
GENERATOR="Unix Makefiles"
set -ex

case "$1" in
"x")
    # cross compiling, environment vars need to be set
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSTEM_NAME="Linux" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/src/kcptun-libev"
    ;;
"xs")
    # cross compile statically linked executable
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSTEM_NAME="Linux" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
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
        -DFORCE_POSIX=1 \
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
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld --rtlib=compiler-rt" \
        -S "." -B "build"
    nice cmake --build "build"
    (cd "build/src" && llvm-objdump -drwS "kcptun-libev" >"kcptun-libev.S")
    ls -lh "build/src/kcptun-libev"
    ;;
"msys2")
    # set FIND_ROOT for finding dependencies
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
        -S "." -B "build"
    nice cmake --build "build"
    TARGET="$(cc -dumpmachine)"
    zip -9j "build/kcptun-libev-win32.${TARGET}.zip" \
        "/usr/bin/msys-2.0.dll" \
        "build/src/kcptun-libev.exe"
    ls -lh "build/kcptun-libev-win32.${TARGET}.zip"
    ;;
"ndk")
    # cross compiling, environment vars need to be set
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_ANDROID_NDK="${NDK}" \
        -DCMAKE_SYSTEM_NAME="Android" \
        -DCMAKE_SYSTEM_VERSION="${API}" \
        -DCMAKE_ANDROID_ARCH_ABI="${ABI}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -DLINK_STATIC_LIBS=ON \
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
    done | gcc -pipe -O3 -s -DNDEBUG -D_GNU_SOURCE -pedantic -Wall -Wextra -std=c11 \
        -Icontrib/csnippets -Icontrib/json -Icontrib/kcp -Icontrib/libbloom -Isrc \
	-include build/src/config.h \
        -o "build/src/kcptun-libev" -xc - -lev -lsodium -lm
    ls -lh "build/src/kcptun-libev"
    ;;
"d")
    find src -type f -regex '.*\.[hc]' -exec clang-format -i {} +
    # debug
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DENABLE_SANITIZERS=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    ln -sf build/compile_commands.json compile_commands.json
    nice cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
    ;;
"san")
    # rebuild with clang & sanitizers
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DENABLE_SANITIZERS=ON \
        -DLINK_STATIC_LIBS=ON \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S "." -B "build"
    nice cmake --build "build" --parallel
    ls -lh "build/src/kcptun-libev"
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
