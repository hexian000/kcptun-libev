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
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/kcptun-libev"
    ;;
"xs")
    # cross compile statically linked executable
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSTEM_NAME="Linux" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -DBUILD_STATIC=ON \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/kcptun-libev"
    ;;
"r")
    # rebuild release
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/kcptun-libev"
    ;;
"s")
    # rebuild statically linked executable
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DBUILD_STATIC=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/kcptun-libev"
    ;;
"p")
    # rebuild for profiling
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S "." -B "build"
    nice cmake --build "build"
    (cd "build/src" && objdump -drwS "kcptun-libev" >"kcptun-libev.S")
    ls -lh "build/bin/kcptun-libev"
    ;;
"posix")
    # force POSIX APIs
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DFORCE_POSIX=1 \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/kcptun-libev"
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld --rtlib=compiler-rt" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S "." -B "build"
    nice cmake --build "build"
    (cd "build/src" && llvm-objdump -drwS "kcptun-libev" >"kcptun-libev.S")
    ls -lh "build/bin/kcptun-libev"
    ;;
"msys2")
    # set FIND_ROOT for finding dependencies
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DENABLE_LTO=OFF \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
        -S "." -B "build"
    nice cmake --build "build"
    HOST="$(cc -dumpmachine)"
    zip -9j "build/kcptun-libev-win32.${HOST}.zip" \
        "/usr/bin/msys-2.0.dll" \
        "build/bin/kcptun-libev.exe"
    ls -lh "build/kcptun-libev-win32.${HOST}.zip"
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
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -DLINK_STATIC_LIBS=ON \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/kcptun-libev"
    ;;
"single")
    # rebuild as single file
    rm -rf "build" && mkdir -p "build/src"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -S "." -B "build"
    find contrib src -name '*.c' | while read -r FILE; do
        echo "#include \"${FILE}\""
    done | gcc -pipe -O3 -s -DNDEBUG -D_GNU_SOURCE -pedantic -Wall -Wextra -std=c11 \
        -Icontrib/csnippets -Icontrib/json -Icontrib/kcp -Icontrib/libbloom -Isrc \
        -include build/src/config.h \
        -o "build/bin/kcptun-libev" -xc - -lev -lsodium -lm
    ls -lh "build/bin/kcptun-libev"
    ;;
"d")
    if command -v clang-format >/dev/null; then
        find src -type f -regex '.*\.[hc]' -exec clang-format -i {} +
    fi
    # debug
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DENABLE_SANITIZERS=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    ln -sf build/compile_commands.json compile_commands.json
    nice cmake --build "build" --parallel
    ls -lh "build/bin/kcptun-libev"
    ;;
"san")
    # rebuild with clang & sanitizers
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_C_COMPILER="clang" \
        -DENABLE_SANITIZERS=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S "." -B "build"
    nice cmake --build "build" --parallel
    ls -lh "build/bin/kcptun-libev"
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
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S "." -B "build"
    ln -sf "build/compile_commands.json" "compile_commands.json"
    nice cmake --build "build" --parallel
    ls -lh "build/bin/kcptun-libev"
    ;;
esac
