add_subdirectory(kcp)
add_subdirectory(json)
add_subdirectory(b64)
add_subdirectory(libbloom)
add_subdirectory(murmur3)

add_executable(kcptun-libev main.c
    aead.c aead.h
    util.c util.h
    sockutil.c sockutil.h
    conf.c conf.h
    jsonutil.c jsonutil.h
    pktqueue.c pktqueue.h
    session.c session.h
    server.c server.h
    serialize.h leakypool.h
    slog.c slog.h
    hashtable.c hashtable.h
    nonce.c nonce.h
    obfs.c obfs.h
    event.h event_impl.h event_tcp.c event_kcp.c event_pkt.c event_timer.c)

option(POSIX "Use POSIX API" OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT POSIX)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
    target_compile_definitions(kcptun-libev PRIVATE _GNU_SOURCE)
    set(WITH_OBFS 1)
else()
    message(STATUS "POSIX System: ${CMAKE_SYSTEM_NAME}")
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_POSIX_C_SOURCE=200809L")
    target_compile_definitions(kcptun-libev PRIVATE _POSIX_C_SOURCE=200809L)
endif()
include(CheckSymbolExists)
check_symbol_exists(sendmmsg "sys/socket.h" HAVE_API_SENDMMSG)
check_symbol_exists(SYS_sendmmsg "sys/syscall.h" HAVE_SYS_SENDMMSG)
check_symbol_exists(recvmmsg "sys/socket.h" HAVE_API_RECVMMSG)
check_symbol_exists(SYS_recvmmsg "sys/syscall.h" HAVE_SYS_RECVMMSG)
check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)
check_symbol_exists(gettimeofday "sys/time.h" HAVE_GETTIMEOFDAY)

target_compile_options(kcptun-libev PRIVATE -include "${CMAKE_CURRENT_BINARY_DIR}/config.h")

# be strict with original sources
target_compile_options(kcptun-libev PRIVATE -pedantic -Wall -Wextra -Werror)
target_link_libraries(kcptun-libev kcp json b64 bloom murmur3)

# find libev
find_path(LIBEV_INCLUDE_DIR NAMES ev.h)
if(LINK_STATIC_LIBS)
    find_library(LIBEV_LIBRARY NAMES libev.a)
else()
    find_library(LIBEV_LIBRARY NAMES ev)
endif()
if((EXISTS ${LIBEV_INCLUDE_DIR}) AND (EXISTS ${LIBEV_LIBRARY}))
    message(STATUS "libev: ${LIBEV_LIBRARY}")
else()
    message(FATAL_ERROR "libev not found")
endif()
target_include_directories(kcptun-libev PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(kcptun-libev ${LIBEV_LIBRARY})

# find libsodium
find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
if(LINK_STATIC_LIBS)
    find_library(SODIUM_LIBRARY NAMES libsodium.a)
else()
    find_library(SODIUM_LIBRARY NAMES sodium)
endif()
if((EXISTS ${SODIUM_INCLUDE_DIR}) AND (EXISTS ${SODIUM_LIBRARY}))
    message(STATUS "libsodium: ${SODIUM_LIBRARY}")
    set(WITH_SODIUM 1)
    target_include_directories(kcptun-libev PRIVATE ${SODIUM_INCLUDE_DIR})
    target_link_libraries(kcptun-libev ${SODIUM_LIBRARY})
else()
    message(WARNING "libsodium not found, crypto features are unavailable")
endif()

target_link_libraries(kcptun-libev pthread m rt)
install(TARGETS kcptun-libev DESTINATION bin)

configure_file(config.h.in config.h ESCAPE_QUOTES)
