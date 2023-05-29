add_executable(kcptun-libev main.c
    crypto.c crypto.h
    util.c util.h
    sockutil.c sockutil.h
    conf.c conf.h
    jsonutil.c jsonutil.h
    pktqueue.c pktqueue.h
    session.c session.h
    server.c server.h
    nonce.c nonce.h
    obfs.c obfs.h
    event_tcp.c event_kcp.c event_pkt.c event_http.c event_timer.c event.h event_impl.h)
target_include_directories(kcptun-libev PRIVATE ../contrib/csnippets ../contrib)
target_compile_definitions(kcptun-libev PRIVATE MCACHE_STATS=1)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT POSIX)
    set(WITH_OBFS ON)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
    target_compile_definitions(kcptun-libev PRIVATE _GNU_SOURCE)
else()
    set(WITH_OBFS OFF)
    message(STATUS "POSIX System: ${CMAKE_SYSTEM_NAME}")
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_POSIX_C_SOURCE=200809L")
    target_compile_definitions(kcptun-libev PRIVATE _POSIX_C_SOURCE=200809L)
endif()
include(CheckSymbolExists)
check_symbol_exists(sendmmsg "sys/socket.h" HAVE_API_SENDMMSG)
check_symbol_exists(SYS_sendmmsg "sys/syscall.h" HAVE_SYS_SENDMMSG)
check_symbol_exists(recvmmsg "sys/socket.h" HAVE_API_RECVMMSG)
check_symbol_exists(SYS_recvmmsg "sys/syscall.h" HAVE_SYS_RECVMMSG)

target_compile_options(kcptun-libev PRIVATE -include "${CMAKE_CURRENT_BINARY_DIR}/config.h")

# be strict with original sources
target_compile_options(kcptun-libev PRIVATE -pedantic -Wall -Wextra -Werror)
target_link_libraries(kcptun-libev kcp json bloom csnippets)

if(LINK_STATIC_LIBS)
    find_library(LIBM NAMES libm.a)
else()
    find_library(LIBM NAMES m)
endif()
if(LIBM)
    target_link_libraries(kcptun-libev ${LIBM})
endif()

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

install(TARGETS kcptun-libev DESTINATION bin)

configure_file(config.h.in config.h ESCAPE_QUOTES)
