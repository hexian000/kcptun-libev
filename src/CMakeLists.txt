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
    event_tcp.c event_kcp.c event_pkt.c event_http.c event_timer.c event.h)

if(FORCE_POSIX)
    target_compile_definitions(kcptun-libev PRIVATE _POSIX_C_SOURCE=200809L)
else()
    target_compile_definitions(kcptun-libev PRIVATE _GNU_SOURCE)
endif()

include(CheckSymbolExists)
check_symbol_exists(sendmmsg "sys/socket.h" HAVE_API_SENDMMSG)
check_symbol_exists(SYS_sendmmsg "sys/syscall.h" HAVE_SYS_SENDMMSG)
check_symbol_exists(recvmmsg "sys/socket.h" HAVE_API_RECVMMSG)
check_symbol_exists(SYS_recvmmsg "sys/syscall.h" HAVE_SYS_RECVMMSG)

if(HAVE_API_SENDMMSG AND HAVE_SYS_SENDMMSG)
    set(HAVE_SENDMMSG TRUE)
endif()
if(HAVE_API_RECVMMSG AND HAVE_SYS_RECVMMSG)
    set(HAVE_RECVMMSG TRUE)
endif()

target_compile_options(kcptun-libev PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/config.h")

# be strict with original sources
target_compile_options(kcptun-libev PRIVATE -pedantic -Wall -Wextra -Werror)

target_link_libraries(kcptun-libev PRIVATE kcp bloom csnippets)

# find json-c
find_path(JSONC_INCLUDE_DIR NAMES json-c/json.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(JSONC_LIBRARY NAMES libjson-c.a)
else()
    find_library(JSONC_LIBRARY NAMES json-c)
endif()
if((NOT EXISTS "${JSONC_INCLUDE_DIR}/json-c/json.h") OR (NOT EXISTS ${JSONC_LIBRARY}))
    message(FATAL_ERROR "json-c not found")
endif()
message(STATUS "json-c: ${JSONC_LIBRARY}")
target_include_directories(kcptun-libev SYSTEM PRIVATE ${JSONC_INCLUDE_DIR})
target_link_libraries(kcptun-libev PRIVATE ${JSONC_LIBRARY})

# find libev
find_path(LIBEV_INCLUDE_DIR NAMES ev.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LIBEV_LIBRARY NAMES libev.a)
else()
    find_library(LIBEV_LIBRARY NAMES ev)
endif()
if(EXISTS "${LIBEV_INCLUDE_DIR}/ev.h")
    file(READ "${LIBEV_INCLUDE_DIR}/ev.h" LIBEV_VERSION_STR)
    string(REGEX MATCH "#define EV_VERSION_MAJOR[ \t]+([0-9]+)" _ ${LIBEV_VERSION_STR})
    set(EV_VERSION_MAJOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "#define EV_VERSION_MINOR[ \t]+([0-9]+)" _ ${LIBEV_VERSION_STR})
    set(EV_VERSION_MINOR ${CMAKE_MATCH_1})
    set(LIBEV_VERSION "${EV_VERSION_MAJOR}.${EV_VERSION_MINOR}")
endif()
if((NOT ${LIBEV_VERSION} VERSION_GREATER_EQUAL "4.31") OR (NOT EXISTS ${LIBEV_LIBRARY}))
    message(FATAL_ERROR "libev (>= 4.31) not found")
endif()
message(STATUS "libev ${LIBEV_VERSION}: ${LIBEV_LIBRARY}")
target_include_directories(kcptun-libev SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(kcptun-libev PRIVATE ${LIBEV_LIBRARY})

# find libsodium
find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(SODIUM_LIBRARY NAMES libsodium.a)
else()
    find_library(SODIUM_LIBRARY NAMES sodium)
endif()
if((NOT EXISTS ${SODIUM_INCLUDE_DIR}) OR (NOT EXISTS ${SODIUM_LIBRARY}))
    message(WARNING "libsodium not found, crypto features are unavailable")
else()
    message(STATUS "libsodium: ${SODIUM_LIBRARY}")
    set(WITH_SODIUM TRUE)
    target_include_directories(kcptun-libev SYSTEM PRIVATE ${SODIUM_INCLUDE_DIR})
    target_link_libraries(kcptun-libev PRIVATE ${SODIUM_LIBRARY})
endif()

if(WITH_SODIUM)
    set(WITH_CRYPTO TRUE)
endif()

if(WITH_CRYPTO AND (CMAKE_SYSTEM_NAME STREQUAL "Linux") AND NOT FORCE_POSIX)
    set(WITH_OBFS TRUE)
endif()

# find systemd
if(ENABLE_SYSTEMD)
    find_path(SYSTEMD_INCLUDE_DIR NAMES systemd/sd-daemon.h)
    find_library(SYSTEMD_LIBRARY NAMES systemd)
    if((EXISTS ${SYSTEMD_INCLUDE_DIR}) AND (EXISTS ${SYSTEMD_LIBRARY}))
        message(STATUS "systemd: ${SYSTEMD_LIBRARY}")
        set(WITH_SYSTEMD TRUE)
        target_include_directories(kcptun-libev SYSTEM PRIVATE ${SYSTEMD_INCLUDE_DIR})
        target_link_libraries(kcptun-libev PRIVATE ${SYSTEMD_LIBRARY})
    else()
        message(WARNING "systemd not found")
    endif()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(WITH_CRASH_HANDLER TRUE)
endif()

include(CheckLibraryExists)
check_library_exists(m fmod "" LIBM)
if(LIBM)
    target_link_libraries(kcptun-libev PRIVATE m)
endif()

install(TARGETS kcptun-libev DESTINATION bin)

configure_file(config.h.in config.h ESCAPE_QUOTES)
configure_file(version.c.in version.c ESCAPE_QUOTES)

target_sources(kcptun-libev
    PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    "${CMAKE_CURRENT_BINARY_DIR}/version.c"
)
