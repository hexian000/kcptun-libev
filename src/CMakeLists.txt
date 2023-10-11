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
target_compile_definitions(kcptun-libev PRIVATE MCACHE_STATS=0)

if(NOT TARGET_POSIX AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "GNU/Linux System: ${CMAKE_SYSTEM_VERSION}")
    set(TARGET_GNU_LINUX ON)
elseif(NOT TARGET_POSIX AND CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(STATUS "Android: ${CMAKE_SYSTEM_VERSION}")
    set(TARGET_ANDROID ON)
else()
    message(STATUS "POSIX-compliant System: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION}")
endif()

if(TARGET_GNU_LINUX OR TARGET_ANDROID)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
    target_compile_definitions(kcptun-libev PRIVATE _GNU_SOURCE)
else()
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_POSIX_C_SOURCE=200809L")
    target_compile_definitions(kcptun-libev PRIVATE _POSIX_C_SOURCE=200809L)
endif()
include(CheckSymbolExists)
check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)
check_symbol_exists(gettimeofday "sys/time.h" HAVE_GETTIMEOFDAY)
check_symbol_exists(sendmmsg "sys/socket.h" HAVE_API_SENDMMSG)
check_symbol_exists(SYS_sendmmsg "sys/syscall.h" HAVE_SYS_SENDMMSG)
check_symbol_exists(recvmmsg "sys/socket.h" HAVE_API_RECVMMSG)
check_symbol_exists(SYS_recvmmsg "sys/syscall.h" HAVE_SYS_RECVMMSG)

target_compile_options(kcptun-libev PRIVATE -include "${CMAKE_CURRENT_BINARY_DIR}/config.h")

# be strict with original sources
target_compile_options(kcptun-libev PRIVATE -pedantic -Wall -Wextra -Werror)
target_link_libraries(kcptun-libev PRIVATE kcp json bloom csnippets)

# find libev
find_path(LIBEV_INCLUDE_DIR NAMES ev.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LIBEV_LIBRARY NAMES libev.a)
else()
    find_library(LIBEV_LIBRARY NAMES ev)
endif()
if((NOT EXISTS ${LIBEV_INCLUDE_DIR}) OR (NOT EXISTS ${LIBEV_LIBRARY}))
    message(FATAL_ERROR "libev not found")
endif()
message(STATUS "libev: ${LIBEV_LIBRARY}")
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
    set(WITH_SODIUM 1)
    target_include_directories(kcptun-libev SYSTEM PRIVATE ${SODIUM_INCLUDE_DIR})
    target_link_libraries(kcptun-libev PRIVATE ${SODIUM_LIBRARY})
endif()

include(CheckLibraryExists)
check_library_exists(m fmod "" LIBM)
if(LIBM)
    target_link_libraries(kcptun-libev PRIVATE m)
endif()

install(TARGETS kcptun-libev DESTINATION bin)

configure_file(config.h.in config.h ESCAPE_QUOTES)
