add_subdirectory(kcp)
add_subdirectory(json)
add_subdirectory(b64)

include(CheckSymbolExists)
list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
check_symbol_exists(sendmmsg "sys/socket.h" HAVE_SENDMMSG)
check_symbol_exists(recvmmsg "sys/socket.h" HAVE_RECVMMSG)
check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)
check_symbol_exists(gettimeofday "sys/time.h" HAVE_GETTIMEOFDAY)

add_executable(kcptun-libev main.c
    aead.c aead.h
    util.c util.h
    sockutil.c sockutil.h
    conf.c conf.h
    packet.c packet.h
    session.c session.h
    proxy.c proxy.h
    server.c server.h
    serialize.h leakypool.h
    slog.c slog.h
    hashtable.c hashtable.h
    event.h event_impl.h event_tcp.c event_kcp.c event_udp.c event_timer.c)

target_compile_definitions(kcptun-libev PRIVATE _GNU_SOURCE)
target_compile_options(kcptun-libev PRIVATE -include "${CMAKE_CURRENT_BINARY_DIR}/config.h")

# be strict with original sources
target_compile_options(kcptun-libev PRIVATE -pedantic -Wall -Wextra -Werror)
target_link_libraries(kcptun-libev kcp json b64)

# find libev
find_path(LIBEV_INCLUDE_DIR NAMES ev.h)
find_library(LIBEV_LIBRARY NAMES ev)
if((EXISTS ${LIBEV_INCLUDE_DIR}) AND (EXISTS ${LIBEV_LIBRARY}))
    message(STATUS "libev: ${LIBEV_LIBRARY}")
else()
    message(FATAL_ERROR "libev not found")
endif()
target_include_directories(kcptun-libev PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(kcptun-libev ${LIBEV_LIBRARY})

# find libsodium
find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
find_library(SODIUM_LIBRARY NAMES sodium)
if((EXISTS ${SODIUM_INCLUDE_DIR}) AND (EXISTS ${SODIUM_LIBRARY}))
    message(STATUS "libsodium: ${SODIUM_LIBRARY}")
    set(WITH_SODIUM 1)
    target_include_directories(kcptun-libev PRIVATE ${SODIUM_INCLUDE_DIR})
    target_link_libraries(kcptun-libev ${SODIUM_LIBRARY})
else()
    message(WARNING "libsodium not found, crypto features are unavailable")
endif()

target_link_libraries(kcptun-libev pthread m rt)

configure_file(config.h.in config.h ESCAPE_QUOTES)
