target_sources(csnippets
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/murmurhash.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/hashtable.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/slog.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/xorshift.c"
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/arraysize.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/mcache.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/murmurhash.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/hashtable.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/serialize.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/slog.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/strbuilder.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/xorshift.h"
)

target_compile_definitions(csnippets
    PUBLIC MCACHE_STATS=1
    PRIVATE HASHTABLE_LOG=1
)
