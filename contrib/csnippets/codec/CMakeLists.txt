target_sources(csnippets
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/json.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/utf8.c"
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/json.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/utf8.h"
)
