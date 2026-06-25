target_sources(csnippets
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/intlog2.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/rand.h"
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/intlog2.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/rand.c"
)
