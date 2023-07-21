target_sources(csnippets
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/hashtable.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/cityhash.h"
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/hashtable.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/cityhash.c"
)
