target_sources(csnippets
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/buffer.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/debug.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/formats.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/slog.c"
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/arraysize.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/buffer.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/debug.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/formats.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/intbound.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/likely.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/mcache.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/minmax.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/serialize.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/slog.h"
)
