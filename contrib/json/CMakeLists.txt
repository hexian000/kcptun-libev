add_library(json STATIC json.c json.h)
target_include_directories(json BEFORE PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(json PRIVATE -w)
