add_library(cjson STATIC cJSON.c cJSON.h)
target_include_directories(cjson BEFORE PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(cjson PRIVATE -w)
