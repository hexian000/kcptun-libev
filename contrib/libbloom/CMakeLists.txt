add_library(bloom STATIC bloom.c bloom.h)
target_include_directories(bloom BEFORE PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bloom PUBLIC csnippets)
target_compile_options(bloom PRIVATE -w)
