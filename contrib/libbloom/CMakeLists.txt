add_library(bloom STATIC bloom.c bloom.h)
target_include_directories(bloom BEFORE PRIVATE ../csnippets)
target_compile_options(bloom PRIVATE -w)
