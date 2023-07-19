add_library(json STATIC json.c json.h)
target_compile_options(json PRIVATE -w)
