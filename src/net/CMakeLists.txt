add_library(net STATIC http.c http.h)
target_compile_options(net PRIVATE -pedantic -Wall -Wextra -Werror)
target_include_directories(net PRIVATE "${PROJECT_SOURCE_DIR}/src")
