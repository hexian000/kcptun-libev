add_library(utils STATIC
    arraysize.h
    hashtable.c hashtable.h
    slog.c slog.h
    xorshift.c xorshift.h)
target_compile_options(utils PRIVATE -pedantic -Wall -Wextra -Werror)
