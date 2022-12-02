add_library(utils STATIC
    arraysize.h mcache.h serialize.h
    hashtable.c hashtable.h murmurhash3.h
    slog.c slog.h
    xorshift.c xorshift.h)
target_compile_options(utils PRIVATE -pedantic -Wall -Wextra -Werror)
