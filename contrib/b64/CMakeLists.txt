add_library(b64 STATIC encode.c decode.c buffer.c b64.h)
target_compile_options(b64 PRIVATE -w)
