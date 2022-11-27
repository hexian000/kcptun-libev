add_library(kcp STATIC ikcp.c ikcp.h
    ../utils/serialize.h
    ../utils/leakypool.h
    ../utils/likely.h)
target_compile_definitions(kcp PRIVATE LEAKYPOOL_STATS=1)
