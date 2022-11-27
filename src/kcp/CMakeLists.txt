add_library(kcp STATIC ikcp.c ikcp.h
    ../utils/serialize.h
    ../utils/mcache.h
    ../utils/likely.h)
target_compile_definitions(kcp PRIVATE MCACHE_STATS=1)
