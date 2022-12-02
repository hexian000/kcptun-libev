add_library(kcp STATIC ikcp.c ikcp.h)
target_compile_definitions(kcp PRIVATE MCACHE_STATS=1)
