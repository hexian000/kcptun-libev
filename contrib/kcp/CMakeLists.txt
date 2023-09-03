add_library(kcp STATIC ikcp.c ikcp.h)
target_include_directories(kcp BEFORE PRIVATE ../csnippets)
target_compile_definitions(kcp PRIVATE IKCP_FASTACK_CONSERVE=1 MCACHE_STATS=0)
target_compile_options(kcp PRIVATE -w)
