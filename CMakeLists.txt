cmake_minimum_required(VERSION 3.10)
project(kcptun-libev
	LANGUAGES C
	HOMEPAGE_URL "http://github.com/hexian000/kcptun-libev")
set(PROJECT_VERSION_STRING "2.0-dev")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lasan -lubsan")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")

add_subdirectory(src)
