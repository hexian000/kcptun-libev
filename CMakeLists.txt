cmake_minimum_required(VERSION 3.11)
project(kcptun-libev
    LANGUAGES C
    HOMEPAGE_URL "https://github.com/hexian000/kcptun-libev")

function(get_git_version)
    find_package(Git)
    if(NOT GIT_FOUND)
        return()
    endif()
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --git-dir
        RESULT_VARIABLE RESULT
        OUTPUT_VARIABLE GIT_REPO
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(RESULT)
        return()
    endif()
    execute_process(
        COMMAND ${GIT_EXECUTABLE} tag --points-at HEAD
        OUTPUT_VARIABLE GIT_HEAD
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if("${GIT_HEAD}" STREQUAL "")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
            OUTPUT_VARIABLE GIT_HEAD
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        set(GIT_HEAD "git-${GIT_HEAD}")
    endif()
    execute_process(COMMAND ${GIT_EXECUTABLE} update-index --refresh -q)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} diff-index --quiet HEAD --
        RESULT_VARIABLE RESULT)
    if(RESULT)
        set(PROJECT_VERSION_STRING "${GIT_HEAD}+" PARENT_SCOPE)
    else()
        set(PROJECT_VERSION_STRING "${GIT_HEAD}" PARENT_SCOPE)
    endif()
endfunction(get_git_version)

if("${PROJECT_VERSION_STRING}" STREQUAL "")
    set(PROJECT_VERSION_STRING "dev")
    get_git_version()
endif()
message(STATUS "Project version: ${PROJECT_VERSION_STRING}")

include(CTest)

option(TARGET_POSIX "Use POSIX API only" OFF)
option(LINK_STATIC_LIBS "Link against static libraries" OFF)
option(BUILD_STATIC "Build static executables" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,leak,undefined -fstack-protector")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,leak,undefined -static-libasan -static-libubsan")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffile-prefix-map=${PROJECT_SOURCE_DIR}/= -flto=auto -ffat-lto-objects")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s -flto=auto -flto-partition=none")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -pg -flto=auto -ffat-lto-objects")
    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} -pg -flto=auto -flto-partition=none")
    if(BUILD_STATIC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    endif()
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld --rtlib=compiler-rt")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,leak,undefined -fstack-protector")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,leak,undefined -static-libsan")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffile-prefix-map=${PROJECT_SOURCE_DIR}/= -flto")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s -flto")
    if(BUILD_STATIC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    endif()
endif()

add_subdirectory(contrib)
add_subdirectory(src)
