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
        OUTPUT_VARIABLE GIT_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(RESULT)
        return()
    endif()
    execute_process(
        COMMAND ${GIT_EXECUTABLE} tag --points-at HEAD
        OUTPUT_VARIABLE GIT_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if("${GIT_VERSION}" STREQUAL "")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
            OUTPUT_VARIABLE GIT_HEAD
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        set(GIT_VERSION "git-${GIT_HEAD}")
    endif()
    execute_process(
        COMMAND ${GIT_EXECUTABLE} diff --quiet HEAD --
        RESULT_VARIABLE RESULT)
    if(RESULT)
        set(GIT_VERSION "${GIT_VERSION}+")
    endif()
    set(PROJECT_VERSION_STRING "${GIT_VERSION}" PARENT_SCOPE)
endfunction(get_git_version)

if("${PROJECT_VERSION_STRING}" STREQUAL "")
    set(PROJECT_VERSION_STRING "dev")
    get_git_version()
endif()
message(STATUS "Project version: ${PROJECT_VERSION_STRING}")

include(CTest)

option(FORCE_POSIX "Build the core features using POSIX-compliant APIs only" OFF)
option(BUILD_STATIC "Build a static executable" OFF)
option(BUILD_PIE "Build a position independent executable" OFF)
option(LINK_STATIC_LIBS "Link against static libraries" OFF)
option(ENABLE_SANITIZERS "Build with sanitizers" OFF)
option(ENABLE_SYSTEMD "Enable systemd integration" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    if(ENABLE_SANITIZERS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address,leak,undefined -fstack-protector-all")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,leak,undefined -static-libasan -static-liblsan -static-libubsan")
    endif()
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffile-prefix-map=${PROJECT_SOURCE_DIR}/= -flto=auto -ffat-lto-objects")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s -flto=auto -flto-partition=none")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -flto=auto -ffat-lto-objects")
    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} -flto=auto -flto-partition=none")
    if(BUILD_PIE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
    endif()
    if(BUILD_STATIC AND BUILD_PIE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-pie")
    elseif(BUILD_STATIC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    elseif(BUILD_PIE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
    endif()
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    if(ENABLE_SANITIZERS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address,leak,undefined -fstack-protector-all")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,leak,undefined -static-libsan")
    endif()
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffile-prefix-map=${PROJECT_SOURCE_DIR}/= -flto")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s -flto")
    if(BUILD_PIE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
    endif()
    if(BUILD_STATIC AND BUILD_PIE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-pie")
    elseif(BUILD_STATIC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    elseif(BUILD_PIE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
    endif()
endif()

if(NOT FORCE_POSIX AND (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android"))
    message(STATUS "Linux system: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION}")
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
    set(TARGET_LINUX TRUE)
else()
    message(STATUS "POSIX-compliant system: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION}")
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_POSIX_C_SOURCE=200809L")
endif()

add_subdirectory(contrib)
add_subdirectory(src)
