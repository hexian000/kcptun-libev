cmake_minimum_required(VERSION 3.10)
project(kcptun-libev
    LANGUAGES C
    HOMEPAGE_URL "http://github.com/hexian000/kcptun-libev")

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
    execute_process(COMMAND ${GIT_EXECUTABLE} update-index --refresh)
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

enable_testing()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lasan -lubsan")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s")

add_subdirectory(src)
