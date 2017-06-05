cmake_minimum_required (VERSION 2.6)

project (contact-hashes C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

enable_testing()

#Setup compiler flags
list(APPEND custom_compiler_flags
    -std=c99
    -pedantic
    -Wall
    -Wextra
    -Werror
    -Wstrict-prototypes
    -Wwrite-strings
    -Wshadow
    -Winit-self
    -Wcast-align
    -Wformat=2
    -Wmissing-prototypes
    -Wstrict-overflow=2
    -Wcast-qual
    -Wundef
    -Wswitch-default
    -Wconversion
    -fstack-protector-strong
    -Wcomma
    -Wdouble-promotion
    -Wparentheses
    -fPIC
    -Wunused-macros
    -Wmissing-variable-declarations
    )

if(NOT ${CMAKE_BUILD_TYPE} MATCHES "Debug")
    list(APPEND custom_compiler_flags
        -O2
        -U_FORTIFY_SOURCE
        -D_FORTIFY_SOURCE=2)
else()
    list(APPEND custom_compiler_flags -O0 -Og)
endif()

# apply custom compiler flags
include(CheckCCompilerFlag)
foreach(compiler_flag ${custom_compiler_flags})
    #remove problematic characters
    string(REGEX REPLACE "[^a-zA-Z0-9]" "" current_variable ${compiler_flag})

    CHECK_C_COMPILER_FLAG(${compiler_flag} "FLAG_SUPPORTED_${current_variable}")
    if (FLAG_SUPPORTED_${current_variable})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${compiler_flag}")
    endif()
endforeach()

#Set linker flags
if(NOT APPLE)
    set(SECURITY_LINK_FLAGS "-z relro -z now -z noexecstack -z noexecheap -pie")
endif()
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} ${SECURITY_LINK_FLAGS}")

find_package(sodium 1.0.12 REQUIRED)

include_directories(${SODIUM_INCLUDE_DIR})


find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS --trace-children=yes --leak-check=full --error-exitcode=10)

if("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")
    message(WARNING "valgrind not found")
endif("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")

# check if protoc-c works with valgrind (check for weird error on ArchlinuxARM on ARMv7 that breaks CI)
if (NOT ("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND"))
    execute_process(
        COMMAND ${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS} ${PROTOC_C_EXECUTABLE}
        RESULT_VARIABLE VALGRIND_ERROR
        OUTPUT_QUIET
        ERROR_QUIET)
    if ("${VALGRIND_ERROR}" MATCHES "10")
        set(MEMORYCHECK_COMMAND "MEMORYCHECK_COMMAND-NOTFOUND")
        message(WARNING "valgrind disabled")
    endif()
endif()

if("${DISABLE_MEMORYCHECK_COMMAND}" MATCHES "TRUE")
    set(MEMORYCHECK_COMMAND "MEMORYCHECK_COMMAND-NOTFOUND")
endif("${DISABLE_MEMORYCHECK_COMMAND}" MATCHES "TRUE")

add_library(contact-hashes contact-hashes.c)
target_link_libraries(contact-hashes sodium)

add_executable(contact-hash-test test.c)
target_link_libraries(contact-hash-test contact-hashes)

add_test(contact-hash-test "./contact-hash-test")
if((NOT APPLE) AND (NOT ("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")))
    add_test("contact-hash-test-valgrind" ${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS} "./contact-hash-test")
endif()
