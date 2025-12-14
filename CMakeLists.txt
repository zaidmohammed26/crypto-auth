cmake_minimum_required(VERSION 3.16)
project(AuthSystem)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

find_package(Boost REQUIRED COMPONENTS system)

set(NANOPB_BUILD_GENERATOR ON CACHE BOOL "Build generator" FORCE)
add_subdirectory(external/nanopb)

include(${CMAKE_CURRENT_SOURCE_DIR}/external/nanopb/extra/FindNanopb.cmake)

file(GLOB TREZOR_SOURCES "external/trezor-crypto/*.c")

list(FILTER TREZOR_SOURCES EXCLUDE REGEX ".*test.*")
list(FILTER TREZOR_SOURCES EXCLUDE REGEX ".*tools.*")

add_library(trezor_lib STATIC ${TREZOR_SOURCES})
target_include_directories(trezor_lib PUBLIC external/trezor-crypto)

target_compile_definitions(trezor_lib PUBLIC RAND_PLATFORM_UNIX)

nanopb_generate_cpp(PROTO_SRCS PROTO_HDRS proto/auth.proto)
add_library(common_lib common/CryptoHelper.cpp ${PROTO_SRCS})
target_include_directories(common_lib PUBLIC common ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(common_lib PUBLIC trezor_lib protobuf-nanopb-static)

add_subdirectory(server)
add_subdirectory(client)