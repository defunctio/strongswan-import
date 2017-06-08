cmake_minimum_required(VERSION 3.7)
project(strongswan-import)

set(STANDALONE_IMPORT)
set(CMAKE_CXX_STANDARD 14)
find_package(PkgConfig REQUIRED)
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_FLAGS "-fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard")
set(CMAKE_CXX_FLAGS "-fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard")

set(SOURCE_FILES main.cc)
add_library(strongswan_profile STATIC strongswan_profile.c)
add_executable(fuzz fuzz.cc)
add_executable(strongswan-import ${SOURCE_FILES})

pkg_search_module(LIBSSL libssl)
pkg_search_module(GLIB glib-2.0)
pkg_search_module(JSON json-glib-1.0)
pkg_search_module(LIBNM libnm)
pkg_search_module(LIBCRYPTO libcrypto)
include_directories(${LIBNM_INCLUDE_DIRS})
include_directories(${GLIB_INCLUDE_DIRS})
link_libraries(${GLIB_LIBRARIES})
link_libraries(${LIBNM_LIBRARIES})

target_include_directories(strongswan_profile PUBLIC
        ${GLIB_INCLUDE_DIRS} ${JSON_INCLUDE_DIRS} ${LIBNM_INCLUDE_DIRS}
        ${JSON_INCLUDE_DIRS} ${LIBSSL_INCLUDE_DIRS} ${LIBCRYPTO_INCLUDE_DIRS})
target_link_libraries(strongswan_profile PUBLIC
        ${GLIB_LIBRARIES} ${JSON_LIBRARIES} ${LIBNM_LIBRARIES}
        ${JSON_LIBRARIES} ${LIBSSL_LIBRARIES} ${LIBCRYPTO_LIBRARIES})

target_link_libraries(fuzz /usr/lib/llvm-4.0/lib/libFuzzer.a)
target_link_libraries(strongswan-import strongswan_profile)
target_link_libraries(fuzz strongswan_profile)