cmake_minimum_required(VERSION 3.16)
project(net-analyzer LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_FLAGS_RELEASE "-O2")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_library(na_parser STATIC src/parser.c src/ring_buffer.c src/detector.c
            src/analyzer.c)
target_include_directories(na_parser PUBLIC include)
target_compile_definitions(na_parser PUBLIC _DEFAULT_SOURCE)
target_compile_options(na_parser PUBLIC -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(na_parser PUBLIC Threads::Threads)

add_executable(net-analyzer src/main.c)
target_link_libraries(net-analyzer PRIVATE na_parser)

enable_testing()
add_executable(test_parser tests/test_parser.c)
target_link_libraries(test_parser PRIVATE na_parser)
add_test(NAME parser COMMAND test_parser)
add_executable(test_ring_buffer tests/test_ring_buffer.c)
target_link_libraries(test_ring_buffer PRIVATE na_parser)
add_test(NAME ring_buffer COMMAND test_ring_buffer)
add_executable(test_detector tests/test_detector.c)
target_link_libraries(test_detector PRIVATE na_parser)
add_test(NAME detector COMMAND test_detector)
add_executable(test_analyzer tests/test_analyzer.c)
target_link_libraries(test_analyzer PRIVATE na_parser)
add_test(NAME analyzer COMMAND test_analyzer)
