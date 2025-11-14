cmake_minimum_required(VERSION 3.16)
project(aegisfim C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_definitions(_FILE_OFFSET_BITS=64 _GNU_SOURCE _POSIX_C_SOURCE=200809L)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CURSES_NEED_WIDE TRUE)
find_package(Curses REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(aegisfim
  src/main.c
  src/scan.c
  src/hash.c
  src/baseline.c
  src/util.c
  src/check.c
  src/tui.c
)

target_include_directories(aegisfim PRIVATE include ${CURSES_INCLUDE_DIR})
target_link_libraries(aegisfim OpenSSL::Crypto ${CURSES_LIBRARIES})

add_executable(aegisport
  src/aegisport.c
)
add_executable(aegishoney src/aegishoney.c)
add_executable(aegisweb src/aegisweb.c)
add_executable(aegispass src/aegispass.c)
target_link_libraries(aegispass OpenSSL::Crypto)
add_executable(aegisnet src/aegisnet.c)
target_link_libraries(aegisnet OpenSSL::SSL OpenSSL::Crypto)