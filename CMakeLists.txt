cmake_minimum_required(VERSION 3.5)
project(cCallPython)
INCLUDE_DIRECTORIES(/usr/src/linux-headers-3.16.0-23/include)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -finstrument-functions")

set(SOURCE_FILES cCallPython.c)


add_executable(cCallPython ${SOURCE_FILES})
target_link_libraries(cCallPython python2.7)
