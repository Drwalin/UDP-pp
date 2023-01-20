cmake_minimum_required(VERSION 3.8)
project(UDPpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

option(BUILD_EXAMPLES "Build examples" ON)
option(BUILD_RELEASE "Build release" OFF)

set(LIBRARY_FILE_NAME UDPpp)



include_directories(src/ip)
include_directories(src/util)



add_library(${LIBRARY_FILE_NAME} SHARED
	src/ip/IP
	src/ip/IPEndpoint
	src/ip/IPPacket
	src/ip/NTP
	src/ip/OSCheck
	src/ip/UDPSocket
	src/util/ReaderWriter
)

target_compile_options(${LIBRARY_FILE_NAME} PRIVATE -Wall -pedantic)

target_link_libraries(${LIBRARY_FILE_NAME} pthread)

if(UNIX)
elseif(WIN32)
	target_link_libraries(${LIBRARY_FILE_NAME} ws2_32)
else()
	# print error message: not tested platform
endif()



if(BUILD_RELEASE)
	target_compile_options(${LIBRARY_FILE_NAME} PRIVATE -ggdb3 -pg)
endif()



if(BUILD_EXAMPLES)
#	add_executable(Benchmarking tests/Benchmarking)
#	target_link_libraries(Benchmarking ${LIBRARY_FILE_NAME})
	add_executable(ntp tests/ntp)
	target_link_libraries(ntp ${LIBRARY_FILE_NAME})
	add_executable(udp tests/udp)
	target_link_libraries(udp ${LIBRARY_FILE_NAME})
	add_executable(udp2 tests/udp2)
	target_link_libraries(udp2 ${LIBRARY_FILE_NAME})
endif()


