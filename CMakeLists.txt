cmake_minimum_required(VERSION 3.19)
project(tcp_block)

set(CMAKE_CXX_STANDARD 14)
include(FindPCAP.cmake)

add_executable(tcp_block main.cpp packet.cpp packet.h util.cpp util.h)
target_link_libraries(tcp_block ${PCAP_LIBRARY})