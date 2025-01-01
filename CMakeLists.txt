cmake_minimum_required(VERSION 3.30)
project(EthernetPacketSniffer C)

set(CMAKE_C_STANDARD 11)

add_executable(EthernetPacketSniffer main.c
        packet_sniffer.h
        packet_sniffer.c)
