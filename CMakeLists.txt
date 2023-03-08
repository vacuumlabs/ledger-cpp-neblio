cmake_minimum_required(VERSION 3.16)
project(Ledger C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(hidapi_name)
if (WIN32)
elseif (APPLE)
    set(hidapi_name hidapi)
elseif (UNIX AND NOT APPLE)
    set(hidapi_name hidapi-libusb)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(HIDAPI REQUIRED ${hidapi_name})

set(HIDAPI_WITH_LIBUSB TRUE)

find_package(hidapi REQUIRED)
find_package(OpenSSL REQUIRED)

set(LEDGERCPP_SOURCE
        ledgercpp/comm.h
        ledgercpp/error.cpp
        ledgercpp/error.h
        ledgercpp/hash.h
        ledgercpp/hid_device.cpp
        ledgercpp/hid_device.h
        ledgercpp/ledger.cpp
        ledgercpp/ledger.h
        ledgercpp/transport.cpp
        ledgercpp/transport.h
        ledgercpp/uint256.h
        ledgercpp/utils.cpp
        ledgercpp/utils.h
        ledgercpp/main.cpp
        )

add_executable(main ${LEDGERCPP_SOURCE})
add_executable(main::main ALIAS main)

target_link_libraries(main PRIVATE 
    hidapi-libusb
    OpenSSL::SSL)

file(GLOB_RECURSE EDV_INCLUDE_FILES "ledgercpp/*.h*")

add_definitions(-w)