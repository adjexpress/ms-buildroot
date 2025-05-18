cmake_minimum_required(VERSION 3.5)

project(mesbah_agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL Found: " ${OPENSSL_FOUND})


add_executable(mesbah_agent src/server_main.cpp
    include/Authenticator.h
    include/Base64.h
    include/Encryption.h
    include/Filesystem.h
    include/md5.h
    include/Packet.h
    include/Server.h
    include/Shell.h
    src/Authenticator.cpp
    src/Base64.cpp
    src/Encryption.cpp
    src/Filesystem.cpp
    src/md5.cpp
    src/Packet.cpp
    src/Server.cpp
    src/Shell.cpp )

target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL)

include(GNUInstallDirs)
install(TARGETS mesbah_agent
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
