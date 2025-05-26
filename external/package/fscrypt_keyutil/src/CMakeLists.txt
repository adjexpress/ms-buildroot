cmake_minimum_required(VERSION 3.10)

project(fscrypt_keyutil LANGUAGES C)


find_library(keyutils NAMES keyutils)

# find_package(keyUtils REQUIRED)

message(STATUS "keyutils Found: " ${KEYUTILS_FOUND})

add_executable(fscrypt_keyutil main.c)

target_link_libraries(${PROJECT_NAME} keyutils)

include(GNUInstallDirs)
install(TARGETS fscrypt_keyutil
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
