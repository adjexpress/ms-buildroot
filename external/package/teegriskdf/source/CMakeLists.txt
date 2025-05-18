cmake_minimum_required(VERSION 3.5)

project(TeegrisKDF LANGUAGES C)

find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL Found: " ${OPENSSL_FOUND})

add_executable(TeegrisKDF src/main.c
    src/vbmeta_handler.c src/secdis_handler.c src/rpmb2_handler.c src/math_handler.c src/keymaster_key_blob_handler.c src/encryption.c src/custom_asn1.c src/core.c
    include/vbmeta.h include/secdis.h include/rpmb2.h include/math.h include/keymaster_key_blob.h include/encryption.h include/custom_asn1.h include/core.h)

target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL)


include(GNUInstallDirs)
install(TARGETS TeegrisKDF
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
