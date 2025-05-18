cmake_minimum_required(VERSION 3.5)

project(meta_data_crypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(meta_data_crypt main.cpp
    libdm2/dm.cpp
    libdm2/dm.h
    libdm2/dm_table.cpp
    libdm2/dm_table.h
    libdm2/dm_target.cpp
    libdm2/dm_target.h
    libdm2/loop_control.cpp
    libdm2/loop_control.h
    libdm2/stringprintf.cpp
    libdm2/stringprintf.h
    libdm2/strings.cpp
    libdm2/strings.h
    libdm2/test_util.cpp
    libdm2/test_util.h
    libdm2/unique_fd.h
    libdm2/utility.cpp
    libdm2/utility.h
    )

include(GNUInstallDirs)
install(TARGETS meta_data_crypt
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
