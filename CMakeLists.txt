cmake_minimum_required(VERSION 3.14)

project(ccc LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address")

find_package(LIBSSH)
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Concurrent)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Concurrent)

add_executable(ccc
  main.cpp
)
target_link_libraries(ccc Qt${QT_VERSION_MAJOR}::Core)
target_link_libraries(ccc Qt${QT_VERSION_MAJOR}::Concurrent)
if (LIBSSH_FOUND)
    message(${LIBSSH_VERSION})
    include_directories(${LIBSSH_INCLUDE_DIR})
    target_link_libraries(ccc ssh)
else ()
    message(Unable to find libssh!)
endif ()

include(GNUInstallDirs)
install(TARGETS ccc
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_custom_target(deb DEPENDS all)
add_custom_command(TARGET deb POST_BUILD COMMAND ${CMAKE_SOURCE_DIR}/deb-build/mkdeb.sh WORKING_DIRECTORY ${CMAKE_BUILD_DIR})
