cmake_minimum_required(VERSION 3.5)
project("check-snmp-extras" VERSION 0.0.5 LANGUAGES C)

## Compiler Flags
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O2")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

## Module Include
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules" "${CMAKE_MODULE_PATH}")

## Force Out Of Tree
include(MacroOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out tree build.")

## Output Directories
include(GNUInstallDirs)
set(ARCHIVE_DIR ${CMAKE_INSTALL_LIBDIR})
set(LIBRARY_DIR ${CMAKE_INSTALL_LIBDIR})
set(RUNTIME_DIR ${CMAKE_INSTALL_LIBDIR}/nagios/plugins)
set(DATA_DIR ${CMAKE_INSTALL_DATADIR}/icinga2/include/plugins-contrib.d)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

## Uninstall Target
configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

##
include(FindNetSnmp)


add_subdirectory("${PROJECT_SOURCE_DIR}/src")
add_subdirectory("${PROJECT_SOURCE_DIR}/conf")

## Package

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "/\\\\..*$;~$;${CMAKE_SOURCE_DIR}/contrib/;${CMAKE_SOURCE_DIR}/scripts/;${CMAKE_SOURCE_DIR}/build/")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${PROJECT_VERSION}")

include(CPack)
