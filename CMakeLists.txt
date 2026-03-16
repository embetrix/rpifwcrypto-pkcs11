cmake_minimum_required(VERSION 3.10)
project(rpifwcrypto-pkcs11 VERSION 1.0.0 LANGUAGES C)

include(GNUInstallDirs)
find_package(GnuTLS REQUIRED)

# Try system-installed librpifwcrypto first, fall back to submodule
find_library(RPIFWCRYPTO_LIB rpifwcrypto)
find_path(RPIFWCRYPTO_INCLUDE rpifwcrypto.h)

if(RPIFWCRYPTO_LIB AND RPIFWCRYPTO_INCLUDE)
    message(STATUS "Using system librpifwcrypto: ${RPIFWCRYPTO_LIB}")
    set(RPIFWCRYPTO_TARGET ${RPIFWCRYPTO_LIB})
    set(RPIFWCRYPTO_INCLUDE_DIR ${RPIFWCRYPTO_INCLUDE})
else()
    message(STATUS "System librpifwcrypto not found, building from 3rdparty/raspi-utils")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    add_subdirectory(3rdparty/raspi-utils/rpifwcrypto)
    set(RPIFWCRYPTO_TARGET rpifwcrypto)
    set(RPIFWCRYPTO_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/raspi-utils/rpifwcrypto)
endif()

add_library(rpifwcrypto-pkcs11 SHARED src/rpifwcrypto_pkcs11.c)
target_include_directories(rpifwcrypto-pkcs11
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${RPIFWCRYPTO_INCLUDE_DIR}
)
target_link_libraries(rpifwcrypto-pkcs11 ${RPIFWCRYPTO_TARGET})
target_compile_options(rpifwcrypto-pkcs11 PRIVATE
    -Wall -Wextra -Werror
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIC
)
target_link_options(rpifwcrypto-pkcs11 PRIVATE
    -Wl,-z,relro,-z,now
    -Wl,-z,noexecstack
)

set_target_properties(rpifwcrypto-pkcs11 PROPERTIES
    OUTPUT_NAME rpifwcrypto-pkcs11
    SOVERSION 0
    VERSION ${PROJECT_VERSION}
    PREFIX ""
    C_STANDARD 99
)

set(PKCS11_MODULE_DIR "${CMAKE_INSTALL_LIBDIR}/pkcs11"
    CACHE PATH "PKCS#11 module install directory")
set(P11KIT_MODULE_DIR "${CMAKE_INSTALL_DATADIR}/p11-kit/modules"
    CACHE PATH "p11-kit module config install directory")

install(TARGETS rpifwcrypto-pkcs11 LIBRARY DESTINATION ${PKCS11_MODULE_DIR})
install(FILES src/rpifwcrypto.module DESTINATION ${P11KIT_MODULE_DIR})
