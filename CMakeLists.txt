cmake_minimum_required(VERSION 3.22)
project(proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(MSVC)
    add_definitions(-D_WIN32_WINNT=0x0A00 -DWIN32_LEAN_AND_MEAN -DNOMINMAX)
else()
endif()

set(COMMON_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
set(ENABLE_APP OFF CACHE BOOL "" FORCE)
set(ENABLE_HPACK_TOOLS OFF CACHE BOOL "" FORCE)
set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)

include(FetchContent)
set(BORINGSSL_GIT_REPOSITORY "https://github.com/google/boringssl.git" CACHE STRING "BoringSSL Git repository")
set(BORINGSSL_GIT_TAG "0.20260211.0" CACHE STRING "Pinned BoringSSL commit to fetch")
set(BORINGSSL_ALLOW_CXX_RUNTIME ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    boringssl
    GIT_REPOSITORY ${BORINGSSL_GIT_REPOSITORY}
    GIT_TAG        ${BORINGSSL_GIT_TAG}
    GIT_SHALLOW    TRUE
    PATCH_COMMAND  sh "${CMAKE_SOURCE_DIR}/patches/apply-boringssl.sh"
                      "${CMAKE_SOURCE_DIR}/patches/boringssl-chrome.patch"
    UPDATE_DISCONNECTED TRUE
)
FetchContent_MakeAvailable(boringssl)

set(NGHTTP2_GIT_REPOSITORY "https://github.com/nghttp2/nghttp2.git" CACHE STRING "nghttp2 Git repository")
set(NGHTTP2_GIT_TAG "v1.68.1" CACHE STRING "Pinned nghttp2 tag or commit to fetch")
FetchContent_Declare(
    nghttp2
    GIT_REPOSITORY ${NGHTTP2_GIT_REPOSITORY}
    GIT_TAG ${NGHTTP2_GIT_TAG}
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(nghttp2)

set(LIBUV_GIT_REPOSITORY "https://github.com/libuv/libuv.git" CACHE STRING "libuv Git repository")
set(LIBUV_GIT_TAG "v1.49.2" CACHE STRING "Pinned libuv tag to fetch")
set(LIBUV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    libuv
    GIT_REPOSITORY ${LIBUV_GIT_REPOSITORY}
    GIT_TAG ${LIBUV_GIT_TAG}
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(libuv)

set(BORINGSSL_INCLUDE_DIR ${boringssl_SOURCE_DIR}/include)
set(NGHTTP2_INCLUDE_DIR ${nghttp2_SOURCE_DIR}/lib/includes)
set(NGHTTP2_BUILD_INCLUDE_DIR ${nghttp2_BINARY_DIR}/lib/includes)

set(HOMEPAGE_HTML_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/code.html)
set(HOMEPAGE_HTML_HEADER ${GENERATED_INCLUDE_DIR}/homepage_html.h)

add_custom_command(
    OUTPUT ${HOMEPAGE_HTML_HEADER}
    COMMAND ${CMAKE_COMMAND}
            -DINPUT_FILE=${HOMEPAGE_HTML_INPUT}
            -DOUTPUT_FILE=${HOMEPAGE_HTML_HEADER}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate_homepage_header.cmake
    DEPENDS ${HOMEPAGE_HTML_INPUT} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate_homepage_header.cmake
    COMMENT "Generating homepage_html.h from code.html"
    VERBATIM
)

add_custom_target(generate_homepage_header DEPENDS ${HOMEPAGE_HTML_HEADER})

set(COMMON_SOURCES
    src/common/reactor.cpp
    src/common/buffer_pool.cpp
    src/common/tls_wrapper.cpp
    src/common/chrome_fingerprint.cpp
)

add_library(proxy_tls_ssl INTERFACE)
target_link_libraries(proxy_tls_ssl INTERFACE ssl crypto)
target_include_directories(proxy_tls_ssl INTERFACE
    ${BORINGSSL_INCLUDE_DIR}
    ${NGHTTP2_INCLUDE_DIR}
    ${NGHTTP2_BUILD_INCLUDE_DIR}
)

if(WIN32)
    set(PROXY_LINK_LIBS proxy_tls_ssl nghttp2_static uv_a ws2_32 iphlpapi userenv psapi)
else()
    set(PROXY_LINK_LIBS proxy_tls_ssl nghttp2_static uv_a pthread)
endif()

# ── server: Linux only ────────────────────────────────────────────────────────
if(NOT WIN32)
    add_executable(qtunnel_server
        src/server.cpp
        src/tls_session.cpp
        src/reality_session.cpp
        src/reality_marker.cpp
        src/dns_resolver.cpp
        src/obfuscator.cpp
        ${COMMON_SOURCES}
        ${HOMEPAGE_HTML_HEADER}
    )
    add_dependencies(qtunnel_server generate_homepage_header)
    target_include_directories(qtunnel_server PRIVATE
        ${COMMON_INCLUDE_DIR}
        ${GENERATED_INCLUDE_DIR}
        ${libuv_SOURCE_DIR}/include
        ${BORINGSSL_INCLUDE_DIR}
        ${NGHTTP2_INCLUDE_DIR}
        ${NGHTTP2_BUILD_INCLUDE_DIR}
    )
    target_compile_options(qtunnel_server PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter -Os)
    target_link_libraries(qtunnel_server PRIVATE ${PROXY_LINK_LIBS})
endif()

# ── client: cross-platform ────────────────────────────────────────────────────
add_executable(qtunnel_client
    src/client.cpp
    src/reality_marker.cpp
    src/obfuscator.cpp
    ${COMMON_SOURCES}
)
target_include_directories(qtunnel_client PRIVATE
    ${COMMON_INCLUDE_DIR}
    ${libuv_SOURCE_DIR}/include
)

if(WIN32)
    target_compile_options(qtunnel_client PRIVATE /W4 /EHsc /permissive- /utf-8 $<$<CONFIG:Release>:/O2>)
else()
    target_compile_options(qtunnel_client PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter -Os)
endif()

target_link_libraries(qtunnel_client PRIVATE ${PROXY_LINK_LIBS})

# ── Install rules ─────────────────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS qtunnel_client DESTINATION ${CMAKE_INSTALL_BINDIR})

if(NOT WIN32)
    install(FILES       ${CMAKE_SOURCE_DIR}/cmake/client.ini
            DESTINATION /etc/wtunnel)
    install(FILES       ${CMAKE_SOURCE_DIR}/patches/chrome146.txt
            DESTINATION /etc/wtunnel)
    install(FILES       ${CMAKE_SOURCE_DIR}/cmake/wtunnel-client.service
            DESTINATION /etc/systemd/system)
endif()
