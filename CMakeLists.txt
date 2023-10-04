cmake_minimum_required(VERSION 2.6)
project(azure-http-proxy)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

include_directories("third_party/networking-ts-impl/include")

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARY_DIR})

if("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  add_compile_options("/std:c++17")
endif()

include_directories("third_party/jsonxx")
add_library(jsonxx STATIC third_party/jsonxx/jsonxx.cc)

include_directories("third_party/curi/src")
add_subdirectory(third_party/curi/src)

add_executable(ahpc src/http_proxy_client_main.cpp src/http_proxy_client.cpp src/http_proxy_client_config.cpp src/http_proxy_client_connection.cpp)
target_link_libraries(ahpc ${OPENSSL_LIBRARIES} jsonxx)

add_executable(ahps src/http_proxy_server_main.cpp src/http_proxy_server.cpp src/http_proxy_server_config.cpp src/http_proxy_server_connection.cpp src/http_header_parser.cpp src/base64.cpp src/authentication.cpp)
target_link_libraries(ahps ${OPENSSL_LIBRARIES} jsonxx curi)

if(UNIX)
  target_link_libraries(ahpc pthread)
  target_link_libraries(ahps pthread)
endif()

if(WIN32)
  if(MINGW)
    target_link_libraries(ahpc ws2_32 wsock32)
    target_link_libraries(ahps ws2_32 wsock32)
  endif()
endif()

install(TARGETS ahpc ahps DESTINATION bin)