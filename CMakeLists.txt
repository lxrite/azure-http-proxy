cmake_minimum_required(VERSION 2.6)
project(azure-http-proxy)

set(Boost_USE_MULTITHREAD ON)

find_package(Boost REQUIRED COMPONENTS system regex)
find_package(OpenSSL REQUIRED)

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})

include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARY_DIR})

if("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  add_definitions(-DBOOST_ASIO_HAS_MOVE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

add_executable(ahpc src/http_proxy_client_main.cpp src/http_proxy_client.cpp src/http_proxy_client_stat.cpp src/http_proxy_client_config.cpp src/http_proxy_client_connection.cpp src/jsonxx/jsonxx.cc)
target_link_libraries(ahpc ${Boost_SYSTEM_LIBRARY} ${OPENSSL_LIBRARIES})

add_executable(ahps src/http_proxy_server_main.cpp src/http_proxy_server.cpp src/http_proxy_server_config.cpp src/http_proxy_server_connection.cpp src/http_header_parser.cpp src/base64.cpp src/authentication.cpp src/jsonxx/jsonxx.cc)
target_link_libraries(ahps ${Boost_SYSTEM_LIBRARY} ${Boost_REGEX_LIBRARY} ${OPENSSL_LIBRARIES})

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_link_libraries(ahpc atomic)
endif()

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