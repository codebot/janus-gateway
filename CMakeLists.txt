cmake_minimum_required(VERSION 3.5)
project(janus)

if (NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
endif()

if (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra)  # -Wpedantic)
endif()

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(glib REQUIRED glib-2.0)
pkg_search_module(nice REQUIRED nice)
pkg_search_module(libsrtp2 REQUIRED libsrtp2)
pkg_search_module(jansson REQUIRED jansson)
pkg_search_module(libssl REQUIRED libssl)
pkg_search_module(libcrypto REQUIRED libcrypto)
pkg_search_module(libwebsockets REQUIRED libwebsockets)

set(janus_SOURCES apierror.c
                  auth.c
                  cmdline.c
                  config.c
                  dtls.c
                  dtls-bio.c
                  events.c
                  ice.c
                  janus.c
                  log.c
                  record.c
                  rtcp.c
                  rtp.c
                  sctp.c
                  sdp.c
                  sdp-utils.c
                  ip-utils.c
                  turnrest.c
                  utils.c
                  version.c
                  text2pcap.c
                  plugins/plugin.c
                  transports/transport.c
                  )


link_directories(${libsrtp2_LIBRARY_DIRS} ${libwebsockets_LIBRARY_DIRS})

add_executable(janus ${janus_SOURCES})
target_compile_definitions(janus PRIVATE -DHAVE_SRTP_2)
target_compile_definitions(janus PRIVATE -DCONFDIR=\"${CMAKE_BINARY_DIR}/conf\")
target_compile_definitions(janus PRIVATE -DEVENTDIR=\"${CMAKE_BINARY_DIR}\")
target_compile_definitions(janus PRIVATE -DPLUGINDIR=\"${CMAKE_BINARY_DIR}/plugins\")
target_compile_definitions(janus PRIVATE -DTRANSPORTDIR=\"${CMAKE_BINARY_DIR}/transports\")
target_include_directories(janus PRIVATE ${glib_INCLUDE_DIRS} ${nice_INCLUDE_DIRS} ${libsrtp2_INCLUDE_DIRS})
target_include_directories(janus PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(janus m dl crypto ${glib_LIBRARIES} ${jansson_LIBRARIES} ${nice_LIBRARIES} ${libssl_LIBRARIES} ${libsrtp2_LIBRARIES})
set_target_properties(janus PROPERTIES LINK_FLAGS "-rdynamic")

####################################################
# Transports
add_library(janus_websockets MODULE transports/janus_websockets.c)
target_include_directories(janus_websockets PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(janus_websockets PRIVATE ${glib_INCLUDE_DIRS} ${nice_INCLUDE_DIRS} ${libsrtp2_INCLUDE_DIRS} ${libwebsockets_INCLUDE_DIRS})
target_link_libraries(janus_websockets ${libwebsockets_LIBRARIES})
set_target_properties(janus_websockets PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/transports)

add_library(janus_ros2 MODULE transports/janus_ros2.cpp)
target_include_directories(janus_ros2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(janus_ros2 PRIVATE ${glib_INCLUDE_DIRS} ${nice_INCLUDE_DIRS} ${libsrtp2_INCLUDE_DIRS})
target_include_directories(janus_ros2 PRIVATE ${rclcpp_INCLUDE_DIRS})
ament_target_dependencies(janus_ros2 rclcpp std_msgs)
#target_link_libraries(janus_ros2 ${libwebsockets_LIBRARIES})
set_target_properties(janus_ros2 PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/transports)


####################################################
# Plugins
add_library(janus_videocall MODULE plugins/janus_videocall.c)
target_include_directories(janus_videocall PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(janus_videocall PRIVATE ${glib_INCLUDE_DIRS} ${nice_INCLUDE_DIRS} ${libsrtp2_INCLUDE_DIRS})
set_target_properties(janus_videocall PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/conf/janus.transport.websockets.cfg.sample ${CMAKE_BINARY_DIR}/conf/janus.transport.websockets.cfg COPYONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/conf/janus.plugin.videocall.cfg.sample ${CMAKE_BINARY_DIR}/conf/janus.plugin.videocall.cfg COPYONLY)

ament_package()
