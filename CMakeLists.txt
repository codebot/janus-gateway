cmake_minimum_required(VERSION 3.5)
project(janus)

if (NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
endif()

if (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

set(janus_SOURCES apierror.c auth.c)

add_executable(janus ${janus_SOURCES})
target_include_directories(janus PRIVATE ${GLIB_INCLUDE_DIRS})
target_include_directories(janus PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(janus libcrypto)

ament_package()
