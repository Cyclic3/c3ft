cmake_minimum_required(VERSION 3.10)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND AND NOT DISABLE_CCACHE)
  message("Using ccache")
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
else()
  message("Not using ccache")
endif()

project(c3ft VERSION 0.0.1)
set(PROJECT_NAMESPACE c3ft)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

file(GLOB_RECURSE ${PROJECT_NAME}_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
add_library(${PROJECT_NAME} ${${PROJECT_NAME}_SOURCES})

file(GLOB_RECURSE ${PROJECT_NAME}_CLI_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cli/*.cpp)
add_executable(${PROJECT_NAME}-cli ${${PROJECT_NAME}_CLI_SOURCES})
SET_TARGET_PROPERTIES(${PROJECT_NAME}-cli PROPERTIES OUTPUT_NAME ${PROJECT_NAME}-cli)

# Begin requirements
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
# End requirements


target_link_libraries(${PROJECT_NAME}
PUBLIC # Libraries needed to use this library
Boost::boost Boost::system Threads::Threads OpenSSL::Crypto
PRIVATE # Libraries only needed to build this library
# @@
)

target_link_libraries(${PROJECT_NAME}-cli PUBLIC ${PROJECT_NAME})

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
target_compile_features(${PROJECT_NAME}-cli PUBLIC cxx_std_20)

target_include_directories(${PROJECT_NAME} PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
