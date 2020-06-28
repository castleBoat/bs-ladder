cmake_minimum_required(VERSION 3.16)
project(bs-ladder)

set(CMAKE_CXX_STANDARD 11)

add_executable(bs-ladder src/main.cpp src/local_server.cpp src/remote_server.cpp src/socks5.cpp src/bs.pb.cc src/utility.cpp)

target_include_directories(bs-ladder PRIVATE include)

if (WIN32)
    message(STATUS ">>> windows")
    add_definitions("-D__USE_W32_SOCKETS -D_WIN32_WINNT=0x0601")
    set(CURRENT_PLATFORM win)

    set_property(TARGET ${PROJECT_NAME} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreadedDebug")

    target_include_directories(bs-ladder PRIVATE ${CMAKE_SOURCE_DIR}/../boost/boost_1_70_0/win_build/include/boost-1_70)
    target_link_libraries(bs-ladder ${CMAKE_SOURCE_DIR}/../boost/boost_1_70_0/stage/lib/*.lib)

    target_include_directories(bs-ladder PRIVATE ${CMAKE_SOURCE_DIR}/third_party/win/gflags/include)
    target_link_libraries(bs-ladder ${CMAKE_SOURCE_DIR}/third_party/win/gflags/lib/gflags_static_debug.lib)
    target_link_libraries(bs-ladder ${CMAKE_SOURCE_DIR}/third_party/win/gflags/lib/ShLwApi.lib)

    target_include_directories(bs-ladder PRIVATE ${CMAKE_SOURCE_DIR}/third_party/win/protobuf/include)
    target_link_libraries(bs-ladder ${CMAKE_SOURCE_DIR}/third_party/win/protobuf/lib/*.lib)
#    target_link_libraries(bs-ladder ${CMAKE_SOURCE_DIR}/third_party/win/protobuf/lib/libprotobuf-lited.lib)

    target_include_directories(bs-ladder PRIVATE ${CMAKE_SOURCE_DIR}/third_party/win/glog/include)
    target_link_libraries(bs-ladder ${CMAKE_SOURCE_DIR}/third_party/win/glog/lib/glogd.lib)
elseif (UNIX)
    set(CURRENT_PLATFORM unix)
    message(STATUS ">>> linux")
    find_package(Boost 1.70 REQUIRED)
    target_include_directories(bs-ladder PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(bs-ladder ${Boost_LIBRARIES})

    find_package(gflags 2.2.2 REQUIRED)
    target_include_directories(bs-ladder PRIVATE ${gflags_INCLUDE_DIRS})
    target_link_libraries(bs-ladder ${gflags_LIBRARIES})

    find_package(Protobuf 3.11 REQUIRED)
    target_include_directories(bs-ladder PRIVATE ${Protobuf_INCLUDE_DIRS})
    target_link_libraries(bs-ladder ${Protobuf_LIBRARIES})

    find_package(Glog REQUIRED)
    target_include_directories(bs-ladder PRIVATE ${Glog_INCLUDE_DIRS})
    target_link_libraries(bs-ladder ${Glog_LIBRARIES})
endif ()

