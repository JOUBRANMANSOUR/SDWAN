cmake_minimum_required(VERSION 3.16)
project(sdwan_classifier_v5 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Wpedantic -Werror=implicit-function-declaration -fstack-protector-strong)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NDPI REQUIRED libndpi)
pkg_check_modules(NFQ REQUIRED libnetfilter_queue)
pkg_check_modules(MNL REQUIRED libmnl)
pkg_check_modules(JSONC REQUIRED json-c)

add_executable(sdwan-classifier-v5
  main.c packet_parser.c flow_table.c ndpi_engine.c policy_snapshot.c
  event_export.c nfqueue_worker.c)
target_include_directories(sdwan-classifier-v5 PRIVATE ${NDPI_INCLUDE_DIRS} ${NFQ_INCLUDE_DIRS} ${MNL_INCLUDE_DIRS} ${JSONC_INCLUDE_DIRS})
target_link_directories(sdwan-classifier-v5 PRIVATE ${NDPI_LIBRARY_DIRS} ${NFQ_LIBRARY_DIRS} ${MNL_LIBRARY_DIRS} ${JSONC_LIBRARY_DIRS})
target_link_libraries(sdwan-classifier-v5 PRIVATE ${NDPI_LIBRARIES} ${NFQ_LIBRARIES} ${MNL_LIBRARIES} ${JSONC_LIBRARIES} pthread)
install(TARGETS sdwan-classifier-v5 RUNTIME DESTINATION sbin)

include(CTest)
if(BUILD_TESTING)
  add_executable(sdwan-parser-tests tests/test_packet_parser.c packet_parser.c)
  target_include_directories(sdwan-parser-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${NDPI_INCLUDE_DIRS})
  add_test(NAME packet-parser COMMAND sdwan-parser-tests)
endif()
