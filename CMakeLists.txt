cmake_minimum_required(VERSION 3.16)
project(casanostr VERSION 0.0.2 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED IMPORTED_TARGET libsecp256k1)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
pkg_check_modules(PQ REQUIRED IMPORTED_TARGET libpq)

add_library(cjson STATIC deps/davegamble-cjson/cJSON.c)
target_include_directories(cjson PUBLIC deps/davegamble-cjson)
target_compile_options(cjson PRIVATE -w)

add_executable(casanostr
  src/main.c
  src/net.c
  src/nostr.c
  src/store.c
  src/store_sqlite3.c
  src/store_postgresql.c)
target_compile_definitions(casanostr PRIVATE VERSION="${PROJECT_VERSION}")
target_compile_options(casanostr PRIVATE -Wall -Wextra)
target_link_libraries(casanostr PRIVATE
  cjson
  PkgConfig::SECP256K1 PkgConfig::SQLITE3 PkgConfig::PQ
  OpenSSL::Crypto Threads::Threads m)

enable_testing()
add_executable(gen_event t/gen_event.c src/nostr.c)
target_include_directories(gen_event PRIVATE src)
target_link_libraries(gen_event PRIVATE
  cjson PkgConfig::SECP256K1 OpenSSL::Crypto m)
add_test(NAME relay
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/t/run.sh)
set_tests_properties(relay PROPERTIES ENVIRONMENT
  "CASANOSTR=$<TARGET_FILE:casanostr>;GEN_EVENT=$<TARGET_FILE:gen_event>")
