cmake_minimum_required(VERSION 3.16)
project(linux_protected_directory_guard VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_executable(dirguardctl src/dirguardctl.c)
target_compile_options(dirguardctl PRIVATE -Wall -Wextra -Wpedantic -Werror)
install(TARGETS dirguardctl RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME policy-audit-smoke COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh)
endif()
