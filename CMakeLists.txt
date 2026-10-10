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
    add_test(NAME policy-audit-smoke
        COMMAND ${CMAKE_COMMAND} -E env "BIN_DIR=$<TARGET_FILE_DIR:dirguardctl>"
                /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh)
    add_executable(fanotify_metadata_test tests/fanotify_metadata_test.c)
    target_compile_options(fanotify_metadata_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME fanotify-metadata-validation COMMAND fanotify_metadata_test)
    add_executable(policy_reload_test tests/policy_reload_test.c)
    target_compile_options(policy_reload_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME policy-reload-transaction COMMAND policy_reload_test)
endif()

option(PDG_ENABLE_FUZZING "Build the Clang libFuzzer policy parser target" OFF)
if(PDG_ENABLE_FUZZING)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "PDG_ENABLE_FUZZING requires Clang with libFuzzer support")
    endif()
    add_executable(policy_parser_fuzz tests/policy_parser_fuzz.c)
    target_compile_options(policy_parser_fuzz PRIVATE
        -O1 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(policy_parser_fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    if(BUILD_TESTING)
        add_test(NAME policy-parser-fuzz-smoke
            COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_policy_fuzzer_smoke.sh
                    $<TARGET_FILE:policy_parser_fuzz>
                    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz_corpus/policy-v1)
        set_tests_properties(policy-parser-fuzz-smoke PROPERTIES TIMEOUT 60)
    endif()
endif()
