# SPDX-License-Identifier: Apache-2.0
#
# HyprNova — build definition
#
# The single most important property of this build is that EVERY external
# dependency is optional and detected at configure time. An EDR that refuses to
# build on a host without libyara is an EDR that does not get deployed, and an EDR
# that is not deployed detects nothing. Each optional dependency therefore has:
#
#   * a user-facing switch   HYPRNOVA_WITH_<dep>   (default ON, "try to use it")
#   * a detected capability  HYPRNOVA_HAVE_<dep>   (set by find_package/find_library)
#   * an in-tree fallback    compiled in when HAVE is false
#
# and every module calls mark_degraded() at runtime when its producer is missing,
# so the gap is visible in the GUI rather than silent.

cmake_minimum_required(VERSION 3.20)

project(hyprnova
        VERSION 1.0.0
        DESCRIPTION "Low-overhead behavioural EDR agent for Linux"
        LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "hyprnova targets Linux only (inotify/fanotify/netlink-audit/cgroup v2)")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(HYPRNOVA_WITH_YARA       "Use libyara when present (else the in-tree YaraLite engine)" ON)
option(HYPRNOVA_WITH_QT6        "Build the Qt6/QML dashboard when Qt6 is present"            ON)
option(HYPRNOVA_WITH_LIBCAP     "Use libcap for capability queries (else parse /proc)"       ON)
option(HYPRNOVA_WITH_OPENSSL    "Use OpenSSL for SHA-256/HMAC (else the in-tree implementation)" ON)
option(HYPRNOVA_WITH_LIBNFTABLES "Use libnftables (else exec the nft binary)"                ON)
option(HYPRNOVA_WITH_AUDIT      "Use libaudit (else the in-tree netlink audit client)"       ON)
option(HYPRNOVA_WERROR          "Treat warnings as errors"                                   OFF)
option(HYPRNOVA_BUILD_TESTS     "Build the unit tests"                                       ON)
option(HYPRNOVA_SANITIZERS      "Build with ASan+UBSan (development only)"                   OFF)

# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------
# This list is the coding standard, enforced by the compiler rather than by review.
# -Wold-style-cast in particular is what keeps the C APIs (libyara, netlink,
# fanotify, epoll) behind RAII wrappers instead of leaking into module code, and
# -Wconversion/-Wsign-conversion catch the narrow/widen bugs that dominate
# syscall-adjacent code.
#
# Deliberately NOT enabled:
#   -Wuseless-cast          fires on every defensive `static_cast<std::int64_t>`
#                           used to pin a JSON field's width. That cast is the
#                           point, not the noise.
#   -Wconditionally-supported  fires on legal implementation-defined constructs
#   -Winline / -Winterference-size  noise from libstdc++ internals
set(HYPRNOVA_WARNINGS
    -Wall -Wextra -Wshadow -Wold-style-cast -Wnon-virtual-dtor -Woverloaded-virtual
    -Wcast-align -Wunused -Wconversion -Wsign-conversion -Wnull-dereference
    -Wdouble-promotion -Wimplicit-fallthrough -Wformat=2 -Wduplicated-cond
    -Wlogical-op)

if(HYPRNOVA_WERROR)
    list(APPEND HYPRNOVA_WARNINGS -Werror)
endif()

if(HYPRNOVA_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "hyprnova: sanitizers ENABLED (never ship this build)")
endif()

# ---------------------------------------------------------------------------
# Optional dependency detection
# ---------------------------------------------------------------------------
include(CheckIncludeFileCXX)
include(CheckSymbolExists)

if(HYPRNOVA_WITH_YARA)
    find_path(YARA_INCLUDE_DIR yara.h PATHS /usr/include /usr/local/include)
    find_library(YARA_LIBRARY NAMES yara PATHS /usr/lib /usr/lib64 /usr/local/lib
                              /usr/lib/x86_64-linux-gnu)
    if(YARA_INCLUDE_DIR AND YARA_LIBRARY)
        set(HYPRNOVA_HAVE_LIBYARA TRUE)
        message(STATUS "hyprnova: libyara found -> ${YARA_LIBRARY}")
    else()
        message(STATUS "hyprnova: libyara NOT found -> using the in-tree YaraLite engine "
                       "(YARA-subset parser + Aho-Corasick + 10 built-in behavioural rules)")
    endif()
endif()

if(HYPRNOVA_WITH_OPENSSL)
    find_package(OpenSSL QUIET COMPONENTS Crypto)
    if(OpenSSL_FOUND)
        set(HYPRNOVA_HAVE_OPENSSL TRUE)
        message(STATUS "hyprnova: OpenSSL Crypto found -> ${OPENSSL_CRYPTO_LIBRARY}")
    else()
        message(STATUS "hyprnova: OpenSSL NOT found -> using the in-tree SHA-256/HMAC/XXH64")
    endif()
endif()

if(HYPRNOVA_WITH_LIBCAP)
    find_path(LIBCAP_INCLUDE_DIR sys/capability.h)
    find_library(LIBCAP_LIBRARY NAMES cap)
    if(LIBCAP_INCLUDE_DIR AND LIBCAP_LIBRARY)
        set(HYPRNOVA_HAVE_LIBCAP TRUE)
        message(STATUS "hyprnova: libcap found -> ${LIBCAP_LIBRARY}")
    else()
        message(STATUS "hyprnova: libcap NOT found -> capabilities parsed from "
                       "/proc/self/status directly")
    endif()
endif()

if(HYPRNOVA_WITH_LIBNFTABLES)
    find_path(LIBNFTABLES_INCLUDE_DIR nftables/libnftables.h)
    find_library(LIBNFTABLES_LIBRARY NAMES nftables)
    if(LIBNFTABLES_INCLUDE_DIR AND LIBNFTABLES_LIBRARY)
        set(HYPRNOVA_HAVE_LIBNFTABLES TRUE)
        message(STATUS "hyprnova: libnftables found -> ${LIBNFTABLES_LIBRARY}")
    else()
        message(STATUS "hyprnova: libnftables NOT found -> shelling out to the nft binary "
                       "via the hardened exec layer (no popen, no shell)")
    endif()
endif()

if(HYPRNOVA_WITH_AUDIT)
    find_path(LIBAUDIT_INCLUDE_DIR libaudit.h)
    find_library(LIBAUDIT_LIBRARY NAMES audit)
    if(LIBAUDIT_INCLUDE_DIR AND LIBAUDIT_LIBRARY)
        set(HYPRNOVA_HAVE_LIBAUDIT TRUE)
        message(STATUS "hyprnova: libaudit found -> ${LIBAUDIT_LIBRARY}")
    else()
        message(STATUS "hyprnova: libaudit NOT found -> using the in-tree NETLINK_AUDIT client "
                       "(rule install, status query, record correlation)")
    endif()
endif()

# Kernel headers we need. These are not optional: without them the agent cannot
# be built for this kernel at all, and saying so loudly beats a confusing error.
check_include_file_cxx(linux/fanotify.h  HYPRNOVA_HAVE_FANOTIFY_H)
check_include_file_cxx(linux/audit.h     HYPRNOVA_HAVE_AUDIT_H)
check_include_file_cxx(linux/netlink.h   HYPRNOVA_HAVE_NETLINK_H)
check_include_file_cxx(sys/epoll.h       HYPRNOVA_HAVE_EPOLL_H)
if(NOT HYPRNOVA_HAVE_FANOTIFY_H OR NOT HYPRNOVA_HAVE_AUDIT_H OR NOT HYPRNOVA_HAVE_NETLINK_H)
    message(FATAL_ERROR "hyprnova requires linux/fanotify.h, linux/audit.h and linux/netlink.h "
                        "(install your distribution's kernel headers)")
endif()

check_symbol_exists(open_by_handle_at "fcntl.h" HYPRNOVA_HAVE_OPEN_BY_HANDLE_AT)

# ---------------------------------------------------------------------------
# The agent library: every module, so tests can link any part of it
# ---------------------------------------------------------------------------
add_library(hyprnova_core STATIC
    core/log.cpp
    core/fd.cpp
    core/json.cpp
    core/event.cpp
    core/hash.cpp
    core/thread_pool.cpp
    core/proc.cpp
    core/config.cpp
    core/sensor.cpp
    core/exec.cpp
    hardening/boot_auditor.cpp
    hardening/kernel_hardening.cpp
hardening/sshd_audit.cpp
    hardening/mac_profile.cpp
    anti_ransomware/canary.cpp
    anti_ransomware/honeypot.cpp
    anti_ransomware/file_monitor.cpp
    scanning/yara_engine.cpp
    scanning/scanner.cpp
    scanning/scan_bridge.cpp
    scanning/carver.cpp
    behavioral/socket_source.cpp
    behavioral/falco_sensor.cpp
    behavioral/audit_sensor.cpp
behavioral/proc_poll.cpp
forensics/mem_inspect.cpp
    behavioral/osquery_sensor.cpp
    heuristics/heuristics_engine.cpp
    remediation/remediation_engine.cpp
    remediation/shadow_copy.cpp
    remediation/rescue_boot.cpp
    remediation/shredder.cpp
    ai/analyst.cpp
    tools/toolbox.cpp
    tools/analysis.cpp
    tools/bench.cpp
    gui/gui_bridge.cpp
    agent/agent.cpp)

target_include_directories(hyprnova_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(hyprnova_core PRIVATE ${HYPRNOVA_WARNINGS})
target_compile_definitions(hyprnova_core PUBLIC
    HYPRNOVA_VERSION="${PROJECT_VERSION}")
target_compile_definitions(hyprnova_core PRIVATE
    $<$<BOOL:${HYPRNOVA_HAVE_LIBYARA}>:HYPRNOVA_HAVE_LIBYARA=1>
    $<$<BOOL:${HYPRNOVA_HAVE_OPENSSL}>:HYPRNOVA_HAVE_OPENSSL=1>
    $<$<BOOL:${HYPRNOVA_HAVE_LIBCAP}>:HYPRNOVA_HAVE_LIBCAP=1>
    $<$<BOOL:${HYPRNOVA_HAVE_LIBNFTABLES}>:HYPRNOVA_HAVE_LIBNFTABLES=1>
    $<$<BOOL:${HYPRNOVA_HAVE_LIBAUDIT}>:HYPRNOVA_HAVE_LIBAUDIT=1>
    $<$<BOOL:${HYPRNOVA_HAVE_OPEN_BY_HANDLE_AT}>:HYPRNOVA_HAVE_OPEN_BY_HANDLE_AT=1>)

# pthread is required by std::jthread / std::thread on every supported toolchain.
find_package(Threads REQUIRED)
target_link_libraries(hyprnova_core PUBLIC Threads::Threads)

if(HYPRNOVA_HAVE_LIBYARA)
    target_include_directories(hyprnova_core PRIVATE ${YARA_INCLUDE_DIR})
    target_link_libraries(hyprnova_core PRIVATE ${YARA_LIBRARY})
endif()
if(HYPRNOVA_HAVE_OPENSSL)
    target_link_libraries(hyprnova_core PRIVATE OpenSSL::Crypto)
endif()
if(HYPRNOVA_HAVE_LIBCAP)
    target_include_directories(hyprnova_core PRIVATE ${LIBCAP_INCLUDE_DIR})
    target_link_libraries(hyprnova_core PRIVATE ${LIBCAP_LIBRARY})
endif()
if(HYPRNOVA_HAVE_LIBNFTABLES)
    target_include_directories(hyprnova_core PRIVATE ${LIBNFTABLES_INCLUDE_DIR})
    target_link_libraries(hyprnova_core PRIVATE ${LIBNFTABLES_LIBRARY})
endif()
if(HYPRNOVA_HAVE_LIBAUDIT)
    target_include_directories(hyprnova_core PRIVATE ${LIBAUDIT_INCLUDE_DIR})
    target_link_libraries(hyprnova_core PRIVATE ${LIBAUDIT_LIBRARY})
endif()

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------
add_executable(hyprnovad agent/main.cpp)
target_link_libraries(hyprnovad PRIVATE hyprnova_core)
target_compile_options(hyprnovad PRIVATE ${HYPRNOVA_WARNINGS})

add_executable(hyprnova-cli agent/cli.cpp)
target_link_libraries(hyprnova-cli PRIVATE hyprnova_core)
add_executable(hyprnova-bench tools/bench_main.cpp)
target_link_libraries(hyprnova-bench PRIVATE hyprnova_core)
add_executable(hyprnova-kernel-drill tools/kernel_drill.cpp)
target_link_libraries(hyprnova-kernel-drill PRIVATE hyprnova_core)
target_compile_options(hyprnova-cli PRIVATE ${HYPRNOVA_WARNINGS})

# ---------------------------------------------------------------------------
# Qt6 dashboard
# ---------------------------------------------------------------------------
# Two independent conditions, and the distinction matters: WITH_QT6 is "the
# operator asked for a GUI", HAVE_QT6 is "this machine can build one". A build host
# without Qt6 must still produce a working agent.
set(HYPRNOVA_HAVE_QT6 FALSE)
if(HYPRNOVA_WITH_QT6)
    find_package(Qt6 QUIET COMPONENTS Core Gui Qml Quick QuickControls2)
    if(Qt6_FOUND)
        set(HYPRNOVA_HAVE_QT6 TRUE)
        message(STATUS "hyprnova: Qt6 ${Qt6_VERSION} found -> building hyprnova-gui")
    else()
        message(STATUS "hyprnova: Qt6 NOT found -> hyprnova-gui will not be built. "
                       "The agent and hyprnova-cli are unaffected.")
    endif()
endif()

# Only configure the GUI target when its sources are actually present, so a
# partial checkout still builds the agent.
set(HYPRNOVA_GUI_SOURCES gui/gui_app.cpp gui/backend.cpp)
set(HYPRNOVA_GUI_PRESENT TRUE)
foreach(_f IN LISTS HYPRNOVA_GUI_SOURCES)
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${_f})
        set(HYPRNOVA_GUI_PRESENT FALSE)
    endif()
endforeach()

if(HYPRNOVA_HAVE_QT6 AND HYPRNOVA_GUI_PRESENT)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)

    # QML ships as loose files, not a .qrc.
    #
    # This is a deliberate choice, not an omission. A resource-embedded console
    # cannot be hot-patched, and the one thing an operator always needs during an
    # incident is to tweak a threshold colour or add a column without a rebuild and
    # a redeploy of the agent. Loose files under ${CMAKE_INSTALL_DATADIR}/hyprnova
    # are read at start-up (resolve_main_qml), so a page edit is one restart of the
    # console and never touches the detection path. It also removes a whole class of
    # build fragility: qrc module imports need a resource prefix that exactly
    # mirrors the on-disk tree, and getting that wrong fails at run time, not build
    # time, in a VM with no debugger attached.
    add_executable(hyprnova-gui ${HYPRNOVA_GUI_SOURCES})
    target_link_libraries(hyprnova-gui PRIVATE
        hyprnova_core
        Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick Qt6::QuickControls2)
    target_compile_options(hyprnova-gui PRIVATE ${HYPRNOVA_WARNINGS})
    # The GUI is a client of the agent, never a part of it: linking hyprnova_core
    # is for the JSON and config types only, and it runs unprivileged.
    target_compile_definitions(hyprnova-gui PRIVATE HYPRNOVA_GUI=1)

    install(TARGETS hyprnova-gui RUNTIME DESTINATION bin)
    # Stage the QML tree beside the binary in the build directory too, so
    # "./build/hyprnova-gui" works without installing. resolve_main_qml() looks
    # there first, which also means a developer can edit a page and re-launch
    # without re-running cmake.
    add_custom_command(TARGET hyprnova-gui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_SOURCE_DIR}/gui/qml $<TARGET_FILE_DIR:hyprnova-gui>/qml
        COMMENT "hyprnova: staging QML tree beside hyprnova-gui"
        VERBATIM)
    if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/gui/qml)
        install(DIRECTORY gui/qml/ DESTINATION share/hyprnova/qml)
    endif()
    if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/gui/theme)
        install(DIRECTORY gui/theme/ DESTINATION share/hyprnova/theme)
    endif()
elseif(HYPRNOVA_HAVE_QT6)
    message(STATUS "hyprnova: Qt6 present but gui/gui_app.cpp is missing; skipping hyprnova-gui")
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(HYPRNOVA_BUILD_TESTS)
    # Glob rather than enumerate: the suite grows file by file and a CMake edit per
    # test is friction that gets tests skipped. CONFIGURE_DEPENDS re-globs on build.
    file(GLOB HYPRNOVA_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp)
    if(HYPRNOVA_TEST_SOURCES)
        enable_testing()
        add_executable(hyprnova-tests ${HYPRNOVA_TEST_SOURCES})
        target_link_libraries(hyprnova-tests PRIVATE hyprnova_core)
        target_compile_options(hyprnova-tests PRIVATE ${HYPRNOVA_WARNINGS})
        target_include_directories(hyprnova-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        add_test(NAME hyprnova-tests COMMAND hyprnova-tests)
        # The suite must pass as an unprivileged user: anything that needs root is
        # reported as SKIPPED, never as a failure.
        set_tests_properties(hyprnova-tests PROPERTIES TIMEOUT 300)
    else()
        message(STATUS "hyprnova: no tests/*.cpp found; skipping the test target")
    endif()
endif()

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS hyprnovad hyprnova-cli RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
# Packaging files are installed when present so a source tarball and a partial
# checkout both configure cleanly.
foreach(_pkgfile
        "config/agent.json|/etc/hyprnova"
        "rules/hyprnova-behaviour.yar|/etc/hyprnova/rules"
        "systemd/hyprnovad.service|${CMAKE_INSTALL_SYSCONFDIR}/systemd/system"
        "systemd/hyprnova-gui.service|${CMAKE_INSTALL_SYSCONFDIR}/systemd/system")
    string(REPLACE "|" ";" _parts "${_pkgfile}")
    list(GET _parts 0 _src)
    list(GET _parts 1 _dst)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${_src})
        install(FILES ${_src} DESTINATION ${_dst})
    endif()
endforeach()

# Runtime directories. tmpfiles.d is the correct mechanism: a mkdir in the
# Makefile does not survive a reboot, because /run is a tmpfs.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/systemd/hyprnova-tmpfiles.conf)
    install(FILES systemd/hyprnova-tmpfiles.conf
            DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/tmpfiles.d
            RENAME hyprnova.conf)
endif()

message(STATUS "")
message(STATUS "hyprnova ${PROJECT_VERSION} configuration:")
message(STATUS "  build type      ${CMAKE_BUILD_TYPE}")
message(STATUS "  compiler        ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  libyara         ${HYPRNOVA_HAVE_LIBYARA}")
message(STATUS "  openssl         ${HYPRNOVA_HAVE_OPENSSL}")
message(STATUS "  libcap          ${HYPRNOVA_HAVE_LIBCAP}")
message(STATUS "  libnftables     ${HYPRNOVA_HAVE_LIBNFTABLES}")
message(STATUS "  libaudit        ${HYPRNOVA_HAVE_LIBAUDIT}")
message(STATUS "  qt6 gui         ${HYPRNOVA_HAVE_QT6}")
message(STATUS "  tests           ${HYPRNOVA_BUILD_TESTS}")
message(STATUS "  werror          ${HYPRNOVA_WERROR}")
message(STATUS "")
