cmake_minimum_required(VERSION 3.19)
project(HyprAgentPortal VERSION "0.4.0")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)
include(GNUInstallDirs)

add_compile_definitions(WLR_USE_UNSTABLE)
add_compile_options(
  -g
  -Wall
  -Wextra
  -Wno-unused-parameter
  -Wno-unused-value
  -Wno-missing-field-initializers
  -Wno-narrowing
  -Wno-pointer-arith
  --no-gnu-unique
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(HYPR_DEPS REQUIRED hyprland)

set(HYPR_AGENT_PORTAL_LUA_PKG_DEFAULT "auto")
if(NOT DEFINED HYPR_AGENT_PORTAL_LUA_PKG AND DEFINED HYPR_AGENT_PROTAL_LUA_PKG)
  message(DEPRECATION "HYPR_AGENT_PROTAL_LUA_PKG is deprecated; use HYPR_AGENT_PORTAL_LUA_PKG")
  set(HYPR_AGENT_PORTAL_LUA_PKG_DEFAULT "${HYPR_AGENT_PROTAL_LUA_PKG}")
endif()
set(HYPR_AGENT_PORTAL_LUA_PKG "${HYPR_AGENT_PORTAL_LUA_PKG_DEFAULT}" CACHE STRING "Lua pkg-config module to link against, or auto")
set(HYPR_AGENT_PORTAL_LUA_CANDIDATES)
if(HYPR_AGENT_PORTAL_LUA_PKG STREQUAL "auto" OR NOT HYPR_AGENT_PORTAL_LUA_PKG)
  find_program(HYPRLAND_EXECUTABLE Hyprland)
  if(HYPRLAND_EXECUTABLE)
    execute_process(
      COMMAND readelf -d "${HYPRLAND_EXECUTABLE}"
      OUTPUT_VARIABLE HYPRLAND_DYNAMIC_SECTION
      ERROR_QUIET
    )
    if(HYPRLAND_DYNAMIC_SECTION MATCHES "liblua\\.so\\.5\\.5")
      list(APPEND HYPR_AGENT_PORTAL_LUA_CANDIDATES lua5.5 lua-5.5 lua55 lua)
    elseif(HYPRLAND_DYNAMIC_SECTION MATCHES "liblua5\\.4\\.so|liblua\\.so\\.5\\.4")
      list(APPEND HYPR_AGENT_PORTAL_LUA_CANDIDATES lua5.4 lua-5.4 lua54 lua)
    endif()
  endif()
  list(APPEND HYPR_AGENT_PORTAL_LUA_CANDIDATES lua5.5 lua-5.5 lua55 lua5.4 lua-5.4 lua54 lua)
  list(REMOVE_DUPLICATES HYPR_AGENT_PORTAL_LUA_CANDIDATES)
  foreach(LUA_CANDIDATE ${HYPR_AGENT_PORTAL_LUA_CANDIDATES})
    pkg_check_modules(LUA QUIET ${LUA_CANDIDATE})
    if(LUA_FOUND)
      set(HYPR_AGENT_PORTAL_LUA_RESOLVED_PKG "${LUA_CANDIDATE}")
      break()
    endif()
  endforeach()
  if(NOT LUA_FOUND)
    message(FATAL_ERROR "Could not find a supported Lua pkg-config module; tried: ${HYPR_AGENT_PORTAL_LUA_CANDIDATES}")
  endif()
else()
  set(HYPR_AGENT_PORTAL_LUA_RESOLVED_PKG "${HYPR_AGENT_PORTAL_LUA_PKG}")
  pkg_check_modules(LUA REQUIRED ${HYPR_AGENT_PORTAL_LUA_RESOLVED_PKG})
endif()
message(STATUS "Using Lua pkg-config module: ${HYPR_AGENT_PORTAL_LUA_RESOLVED_PKG}")
find_package(nlohmann_json REQUIRED)
find_package(Python3 COMPONENTS Interpreter)

set(HYPRLAND_SOURCE_DIR "" CACHE PATH "Optional Hyprland source checkout to build against")
if(HYPRLAND_SOURCE_DIR)
  get_filename_component(HYPRLAND_SOURCE_DIR "${HYPRLAND_SOURCE_DIR}" ABSOLUTE)
  set(HYPRLAND_SOURCE_INCLUDE_DIR "${CMAKE_BINARY_DIR}/hyprland-source-include")
  file(MAKE_DIRECTORY "${HYPRLAND_SOURCE_INCLUDE_DIR}")
  file(REMOVE "${HYPRLAND_SOURCE_INCLUDE_DIR}/hyprland")
  execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink "${HYPRLAND_SOURCE_DIR}" "${HYPRLAND_SOURCE_INCLUDE_DIR}/hyprland")
  list(PREPEND HYPR_DEPS_INCLUDE_DIRS
    "${HYPRLAND_SOURCE_INCLUDE_DIR}"
    "${HYPRLAND_SOURCE_DIR}/src"
    "${HYPRLAND_SOURCE_DIR}/protocols"
  )
endif()

foreach(HYPRLAND_INCLUDE_DIR ${HYPR_DEPS_INCLUDE_DIRS})
  foreach(HYPRLAND_DERIVED_INCLUDE_DIR
      "${HYPRLAND_INCLUDE_DIR}/hyprland/src"
      "${HYPRLAND_INCLUDE_DIR}/hyprland/protocols"
      "${HYPRLAND_INCLUDE_DIR}/src"
      "${HYPRLAND_INCLUDE_DIR}/protocols")
    if(EXISTS "${HYPRLAND_DERIVED_INCLUDE_DIR}")
      list(APPEND HYPR_DEPS_INCLUDE_DIRS "${HYPRLAND_DERIVED_INCLUDE_DIR}")
    endif()
  endforeach()
endforeach()

if(NOT HYPRLAND_SOURCE_DIR)
  set(HYPRLAND_FOUND_PLUGIN_API FALSE)
  foreach(HYPRLAND_INCLUDE_DIR ${HYPR_DEPS_INCLUDE_DIRS})
    if(EXISTS "${HYPRLAND_INCLUDE_DIR}/hyprland/src/plugins/PluginAPI.hpp")
      set(HYPRLAND_FOUND_PLUGIN_API TRUE)
    endif()
  endforeach()
  if(NOT HYPRLAND_FOUND_PLUGIN_API AND EXISTS "/usr/include/hyprland/src/plugins/PluginAPI.hpp")
    list(APPEND HYPR_DEPS_INCLUDE_DIRS
      /usr/include
      /usr/include/hyprland
      /usr/include/hyprland/src
      /usr/include/hyprland/protocols
    )
  endif()
endif()
list(REMOVE_DUPLICATES HYPR_DEPS_INCLUDE_DIRS)

add_library(hypr_agent_portal SHARED
  src/plugin/main.cpp
  src/plugin/screenshot_capture.cpp
)

set_target_properties(hypr_agent_portal PROPERTIES OUTPUT_NAME "hypr-agent-portal")
add_custom_command(TARGET hypr_agent_portal POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:hypr_agent_portal>
    $<TARGET_FILE_DIR:hypr_agent_portal>/libhypr-agent-protal.so
  COMMENT "Creating one-release hypr-agent-protal compatibility artifact"
)

target_include_directories(hypr_agent_portal PRIVATE src ${HYPR_DEPS_INCLUDE_DIRS} ${LUA_INCLUDE_DIRS})
target_link_directories(hypr_agent_portal PRIVATE ${HYPR_DEPS_LIBRARY_DIRS} ${LUA_LIBRARY_DIRS})
target_link_libraries(hypr_agent_portal PRIVATE ${HYPR_DEPS_LIBRARIES} ${LUA_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_options(hypr_agent_portal PRIVATE -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)

install(TARGETS hypr_agent_portal LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(PROGRAMS
  scripts/hypr-agent-portalctl
  scripts/hypr-agent-protalctl
  scripts/hypr-agent-portal-sandbox
  scripts/install-codex-cursor-asset
  mcp/hypr-agent-portal-mcp.py
  mcp/hypr-agent-protal-mcp.py
  DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES
  mcp/action_sequence.py
  mcp/compat_env.py
  mcp/hypr_management.py
  mcp/hypr_socket2.py
  mcp/image_pipeline.py
  mcp/ocr_backend.py
  mcp/process_lease.py
  mcp/security_audit.py
  mcp/security_doctor.py
  mcp/security_policy.py
  mcp/target_identity.py
  mcp/visual_targets.py
  DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(BUILD_TESTING AND Python3_Interpreter_FOUND)
  add_test(
    NAME hypr-agent-portal-python-compile
    COMMAND ${Python3_EXECUTABLE} -m py_compile
      ${CMAKE_SOURCE_DIR}/scripts/hypr-agent-portalctl
      ${CMAKE_SOURCE_DIR}/scripts/hypr-agent-protalctl
      ${CMAKE_SOURCE_DIR}/scripts/hypr-agent-portal-sandbox
      ${CMAKE_SOURCE_DIR}/scripts/install-codex-cursor-asset
      ${CMAKE_SOURCE_DIR}/mcp/hypr-agent-portal-mcp.py
      ${CMAKE_SOURCE_DIR}/mcp/hypr-agent-protal-mcp.py
      ${CMAKE_SOURCE_DIR}/mcp/action_sequence.py
      ${CMAKE_SOURCE_DIR}/mcp/compat_env.py
      ${CMAKE_SOURCE_DIR}/mcp/hypr_management.py
      ${CMAKE_SOURCE_DIR}/mcp/hypr_socket2.py
      ${CMAKE_SOURCE_DIR}/mcp/image_pipeline.py
      ${CMAKE_SOURCE_DIR}/mcp/ocr_backend.py
      ${CMAKE_SOURCE_DIR}/mcp/process_lease.py
      ${CMAKE_SOURCE_DIR}/mcp/security_audit.py
      ${CMAKE_SOURCE_DIR}/mcp/security_doctor.py
      ${CMAKE_SOURCE_DIR}/mcp/security_policy.py
      ${CMAKE_SOURCE_DIR}/mcp/target_identity.py
      ${CMAKE_SOURCE_DIR}/mcp/visual_targets.py
      ${CMAKE_SOURCE_DIR}/tests/action_sequence.py
      ${CMAKE_SOURCE_DIR}/tests/mcp_smoke.py
      ${CMAKE_SOURCE_DIR}/tests/mcp_security.py
      ${CMAKE_SOURCE_DIR}/tests/compat_env.py
      ${CMAKE_SOURCE_DIR}/tests/hypr_management.py
      ${CMAKE_SOURCE_DIR}/tests/image_pipeline.py
      ${CMAKE_SOURCE_DIR}/tests/ocr_backend.py
      ${CMAKE_SOURCE_DIR}/tests/process_lease.py
      ${CMAKE_SOURCE_DIR}/tests/sandbox_runner.py
      ${CMAKE_SOURCE_DIR}/tests/socket2_events.py
      ${CMAKE_SOURCE_DIR}/tests/visual_targets.py
      ${CMAKE_SOURCE_DIR}/tests/mcp_geometry.py
      ${CMAKE_SOURCE_DIR}/tests/keyboard_routing.py
      ${CMAKE_SOURCE_DIR}/tests/cursor_render.py
      ${CMAKE_SOURCE_DIR}/tests/identity_binding.py
      ${CMAKE_SOURCE_DIR}/tests/atspi_strict_resolver.py
      ${CMAKE_SOURCE_DIR}/tests/secure_screenshot_storage.py
  )
  add_test(
    NAME hypr-agent-portal-cursor-render
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/cursor_render.py
  )
  add_test(
    NAME hypr-agent-portal-mcp-smoke
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/mcp_smoke.py ${CMAKE_SOURCE_DIR}/mcp/hypr-agent-portal-mcp.py
  )
  add_test(
    NAME hypr-agent-protal-mcp-compat-smoke
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/mcp_smoke.py ${CMAKE_SOURCE_DIR}/mcp/hypr-agent-protal-mcp.py
  )
  add_test(
    NAME hypr-agent-portal-mcp-geometry
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/mcp_geometry.py
  )
  add_test(
    NAME hypr-agent-portal-keyboard-routing
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/keyboard_routing.py
  )
  add_test(
    NAME hypr-agent-portal-security
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/mcp_security.py
  )
  add_test(
    NAME hypr-agent-portal-compat-environment
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/compat_env.py
  )
  add_test(
    NAME hypr-agent-portal-process-lease
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/process_lease.py
  )
  add_test(
    NAME hypr-agent-portal-sandbox-runner
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/sandbox_runner.py
  )
  add_test(
    NAME hypr-agent-portal-action-sequence
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/action_sequence.py
  )
  add_test(
    NAME hypr-agent-portal-hypr-management
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/hypr_management.py
  )
  add_test(
    NAME hypr-agent-portal-image-pipeline
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/image_pipeline.py
  )
  add_test(
    NAME hypr-agent-portal-ocr-backend
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/ocr_backend.py
  )
  add_test(
    NAME hypr-agent-portal-socket2-events
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/socket2_events.py
  )
  add_test(
    NAME hypr-agent-portal-visual-targets
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/visual_targets.py
  )
  add_test(
    NAME hypr-agent-portal-target-identity
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/identity_binding.py
  )
  add_test(
    NAME hypr-agent-portal-atspi-strict-resolver
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/atspi_strict_resolver.py
  )
  add_test(
    NAME hypr-agent-portal-secure-screenshot-storage
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/secure_screenshot_storage.py
  )
endif()
