# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0

# Documentation build.
#
# Two independent documentation sets are provided, each with its own Sphinx
# source tree, Doxygen configuration and generated output directory:
#
#   RTP (Remote Trust Provisioning agent) - doc/rtp/api/
#   OTA (Over-the-Air update agent)        - doc/ota/api/
#
# Usage:
#   cmake -S . -B build -DDOC_FORMAT=html      # generate HTML only
#   cmake -S . -B build -DDOC_FORMAT=xml       # generate docutils XML (input
#                                               # for the NXP CreatePDF tool)
#   cmake -S . -B build -DDOC_FORMAT=all       # generate HTML and XML

#   cmake --build build --target rtp_docs      # build RTP docs (default target "docs" alias)
#   cmake --build build --target ota_docs      # build OTA docs
#   cmake --build build --target rtp_docs_clean   # remove generated RTP doc artifacts
#   cmake --build build --target ota_docs_clean   # remove generated OTA doc artifacts
#
# DOC_ONLY=ON can be used together with DOC_FORMAT to skip configuring the
# rest of the project (useful for CI jobs that only build documentation).
#
# Currently only the RTP documentation target is built when running
# `cmake --build build --target docs` (kept as an alias to rtp_docs);
# the OTA target must be invoked explicitly with `--target ota_docs`.

function(find_python_modules source_dir all_found inst_mod)
  set(${all_found} FALSE PARENT_SCOPE)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)

  file(STRINGS ${source_dir}/requirements.txt py_modules)

  foreach(mod_spec ${py_modules})
    string(STRIP "${mod_spec}" mod_spec)
    if("${mod_spec}" STREQUAL "" OR "${mod_spec}" MATCHES "^#")
      continue()
    endif()

    string(REGEX MATCH "^([a-zA-Z0-9_-]+)([=<>!]+)(.+)$" match "${mod_spec}")
    if(match)
      set(mod_name "${CMAKE_MATCH_1}")
      set(version_op "${CMAKE_MATCH_2}")
      set(required_version "${CMAKE_MATCH_3}")
    else()
      set(mod_name "${mod_spec}")
      set(version_op "")
      set(required_version "")
    endif()

    message(STATUS "Check if python3 module ${mod_name} installed")

    execute_process(COMMAND ${Python3_EXECUTABLE} -m pip show ${mod_name}
                    OUTPUT_VARIABLE pip_output
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    RESULT_VARIABLE res
                    ERROR_QUIET)

    if(${res} EQUAL 0)
      string(REGEX MATCH "Version: ([^\n]+)" version_match "${pip_output}")
      if(version_match)
        set(installed_version "${CMAKE_MATCH_1}")
        message(STATUS "  Found ${mod_name} version ${installed_version}")

        if(NOT "${version_op}" STREQUAL "")
          execute_process(COMMAND ${Python3_EXECUTABLE} -c
                          "from packaging import version; import sys; sys.exit(0 if version.parse('${installed_version}') ${version_op} version.parse('${required_version}') else 1)"
                          RESULT_VARIABLE version_check
                          ERROR_QUIET)

          if(NOT ${version_check} EQUAL 0)
            message(STATUS "  Version mismatch: ${installed_version} does not satisfy ${version_op}${required_version}")
            set(res 1)
          else()
            message(STATUS "  Version ${installed_version} satisfies ${version_op} ${required_version}")
          endif()
        endif()
      endif()
    else()
      message(STATUS "  Module ${mod_name} not found")
    endif()

    if(NOT ${res} EQUAL 0)
      if(${inst_mod})
        message(STATUS "  Installing ${mod_spec}")
        execute_process(COMMAND ${Python3_EXECUTABLE} -m pip install "${mod_spec}"
                        OUTPUT_QUIET
                        RESULT_VARIABLE res)
        if(NOT ${res} EQUAL 0)
          message(FATAL_ERROR "Cannot install python3 module ${mod_spec}: ${res}")
        endif()
        message(STATUS "  Successfully installed ${mod_spec}")
      else()
        return()
      endif()
    endif()
  endforeach()

  set(${all_found} TRUE PARENT_SCOPE)
endfunction()

# Defines:
#   <PREFIX>_docs       custom target running Doxygen + Sphinx
#   <PREFIX>_docs_clean custom target removing generated artifacts
#
# Also configures ${source_dir}/conf.py from ${source_dir}/conf.py.in,
# substituting PROJECT_COPYRIGHT and EL2GO_VERSION (same pattern as SMW's
# Documentations/CMakeLists.txt + conf.py.in).
function(add_doc_target prefix source_dir output_dir)
  string(TIMESTAMP CURRENT_YEAR "%Y")
  set(PROJECT_COPYRIGHT "2018-${CURRENT_YEAR} - NXP - Non-Confidential")

  configure_file(${source_dir}/conf.py.in
                 ${source_dir}/conf.py
                 @ONLY)

  if(NOT EXISTS "${CMAKE_BINARY_DIR}/venv")
     find_python_modules(${source_dir} ALL_PY_MOD_FOUND FALSE)
  endif()

  if(NOT ALL_PY_MOD_FOUND)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)

    if(NOT EXISTS "${CMAKE_BINARY_DIR}/venv")
      execute_process(COMMAND ${Python3_EXECUTABLE} -m venv venv
                      WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
                      RESULT_VARIABLE res)
      if(NOT ${res} EQUAL 0)
        message(FATAL_ERROR "Unable to create python3 virtual environment ${res}")
      endif()
    endif()

    set(ENV{VIRTUAL_ENV} "${CMAKE_BINARY_DIR}/venv")
    set(Python3_FIND_VIRTUALENV FIRST)
    unset(Python3_EXECUTABLE)

    find_python_modules(${source_dir} ALL_PY_MOD_FOUND TRUE)

    unset(ENV{VIRTUAL_ENV})
  endif()

  # Doxygen XML extraction output is generated directly in the build tree
  # (alongside the Sphinx html/xml/doctrees output), keeping all generated
  # documentation artifacts out of the source tree.
  set(doxygen_output_dir ${output_dir}/doxygen_output)

  add_custom_target(${prefix}_docs
                    COMMAND ${CMAKE_COMMAND} -DBUILD_DOC_BUILDER=${BUILD_DOC_BUILDER}
                        -DBUILD_DOC_SOURCE_DIR=${source_dir}
                        -DBUILD_DOC_OUTPUT_DIR=${output_dir}
                        -DBUILD_DOC_DOXYGEN_OUTPUT_DIR=${doxygen_output_dir}
                        -DBUILD_DOC_PRJ_DIR=${CMAKE_SOURCE_DIR}
                        -DCMAKE_SCRIPT_PATH=${CMAKE_SOURCE_DIR}
                        -DCMAKE_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}
                        -P ${CMAKE_SOURCE_DIR}/scripts/linux/build_doc.cmake
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                    VERBATIM)

  add_custom_target(${prefix}_docs_clean
                    COMMAND ${CMAKE_COMMAND} -E rm -rf
                        ${output_dir}/html
                        ${output_dir}/xml
                        ${output_dir}/doctrees
                        ${doxygen_output_dir}
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                    COMMENT "Removing generated ${prefix} documentation artifacts"
                    VERBATIM)
endfunction()

if(DEFINED DOC_ONLY)
    if(${DOC_ONLY} AND NOT DEFINED DOC_FORMAT)
        set(DOC_FORMAT "all")
    endif()
endif()

if(NOT DEFINED DOC_FORMAT)
    return()
endif()

message(STATUS "Documentation")

if(${DOC_FORMAT} STREQUAL "html" OR ${DOC_FORMAT} STREQUAL "all")
    list(APPEND BUILD_DOC_BUILDER html)
endif()

if(${DOC_FORMAT} STREQUAL "xml" OR ${DOC_FORMAT} STREQUAL "all")
    list(APPEND BUILD_DOC_BUILDER xml)
endif()

if(DEFINED BUILD_DOC_BUILDER)
    string(REPLACE ";" " " BUILD_DOC_BUILDER "${BUILD_DOC_BUILDER}")
else()
    message(FATAL_ERROR "Unsupported DOC_FORMAT '${DOC_FORMAT}' (expected html, xml or all)")
endif()


# RTP documentation (always configured; "docs" is kept as an alias).
set(DOC_RTP_API_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rtp/api/source)
set(DOC_RTP_API_OUTPUT_DIR ${CMAKE_BINARY_DIR}/doc/rtp/api)
add_doc_target(rtp ${DOC_RTP_API_SOURCE_DIR} ${DOC_RTP_API_OUTPUT_DIR})


# "docs" is an alias for the RTP target, since RTP is currently the only
# documentation set built by default.
add_custom_target(docs)
add_dependencies(docs rtp_docs)

add_custom_target(docs_clean)
add_dependencies(docs_clean rtp_docs_clean)

# OTA documentation (opt-in: must be built explicitly via `--target ota_docs`).
set(DOC_OTA_API_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ota/api/source)
set(DOC_OTA_API_OUTPUT_DIR ${CMAKE_BINARY_DIR}/doc/ota/api)
add_doc_target(ota ${DOC_OTA_API_SOURCE_DIR} ${DOC_OTA_API_OUTPUT_DIR})

