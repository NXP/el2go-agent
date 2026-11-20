# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Script executed via `cmake -P` by the `docs` custom target to generate the
# RTP API documentation (Doxygen XML extraction + Sphinx/Breathe rendering).
#
# Expected variables (passed with -D on the command line):
#   BUILD_DOC_SOURCE_DIR        - Sphinx source directory (contains conf.py)
#   BUILD_DOC_OUTPUT_DIR        - Sphinx output directory (contains html/, xml/, ...)
#   BUILD_DOC_DOXYGEN_OUTPUT_DIR - Doxygen XML extraction output directory
#                                  (contains xml/); located in the build tree,
#                                  not the source tree.
#   BUILD_DOC_PRJ_DIR           - Project root directory (srctree)
#   BUILD_DOC_BUILDER           - Space separated list of Sphinx builders (html, xml, ...)
#   CMAKE_SCRIPT_PATH           - Project root, used to locate cmake/ modules
#   CMAKE_INSTALL_BINDIR        - Used by Find modules to locate venv binaries

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SCRIPT_PATH}/cmake)

if(EXISTS "${CMAKE_BINARY_DIR}/venv")
  set(ENV{VIRTUAL_ENV} "${CMAKE_BINARY_DIR}/venv")
  set(Python3_FIND_VIRTUALENV FIRST)
  unset(Python3_EXECUTABLE)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(Sphinx REQUIRED)

# NOTE: find_package(Doxygen) relies on add_executable() for its imported
# target and is not usable in cmake -P script mode, so look it up directly.
#
# Doxygen is a standalone native executable (unlike Sphinx/Breathe, which
# are Python packages auto-installed into a venv above). If it is not found
# on the system PATH, download a pinned, pre-built release binary from
# doxygen.nl and cache it under the build tree, so that CI/Docker images
# without a pre-installed "doxygen" package can still build the docs
# without requiring manual image changes.
set(DOXYGEN_FALLBACK_VERSION "1.11.0")
set(DOXYGEN_FALLBACK_ARCHIVE "doxygen-${DOXYGEN_FALLBACK_VERSION}.linux.bin.tar.gz")
set(DOXYGEN_FALLBACK_URL "https://www.doxygen.nl/files/${DOXYGEN_FALLBACK_ARCHIVE}")
set(DOXYGEN_FALLBACK_SHA256 "db68ca22b43c3d7efd15351329db5af9146ab1ac7eaccd61a894fe36612da8fb")
set(DOXYGEN_FALLBACK_DIR "${CMAKE_BINARY_DIR}/doxygen-${DOXYGEN_FALLBACK_VERSION}")
set(DOXYGEN_FALLBACK_EXECUTABLE "${DOXYGEN_FALLBACK_DIR}/bin/doxygen")

find_program(DOXYGEN_EXECUTABLE NAMES doxygen DOC "Doxygen executable")

if(NOT DOXYGEN_EXECUTABLE)
    if(EXISTS "${DOXYGEN_FALLBACK_EXECUTABLE}")
        message(STATUS "Doxygen not found on PATH, using previously downloaded ${DOXYGEN_FALLBACK_EXECUTABLE}")
        set(DOXYGEN_EXECUTABLE "${DOXYGEN_FALLBACK_EXECUTABLE}")
    else()
        message(STATUS "Doxygen not found on PATH, downloading ${DOXYGEN_FALLBACK_ARCHIVE} from ${DOXYGEN_FALLBACK_URL}")

        set(DOXYGEN_FALLBACK_ARCHIVE_PATH "${CMAKE_BINARY_DIR}/${DOXYGEN_FALLBACK_ARCHIVE}")
        file(DOWNLOAD
             "${DOXYGEN_FALLBACK_URL}"
             "${DOXYGEN_FALLBACK_ARCHIVE_PATH}"
             EXPECTED_HASH SHA256=${DOXYGEN_FALLBACK_SHA256}
             INACTIVITY_TIMEOUT 30
             SHOW_PROGRESS
             STATUS DOXYGEN_DOWNLOAD_STATUS)

        list(GET DOXYGEN_DOWNLOAD_STATUS 0 DOXYGEN_DOWNLOAD_RESULT)
        if(NOT ${DOXYGEN_DOWNLOAD_RESULT} EQUAL 0)
            list(GET DOXYGEN_DOWNLOAD_STATUS 1 DOXYGEN_DOWNLOAD_ERROR)
            message(FATAL_ERROR "Failed to download Doxygen: ${DOXYGEN_DOWNLOAD_ERROR}")
        endif()

        message(STATUS "Extracting ${DOXYGEN_FALLBACK_ARCHIVE}")
        execute_process(
            COMMAND ${CMAKE_COMMAND} -E tar xf ${DOXYGEN_FALLBACK_ARCHIVE_PATH}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            RESULT_VARIABLE DOXYGEN_EXTRACT_RESULT)

        if(NOT ${DOXYGEN_EXTRACT_RESULT} EQUAL 0)
            message(FATAL_ERROR "Cannot extract Doxygen archive: ${DOXYGEN_EXTRACT_RESULT}")
        endif()

        if(NOT EXISTS "${DOXYGEN_FALLBACK_EXECUTABLE}")
            message(FATAL_ERROR "Doxygen executable not found after extraction: ${DOXYGEN_FALLBACK_EXECUTABLE}")
        endif()

        set(DOXYGEN_EXECUTABLE "${DOXYGEN_FALLBACK_EXECUTABLE}")
    endif()

    message(STATUS "Using downloaded Doxygen: ${DOXYGEN_EXECUTABLE}")
endif()


set(ENV{srctree} ${BUILD_DOC_PRJ_DIR})
set(ENV{PYTHONDONTWRITEBYTECODE} 1)

# Step 1: run Doxygen to extract the XML used by Breathe.
# OUTPUT_DIRECTORY is overridden by generating a combined config file
# (base Doxyfile content + an appended OUTPUT_DIRECTORY override line,
# relying on Doxygen's "last definition wins" semantics) rather than
# editing the checked-in Doxyfile. This way the generated XML lands in
# the build tree alongside the Sphinx output, instead of polluting the
# source tree under ${BUILD_DOC_SOURCE_DIR}/doxygen_output.
#
# WORKING_DIRECTORY is kept as BUILD_DOC_SOURCE_DIR so that the Doxyfile's
# relative INPUT = ../../../../include/... paths still resolve correctly.
file(MAKE_DIRECTORY ${BUILD_DOC_DOXYGEN_OUTPUT_DIR})

file(READ ${BUILD_DOC_SOURCE_DIR}/Doxyfile DOXYFILE_BASE_CONTENT)
set(DOXYFILE_GENERATED "${BUILD_DOC_DOXYGEN_OUTPUT_DIR}/Doxyfile.generated")
file(WRITE ${DOXYFILE_GENERATED} "${DOXYFILE_BASE_CONTENT}\nOUTPUT_DIRECTORY = ${BUILD_DOC_DOXYGEN_OUTPUT_DIR}\n")

message(STATUS "Running Doxygen in ${BUILD_DOC_SOURCE_DIR} (output: ${BUILD_DOC_DOXYGEN_OUTPUT_DIR})")
execute_process(COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_GENERATED}
                WORKING_DIRECTORY ${BUILD_DOC_SOURCE_DIR}
                RESULT_VARIABLE DOXYGEN_RESULT
                COMMAND_ECHO STDOUT)

if(NOT ${DOXYGEN_RESULT} EQUAL 0)
    message(FATAL_ERROR "Doxygen failed with error code ${DOXYGEN_RESULT}")
endif()


# Step 2: run Sphinx for every requested builder.
# Point Breathe at the Doxygen XML just generated in the build tree via the
# DOXYGEN_XML_DIR environment variable, read by conf.py.in.
set(ENV{DOXYGEN_XML_DIR} ${BUILD_DOC_DOXYGEN_OUTPUT_DIR}/xml)

string(REPLACE " " ";" BUILD_DOC_BUILDER "${BUILD_DOC_BUILDER}")


foreach(BUILDER ${BUILD_DOC_BUILDER})
    message(STATUS "BUILDER: ${BUILDER}")
    execute_process(COMMAND
                    ${SPHINX_EXECUTABLE} -M ${BUILDER}
                    ${BUILD_DOC_SOURCE_DIR} ${BUILD_DOC_OUTPUT_DIR} -T -E
                    RESULT_VARIABLE SPHINX_RESULT
                    COMMAND_ECHO STDOUT)

    if(NOT ${SPHINX_RESULT} EQUAL 0)
        message(FATAL_ERROR "Sphinx builder '${BUILDER}' failed with error code ${SPHINX_RESULT}")
    endif()

    # The "xml" builder produces plain docutils XML (one file per page,
    # with all Breathe directives already resolved into plain content).
    # This is the "DocUtils for Sphinx sources" input format expected by
    # the NXP internal CreatePDF tool; index.xml is the top-level map.
    #
    # The "xml" builder does not copy any files referenced by plain
    # "image::"/"figure::" directives into the output tree. However,
    # ".. graphviz::" (from the sphinx.ext.graphviz extension enabled in
    # conf.py.in) is different: it is rendered by Sphinx into a native
    # <graphviz code="..."> element embedded directly in the generated
    # XML (the GraphViz source is inlined as an attribute, not left as a
    # loose file reference), which the NXP internal CreatePDF tool
    # converts natively -- provided graphviz.zip is installed next to
    # createPDF.exe on the machine running the tool. No extra file copy
    # step is needed here for that case.
    if(BUILDER STREQUAL "xml")
        message(STATUS "XML generated: ${BUILD_DOC_OUTPUT_DIR}/xml (top-level map: index.xml)")
    endif()

endforeach()


unset(ENV{srctree})
unset(ENV{PYTHONDONTWRITEBYTECODE})
unset(ENV{DOXYGEN_XML_DIR})

unset(ENV{VIRTUAL_ENV})
unset(Python3_EXECUTABLE)

