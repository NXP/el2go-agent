# Copyright 2024,2026 NXP
# SPDX-License-Identifier: Apache-2.0

function(remove_boot_header)
    message(STATUS "Remove boot header and extract FCBs")
    set(HEADER_PADDING "0x00")
    if(NOT CONFIG_TFM_BL2)
        set(EXTRACT_HEADER_INPUT_IMAGE "${CMAKE_BINARY_DIR}/../tfm/bin/tfm_s.bin")
    else()
        set(EXTRACT_HEADER_INPUT_IMAGE "${CMAKE_BINARY_DIR}/../tfm/bin/bl2.bin")
    endif()
    message(STATUS "Header size: ${FCB_SIZE} bytes")

    # Extract FCBs
    execute_process(COMMAND nxpimage -vv utils binary-image extract
        -b ${EXTRACT_HEADER_INPUT_IMAGE}
        -a ${HEADER_PADDING}
        -s ${FCB_SIZE}
        -o ${FCB_BIN}
        OUTPUT_VARIABLE NXPIMAGE_OUTPUT
        COMMAND_ERROR_IS_FATAL ANY)
    message(STATUS "${NXPIMAGE_OUTPUT}")

    # Extract s part without FCBs and header
    execute_process(COMMAND nxpimage -vv utils binary-image extract
        -b ${EXTRACT_HEADER_INPUT_IMAGE}
        -a ${FCB_SIZE}
        -s 0x00
        -o ${HEADERLESS_BIN}
        OUTPUT_VARIABLE NXPIMAGE_OUTPUT
        COMMAND_ERROR_IS_FATAL ANY)
    message(STATUS "${NXPIMAGE_OUTPUT}")
endfunction()

remove_boot_header()
