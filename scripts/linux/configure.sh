#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 */
#
# Copyright 2026 NXP
#

set -e

function pr_err()
{
    printf "\033[1;31m\n"
    printf "%s" "$@"
    printf "\033[0m\n"
}

function pr_success()
{
    printf "\033[0;32m\n"
    printf "%s" "$@"
    printf "\033[0m\n"
}

function check_directory()
{
    declare -n mydir=$1
    mydir="${mydir/\~/$HOME}"

    if [[ ! -d "${mydir}" ]]; then
        pr_err "${mydir} is not a directory"
    fi
}

function usage()
{
    cat << EOF

    **********************************************************
    * Usage of EL2GO Agent configure script *
    **********************************************************

    The script is configuring the EL2GO Agent by
    installing the external dependencies.

    CAUTION: This script must be executed from the EL2GO Agent directory.
    The dependency sources should be located as sibling directories at the
    same level as the project folder:

    Expected folder structure:
      parent-folder/
      ├── smw/  (EL2GO Agent dependency)
      |── optee-client  (smw dependency)
      |── optee-os  (smw dependency)
      |── secure_enclave  (smw dependency)
      └── simw-devicelink/  ((run script from here))

    $(basename "$0") <dir> <smw_subsystem> toolpath=[dir] [testing] [ota]
      <dir>           : Output build directory
      <smw_subsystem> : SMW subsystem(s) - comma-separated list (no spaces)
                        Valid combinations:
                          tee           : TEE Only
                          seco          : SECO Only
                          ele           : ELE Only
                          tee,seco      : SECO + TEE
                          tee,ele       : ELE + TEE
      <toolpath>      : [Optional] Toolchain installation path
      testing         : [Optional] Enable unit test build (BUILD_TESTING=ON)
      ota             : [Optional] Enable OTA build (BUILD_OTA=ON)

EOF
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

out=$1
smw_subsystem="$2"
shift 2
# change to absolute path to avoid relative path issues
out=$(realpath -m "$out")

readonly smw_out="${out}/smw-build"
readonly smw_export_dir="${out}/export-smw"
readonly export_dir="${out}/export"

opt_toolpath="toolpath=/toolchains"
opt_testing=
opt_ota=
for arg in "$@"
do
    case ${arg} in
        toolpath=*)
            opt_toolpath="${arg#*=}"
            check_directory opt_toolpath
            opt_toolpath="toolpath=${opt_toolpath}"
            ;;
        testing)
            opt_testing="testing"
            ;;
        ota)
            opt_ota="ota"
            ;;
        *)
            pr_err "Unknown argument \"${arg}\""
            usage
            ;;
    esac
done

readonly smw_config="${smw_export_dir}/usr/lib/cmake"
readonly mbedtls_config="${export_dir}/usr/local/el2go/lib/pkgconfig"
#
# Build/Prepare external dependencies
#
function build_component() {
    local component="$1"
    shift
    printf "Executing: %s %s\n" "$component" "$*"

    if ! ./scripts/linux/build.sh "$component" "$@"; then
        pr_err "Failed to build ${component}"
        exit 1
    fi
    pr_success "${component} build completed"
}

# Set default source directories
MBEDTLS_SRC_DIR="${MBEDTLS_SRC_DIR:-../mbedtls}"
SMW_SRC_DIR="${SMW_SRC_DIR:-../smw}"

# toolchain
build_component "toolchain" "${opt_toolpath}"

# MbedTLS
build_component "mbedtls" \
    "export=${export_dir}" \
    "src=${MBEDTLS_SRC_DIR}" \
    "out=${out}" \
    "${opt_toolpath}"

# SMW
build_component "smw" \
    "export=${smw_export_dir}" \
    "out=${smw_out}" \
    "src=${SMW_SRC_DIR}" \
    "subsystem=${smw_subsystem}" \
    "${opt_toolpath}"

# Build configuration options
conf_opts_array=(
    "${opt_toolpath}"
    "smw=${smw_config}"
    "mbedtls=${mbedtls_config}"
)

if [[ -n "${opt_testing}" ]]; then
    conf_opts_array+=("${opt_testing}")
fi

if [[ -n "${opt_ota}" ]]; then
    conf_opts_array+=("${opt_ota}")
fi

# Configure build targets
build_component "configure" \
    "out=${out}" \
    "${conf_opts_array[@]}"
