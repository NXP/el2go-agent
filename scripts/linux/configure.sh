#!/bin/bash
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: Apache-2.0

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

    $(basename "$0") <dir> <smw_subsystem> [toolpath=<dir>] [testing] [ota] [doc_format=html|xml|all] [doc_only]
      <dir>           : Output build directory
      <smw_subsystem> : SMW subsystem(s) - comma-separated list (no spaces)
                        Valid combinations:
                          tee           : TEE Only
                          seco          : SECO Only
                          ele           : ELE Only
                          tee,seco      : SECO + TEE
                          tee,ele       : ELE + TEE
      toolpath=<dir>  : [Optional] Toolchain installation path
      testing         : [Optional] Enable unit test build (BUILD_TESTING=ON)
      ota             : [Optional] Enable OTA build (BUILD_OTA=ON)
      doc_format=html|xml|all
                      : [Optional] Documentation format
      doc_only        : [Optional] Documentation-only configuration. Skips the
                         toolchain, MbedTLS and SMW dependency builds entirely
                         and configures only the documentation targets. Can be
                         combined with doc_format (defaults to
                         DOC_FORMAT=all if doc_format is not given). When
                         doc_only is used, <smw_subsystem> may be omitted (it
                         is not used).

    Examples:
      # Documentation-only configuration (no SMW subsystem required)
      $(basename "$0") build doc_only doc_format=html

      # Normal configuration with SMW subsystem
      $(basename "$0") build tee toolpath=/opt/toolchains

EOF
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

out=$1
shift 1

# Documentation-only configuration does not require a SMW subsystem since the
# SMW dependency build is entirely skipped in that mode.
# Accept "doc_only" here as a convenience shorthand for the mandatory
# <smw_subsystem> positional slot; otherwise a SMW subsystem is required.
smw_subsystem=
if [[ "$1" == "doc_only" ]]; then
    : # leave smw_subsystem empty; "doc_only" stays in "$@" to be parsed below
else
    if [[ $# -lt 1 ]]; then
        usage
    fi
    smw_subsystem="$1"
    shift 1
fi

# change to absolute path to avoid relative path issues
out=$(realpath -m "$out")

readonly smw_out="${out}/smw-build"
readonly smw_export_dir="${out}/export-smw"
readonly export_dir="${out}/export"

opt_toolpath="toolpath=/toolchains"
opt_testing=
opt_ota=
opt_doc_format=
opt_doc_only=
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
        doc_format=*)
            opt_doc_format="${arg}"
            ;;
        doc_only)
            opt_doc_only="doc_only"
            ;;
        *)
            pr_err "Unknown argument \"${arg}\""
            usage
            ;;
    esac
done

if [[ -z "${opt_doc_only}" && -z "${smw_subsystem}" ]]; then
    pr_err "Missing mandatory <smw_subsystem> argument"
    usage
fi

readonly smw_config="${smw_export_dir}/usr/lib/cmake"
readonly mbedtls_config="${export_dir}/usr/lib/pkgconfig"
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

# Documentation-only configuration: skip all external dependencies (toolchain,
# MbedTLS, SMW) and go straight to configuring the documentation targets.
if [[ -n "${opt_doc_only}" ]]; then
    doc_conf_opts_array=("${opt_doc_only}")

    if [[ -n "${opt_doc_format}" ]]; then
        doc_conf_opts_array+=("${opt_doc_format}")
    fi

    build_component "configure" \
        "out=${out}" \
        "${doc_conf_opts_array[@]}"
    exit 0
fi

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

if [[ -n "${opt_doc_format}" ]]; then
    conf_opts_array+=("${opt_doc_format}")
fi

if [[ -n "${opt_doc_only}" ]]; then
    conf_opts_array+=("${opt_doc_only}")
fi

# Configure build targets
build_component "configure" \
    "out=${out}" \
    "${conf_opts_array[@]}"
