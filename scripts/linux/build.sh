#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0 */
#
# Copyright 2026 NXP
#

set -eE
trap 'error ${LINENO}' ERR
#
# Default build options
#
opt_build=all
opt_verbose=
opt_buildtype=
opt_format=
opt_doc_only=
opt_cmake_ver="3.13"

#
# Get script name and path
#
script_name=$0
script_full=$(realpath "${script_name}")
script_dir=$(dirname "${script_full}")

function pr_err()
{
    printf "\033[1;31m\n"
    printf "%s" "$@"
    printf "\033[0m\n"
}

function error() {
    pr_err "Error occurred at line $1"
    exit 1
}

function pr_operation_header() {
    local message="$*"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    if [[ -n "$message" ]]; then
        printf " %s\n" "${message}"
    fi
    printf "***************************************\n"
    printf "\033[0m\n"
}

function check_cmake_version()
{
    #
    # Check if cmake is installed and minimum version is expected
    #
    if [[ ! -x $(command -v cmake) ]]; then
        pr_err "cmake not installed\n"
        pr_err "cmake version required is minimum ${opt_cmake_ver}\n"
        exit 1
    fi

    # Get the current cmake version installed
    cmake_ver=$(cmake -version 2>&1 | grep -Eo "cmake version [0-9]\.[0-9]+")
    cmake_ver=$(echo "${cmake_ver}" | grep -Eo '[0-9]\.[0-9]+')

    IFS='.' read -ra acmake_ver <<< "${cmake_ver}"
    IFS='.' read -ra aexp_ver <<< "${opt_cmake_ver}"

    match=${#aexp_ver[@]}
    if [[ ${#acmake_ver[@]} -eq ${#aexp_ver[@]} ]]; then
        for (( i=0; i<${#aexp_ver[@]}; i++ )); do
            if [[ ${acmake_ver[$i]} -lt ${aexp_ver[$i]} ]]; then
                break;
            fi
            match=$((match-1))
        done
    fi

    if [[ ${match} -ne 0 ]]; then
        printf "Bad cmake version got %s expected %s or newer\n" \
               "${cmake_ver}" "${opt_cmake_ver}"
        exit 1
    fi
}

function check_directory()
{
    declare -n mydir=$1
    mydir="${mydir/\~/$HOME}"

    if [[ ! -d "${mydir}" ]]; then
        pr_err "${mydir} is not a directory"
    fi
}

function usage_toolchain()
{
    printf "\n"
    printf "To install the toolchain\n"
    printf "  %s toolchain toolpath=[dir] " "${script_name}"
    printf "toolname=[name]\n"
    printf "    toolpath = [optional] Toolchain installation path\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_mbedtls()
{
    printf "\n"
    printf "To build and install the MbedTLS Library\n"
    printf "  %s mbedtls export=[dir] src=[dir] out=[dir] " "${script_name}"
    printf "toolpath=[dir] toolname=[name]\n"
    printf "    export   = Export directory\n"
    printf "    src      = Temporary directory where to install sources\n"
    printf "    out      = Temporary directory where to build sources\n"
    printf "    toolpath = [optional] Toolchain installation path\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_smw()
{
    printf "\n"
    printf "To build and install the SMW Library\n"
    printf "  %s smw export=[dir] src=[dir] out=[dir]" "${script_name}"
    printf " toolpath=[dir] toolname=[name] subsystem=[subsystem]\n"
    printf "    export     = Export directory\n"
    printf "    src        = Temporary directory where to install sources\n"
    printf "    out        = Install directory\n"
    printf "    toolpath   = [optional] Toolchain installation path\n"
    printf "    subsystem  = SMW subsystem(s) - comma-separated list (no spaces)\n"
    printf "                 Valid combinations:\n"
    printf "                   tee           : TEE Only\n"
    printf "                   seco          : SECO Only\n"
    printf "                   ele           : ELE Only\n"
    printf "                   tee,seco      : SECO + TEE\n"
    printf "                   tee,ele       : ELE + TEE\n"
    printf "\n"
}

function usage_configure_doc_only()
{
    printf "\n"
    printf "To configure the EL2GO Agent (Documentation Only)\n"
    printf " - Note: with this configuration option, the library is not built"
    printf " and other configuration parameters are useless.\n"
    printf "  %s configure out=[dir] doc_only doc_format=[name]\n " "${script_name}"
    printf "    doc_format = [optional] Documentation format (html|xml|all, default: all)\n"
    printf "\n"
}

function usage_configure()
{
    printf "\n"
    printf "To configure the EL2GO Agent\n"
    printf " - Note: all dependencies must be present\n"
    printf "  %s configure out=[dir] " "${script_name}"
    printf "mbedtls=[dir]\n"
    printf "    out          = Build directory\n"
    printf "    mbedtls      = MbedTLS pkg-config directory (path containing .pc files)\n"
    printf "    testing      = [optional] Enable unit test build (BUILD_TESTING=ON)\n"
    printf "    ota          = [optional] Enable OTA build (BUILD_OTA=ON)\n"
    printf "    doc_format   = [optional] Documentation format (html|xml|all)\n"
    printf "\n"
}

function usage_build()
{
    printf "\n"
    printf "To build the EL2GO Agent\n"
    printf " - Note: Project must have been configure first\n"
    printf " (ref. %s configure)\n" "${script_name}"
    printf "  %s build out=[dir] [testing] [docs] [docs_ota]" "${script_name}"
    printf "\n"
    printf "    out       = Build directory\n"
    printf "    testing   = [optional] Also build unit tests (requires BUILD_TESTING=ON)\n"
    printf "    docs      = [optional] Build RTP documentation (html/xml, see 'docs' CMake target)\n"
    printf "    docs_ota  = [optional] Build OTA documentation (html/xml, see 'ota_docs' CMake target)\n"
    printf "\n"
}

function usage_install()
{
    printf "\n"
    printf "To install the EL2GO Agent binaries\n"
    printf "  %s install out=[dir] dest=[dir] [testing]\n" "${script_name}"
    printf "    out      = Build directory\n"
    printf "    dest     = [optional] Installation directory\n"
    printf "    testing  = [optional] Also install unit tests (requires BUILD_TESTING=ON)\n"
    printf "\n"
}

function usage_package()
{
    printf "\n"
    printf "To package the EL2GO Agent objects\n"
    printf "  %s package out=[dir] dest=[dir]\n" "${script_name}"
    printf "    out      = Build directory\n"
    printf "    dest     = [optional] Installation directory\n"
    printf "\n"
}

function usage()
{
    printf "\n"
    printf "****************************************************\n"
    printf " Usage of EL2GO Agent build script \n"
    printf "****************************************************\n"
    usage_toolchain
    usage_mbedtls
    usage_smw
    usage_configure
    usage_configure_doc_only
    usage_build
    usage_install
    usage_package
    exit 1
}

function toolchain()
{
    cmd_script="cmake -DFORCE_TOOLCHAIN_INSTALL=True"
    cmd_script="${cmd_script} ${opt_toolpath} ${opt_toolname}"

    pr_operation_header "Install toolchain"

    cmd_script="${cmd_script} -P ${toolchain_script}"
    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}


function mbedtls()
{
    cmd_script="cmake ${opt_toolchain}"
    mbedtls_script="${script_dir}/build_mbedtls.cmake"

    pr_operation_header "Install MBedTLS to ${opt_export}"

    if [[ -z ${opt_export} || -z ${opt_src} || -z ${opt_out} ]]; then
        usage_mbedtls
        exit 1
    fi

    cmd_script="${cmd_script} -DMbedTLS_SRC_PATH=${opt_src}"
    cmd_script="${cmd_script} -DMbedTLS_BUILD_DIR=${opt_out}"
    cmd_script="${cmd_script} -DMbedTLS_ROOT=${opt_export} -P ${mbedtls_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function smw()
{
    pr_operation_header "Install SMW to ${opt_export}"

    cmd_conf_script="./scripts/smw_configure.sh"
    cmd_build_script="./scripts/smw_build.sh"

    if [[ -z ${opt_out} || -z ${opt_src} || -z ${opt_export} || -z ${opt_subsystem} ]]; then
        usage_smw
        exit 1
    fi
    # Save current directory
    local original_dir
    original_dir="$(pwd)"

    # Change to the source directory
    printf "Changing directory to $opt_src\n"
    cd "${opt_src}" || { echo "Failed to change directory to ${opt_src}"; exit 1; }

    cmd_conf_script="${cmd_conf_script} ${opt_out}"
    cmd_conf_script="${cmd_conf_script} aarch64 ${opt_subsystem}"
    cmd_conf_script="${cmd_conf_script} toolpath=${opt_toolpath_raw}"

    cmd_build_script="${cmd_build_script} install out=${opt_out}"
    cmd_build_script="${cmd_build_script} dest=${opt_export}"

    printf "Execute %s\n" "${cmd_conf_script}"
    eval "${cmd_conf_script}"

    printf "Execute %s\n" "${cmd_build_script}"
    eval "${cmd_build_script}"

    # Return to the original directory
    cd "${original_dir}" || { echo "Failed to return to original directory"; exit 1; }
}

function configure()
{
    pr_operation_header "Configure EL2GO Agent to ${opt_out}"

    if [[ -z ${opt_out} ]]; then
        usage_configure
        exit 1
    fi

    if [[ -n ${opt_mbedtls} ]]; then
        export PKG_CONFIG_PATH="${opt_mbedtls}:${PKG_CONFIG_PATH}"
        # For standalone cross-compilation the linker needs -L (to resolve bare
        # -lmbedtls names) and -rpath-link (to resolve versioned DT_NEEDED
        # entries such as libmbedtls.so.21 when linking executables against
        # libel2go_rtp.so).  In Yocto the sysroot handles this automatically.
        mbedtls_lib_dir="$(dirname "${opt_mbedtls}")"
        opt_mbedtls_ldflags="-L${mbedtls_lib_dir} -Wl,-rpath-link,${mbedtls_lib_dir}"
    fi

    export PKG_CONFIG_PATH="${opt_cyaml}:${PKG_CONFIG_PATH}"

    # Build cmake command as an array.
    # The cross-compile toolchain file is neither needed nor available for
    # documentation-only configuration (no C/C++ compilation happens in that
    # mode), so it is intentionally omitted when doc_only is set.
    local cmake_args=(
        -S .
        -B "${opt_out}"
    )

    if [[ -z ${opt_doc_only} ]]; then
        cmake_args+=(${opt_toolchain})
    fi

    cmake_args+=(
        ${opt_buildtype}
        ${opt_verbose}
        ${opt_test}
        ${opt_testing}
        ${opt_ota}
        ${opt_format}
        ${opt_doc_only}
        -DCMAKE_INSTALL_PREFIX="${el2go_agent_ROOT}/usr"
        -DCMAKE_INSTALL_LIBDIR=lib
    )

    if [[ -n ${opt_mbedtls_ldflags} ]]; then
        cmake_args+=(
            "-DCMAKE_EXE_LINKER_FLAGS=${opt_mbedtls_ldflags}"
            "-DCMAKE_SHARED_LINKER_FLAGS=${opt_mbedtls_ldflags}"
        )
    fi

    if [[ -n ${opt_smw} ]]; then
        cmake_args+=(-DNXP_SMW_DIR="${opt_smw}")
    fi

    printf "Execute: cmake %s\n" "${cmake_args[*]}"
    cmake "${cmake_args[@]}"
}

function build()
{
    pr_operation_header "Build EL2GO Agent (${opt_build}) to ${opt_out}"

    if [[ -z ${opt_out} ]]; then
        usage_build
        exit 1
    fi

    cmd_make="make -C ${opt_out}"
    printf "Execute %s\n" "${cmd_make}"
    eval "${cmd_make}"

    # Build test executables when testing is requested. Test targets are
    # EXCLUDE_FROM_ALL so they are not part of the default make target.
    if [[ -n ${opt_testing} ]]; then
        cmd_make_tests="make -C ${opt_out} build_tests"
        printf "Execute %s\n" "${cmd_make_tests}"
        eval "${cmd_make_tests}"
    fi

    # Build the RTP documentation (Sphinx + Breathe + Doxygen) when requested.
    # Requires the project to have been configured with doc_format=<html|xml|all>
    # (and optionally doc_only) so that the "docs" CMake target exists.
    if [[ -n ${opt_build_docs} ]]; then
        cmd_make_docs="make -C ${opt_out} docs"
        printf "Execute %s\n" "${cmd_make_docs}"
        eval "${cmd_make_docs}"
    fi

    # Build the OTA documentation (Sphinx + Breathe + Doxygen) when requested.
    # Requires the project to have been configured with doc_format=<html|xml|all>
    # (and optionally doc_only) so that the "ota_docs" CMake target exists.
    if [[ -n ${opt_build_docs_ota} ]]; then
        cmd_make_docs_ota="make -C ${opt_out} ota_docs"
        printf "Execute %s\n" "${cmd_make_docs_ota}"
        eval "${cmd_make_docs_ota}"
    fi
}

function install()
{
    pr_operation_header "Install EL2GO Agent to ${opt_dest}"

    if [[ -z ${opt_out} ]]; then
        usage_install
        exit 1
    fi

    cmd_make="make -C ${opt_out}"

    cmd_script=""
    if [[ -n ${opt_dest} ]]; then
        cmd_script="DESTDIR=${opt_dest}"
    fi
    printf "Execute %s install %s\n" "${cmd_make}" "${cmd_script}"
    eval "${cmd_make} install ${cmd_script}"

    # Install test executables and CTestTestfile.cmake when testing is requested.
    # The install_tests target is EXCLUDE_FROM_ALL so it must be called explicitly.
    if [[ -n ${opt_testing} ]]; then
        cmd_make_tests="make -C ${opt_out} install_tests"
        if [[ -n ${opt_dest} ]]; then
            cmd_make_tests="${cmd_make_tests} DESTDIR=${opt_dest}"
        fi
        printf "Execute %s\n" "${cmd_make_tests}"
        eval "${cmd_make_tests}"
    fi
}

function package()
{
    local package_name="el2go_agent.tar.gz"
    pr_operation_header "Package EL2GO Agent in ${opt_out}/${package_name}"

    if [[ -z ${opt_out} ]]; then
        usage_package
        exit 1
    fi

    local tmp_inst_dir=$(mktemp -d)

    # First do the installation
    if [[ -z ${opt_dest} ]]; then
        opt_dest="${tmp_inst_dir}"
    else
        # Convert relative path to absolute path
        if [[ ! "${opt_dest}" = /* ]]; then
            opt_dest="$(pwd)/${opt_dest}"
        fi
    fi

    install

    # Create the archive from the installation directory
    eval "cd ${opt_dest} && tar -czf ${opt_out}/${package_name} ."

    rm -rf "${opt_dest}"
}

check_cmake_version

if [[ $# -eq 0 ]]; then
    usage
fi

opt_action="$1"
shift

for arg in "$@"
do
    case ${arg} in
        toolpath=*)
            opt_toolpath_raw="${arg#*=}"
            check_directory opt_toolpath_raw
            opt_toolpath="-DTOOLCHAIN_PATH=${opt_toolpath_raw}"
            ;;
        toolname=*)
            opt_toolname="${arg#*=}"
            opt_toolname="-DTOOLCHAIN_NAME=${opt_toolname}"
            ;;
        export=*)
            opt_export="${arg#*=}"
            check_directory opt_export
            ;;
        src=*)
            opt_src="${arg#*=}"
            check_directory opt_src
            ;;
        smw=*)
            opt_smw="${arg#*=}"
            check_directory opt_smw
            ;;
        mbedtls=*)
            opt_mbedtls="${arg#*=}"
            check_directory opt_mbedtls
            ;;
        subsystem=*)
            opt_subsystem="${arg#*=}"
            ;;
        out=*)
            opt_out="${arg#*=}"
            opt_builddir="-DBUILD_DIR=${opt_out}"
            ;;
        dest=*)
            opt_dest="${arg#*=}"
            ;;
        debug)
            opt_buildtype="-DCMAKE_BUILD_TYPE=Debug"
            ;;
        verbose=*)
            opt_verbose="${arg#*=}"
            opt_verbose="-DVERBOSE=${opt_verbose}"
            ;;
        hash=*)
            opt_hash="${arg#*=}"
            ;;
# configure options
        test)
            opt_test="-DCLOSE_COMMIT_DRY_RUN=ON"
            ;;
        testing)
            opt_testing="-DBUILD_TESTING=ON"
            ;;
        ota)
            opt_ota="-DBUILD_OTA=ON"
            ;;
        doc_format=*)
            opt_format="${arg#*=}"
            opt_format="-DDOC_FORMAT=${opt_format}"
            ;;
        doc_only)
            opt_doc_only="-DDOC_ONLY=ON"
            ;;
        docs)
            opt_build_docs=1
            ;;
        docs_ota)
            opt_build_docs_ota=1
            ;;
        *)

            pr_err "Unknown argument \"${arg}\""
            usage
            ;;
    esac

    shift
done

toolchain_script="${script_dir}/aarch64_toolchain.cmake"
if [[ ! -e "$toolchain_script" ]]; then
    pr_err "Toolchain script is missing: ${toolchain_script}"
    usage
fi
opt_toolscript="-DCMAKE_TOOLCHAIN_FILE=${toolchain_script}"
opt_toolchain="${opt_toolname} ${opt_toolpath} ${opt_toolscript}"

case ${opt_action} in
    toolchain)
        toolchain
        ;;
    configure)
        configure
        ;;
    mbedtls)
        mbedtls
        ;;
    smw)
        smw
        ;;
    build)
        build
        ;;
    install)
        install
        ;;
    package)
        package
        ;;
    *)
        usage
        ;;
esac
