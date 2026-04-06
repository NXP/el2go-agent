#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2026 NXP
#

set -e

function usage()
{
    cat << EOF
    ***************************************************************
    * Usage of EL2GO Agent Coverity build script                 *
    ***************************************************************

    Script is cleaning first the EL2GO Agent targets
    and then rebuild all targets configured in given directory.

    It is assumed that projects have been configured before calling
    this script and dependencies built as well.

    $(basename "$0") <dir>

      <dir> : Mandatory build directory

EOF
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
fi

# Clean build targets first
eval "cd $1 && make clean && cd .."

# Rebuild targets
eval "./scripts/linux/build.sh build out=$1"
