#!/bin/bash
# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0
# Regenerate nanopb stubs from ota_delivery.proto.
# Requires: nanopb 0.3.9.8 (python -m nanopb_generator or nanopb_generator.py)
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"
python -m nanopb_generator \
    --options-file=ota_delivery.options \
    ota_delivery.proto
echo "Stubs regenerated: ota_delivery.pb.h ota_delivery.pb.c"
