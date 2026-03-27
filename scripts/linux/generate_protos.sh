#!/bin/bash

# Script to generate nanopb C files from protobuf definitions
# Usage: ./generate_protos.sh --nanopb <path> [--proto-dir <dir>] [--output-dir <dir>]

# Default values
PROTO_DIR="doc/protobuf"
OUTPUT_DIR="libs/protobuf/el2go"
NANOPB_DIR=""
PROTOC_CMD="protoc"
LICENSE_FILE=""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo "Usage: $0 --nanopb <path> [OPTIONS]"
    echo ""
    echo "Required arguments:"
    echo "  --nanopb <path>          Path to nanopb directory or nanopb_generator.py"
    echo ""
    echo "Optional arguments:"
    echo "  --proto-dir <dir>        Directory containing .proto files (default: doc/protobuf)"
    echo "  --output-dir <dir>       Directory for generated files (default: protobufs)"
    echo "  --protoc <path>          Path to protoc binary (default: system protoc)"
    echo "  --license-file <path>    Path to license header file to prepend to generated files"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --nanopb /path/to/nanopb"
    echo "  $0 --nanopb /path/to/nanopb/generator/nanopb_generator.py"
    echo "  $0 --nanopb /path/to/nanopb --protoc /path/to/protoc"
    echo "  $0 --nanopb /path/to/nanopb --license-file /path/to/license_header.txt"
    echo "  $0 --nanopb /path/to/nanopb --proto-dir /path/to/protos --output-dir /path/to/generated --license-file /path/to/license.txt"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --nanopb)
            NANOPB_DIR="$2"
            shift 2
            ;;
        --proto-dir)
            PROTO_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --protoc)
            PROTOC_CMD="$2"
            shift 2
            ;;
        --license-file)
            LICENSE_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Check if NANOPB_DIR is provided
if [ -z "${NANOPB_DIR}" ]; then
    echo -e "${RED}Error: --nanopb argument is required${NC}"
    echo ""
    usage
fi

# Determine nanopb generator path
if [[ "${NANOPB_DIR}" == *"nanopb_generator.py" ]]; then
    # Path to nanopb_generator.py was provided
    NANOPB_GENERATOR="${NANOPB_DIR}"
    NANOPB_BASE_DIR="$(dirname $(dirname ${NANOPB_DIR}))"
else
    # Path to nanopb directory was provided
    NANOPB_GENERATOR="${NANOPB_DIR}/generator/nanopb_generator.py"
    NANOPB_BASE_DIR="${NANOPB_DIR}"
fi

# Check if nanopb comes with its own protoc (only if using default protoc)
if [ "${PROTOC_CMD}" = "protoc" ]; then
    # Check for nanopb bundled protoc
    if [ -f "${NANOPB_BASE_DIR}/generator-bin/protoc" ]; then
        PROTOC_CMD="${NANOPB_BASE_DIR}/generator-bin/protoc"
        echo "Found nanopb bundled protoc: ${PROTOC_CMD}"
    elif [ -f "${NANOPB_BASE_DIR}/generator/protoc" ]; then
        PROTOC_CMD="${NANOPB_BASE_DIR}/generator/protoc"
        echo "Found nanopb bundled protoc: ${PROTOC_CMD}"
    fi
fi

echo "Starting protobuf generation..."
echo "Proto directory: ${PROTO_DIR}"
echo "Output directory: ${OUTPUT_DIR}"
echo "Nanopb generator: ${NANOPB_GENERATOR}"
echo "Protoc command: ${PROTOC_CMD}"

# Check if license file is provided and exists
if [ -n "${LICENSE_FILE}" ]; then
    if [ ! -f "${LICENSE_FILE}" ]; then
        echo -e "${RED}Error: License file not found at ${LICENSE_FILE}${NC}"
        exit 1
    fi
    echo "License file: ${LICENSE_FILE}"
fi

# Check if protoc exists
if ! command -v "${PROTOC_CMD}" &> /dev/null; then
    echo -e "${RED}Error: protoc not found at ${PROTOC_CMD}${NC}"
    exit 1
fi

# Check if nanopb generator exists
if [ ! -f "${NANOPB_GENERATOR}" ]; then
    echo -e "${RED}Error: nanopb generator not found at ${NANOPB_GENERATOR}${NC}"
    exit 1
fi

echo "protoc version: $(${PROTOC_CMD} --version)"
echo "nanopb version: $(python ${NANOPB_GENERATOR} --version 2>&1 | grep nanopb)"
echo ""

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

# Check if proto directory exists
if [ ! -d "${PROTO_DIR}" ]; then
    echo -e "${RED}Error: Proto directory not found at ${PROTO_DIR}${NC}"
    exit 1
fi

# Counter for statistics
SUCCESS_COUNT=0
FAIL_COUNT=0
FAILED_FILES=()

# Function to add license header from file
add_license_header() {
    local file="$1"
    local tmp_file="${file}.tmp"

    # Copy license file content to temp file
    cat "${LICENSE_FILE}" > "${tmp_file}"
    echo "" >> "${tmp_file}"

    # Append the generated file content
    cat "${file}" >> "${tmp_file}"

    # Replace original file
    mv "${tmp_file}" "${file}"
}

# Process each .proto file using two-step method
for proto_file in ${PROTO_DIR}/*.proto; do
    if [ -f "$proto_file" ]; then
        basename=$(basename "$proto_file" .proto)
        echo -e "${GREEN}Processing ${basename}.proto...${NC}"

        # Step 1: Generate descriptor set in output directory
        echo "  - Generating descriptor set..."
        ${PROTOC_CMD} -I="${PROTO_DIR}" \
               --descriptor_set_out="${OUTPUT_DIR}/${basename}.pb" \
               "$proto_file"

        if [ $? -ne 0 ]; then
            echo -e "${RED}  ✗ Error: Failed to generate descriptor for ${basename}${NC}"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            FAILED_FILES+=("${basename} (protoc failed)")
            continue
        fi

        # Step 2: Generate C files with nanopb
        echo "  - Generating C files..."

        # Check if options file exists
        OPTIONS_FLAG=""
        if [ -f "${PROTO_DIR}/${basename}.options" ]; then
            OPTIONS_FLAG="-f ${PROTO_DIR}/${basename}.options"
            echo "  - Using options file: ${basename}.options"
        fi

        python "${NANOPB_GENERATOR}" \
               -I "${PROTO_DIR}" \
               ${OPTIONS_FLAG} \
               "${OUTPUT_DIR}/${basename}.pb"

        if [ $? -eq 0 ]; then
            # Check if files were generated in output directory
            if [ -f "${OUTPUT_DIR}/${basename}.pb.h" ] && [ -f "${OUTPUT_DIR}/${basename}.pb.c" ]; then
                echo -e "${GREEN}  ✓ Successfully generated ${basename}.pb.h and ${basename}.pb.c${NC}"

                # Add license header if license file is provided
                if [ -n "${LICENSE_FILE}" ]; then
                    add_license_header "${OUTPUT_DIR}/${basename}.pb.h"
                    add_license_header "${OUTPUT_DIR}/${basename}.pb.c"
                    echo "  - Added license header"
                fi

                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            else
                echo -e "${RED}  ✗ Error: Generated files not found in ${OUTPUT_DIR}/${NC}"
                FAIL_COUNT=$((FAIL_COUNT + 1))
                FAILED_FILES+=("${basename} (files not found)")
            fi
        else
            echo -e "${RED}  ✗ Error: Failed to generate C files for ${basename}${NC}"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            FAILED_FILES+=("${basename} (nanopb failed)")
        fi

        # Clean up descriptor file
        rm -f "${OUTPUT_DIR}/${basename}.pb"
        echo ""
    fi
done

echo "========================================="
echo -e "${GREEN}Protobuf generation complete!${NC}"
echo "Success: ${SUCCESS_COUNT} files"
echo "Failed: ${FAIL_COUNT} files"

if [ ${FAIL_COUNT} -gt 0 ]; then
    echo -e "${YELLOW}Failed files:${NC}"
    for failed in "${FAILED_FILES[@]}"; do
        echo "  - ${failed}"
    done
fi

echo ""
echo "Generated files are in: ${OUTPUT_DIR}/"
if [ ${SUCCESS_COUNT} -gt 0 ]; then
    ls -lh "${OUTPUT_DIR}/" | grep "\.pb\.[ch]$"
fi