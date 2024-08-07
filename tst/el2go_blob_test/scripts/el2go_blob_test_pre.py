#!/usr/bin/env python3
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import json
import base64
import uttlv
import datetime
import pathlib

# TODO: Request Blobs from EL2GO ENV with LC,UUID,RKTH,NC12 & wait for generation

# TODO: Fetch JSON with all possible blob combinations from server when available

parser = argparse.ArgumentParser(description='Converts EL2GO RTP JSON for the el2go_blob_test framework')

parser.add_argument('rtp_json_path', type=pathlib.Path, help='Path to a JSON file containing RTP objects')
parser.add_argument('--object_type', type=str, choices=['psa', 'apdu'], default="psa", help='The type of the RTP objects')
parser.add_argument('--storage_mode', type=str, choices=['inline', 'filesystem'], default="inline", help='The way in which the blobs should be stored and referenced')

args = parser.parse_args()

if not args.rtp_json_path.is_file():
    parser.error("No file found at rtp_json_path")

if args.object_type != "psa" or args.storage_mode != "inline":
    parser.error("Currently only PSA RTP objects in inline mode are supported")

work_dir_path = pathlib.Path(os.path.abspath(os.path.dirname(__file__)))
inc_path = work_dir_path.parent.joinpath("inc")
el2go_blob_test_generic_header_path = inc_path.joinpath("el2go_blob_test_suite_generic.h")

test_vector_file = open(args.rtp_json_path)
test_vectors = json.load(test_vector_file)

data_arrays = []
test_entries = []
device = test_vectors[0]

def get_usage(usage):
    match usage:
        case 0x00000000: return "NONE"
        case 0x00000001: return "EXPORT"
        case 0x00000100: return "ENCRYPT"
        case 0x00000200: return "DECRYPT"
        case 0x00000300: return "CRYPT"
        case 0x00000400: return "SIGMSG"
        case 0x00000800: return "VERMSG"
        case 0x00000C00: return "SIGVERMSG"
        case 0x00001000: return "SIGHASH"
        case 0x00002000: return "VERHASH"
        case 0x00003000: return "SIGVERHASH"
        case 0x00004000: return "DERIVE"
        case _: return "UNKNOWN"

def get_hash(hash):
    match hash:
        case 0x02000005: return "SHA1"
        case 0x02000008: return "SHA224"
        case 0x02000009: return "SHA256"
        case 0x0200000a: return "SHA384"
        case 0x0200000b: return "SHA512"
        case 0x0200000c: return "SHA512224"
        case 0x0200000d: return "SHA512256"
        case 0x020000ff: return "ANYHASH"
        case _: return "UNKNOWN"

def get_algorithm(algorithm):
    match algorithm:
        case 0x00000000: return "NONE"
        case 0x03c00200: return "CMAC"
        case 0x04c01000: return "CTR"
        case 0x04404400: return "ECB"
        case 0x04404000: return "CBC"
        case 0x05500200: return "GCM"
        case 0x06000200: return "RAW"
        case 0x06000600: return "ECDSAANY"
        case 0x07000200: return "PKCS1V15"
        case 0x09020000: return "ECDH"
        case _: 
            hash_string = get_hash(0x02000000 | (algorithm & 0x000000ff))
            match algorithm & ~0x000000ff:
                case 0x03800000: return "HMAC" + hash_string
                case 0x06000200: return "PKCS1V15" + hash_string
                case 0x06000300: return "PSS" + hash_string
                case 0x06000600: return "ECDSA" + hash_string
                case 0x07000300: return "OAEP" + hash_string
                case 0x08000100: return "HKDF" + hash_string
                case _: return "UNKNOWN"

def data_to_c_array(name, data):
    return f"static const uint8_t {name}[] = {{{', '.join([hex(byte) for byte in data])}}};"

def get_description(internal, obj_class, obj_type, bits, usage, algorithm):
    obj_type = obj_type.replace("_", "")
    return f"{'Internal' if internal else 'External'} {obj_class} {obj_type if len(obj_type) else str(int(bits / 8)) + 'B'} {get_usage(usage)} {get_algorithm(algorithm)}"

def get_test_entry(index, name, description):
    return f"    {{NULL, \"EL2GO_BLOB_TEST_GENERIC_{index:04d}\", \"{description}\", {name}, sizeof({name})}},"

for index, provisioning in enumerate(device['rtpProvisionings'], start=1):
    base64_string = provisioning['apdus']['createApdu']['apdu']
    blob = base64.b64decode(base64_string)

    obj_class = provisioning['secureObject']['type']
    obj_type = ""
    if 'algorithm' in provisioning['secureObject']:
        obj_type = provisioning['secureObject']['algorithm']
    name = f"{obj_class}_{obj_type + '_' if len(obj_type) else ''}{provisioning['secureObject']['id']}_{provisioning['provisioningId']}"

    blob_tlv = uttlv.TLV()
    blob_tlv.parse_array(blob)

    internal = int.from_bytes(blob_tlv[0x46], "big") == 0xE0000101
    bits = int.from_bytes(blob_tlv[0x45], "big")
    usage = int.from_bytes(blob_tlv[0x43], "big")
    algorithm = int.from_bytes(blob_tlv[0x42], "big")

    data_arrays.append(data_to_c_array(name, blob))
    description = get_description(internal, obj_class, obj_type, bits, usage, algorithm)
    test_entries.append(get_test_entry(index, name, description))

    
el2go_blob_test_generic_header=f"""/*
 * Copyright {datetime.date.today().year} NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_BLOB_TEST_SUITE_GENERIC_H__
#define __EL2GO_BLOB_TEST_SUITE_GENERIC_H__

#ifdef __cplusplus
extern \"C\" {{
#endif

#include "el2go_blob_test.h"

// Generated for UUID {device['deviceId']}

{chr(10).join(data_arrays)}

static struct test_t blob_generic_tests[] = {{
{chr(10).join(test_entries)}
}};

#ifdef __cplusplus
}}
#endif

#endif /* __EL2GO_BLOB_TEST_SUITE_GENERIC_H__ */
"""

el2go_blob_test_generic_header_path.write_text(el2go_blob_test_generic_header)

print(f"Successfully processed {len(test_entries)} blobs for device UUID {device['deviceId']}")
