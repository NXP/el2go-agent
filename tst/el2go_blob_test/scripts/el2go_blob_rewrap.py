#!/usr/bin/env python3
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0

import pathlib
import subprocess
import argparse
import json
import base64
import os
import shutil
import sys
import time
import datetime

workspace = pathlib.Path(os.path.abspath(os.path.dirname(__file__))).joinpath("workspace")

unprocessed_blobs_path = workspace.joinpath("unprocessed_blobs.json")
processed_blobs_path = workspace.joinpath("processed_blobs.json")
user_config_path = workspace.joinpath("user_config.bin")
raw_blobs_path = workspace.joinpath("raw_blobs.bin")
wrapped_blobs_path = workspace.joinpath("wrapped_blobs.bin")
required_rw61x_product_based_path = workspace.joinpath("required_data.json")


def wrap_blobs(raw_blobs, blhost_args, args, blob_flash_address, blobs_total_size, user_config=None ) -> bytes:
    if args.provisioning_flow == 'proxy_mode':
        if user_config:
            with open(user_config_path, "wb") as user_config_file:
                user_config_file.write(user_config)

            with open(raw_blobs_path, "wb") as raw_blobs_file:
                raw_blobs_file.write(raw_blobs)

            subprocess.run(["nxpdebugmbox", "ispmode", "-m", "1"], check=True)

            subprocess.run(blhost_args + ["write-memory", "0x20000000", user_config_path], check=True)
            subprocess.run(blhost_args + ["write-memory", "0x20000100", raw_blobs_path], check=True)
            subprocess.run(blhost_args + ["receive-sb-file", args.provisioning_fw_path], check=True)

            time.sleep(3)

            subprocess.run(["nxpdebugmbox", "cmd", "-f", args.soc, "ispmode", "-m", "1"], check=True)
    elif args.provisioning_flow == 'product_based':
        if str(args.soc).lower() == 'rw612' or str(args.soc).lower() == 'rw610':

            with open(raw_blobs_path, "wb") as raw_blobs_file:
                raw_blobs_file.write(raw_blobs)

            subprocess.run(["nxpdebugmbox", "cmd", "-f", args.soc, "ispmode", "-m", "1"], check=True)
            subprocess.run(blhost_args + ["fill-memory", "0x20001000", "0x4", "0xC0000008"], check=True)
            subprocess.run(blhost_args + ["configure-memory", "0x9", "0x20001000"], check=True)
            subprocess.run(blhost_args + ["flash-erase-region", "0x084B0000", "0x4800"], check=True)

            subprocess.run(blhost_args + ["write-memory", "0x084B0000", raw_blobs_path], check=True)

            subprocess.run(blhost_args + ["fill-memory", "0x20001000", "0x4", "0xC0000004"], check=True)
            subprocess.run(blhost_args + ["configure-memory", "0x9", "0x20001000"], check=True)
            subprocess.run(blhost_args + ["flash-erase-region", "0x08000000", "0x20000"], check=True)
            subprocess.run(blhost_args + ["write-memory", "0x20001000", "{{ 000000b000040008 }}"], check=True)
            subprocess.run(blhost_args + ["configure-memory", "0x9", "0x20001000"], check=True)

            subprocess.run(blhost_args + ["write-memory", "0x08001000", args.provisioning_fw_path], check=True)

            subprocess.run(blhost_args + ["reset"], check=True)

            subprocess.run(["el2go-host", "utils","get-fw-version", "-p", f"{args.com_port},115200"], check=True)
            subprocess.run(["el2go-host", "prod", "run-provisioning", "-p", f"{args.com_port},115200", "-c", args.spsdk_config_file_path, "-f",  args.soc, "--dry-run"], check=True)

            subprocess.run(["nxpdebugmbox", "cmd", "-f", args.soc, "ispmode", "-m", "1"], check=True)
            subprocess.run(blhost_args + ["fill-memory", "0x20001000", "0x4", "0xC0000008"], check=True)
            subprocess.run(blhost_args + ["configure-memory", "0x9", "0x20001000"], check=True)

    subprocess.run(blhost_args + ["read-memory", blob_flash_address, hex(blobs_total_size), wrapped_blobs_path], check=True)

    with open(wrapped_blobs_path, "rb") as wrapped_blobs_file:
        wrapped_blobs = wrapped_blobs_file.read()

    if args.provisioning_flow == 'proxy_mode' and user_config:
        os.remove(user_config_path)
    os.remove(raw_blobs_path)
    os.remove(wrapped_blobs_path)

    return wrapped_blobs


def proxy_rewrapping(args, blob_flash_address, blhost_args):
    if str(args.soc).lower() == "mcxn947":
        blob_flash_little_endian_add = b'\x00\x00\x1C\x00'
    elif str(args.soc).lower() == "mcxn236":
        blob_flash_little_endian_add = b'\x00\x40\x0C\x00'

    user_config = b'\x45\x4C\x55\x43\x00\x01\x00\x20' + blob_flash_little_endian_add + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    if unprocessed_blobs_path.is_file():
        filetime = datetime.datetime.fromtimestamp(os.path.getmtime(unprocessed_blobs_path))
        sys.stdout.write(f"Continue with remaining unprocessed blobs from last run ({filetime.isoformat()})? [Y/n] ")
        if input().lower() not in ["y", ""]:
            shutil.rmtree(workspace)

    if not unprocessed_blobs_path.is_file():
        if workspace.is_dir():
            shutil.rmtree(workspace)
        workspace.mkdir()

        with open(args.rtp_json_path) as rtp_json_file:
            rtp_json = json.load(rtp_json_file)

        device = rtp_json[0]

        previous_count = len(device['rtpProvisionings'])
        device['rtpProvisionings'] = list(filter(lambda prov: prov['state'] == "GENERATION_COMPLETED", device['rtpProvisionings']))
        diff_count = previous_count - len(device['rtpProvisionings'])
        if diff_count:
            print(f"Ignoring {diff_count} blobs that failed to generate")

        previous_count = len(device['rtpProvisionings'])
        device['rtpProvisionings'] = list(filter(lambda prov: prov['secureObject']['type'] != "OEM_FW_AUTH_KEY_HASH" and prov['secureObject']['type'] != "OEM_FW_DECRYPT_KEY", device['rtpProvisionings']))
        diff_count = previous_count - len(device['rtpProvisionings'])
        if diff_count:
            print(f"Ignoring OEM_FW_AUTH_KEY_HASH and OEM_FW_DECRYPT_KEY (device needs to be provisioned already)")

        with open(unprocessed_blobs_path, "w") as unprocessed_blobs_file:
            json.dump([device], unprocessed_blobs_file, indent=4)

    while True:
        with open(unprocessed_blobs_path) as unprocessed_blobs_file:
            unprocessed_blobs = json.load(unprocessed_blobs_file)

        device = unprocessed_blobs[0]

        blobs = []
        blobs_total_size = 0
        for provisioning in device['rtpProvisionings']:
            base64_string = provisioning['apdus']['createApdu']['apdu']
            blob = base64.b64decode(base64_string)

            if len(blobs) + 1 <= 16 and blobs_total_size + len(blob) <= 16128:
                blobs.append(blob)
                blobs_total_size += len(blob)
            else:
                break

        print(f"Rewrapping batch of {len(blobs)} blobs totalling {blobs_total_size} bytes")
        wrapped_blobs = wrap_blobs(b"".join(blobs), blhost_args, args, blob_flash_address,
                                   blobs_total_size, user_config)
        current_byte = 0
        for index, provisioning in enumerate(device['rtpProvisionings'][:len(blobs)]):
            blob_len = len(blobs[index])
            wrapped_blob = wrapped_blobs[current_byte:current_byte + blob_len]
            provisioning['apdus']['createApdu']['apdu'] = base64.b64encode(wrapped_blob).decode('ascii')
            current_byte += len(blobs[index])

        processed = device['rtpProvisionings'][:len(blobs)]
        unprocessed = device['rtpProvisionings'][len(blobs):]

        if processed_blobs_path.is_file():
            with open(processed_blobs_path) as processed_blobs_file:
                processed_blobs = json.load(processed_blobs_file)

            device = processed_blobs[0]
            device['rtpProvisionings'] += processed
        else:
            device['rtpProvisionings'] = processed

        with open(processed_blobs_path, "w") as processed_blobs_file:
            json.dump([device], processed_blobs_file, indent=4)

        if len(unprocessed):
            device['rtpProvisionings'] = unprocessed

            with open(unprocessed_blobs_path, "w") as unprocessed_blobs_file:
                json.dump([device], unprocessed_blobs_file, indent=4)
        else:
            os.remove(unprocessed_blobs_path)
            os.replace(processed_blobs_path, args.rewrapped_rtp_json_out_path)
            workspace.rmdir()
            print(f"Successfully rewrapped {len(device['rtpProvisionings'])} blobs for device UUID {device['deviceId']}")
            break


def product_based_rewrapping(args, blob_flash_address, blhost_args):
    required_data = []

    if unprocessed_blobs_path.is_file():
        filetime = datetime.datetime.fromtimestamp(os.path.getmtime(unprocessed_blobs_path))
        sys.stdout.write(f"Continue with remaining unprocessed blobs from last run ({filetime.isoformat()})? [Y/n] ")
        if input().lower() not in ["y", ""]:
            shutil.rmtree(workspace)

        if args.soc == 'rw612' or args.soc == 'rw610':
            with open(required_rw61x_product_based_path, 'r') as required_rw61x_product_based_file:
                required_data = json.load(required_rw61x_product_based_file)

    if not unprocessed_blobs_path.is_file():
        if workspace.is_dir():
            shutil.rmtree(workspace)
        workspace.mkdir()

        with open(args.rtp_json_path) as rtp_json_file:
            rtp_json = json.load(rtp_json_file)

        print(f"Provisioning flow is {args.provisioning_flow}")

        diff_count = 0
        device = rtp_json
        previous_count = len(device['staticProvisionings'])
        for key, value in device['dynamicProvisionings'].items():
            dynamic_uid = key
            break
        previous_count += len(device['dynamicProvisionings'][dynamic_uid])

        device['staticProvisionings'] = list(filter(lambda prov: prov['state'] == "GENERATION_COMPLETED", device['staticProvisionings']))
        device['dynamicProvisionings'][dynamic_uid] = list(filter(lambda prov: prov['state'] == "GENERATION_COMPLETED", device['dynamicProvisionings'][dynamic_uid]))
        diff_count = previous_count - (len(device['staticProvisionings']) + len(device['dynamicProvisionings'][dynamic_uid]))
        if diff_count:
            print(f"Ignoring {diff_count} blobs that failed to generate")

        if str(args.soc).lower() == "rw612" or str(args.soc).lower() == "rw610":
            target_type_ids = {'2147451265', '2147451258', '2147451259', '2147451260'}
            for entry in device['staticProvisionings']:
                if entry.get("secureObject", {}).get("objectId") in target_type_ids:
                    required_data.append(entry['data'])
                    with open(required_rw61x_product_based_path, 'w') as required_rw61x_product_based_file:
                        json.dump(required_data, required_rw61x_product_based_file)

            device['staticProvisionings'] = list(filter(lambda prov: prov['secureObject']['type'] != "OEM_FW_AUTH_KEY_HASH" and prov['secureObject']['type'] != "OEM_FW_DECRYPT_KEY"
                                                                     and prov['secureObject']['objectId'] != "2147451260" and prov['secureObject']['type'] != "DEVICE_GROUP_PROVISIONING_KEY", device['staticProvisionings']))
        elif str(args.soc).lower() == "mcxn947" or str(args.soc).lower() == "mcxn236":
            device['staticProvisionings'] = list(filter(lambda prov: prov['secureObject']['type'] != "OEM_FW_AUTH_KEY_HASH" and prov['secureObject']['type'] != "OEM_FW_DECRYPT_KEY", device['staticProvisionings']))
        diff_count = previous_count - (len(device['staticProvisionings']) + len(device['dynamicProvisionings'][dynamic_uid]))

        with open(unprocessed_blobs_path, "w") as unprocessed_blobs_file:
            bare_provisionings = device['staticProvisionings'] + device['dynamicProvisionings'][dynamic_uid]
            json.dump(bare_provisionings, unprocessed_blobs_file, indent=4)

    while True:
        with open(unprocessed_blobs_path) as unprocessed_blobs_file:
            unprocessed_blobs = json.load(unprocessed_blobs_file)

        blobs = []
        blobs_total_size = 0

        device = unprocessed_blobs
        for provisioning in device:
            base64_string = provisioning['data']
            blob = base64.b64decode(base64_string)
            if len(blobs) + 1 <= 16 and blobs_total_size + len(blob) <= 16128:
                blobs.append(blob)
                blobs_total_size += len(blob)
            else:
                break
        for req_blob in required_data:
            blob = base64.b64decode(req_blob)
            blobs.append(blob)
            blobs_total_size += len(blob)

        print(f"Rewrapping batch of {len(blobs)} blobs totalling {blobs_total_size} bytes")
        wrapped_blobs = wrap_blobs(b"".join(blobs), blhost_args, args, blob_flash_address,
                                   blobs_total_size)

        current_byte = 0
        wrapped_blobs = wrapped_blobs[:-len(required_data)]
        blobs = blobs[:-len(required_data)]
        for index, provisioning in enumerate(device[:len(blobs)]):
            blob_len = len(blobs[index])
            wrapped_blob = wrapped_blobs[current_byte:current_byte + blob_len]
            provisioning['data'] = base64.b64encode(wrapped_blob).decode('ascii')
            current_byte += len(blobs[index])

        processed = device[:len(blobs)]
        unprocessed = device[len(blobs):]

        if processed_blobs_path.is_file():
            with open(processed_blobs_path) as processed_blobs_file:
                processed_blobs = json.load(processed_blobs_file)
                device = processed_blobs
                device += processed
        else:
            device = processed

        with open(processed_blobs_path, "w") as processed_blobs_file:
            json.dump(device, processed_blobs_file, indent=4)

        if len(unprocessed):
            device = unprocessed

            with open(unprocessed_blobs_path, "w") as unprocessed_blobs_file:
                json.dump(device, unprocessed_blobs_file, indent=4)
        else:
            os.remove(unprocessed_blobs_path)
            os.replace(processed_blobs_path, args.rewrapped_rtp_json_out_path)
            print(f"Successfully rewrapped {len(device)} blobs for {args.soc} device with product-based flow")
            os.remove(required_rw61x_product_based_path)
            workspace.rmdir()
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Rewraps EL2GO Secure Objects for N10/N11 based devices and RW61x')

    parser.add_argument('rtp_json_path', type=pathlib.Path, help='Path to a JSON file containing raw EL2GO RTP objects')
    parser.add_argument('provisioning_fw_path', type=pathlib.Path, help='Path to the provisioning firmware SB3 container')
    parser.add_argument('com_port', type=str, help='The COM port to use for contacting the device in ISP mode')
    parser.add_argument('rewrapped_rtp_json_out_path', type=pathlib.Path, help='Output path for the JSON file containing the rewrapped EL2GO objects')
    parser.add_argument('soc', type=str, default="mcxn947", help='Soc name, for which re_wrapping is being done e.g: mcxn236, mcxn947, rw610, rw612')
    parser.add_argument('provisioning_flow', type=str, choices=['proxy', 'product_based'], default="proxy", help='The provisioning flow used to for Secure Objects creation')
    parser.add_argument('spsdk_config_file_path', type=pathlib.Path, help='Path to config file required from SPSDK tool in case of Product-bsed Provisioning flow')

    args = parser.parse_args()

    if not args.rtp_json_path.is_file():
        parser.error("No file found at rtp_json_path")

    if not args.provisioning_fw_path.is_file():
        parser.error("No file found at provisioning_fw_path")

    if args.provisioning_flow == 'product_based' and not args.spsdk_config_file_path.is_file():
        parser.error('No SPSDK file found')

    if str(args.soc).lower() == "mcxn947":
        blob_flash_address = "0x001C0000"
        print(f"SOC is MCXN947")
    elif str(args.soc).lower() == "mcxn236":
        blob_flash_address = "0x000C4000"
        print(f"SOC is MCXN236")
    elif str(args.soc).lower() == "rw612" or str(args.soc).lower() == "rw610":
        blob_flash_address = "0x084B0000"
        print(f"SOC is RW61x")
    else:
        print(f"No SOC selected, default value will be used")

    blhost_args = ["blhost", "-p", f"{args.com_port},115200", "--"]

    if args.provisioning_flow == 'proxy':
        proxy_rewrapping(args, blob_flash_address, blhost_args)
    elif args.provisioning_flow == 'product_based':
        product_based_rewrapping(args, blob_flash_address, blhost_args)
