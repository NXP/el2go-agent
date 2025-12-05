#!/usr/bin/env python3
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0

import re
import os
import sys
import time
import json
import yaml
import base64
import shutil
import argparse
from enum import Enum
import subprocess as sp
from pathlib import Path
from typing import Optional
from datetime import datetime
from dataclasses import dataclass, field

workspace = Path(os.path.abspath(os.path.dirname(__file__))).joinpath("workspace")

unprocessed_blobs_path = workspace.joinpath("unprocessed_blobs.json")
processed_blobs_path = workspace.joinpath("processed_blobs.json")
user_config_path = workspace.joinpath("user_config.bin")
raw_blobs_path = workspace.joinpath("raw_blobs.bin")
wrapped_blobs_path = workspace.joinpath("wrapped_blobs.bin")
required_product_based_path = workspace.joinpath("required_data.json")
el2go_host_config_path = workspace.joinpath("el2go_config.yml")

debug_logging_enabled = False

MAX_BLOBS_REWRAP_RUN = 16
MAX_BLOB_SIZE_REWRAP_RUN = 16128

class SupportedDevices(Enum):
    rw610 = 0
    rw612 = 1
    mcxn947 = 2
    mcxn236 = 3
    
    def __str__(self) -> str:
        return self.name

class SupportedProvisionFlows(Enum):
    proxy = 0
    product_based = 1

    def __str__(self) -> str:
        return self.name

class ConsoleColor(Enum):
    INFO = "\033[94m"
    WARN = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"

    def __str__(self) -> str:
        return self.name

@dataclass
class RewrapConfig:
    family: SupportedDevices
    prov_flow: SupportedProvisionFlows
    com_port: str
    rtp_json_path: Path
    prov_fw_path: Path
    output_path: Path

    def is_valid_data(self) -> bool:
        result = True

        if(type(self.family) is not SupportedDevices):
            try:
                self.family = SupportedDevices[str(self.family)]
            except KeyError:
                print_colored(f"Family type '{self.family}' is not valid!", ConsoleColor.WARN)
                result = False

        if(type(self.prov_flow) is not SupportedProvisionFlows):
            try:
                self.prov_flow = SupportedProvisionFlows[str(self.prov_flow)]
            except KeyError:
                print_colored(f"Provisioning flow '{self.prov_flow}' is not valid!", ConsoleColor.WARN)
                result = False

        if(not re.match(r"^COM\d+$", self.com_port)):
            print_colored(f"COM port '{self.com_port}' is not in the correct format!", ConsoleColor.WARN)
            result = False

        self.rtp_json_path = Path(self.rtp_json_path)
        if(not self.rtp_json_path.is_file()):
            print_colored(f"No file found at rtp_json_path: '{self.rtp_json_path.as_posix()}'", ConsoleColor.WARN)
            result = False

        self.prov_fw_path = Path(self.prov_fw_path)
        if(not self.prov_fw_path.is_file()):
            print_colored(f"No file found at prov_fw_path: '{self.prov_fw_path.as_posix()}'", ConsoleColor.WARN)
            result = False

        self.output_path = Path(self.output_path)

        return result

    @classmethod
    def getTemplate(cls) -> str:
        template: list[str] = []
        template.append(f"# Family ({', '.join([device.name for device in SupportedDevices])})")
        template.append("family: <family>")
        template.append("")
        template.append(f"# Provisioning Flow ({', '.join([flow.name for flow in SupportedProvisionFlows])})")
        template.append("prov_flow: <flow>")
        template.append("")
        template.append("# COM port (COM1, COM2, COMX)")
        template.append("com_port: <COM port>")
        template.append("")
        template.append("# Path to a JSON file containing raw EL2GO RTP objects")
        template.append("rtp_json_path: <path to json>")
        template.append("")
        template.append("# Path to the provisioning firmware SB3 container")
        template.append("prov_fw_path: <path to binary>")
        template.append("")
        template.append("# Output path for the JSON file containing the rewrapped EL2GO objects")
        template.append("output_path: <path to json>")
        template.append("")
        return "\n".join(template)

@dataclass
class DeviceSettings:
    soc: SupportedDevices
    blob_flash_address: str
    nc12: str
    baudrate: int = 115200
    json_path: Optional[Path] = None
    prov_fw_path: Optional[Path] = None
    rewrapped_json_path: Optional[Path] = None
    com: Optional[str] = None
    prov_flow: Optional[SupportedProvisionFlows] = None
    blob_flash_le_add: Optional[bytes] = None

    def __str__(self) -> str:
        result = ""

        result += f"DeviceFamily: {self.soc}\n"
        result += f"12nc: {self.nc12}\n"
        result += f"Flash address: {self.blob_flash_address}\n"
        result += f"COM-Port/Baudrate: {self.com}, {self.baudrate}\n"

        if(self.json_path):
            result += f"Blob json: {self.json_path.as_posix()}\n"
        if(self.prov_fw_path):
            result += f"Provisioning firmware: {self.prov_fw_path.as_posix()}\n"

        result += f"Provisioning flow: {self.prov_flow}"

        return result

PREDEFINED_SETTINGS: dict[SupportedDevices, DeviceSettings] = {
    SupportedDevices.rw610: DeviceSettings(SupportedDevices.rw610, "0x084B0000", "999340000610"),
    SupportedDevices.rw612: DeviceSettings(SupportedDevices.rw612, "0x084B0000", "999340000612"),
    SupportedDevices.mcxn947: DeviceSettings(SupportedDevices.mcxn947, "0x001C0000", "999340000274", blob_flash_le_add=b'\x00\x00\x1C\x00'),
    SupportedDevices.mcxn236: DeviceSettings(SupportedDevices.mcxn236, "0x000C4000", "999340002301", blob_flash_le_add=b'\x00\x40\x0C\x00'),
}

def enable_debug_logging(state: bool) -> None:
    global debug_logging_enabled
    debug_logging_enabled = state

def get_spsdk_version() -> list:
    stdout, _ = run_command("spsdk --version", show_output = False)

    version_code: list = (re.findall(r"\d\.\d\.\d.*", stdout[0])[0]).split('.')

    for idx, code in enumerate(version_code):
        try:
            version_code[idx] = int(code)
        except ValueError:
            pass

    return version_code

def is_spsdk_version_higher(compare_version: str) -> bool:
    max_version_numbers = 3

    spsdk_version = get_spsdk_version()[:max_version_numbers]

    comp_version: list = compare_version.split('.')[:max_version_numbers]
    for idx, code in enumerate(comp_version):
        try:
            comp_version[idx] = int(code)
        except ValueError:
            pass

    for idx, n in enumerate(spsdk_version):
        if(n > comp_version[idx]):
            return True

    return False

def print_colored(message: str, color: ConsoleColor = ConsoleColor.INFO, sep: str | None = " ", end: str | None = "\n") -> None:
    print(color.value + message + ConsoleColor.ENDC.value, sep=sep, end=end)

def run_command(command: str, check: bool = True, show_output: bool = False) -> tuple[list[str], list[str]]:
    result = sp.run(command, capture_output=True)

    stdout = result.stdout.decode("utf-8").splitlines()
    stderr = result.stderr.decode("utf-8").splitlines()

    if(show_output or debug_logging_enabled):
        divider = "=" * 45
        spacing = "\n" * 1

        print_colored(spacing, ConsoleColor.INFO)
        print_colored(divider + "========" + divider, ConsoleColor.INFO)
        print_colored(f"Command: '{command}'", ConsoleColor.INFO)

        if len(stdout) > 0:
            print_colored(divider + " stdout " + divider, ConsoleColor.INFO)
            for line in stdout:
                print_colored(line, ConsoleColor.INFO)

        if len(stderr) > 0:
            print_colored(divider + " stderr " + divider, ConsoleColor.INFO)
            for line in stderr:
                print_colored(line, ConsoleColor.WARN)

        print_colored(divider + "========" + divider, ConsoleColor.INFO)

    if(check and (result.returncode != 0)):
        print_colored(f"Command '{command}' failed! returncode: {result.returncode}", ConsoleColor.FAIL)
        sys.exit(result.returncode)
    
    return (stdout, stderr)

def generate_el2go_config(settings: DeviceSettings):
    assert(settings.prov_fw_path != None)

    el2go_config = ""
    el2go_config += f"family: {settings.soc}\n"
    el2go_config += f"revision: latest\n"
    el2go_config += f"url: https://api.edgelock2go.com\n"
    el2go_config += f"api_key: none\n"
    el2go_config += f"device_group_id: 0\n"
    el2go_config += f"nc12: {settings.nc12}\n"
    el2go_config += f"domains:\n"
    el2go_config += f"  - RTP\n"
    el2go_config += f"  - MATTER\n"
    el2go_config += f"delay: 5\n"
    el2go_config += f"timeout: 60\n"
    el2go_config += f"download_timeout: 300\n"
    el2go_config += f"secure_objects_address: {settings.blob_flash_address}\n"
    el2go_config += f"prov_fw_path: {settings.prov_fw_path.as_posix()}"

    el2go_host_config_path.write_text(el2go_config)

def wrap_blobs(settings: DeviceSettings, raw_blobs: bytes, blobs_total_size: int, spsdk_higher_than_340: bool) -> bytes:
    assert(settings.prov_fw_path != None)
    
    com: str = f"-p {settings.com},{settings.baudrate}"

    with open(raw_blobs_path, "wb") as raw_blobs_file:
        raw_blobs_file.write(raw_blobs)
    
    run_command(f"nxpdebugmbox cmd -f {settings.soc} ispmode -m 1")

    if((settings.soc == SupportedDevices.rw610) or (settings.soc == SupportedDevices.rw612)):
        assert(settings.prov_flow == SupportedProvisionFlows.product_based)

        run_command(f"blhost {com} -- fill-memory 0x20001000 0x4 0xC0000008")
        run_command(f"blhost {com} -- configure-memory 0x9 0x20001000")
        run_command(f"blhost {com} -- flash-erase-region {settings.blob_flash_address} 0x4800")

        run_command(f"blhost {com} -- write-memory {settings.blob_flash_address} {raw_blobs_path.as_posix()}")

        run_command(f"blhost {com} -- fill-memory 0x20001000 0x4 0xC0000008")
        run_command(f"blhost {com} -- configure-memory 0x9 0x20001000")
        run_command(f"blhost {com} -- flash-erase-region 0x08000000 0x20000")
        run_command(f"blhost {com} -- write-memory 0x20001000 {{{{000000b000040008}}}}")
        run_command(f"blhost {com} -- configure-memory 0x9 0x20001000")

        run_command(f"blhost {com} -- write-memory 0x08001000 {settings.prov_fw_path.as_posix()}")

        run_command(f"blhost {com} -- reset")

        run_command(f"el2go-host utils get-fw-version {com}")
        run_command(f"el2go-host prod run-provisioning {com} -c {el2go_host_config_path.as_posix()} -f {settings.soc} --dry-run")

        run_command(f"nxpdebugmbox cmd -f {settings.soc} ispmode -m 1")
        run_command(f"blhost {com} -- fill-memory 0x20001000 0x4 0xC0000008")
        run_command(f"blhost {com} -- configure-memory 0x9 0x20001000")
    elif((settings.soc == SupportedDevices.mcxn947) or (settings.soc == SupportedDevices.mcxn236)):
        if(spsdk_higher_than_340):
            prov_flow = "prod" if (settings.prov_flow == SupportedProvisionFlows.product_based) else "dev"

            run_command(f"blhost {com} -- write-memory 0x20000100 {raw_blobs_path.as_posix()}")
            run_command(f"blhost {com} -- receive-sb-file {settings.prov_fw_path.as_posix()}")
            time.sleep(1)
            run_command(f"el2go-host utils get-fw-version {com}")
            run_command(f"el2go-host {prov_flow} run-provisioning {com} -c {el2go_host_config_path.as_posix()} -f {settings.soc}")
            run_command(f"nxpdebugmbox cmd -f {settings.soc} ispmode -m 1")
        else:
            assert(settings.blob_flash_le_add is not None)
            user_config: bytes = (
                b'\x45\x4C\x55\x43\x00\x01\x00\x20' + 
                settings.blob_flash_le_add + 
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            )

            with open(user_config_path, "wb") as user_config_file:
                user_config_file.write(user_config)

            run_command(f"blhost {com} -- write-memory 0x20000000 {user_config_path.as_posix()}")
            run_command(f"blhost {com} -- write-memory 0x20000100 {raw_blobs_path.as_posix()}")
            run_command(f"blhost {com} -- receive-sb-file {settings.prov_fw_path.as_posix()}")
            time.sleep(1)
            run_command(f"nxpdebugmbox cmd -f {settings.soc} ispmode -m 1")
    else:
        print_colored(f"The device '{settings.soc}' is not implemented!", ConsoleColor.FAIL)
        sys.exit(-1)

    run_command(f"blhost {com} -- read-memory {settings.blob_flash_address} {hex(blobs_total_size)} {wrapped_blobs_path.as_posix()}")
    with open(wrapped_blobs_path, "rb") as wrapped_blobs_file:
        wrapped_blobs = wrapped_blobs_file.read()
        
    if(user_config_path.exists()):
        os.remove(user_config_path)
    if(raw_blobs_path.exists()):
        os.remove(raw_blobs_path)
    if(wrapped_blobs_path.exists()):
        os.remove(wrapped_blobs_path)

    return wrapped_blobs

def transform_json_input(settings: DeviceSettings, rtp_json) -> dict:
    if(settings.prov_flow == SupportedProvisionFlows.proxy):
        device = rtp_json[0]

    elif(settings.prov_flow == SupportedProvisionFlows.product_based):
        dictionary: dict = rtp_json

        device: dict = {}
        device['rtpProvisionings'] = rtp_json['staticProvisionings']

        dynamic_provs = dictionary.get('dynamicProvisionings', None)
        if(dynamic_provs):
            for key in dynamic_provs.keys():
                device['rtpProvisionings'] = device['rtpProvisionings'] + dynamic_provs[key]

    else:
        print_colored(f"Can not load blobs for this provisioning flow! {settings.prov_flow}", ConsoleColor.FAIL)
        sys.exit(-3)

    return device

def filter_blobs(settings: DeviceSettings, device: dict) -> tuple[dict, list]:
    filter_secure_object_type: list[str] = [
        "OEM_FW_AUTH_KEY_HASH", "OEM_FW_DECRYPT_KEY", "DEVICE_GROUP_PROVISIONING_KEY"
    ]

    previous_count = len(device['rtpProvisionings'])
    device['rtpProvisionings'] = list(filter(lambda prov: prov['state'] == "GENERATION_COMPLETED", device['rtpProvisionings']))
    diff_count = previous_count - len(device['rtpProvisionings'])
    if(diff_count):
        print_colored(f"Ignoring {diff_count} blobs that failed to generate!", ConsoleColor.WARN)

    previous_count = len(device['rtpProvisionings'])

    required_data = []
    if(settings.prov_flow == SupportedProvisionFlows.product_based):
        filtered = list(filter(lambda prov: prov['secureObject']['type'] in filter_secure_object_type, device['rtpProvisionings']))
        required_data = [data['data'] for data in filtered]
        
        # For RW610 and RW612, also include object with objectId OTP CONFIG DATA as required
        if(settings.soc == SupportedDevices.rw610 or settings.soc == SupportedDevices.rw612):
            filtered_by_id = list(filter(lambda prov: prov['secureObject'].get('objectId') == "2147451260", device['rtpProvisionings']))
            if filtered_by_id:
                required_data.extend([data['data'] for data in filtered_by_id])

    # Filter out objects by type
    device['rtpProvisionings'] = list(filter(lambda prov: prov['secureObject']['type'] not in filter_secure_object_type, device['rtpProvisionings']))
    
    # For RW610 and RW612, also filter out the object with objectId OTP CONFIG DATA
    if(settings.soc == SupportedDevices.rw610 or settings.soc == SupportedDevices.rw612):
        device['rtpProvisionings'] = list(filter(lambda prov: prov['secureObject'].get('objectId') != "2147451260", device['rtpProvisionings']))
    
    diff_count = previous_count - len(device['rtpProvisionings'])
    if(diff_count):
        filter_msg = ' and '.join(filter_secure_object_type)
        if(settings.soc == SupportedDevices.rw610 or settings.soc == SupportedDevices.rw612):
            filter_msg += ' and objectId 2147451260'
        print_colored(f"Ignoring {filter_msg}!", ConsoleColor.WARN)

    return (device, required_data)

def rewrap_blobs(settings: DeviceSettings) -> None:
    assert(workspace.exists())
    assert(settings.json_path)
    assert(settings.rewrapped_json_path)

    spsdk_higher_than_340 = is_spsdk_version_higher("3.4.0")

    if(((settings.soc == SupportedDevices.rw610) or (settings.soc == SupportedDevices.rw612)) and (settings.prov_flow == SupportedProvisionFlows.proxy)):
        print_colored("Device Individual provisioning is not supported for rw610 and rw612!", ConsoleColor.FAIL)
        return
    
    if(not spsdk_higher_than_340):
        if(((settings.soc == SupportedDevices.mcxn947) or (settings.soc == SupportedDevices.mcxn236)) and (settings.prov_flow == SupportedProvisionFlows.product_based)):
            print_colored("Your spsdk version doesn't support Product Based provisioning for mcxn947 and mcxn236! Please use spsdk 3.4.1 or higher!", ConsoleColor.FAIL)
            return
    
    required_data = []
    if(required_product_based_path.exists() and (settings.prov_flow == SupportedProvisionFlows.product_based)):
        required_data = json.loads(required_product_based_path.read_text())

    if(not unprocessed_blobs_path.exists()):
        device = transform_json_input(settings, json.loads(settings.json_path.read_text()))
        device, required_data = filter_blobs(settings, device)

        if(settings.prov_flow == SupportedProvisionFlows.product_based):
            with open(required_product_based_path, 'w') as required_product_based_file:
                json.dump(required_data, required_product_based_file, indent=4)

        with open(unprocessed_blobs_path, "w") as unprocessed_blobs_file:
            json.dump([device], unprocessed_blobs_file, indent=4)

    while True:
        unprocessed_blobs = json.loads(unprocessed_blobs_path.read_text())
        device: dict = unprocessed_blobs[0]

        blobs = []
        blobs_total_size = 0

        for req_blob in required_data:
            blob = base64.b64decode(req_blob)
            blobs.append(blob)
            blobs_total_size += len(blob)
        
        if(len(blobs) >= (MAX_BLOBS_REWRAP_RUN - 1)):
            print_colored(f"You have too many required secure objects! ({len(blobs)}/15)", ConsoleColor.FAIL)
            sys.exit(-6)
        if(blobs_total_size >= (MAX_BLOB_SIZE_REWRAP_RUN - 500)):
            print_colored(f"Your required secure objects are using too much memory! ({blobs_total_size}/{MAX_BLOB_SIZE_REWRAP_RUN - 500})", ConsoleColor.FAIL)
            sys.exit(-6)

        for provisioning in device['rtpProvisionings']:
            if(settings.prov_flow == SupportedProvisionFlows.proxy):
                base64_string = provisioning['apdus']['createApdu']['apdu']
            elif(settings.prov_flow == SupportedProvisionFlows.product_based):
                base64_string = provisioning['data']
            else:
                print_colored(f"Can not parse data for this provisioning flow! {settings.prov_flow}", ConsoleColor.FAIL)
                sys.exit(-4)

            blob = base64.b64decode(base64_string)

            if((len(blobs) + 1 <= MAX_BLOBS_REWRAP_RUN) and (blobs_total_size + len(blob) <= MAX_BLOB_SIZE_REWRAP_RUN)):
                blobs.append(blob)
                blobs_total_size += len(blob)
            else:
                break

        print_colored(f"Rewrapping batch of {len(blobs)} blobs totalling {blobs_total_size} bytes", ConsoleColor.INFO)
        wrapped_blobs = wrap_blobs(settings, b"".join(blobs), blobs_total_size, spsdk_higher_than_340)

        required_data_size = sum(len(base64.b64decode(req_blob)) for req_blob in required_data)
        if((settings.soc == SupportedDevices.rw610) or (settings.soc == SupportedDevices.rw612)):
            wrapped_blobs = wrapped_blobs[required_data_size:] if required_data_size > 0 else wrapped_blobs
        else:
            wrapped_blobs = wrapped_blobs[:-required_data_size] if required_data_size > 0 else wrapped_blobs
        blobs = blobs[len(required_data):] if len(required_data) > 0 else blobs

        current_byte = 0
        for index, provisioning in enumerate(device['rtpProvisionings'][:len(blobs)]):
            blob_len = len(blobs[index])
            wrapped_blob = wrapped_blobs[current_byte:current_byte + blob_len]

            if(settings.prov_flow == SupportedProvisionFlows.proxy):
                provisioning['apdus']['createApdu']['apdu'] = base64.b64encode(wrapped_blob).decode('ascii')
            elif(settings.prov_flow == SupportedProvisionFlows.product_based):
                provisioning['data'] = base64.b64encode(wrapped_blob).decode('ascii')
            else:
                print_colored(f"Can not parse data for this provisioning flow! {settings.prov_flow}", ConsoleColor.FAIL)
                sys.exit(-5)

            current_byte += len(blobs[index])

        processed = device['rtpProvisionings'][:len(blobs)]
        unprocessed = device['rtpProvisionings'][len(blobs):]

        if(processed_blobs_path.exists()):
            processed_blobs = json.loads(processed_blobs_path.read_text())
            device = processed_blobs[0]
            device['rtpProvisionings'] += processed
        else:
            device['rtpProvisionings'] = processed

        with open(processed_blobs_path, "w") as processed_blobs_file:
            json.dump([device], processed_blobs_file, indent=4)

        
        if(len(unprocessed) > 0):
            device['rtpProvisionings'] = unprocessed

            with open(unprocessed_blobs_path, "w") as unprocessed_blobs_file:
                json.dump([device], unprocessed_blobs_file, indent=4)
        else:
            try:
                if(settings.prov_flow == SupportedProvisionFlows.proxy):
                    os.replace(processed_blobs_path, settings.rewrapped_json_path)

                    print_colored(f"Successfully rewrapped {len(device['rtpProvisionings'])} blobs for device UUID {device['deviceId']}!", ConsoleColor.INFO)
                elif(settings.prov_flow == SupportedProvisionFlows.product_based):
                    processed_blobs = json.loads(processed_blobs_path.read_text())[0]
                    with open(settings.rewrapped_json_path, "w") as rewrapped_blobs_file:
                        json.dump(processed_blobs['rtpProvisionings'], rewrapped_blobs_file, indent=4)

                    print_colored(f"Successfully rewrapped {len(processed_blobs['rtpProvisionings'])} blobs for {settings.soc} device with product-based flow!", ConsoleColor.INFO)
                else:
                    print_colored(f"Can not save rewrapped blobs for this provisioning flow! {settings.prov_flow}", ConsoleColor.FAIL)
                    sys.exit(-6)
            except PermissionError:
                print_colored(f"Your output path should point to an file in a accessible location! (path: {settings.rewrapped_json_path.as_posix()})", ConsoleColor.FAIL)
            return

            break


def main():
    parser = argparse.ArgumentParser(description='Rewraps EL2GO Secure Objects for N10/N11 based devices and RW61x')
    
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable advanved debugging information')
    parser.add_argument('-c', '--config', type=Path, help='Path to a rewrap config')
    parser.add_argument('--get-template', action='store_true', help='Get a template of the rewrap config')
    parser.add_argument('-o', '--output', type=Path, help='Output path for any output files')

    parser.add_argument('--rtp-json-path', type=Path, help='Path to a JSON file containing raw EL2GO RTP objects')
    parser.add_argument('--prov-fw-path', type=Path, help='Path to the provisioning firmware SB3 container')
    parser.add_argument('--com', type=str, help='The COM port to use for contacting the device in ISP mode')
    parser.add_argument('--family', type=str, choices=[device.name for device in SupportedDevices], 
                        default=SupportedDevices.mcxn947.name, help='Soc name, for which re_wrapping is being done')
    parser.add_argument('--prov-flow', type=str, choices=[flow.name for flow in SupportedProvisionFlows], 
                        default=SupportedProvisionFlows.proxy.name, help='The provisioning flow used to for Secure Objects creation')
    args = parser.parse_args()

    enable_debug_logging(args.verbose)

    if(args.get_template):
        if(args.output is None):
            parser.error("You have to define an output file!")
        out_path: Path = args.output

        try:
            out_path.write_text(RewrapConfig.getTemplate())
        except PermissionError:
            print_colored(f"Your output path should point to an file in a accessible location! (path: {out_path.as_posix()})", ConsoleColor.FAIL)
        return

    if(args.config is None):
        no_config_str = "No config given!"

        if(args.output is None):
            parser.error(no_config_str + " You have to define a output file!")
        if(args.rtp_json_path is None):
            parser.error(no_config_str + " You have to define a secure object path!")
        if(args.prov_fw_path is None):
            parser.error(no_config_str + " You have to define a provisioning firmware path!")
        if(args.com is None):
            parser.error(no_config_str + " You have to define a COM port!")
        if(args.family is None):
            parser.error(no_config_str + " You have to define a family!")
        if(args.prov_flow is None):
            parser.error(no_config_str + " You have to define a provisioning flow!")

        rewrapConf = RewrapConfig(args.family, args.prov_flow, args.com, args.rtp_json_path, args.prov_fw_path, args.output)
    else:
        config_path: Path =  args.config
        if(not config_path.is_file()):
            parser.error("The config file has to be an existing file!")

        data = yaml.safe_load(config_path.read_text())

        try:
            rewrapConf = RewrapConfig(**data)
        except TypeError as e:
            missing_args = str(e.args[0]).split("'")[1::2]
            error_msg = f"The config '{config_path.as_posix()}' is missing following arguments: {missing_args}"
            parser.error(error_msg)

    if(not rewrapConf.is_valid_data()):
        print_colored("Fix the warnings to proceed!", ConsoleColor.FAIL)
        sys.exit(1)

    settings = PREDEFINED_SETTINGS[rewrapConf.family]
    settings.json_path = rewrapConf.rtp_json_path
    settings.prov_fw_path = rewrapConf.prov_fw_path
    settings.rewrapped_json_path = rewrapConf.output_path
    settings.com = rewrapConf.com_port
    settings.prov_flow = rewrapConf.prov_flow
    
    if(unprocessed_blobs_path.exists() and unprocessed_blobs_path.is_file()):
        filetime = datetime.fromtimestamp(os.path.getmtime(unprocessed_blobs_path))
        while True:
            user_input = input(f"Continue with remaining unprocessed blobs from last run ({filetime.isoformat()})? [y/n] ")

            if(user_input in ["y", "n"]):
                break

        if(user_input == "n"):
            print_colored("Deleting old workspace and restart rewrapping!\n", ConsoleColor.WARN)
            shutil.rmtree(workspace)
        else:
            print_colored("Continue with previous rewrapping!\n", ConsoleColor.INFO)

    print_colored("Starting rewrapping with settings:", ConsoleColor.INFO)
    print_colored("  " + str(settings).replace("\n", "\n  ") + "\n", ConsoleColor.INFO)

    workspace.mkdir(exist_ok=True)

    generate_el2go_config(settings)
    rewrap_blobs(settings)

    if(workspace.exists()):
        shutil.rmtree(workspace)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_colored("\n\nCaught a KeyboardInterrupt! Quitting Rewrapping...", ConsoleColor.WARN)