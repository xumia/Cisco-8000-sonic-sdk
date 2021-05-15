#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

import json
import sys
import os


# This script reads JSON file that contains info about locations of releases
# for different devices, extracts only info about specific device, and writes
# it to output file.
#
# Arg[1] - Path to input JSON file which is dictionary where key is device name, and value
#    is location to its release. Example: 
#    {"gibraltar": "/path/to/gibraltar/release",
#     "pacific": "/path/to/pacific/release"}
# Arg[2] - Name of the device for which info needs to be extracted.
# Arg[3] - Path on which output file will be created, containing only info about device
#    specified by Arg[2]. If input file given by Arg[1] does not contain info for specified
#    device, empty JSON file is created.


def main():
    device_name = sys.argv[1]
    src_json_filename = sys.argv[2]
    dst_json_filename = sys.argv[3]

    try:
        with open(src_json_filename, 'r') as fd:
            src_json_dict = json.load(fd)
    except Exception as e:
        print('{}: Could not read file {}: {}'.format(os.path.basename(__file__), src_json_filename, str(e)))
        return
        
    dst_json_dict = {}
    if device_name in src_json_dict:
        dst_json_dict[device_name] = src_json_dict[device_name]

    try:
        with open(dst_json_filename, 'w') as fd:
            json.dump(dst_json_dict, fd)
    except Exception as e:
        print('{}: Could not write file {}: {}'.format(os.path.basename(__file__), dst_json_filename, str(e)))
        return


if __name__ == '__main__':
    main()