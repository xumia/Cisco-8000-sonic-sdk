#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import sys
import argparse
import logging
import re


# configure an argument parser
parser = argparse.ArgumentParser(
    description="Sets updated block addresses from design data to the list of block IDs, relevant for SDK.",
    add_help=True)

req_group = parser.add_argument_group(title='required arguments')
req_group.add_argument('-d', '--design_defines', required=True, help='input file. Design definitions of block IDs.')
req_group.add_argument('-s', '--sdk_defines', required=True, help='input file. List of block IDs, used by SDK.')
req_group.add_argument(
    '-o',
    '--output',
    required=True,
    help='output file containing list of block IDs, used by SDK, with updated addresses.')

# parse arguments
parsed_args = parser.parse_args()

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='-I- %(message)s')

res = {}

with open(parsed_args.design_defines, 'r') as f:
    design_defines = f.readlines()

defines_map = {}

# `define CDB_CORE5_UID  {2'b00, 4'b1010, 6'd6}
define_line_regex = r'^`define\s+(\S+)\s+({.*}).*'

# `define SDB_MACDB_UID  `SDB_TERMDB_UID
# `define CIFG_SLICE_0_MAC_POOL0_UNIT_OFF `CIFG_CHAIN0_START_UID + 0
symbol_line_regex = r'^`define\s+(\S+)\s+`(.*)'

for line in design_defines:
    line = line.strip()

    match = re.search(define_line_regex, line)
    if match:
        defines_map[match.group(1)] = match.group(2)

    else:
        match = re.search(symbol_line_regex, line)
        if match:
            parts = match.group(2).strip().split()
            value = defines_map[parts[0]]
            if len(parts) == 3 and parts[1] == '+':
                value_parts = value.split('}')[0].split("'d")
                value = "{}'d{}}}".format(value_parts[0],
                                          int(value_parts[1]) + int(parts[2]))
            defines_map[match.group(1)] = value

with open(parsed_args.sdk_defines, 'r') as f:
    sdk_defines = f.readlines()

output_lines = []
for line in sdk_defines:
    line = line.strip()

    match = re.search(define_line_regex, line)
    if match:
        if match.group(1) not in defines_map.keys():
            print("-ERROR- Block ID %s is not in design definitions file %s. Please review." %
                  (match.group(1), parsed_args.design_defines))
            sys.exit(1)
        else:
            output_lines.append("`define %s%s%s" % (match.group(1), match.group(2), defines_map[match.group(1)]))
    else:
        output_lines.append(line)

with open(parsed_args.output, 'w') as f:
    for l in output_lines:
        f.write(l + '\n')
