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

import argparse
import importlib
import sys
import json
import re


def main():
    parser = argparse.ArgumentParser()
    parser.prog = 'gen_pacific_tree_interrupt'
    parser.description = 'Generate metadata for device interrupt tree and store it in JSON format.'
    parser.add_argument('--asic', required=True, help='ASIC name, e.g. pacific, gibraltar')
    parser.add_argument('--lbr', required=True, help='Path to LBR data in JSON format')
    parser.add_argument('--out', required=True, help='Output file')
    args = parser.parse_args()

    tree = importlib.import_module(args.asic + '_interrupt_tree', package=None)

    tr = tree.create_interrupt_tree(args.lbr)
    json_buffer = tree.to_json(tr)
    with open(args.out, 'w') as f:
        f.write(json_buffer)

    table_file_name = re.sub(r'.json', '.csv', args.out)
    with open(table_file_name, "w") as f:
        tree.print_tree(f, tr, args.asic)

    return 0


if __name__ == '__main__':
    sys.exit(main())
