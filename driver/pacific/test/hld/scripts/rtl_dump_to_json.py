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

# Transform design test output to JSON expected values.

import os.path
import re
import json
import sys


def main():
    # Parse arguments
    if (len(sys.argv) != 2):
        usage()
        sys.exit(2)

    input_file = sys.argv[1]

    # Process file
    process_file(input_file)


def usage():
    print('Usage: {0} <design test>\n'.format(sys.argv[0]))


def process_file(in_file):
    with open(in_file, 'r') as fh_in:
        test_dict = {}
        test_dict['register'] = {}
        test_dict['memory'] = {}
        test_dict['tcam'] = {}
        for line in fh_in:
            if '#' in line:
                # skip comment line
                continue

            elif 'write_register' in line:
                write_reg = re.sub(r'.+\((.+)\)\n', r'\1', line)
                (reg_path, reg_val) = write_reg.strip(' ').split(',')
                test_dict['register'][reg_path] = reg_val

            elif 'write_memory' in line:
                write_mem = re.sub(r'.+\((.+)\)\n', r'\1', line)
                (mem_path, mem_line, mem_val) = write_mem.strip(' ').split(',')
                test_dict['memory']['{0}:{1}'.format(mem_path, mem_line)] = mem_val

            elif 'write_tcam' in line:
                write_tcam = re.sub(r'.+\((.+)\)\n', r'\1', line)
                (tcam_path, tcam_line, tcam_val, tcam_mask) = write_tcam.strip(' ').split(',')
                test_dict['tcam']['{0}:{1}'.format(tcam_path, tcam_line)] = {"val": tcam_val, "mask": tcam_mask}

    tests = {}
    tests['test'] = test_dict
    print(json.dumps(tests, indent=4, sort_keys=True))


if __name__ == "__main__":
    main()
