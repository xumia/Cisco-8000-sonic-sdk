#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import gzip
import argparse
import os

verbosity = 0


def main():
    global verbosity

    if sys.version_info[0] < 3:
        print('Must use python3')
        sys.exit(1)

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("fname", help="test input file to check (gzip)", type=str)
    parser.add_argument("-v", "--verbosity", action="count", help="Verbose. Can use multiple times")
    args = parser.parse_args()

    verbosity = args.verbosity if args.verbosity else 0

    inserts = 0
    removes = 0
    modifies = 0

    _, fextension = os.path.splitext(args.fname)

    if fextension == '.gz':
        f = gzip.open(args.fname, 'r')
    else:
        f = open(args.fname, 'r')

    for line in f:
        line = str(line)
        if 'lpm_insert' in line:
            inserts += 1
        elif 'lpm_remove' in line:
            removes += 1
        elif 'lpm_modify' in line:
            modifies += 1
        total_entries = inserts - removes
        if (verbosity > 0):
            print('Total: %d  Inserts: %d  Removes: %d  Modifes: %d' % (total_entries, inserts, removes, modifies))

    f.close()

    total_entries = inserts - removes
    print('Total: %d  Inserts: %d  Removes: %d  Modifes: %d' % (total_entries, inserts, removes, modifies))


if __name__ == '__main__':
    main()
