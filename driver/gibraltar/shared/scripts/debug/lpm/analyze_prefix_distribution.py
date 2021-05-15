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

import re
import os
import sys
import argparse
import gzip
import math
from bit_utils import get_bits

VRF_LEN = 11


def get_related_descriptors(prefix_len, list_of_descriptors):
    return [d for d in list_of_descriptors if (prefix_len >= d.start) and (prefix_len <= d.end)]


def analyze_test_file(fname, list_of_descriptors, csvfile=None):

    widths_v4 = [0 for _ in range(129)]  # pad for easier handling when using CSV
    widths_v6 = [0 for _ in range(129)]

    _, ext = os.path.splitext(fname)
    if ext == '.gz':
        f = gzip.open(fname, 'r')
    else:
        f = open(fname, 'r')

    unique_prefixes = {d: set() for d in list_of_descriptors}

    print('Filename: %s' % fname)
    for l in f:
        if isinstance(l, bytes):
            l = str(l, 'utf-8')
            l = l.rstrip()
        m = re.match(r'lpm_insert (?P<prefix>[0-9a-f]+) (?P<full_length>[0-9]+) [0-9a-f]', l)
        if m is not None:
            prefix = int(m['prefix'], 16)
            prefix_len = int(m['full_length'], 10)
            is_ipv6 = (prefix >> (prefix_len - 1))
            ip_prefix_len = prefix_len - 1 - VRF_LEN
            ip_prefix = get_bits(prefix, ip_prefix_len - 1, 0)
            if is_ipv6:
                widths_v6[ip_prefix_len] += 1
            else:
                widths_v4[ip_prefix_len] += 1

            if is_ipv6:
                related_desciptors = get_related_descriptors(ip_prefix_len, list_of_descriptors)
                for d in related_desciptors:
                    bits_to_strip = ip_prefix_len - d.uniq_bits
                    unique_prefixes[d].add(ip_prefix >> bits_to_strip)

    total_v4 = sum(widths_v4)
    total_v6 = sum(widths_v6)

    if total_v4 > 0:
        print('IPv4 Distribution (total=%d)' % total_v4)
        csv_v4 = [fname, 'IPV4', str(total_v4)]

        for w, c in enumerate(widths_v4):
            csv_v4.append(str(c))
            if c != 0:
                print('%-4d  %-8d    %6.2f%%    %s' % (w, c, c / total_v4 * 100, '' * math.ceil((c * 100) / total_v4)))

        csv_v4 += [' ' for _ in list_of_descriptors]

        if csvfile is not None:
            csvfile.write('%s\n' % ','.join(csv_v4))

    if total_v6 > 0:
        print('IPv6 Distribution (total=%d)' % total_v6)
        csv_v6 = [fname, 'IPV6', str(total_v6)]

        for w, c in enumerate(widths_v6):
            csv_v6.append(str(c))
            if c != 0:
                print('%-4d  %-8d    %6.2f%%    %s' % (w, c, c / total_v6 * 100, '' * math.ceil((c * 100) / total_v6)))

        for d in list_of_descriptors:
            csv_v6.append(str(len(unique_prefixes[d])))

        if csvfile is not None:
            csvfile.write('%s\n' % ','.join(csv_v6))

    print('-----------')


class UniqPrefixDescriptor:
    def __init__(self, start, end, uniq_bits):
        self.start = start
        self.end = end
        self.uniq_bits = uniq_bits

    def __repr__(self):
        if self.start == self.end:
            return 'uniq %d/%d' % (self.uniq_bits, self.start)
        else:
            return 'uniq %d/%d-%d' % (self.uniq_bits, self.start, self.end)


def main():
    if sys.version_info[0] < 3:
        print('Must use python3')
        sys.exit(1)

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("files", help="test files to analyze", nargs='*')
    parser.add_argument("--csv", type=str, help="CSV filename", default=None)
    args = parser.parse_args()

    list_of_descriptors = [UniqPrefixDescriptor(start=48, end=64, uniq_bits=48),
                           UniqPrefixDescriptor(start=49, end=64, uniq_bits=48),
                           UniqPrefixDescriptor(start=48, end=64, uniq_bits=32),
                           UniqPrefixDescriptor(start=64, end=64, uniq_bits=48),
                           UniqPrefixDescriptor(start=64, end=64, uniq_bits=32),
                           UniqPrefixDescriptor(start=68, end=128, uniq_bits=68)]

    uniq_prefix_cnt = []
    for desc in list_of_descriptors:
        uniq_prefix_cnt.append(str(desc))

    if args.csv is not None:
        csvfile = open(args.csv, 'w')
        header = ','.join(['File Name', 'IP Version', 'Total'] + [str(i) for i in range(129)] + uniq_prefix_cnt)
        csvfile.write('%s\n' % header)
    else:
        csvfile = None

    for f in args.files:
        if os.path.isfile(f):
            analyze_test_file(f, list_of_descriptors, csvfile)

    if csvfile:
        csvfile.close()


if __name__ == '__main__':
    main()
