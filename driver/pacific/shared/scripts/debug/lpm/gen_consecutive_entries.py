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
import argparse
import random

VRF_LEN = 11


def main():
    if sys.version_info[0] < 3:
        print('Must use python3', file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--nentries", type=int, required=True, help="number of entries to generate")
    parser.add_argument("-p", "--prefix_length", type=int, default=0, help="prefix length")
    parser.add_argument("-s", "--log_stride", type=int, default=0, help="log2 of stride between entries")
    parser.add_argument("-r", "--ip_version", type=int, default=6, help="IP version (v4/v6)")
    args = parser.parse_args()

    nentries = args.nentries
    version = args.ip_version
    is_ipv6 = (version == 6)
    prefix_length = args.prefix_length
    max_prefix_length = 128 if is_ipv6 else 32
    if prefix_length == 0:
        prefix_length = max_prefix_length
    log_stride = args.log_stride

    if prefix_length > max_prefix_length:
        print('prefix_length is too large', file=sys.stderr)
        sys.exit(1)

    if log_stride > prefix_length:
        print('log(stride) is larger than prefix length', file=sys.stderr)
        sys.exit(1)

    random.seed(0)

    vrf = random.randint(0, (1 << VRF_LEN) - 1)
    ip_base = 1
    ip_version_bit = 1 if is_ipv6 else 0
    prefix_base = (is_ipv6 << (prefix_length + VRF_LEN)) | (vrf << prefix_length) | ip_base

    for i in range(0, nentries):
        prefix = prefix_base + (i << log_stride)
        if (prefix >> (prefix_length + VRF_LEN)) != ip_version_bit:
            print('MSB override', file=sys.stderr)
            sys.exit(1)
        if (prefix >> (prefix_length + VRF_LEN + 1)) != 0:
            print('prefix overflow', file=sys.stderr)
            sys.exit(1)
        payload = random.randint(0, (1 << 20) - 1)
        print('lpm_insert %036x %d %05x' % (prefix, prefix_length + VRF_LEN + 1, payload))


if __name__ == '__main__':
    main()
