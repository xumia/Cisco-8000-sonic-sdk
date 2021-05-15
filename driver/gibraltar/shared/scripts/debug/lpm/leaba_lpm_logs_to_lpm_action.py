#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sys
import argparse
from bit_utils import get_bits

orig_key = None
orig_width = None
fixed_key = None
fixed_width = None

VRF_LEN = 11


def ip_to_str(ip, is_ipv6):
    if is_ipv6:
        ip_as_hex_str = '%032x' % ip
        ip_groups_str = [ip_as_hex_str[i:i + 4] for i in range(0, 32, 4)]
        ip_str = ':'.join(ip_groups_str)
    else:
        ip_as_hex_str = '%08x' % ip
        ip_groups_str = ['%d' % int(ip_as_hex_str[i:i + 2], 16) for i in range(0, 8, 2)]
        ip_str = '.'.join(ip_groups_str)

    return ip_str


def make_ip_from_key(key, width):
    if (width < 1 + VRF_LEN):
        return (None, None, None)

    is_ipv6 = (get_bits(key, width - 1, width - 1) == 1)
    ip_full_length = 128 if is_ipv6 else 32
    remaining_length = ip_full_length + VRF_LEN + 1 - width
    prefix_full = key << remaining_length

    ip = get_bits(prefix_full, ip_full_length - 1, 0)
    vrf = get_bits(prefix_full, ip_full_length + VRF_LEN - 1, ip_full_length)
    ip_width = width - 1 - VRF_LEN

    ip_str = ip_to_str(ip, is_ipv6)
    return (vrf, ip_str, ip_width)


def match_insert(line):
    if 'LPM ACTION: INSERT' not in line:
        return False

    m = re.match(
        r'.*LPM ACTION: INSERT key 0x(?P<key>([0-9a-f]+))   key width (?P<width>([0-9]+))   payload = 0x(?P<payload>([0-9a-f]+))',
        line)
    if m is None:
        assert(False)
        return False

    key = int(m['key'], 16)
    width = int(m['width'], 10)
    payload = int(m['payload'], 16)
    if (key == fixed_key) and (width == fixed_width):
        key = orig_key
        width = orig_width

    (vrf, ip, ip_width) = make_ip_from_key(key, width)
    print('lpm_insert %040x %04d %5x //vrf=0x%-3x  ip=%s/%d' % (key, width, payload, vrf, ip, ip_width))
    return True


def match_modify(line):
    if 'LPM ACTION: MODIFY' not in line:
        return False

    m = re.match(
        r'.*LPM ACTION: MODIFY key 0x(?P<key>([0-9a-f]+))   key width (?P<width>([0-9]+))   payload = 0x(?P<payload>([0-9a-f]+))',
        line)
    if m is None:
        assert(False)
        return False

    key = int(m['key'], 16)
    width = int(m['width'], 10)
    payload = int(m['payload'], 16)
    if (key == fixed_key) and (width == fixed_width):
        key = orig_key
        width = orig_width
    (vrf, ip, ip_width) = make_ip_from_key(key, width)
    print('lpm_modify %040x %04d %5x //vrf=0x%-3x  ip=%s/%d' % (key, width, payload, vrf, ip, ip_width))
    return True


def match_remove(line):
    if 'LPM ACTION: REMOVE' not in line:
        return False

    m = re.match(
        r'.*LPM ACTION: REMOVE key 0x(?P<key>([0-9a-f]+))   key width (?P<width>([0-9]+))',
        line)
    if m is None:
        assert(False)
        return False

    key = int(m['key'], 16)
    width = int(m['width'], 10)
    if (key == fixed_key) and (width == fixed_width):
        key = orig_key
        width = orig_width
    (vrf, ip, ip_width) = make_ip_from_key(key, width)
    print('lpm_remove %040x %04d       //vrf=0x%-3x  ip=%s/%d' % (key, width, vrf, ip, ip_width))
    return True


def match_fix_key(line):
    global orig_key
    global orig_width
    global fixed_key
    global fixed_width

    if 'LPM: encode_lpm_key' not in line:
        return False

    m = re.match(
        r'.*LPM: encode_lpm_key\(k=0x(?P<orig_key>([0-9a-f]+)) w=(?P<orig_width>([0-9]+))\) -> k=0x(?P<fixed_key>([0-9a-f]+)) w=(?P<fixed_width>([0-9]+))',
        line)
    if m is None:
        assert(False)
        return False
    orig_key = int(m['orig_key'], 16)
    orig_width = int(m['orig_width'], 10)
    fixed_key = int(m['fixed_key'], 16)
    fixed_width = int(m['fixed_width'], 10)
    return True


rebalance_due_to_failure = False


def match_rebalance(line):
    global rebalance_due_to_failure
    if 'LPM Rebalance triggered after failed update' in line:
        rebalance_due_to_failure = True
        return True
    elif 'Rebalance starting' in line:
        if not rebalance_due_to_failure:
            print('lpm_rebalance')
        rebalance_due_to_failure = False
        return True
    else:
        return False


def main():
    if sys.version_info[0] < 3:
        print('Must use python3')
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", help="log file to parse", type=str)
    parser.add_argument("-r", "--record_rebalance", action="store_true", help="record rebalance as an explicit action")
    args = parser.parse_args()

    with open(args.logfile, 'r') as f:
        for i, l in enumerate(f):
            matched = False

            if not matched:
                matched = match_fix_key(l)

            if not matched:
                matched = match_insert(l)

            if not matched:
                matched = match_modify(l)

            if not matched:
                matched = match_remove(l)

            if not matched:
                if args.record_rebalance:
                    matched = match_rebalance(l)
            if (i % 100000 == 0):
                print('Line %d done' % i, file=sys.stderr)


if __name__ == '__main__':
    main()
