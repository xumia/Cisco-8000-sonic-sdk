#!/common/pkgs/python/3.6.10/bin/python3.6
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

import os
import re
import socket
import argparse
import sys
import gzip

MAX_LINES_BETWEEN_ENTRIES = 32
VRF_LEN = 11
IPV6_MAXLEN = 128
IPV4_MAXLEN = 32
BITS_IN_BYTE = 8
BYTES_IN_IPV4 = int(IPV4_MAXLEN / BITS_IN_BYTE)
MAX_BYTE_VALUE = (1 << BITS_IN_BYTE) - 1


def is_valid_address(address, ip_ver):
    if ((ip_ver != 4) and (ip_ver != 6)):
        raise ValueError('IP version should be either 4 or 6')
    family = socket.AF_INET6 if ip_ver == 6 else socket.AF_INET

    retval = None
    try:
        retval = socket.inet_pton(family, address)
    except socket.error:  # invalid address
        return None
    return retval


def match_ipv6_line(line, vrf, vrf_width, beginning_match_str):
    ipv6_match_str = r'(?P<address>([0-9a-f:\.]+))/(?P<width>([0-9]+))'
    m = re.match(beginning_match_str + ipv6_match_str, line)
    if not m:
        return None, None, None

    width = int(m['width'])
    if width < 0 or width > IPV6_MAXLEN:
        print('BAD IPV6 WIDTH', file=sys.stderr)
        return None, None, None

    address = m['address']
    bytes_address = is_valid_address(address, 6)
    if not bytes_address:
        print('BAD IPV6 ADDRESS', file=sys.stderr)
        return None, None, None

    int_address = int.from_bytes(bytes_address, byteorder='big')
    key = int_address >> (IPV6_MAXLEN - width)

    key = key | (vrf << width)
    key = key | (1 << (vrf_width + width))

    return key, width, m.end()


def match_ipv4_line(line, vrf, vrf_width, beginning_match_str):
    ipv4_match_str = r'(?P<byte3>([0-9]+))\.(?P<byte2>([0-9]+))\.(?P<byte1>([0-9]+))\.(?P<byte0>([0-9]+))/(?P<width>([0-9]+))'
    m = re.match(beginning_match_str + ipv4_match_str, line)
    if not m:
        return None, None, None

    width = int(m['width'])
    ip_bytes = [int(m['byte0']), int(m['byte1']), int(m['byte2']), int(m['byte3'])]
    if width > IPV4_MAXLEN or width < 0:
        print('BAD IPV4 WIDTH', file=sys.stderr)
        return None, None, None
    for i in range(BYTES_IN_IPV4):
        if ip_bytes[i] > MAX_BYTE_VALUE or ip_bytes[i] < 0:
            print('BAD IPV4 ADDRESS', file=sys.stderr)
            return None, None, None

    key = (vrf << IPV4_MAXLEN)
    for i in range(BYTES_IN_IPV4):
        key |= (ip_bytes[i] << i * BITS_IN_BYTE)
    key = key >> (IPV4_MAXLEN - width)

    return key, width, m.end()


def match_lines_to_next_hop(lines, beginning_match_str):
    next_key_match_str = '\n' + beginning_match_str + '[0-9a-f:]'
    m = re.search('(VRF)|(' + next_key_match_str + ')', lines)
    if not m:
        print("A lot of rows between entries!", file=sys.stderr)
        print(lines, file=sys.stderr)

    lines_without_key = lines[:m.start()] if m else lines
    nh_str = lines_without_key.replace(' ', '').replace('\n', '')

    return nh_str


def convert_lines_to_entry(lines, nh_to_payload_dict, vrf, vrf_width, att_format):
    beginning_match_str = r'(([BCLOSi][\* ][ILE> ][A12 ] )|(\*[ >][ i]))' if att_format else ''

    # Try IPv6.
    key, width, key_str_len = match_ipv6_line(lines[:lines.find('\n')], vrf, vrf_width, beginning_match_str)
    if key is None or width is None:
        # If row isn't IPv6, try IPv4.
        key, width, key_str_len = match_ipv4_line(lines[:lines.find('\n')], vrf, vrf_width, beginning_match_str)

    # Row is not a routing IP.
    if key is None or width is None:
        print('Could not match line: ' + lines, file=sys.stderr)
        return None

    total_width = width + vrf_width + 1

    nh_str = match_lines_to_next_hop(lines[key_str_len:], beginning_match_str)
    if nh_str not in nh_to_payload_dict:
        nh_to_payload_dict[nh_str] = len(nh_to_payload_dict) + 1
    payload = nh_to_payload_dict[nh_str]

    new_line = "lpm_insert {} {} {}".format(hex(key)[2:], total_width, hex(payload)[2:])

    return new_line


def convert_file(filepath):
    print('Starting convertion of file: {}'.format(filepath), file=sys.stderr)
    dirpath, filename = os.path.split(filepath)
    name, ext = os.path.splitext(filename)

    open_func = gzip.open if (ext == '.gz') else open

    with open_func(filepath, 'r') as fin:
        lines = fin.readlines()

    lines = [(str(line, 'utf-8').rstrip() if (type(line) == bytes) else line) for line in lines]

    new_filename = "lpm_data.{}.txt".format(name if ext in ['.txt', '.gz'] else filename).replace(' ', '_')
    nh_to_payload_dict = {}

    with open(new_filename, 'w') as fout:
        vrf = 0
        for i in range(len(lines)):
            if re.match(r"^VRF", lines[i]):
                vrf += 1
                continue

            j = min(len(lines), i + MAX_LINES_BETWEEN_ENTRIES)
            lines_to_match = '\n'.join(lines[i:j])

            new_line = convert_lines_to_entry(lines_to_match, nh_to_payload_dict, vrf, VRF_LEN, att_format=False)
            if not new_line:
                new_line = convert_lines_to_entry(lines_to_match, nh_to_payload_dict, vrf, VRF_LEN, att_format=True)
            if not new_line:
                continue
            fout.write(new_line + "\n")


def main():
    parser = argparse.ArgumentParser(description='Convert tables to lpm_data format.')
    parser.add_argument('--directory-mode', action='store_true')
    parser.add_argument('path', type=str)
    args = parser.parse_args()

    # Single file mode used.
    if not args.directory_mode:
        filepath = args.path
        print('Single file mode used with file %s' % filepath)
        convert_file(filepath)
        return

    # Directory mode used.
    directory = args.path
    print('directory mode used with directory %s' % directory)
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            convert_file(filepath)


if __name__ == '__main__':
    main()
