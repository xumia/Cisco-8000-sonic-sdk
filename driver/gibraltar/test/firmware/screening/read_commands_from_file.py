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


def main():
    if (len(sys.argv) != 2):
        print('USAGE: {0} <IN_commands.bin>'.format(sys.argv[0]))
        return -1

    with open(sys.argv[1], 'rb') as fin:
        data = fin.read()
        for i, b in enumerate(data):
            if (i) % 16 == 0:
                sys.stdout.write('%04x: ' % i)
            rc = sys.stdout.write('%02x ' % b)
            if (i + 1) % 4 == 0:
                sys.stdout.write(' ')
            if (i + 1) % 16 == 0:
                sys.stdout.write('\n')

    return 0


if __name__ == '__main__':
    sys.exit(main())
