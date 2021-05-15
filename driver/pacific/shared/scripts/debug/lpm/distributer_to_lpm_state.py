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
import sys


def convert_report_to_lpm_state(report_fname):
    ngroups = 128
    group_to_core = [0 for _ in range(ngroups)]
    v4_distributer = {}
    v6_distributer = {}

    with open(report_fname, 'r') as f:
        for l in f:
            m = re.match(
                '\| *(?P<line>([0-9]*)) *\| ipv(?P<ip_ver>([46])) *\| (?P<width>([0-9]*)) *\| 0x(?P<prefix>([0-9a-f]*)) *\| *(?P<group>([0-9]*)) *\| *(?P<core>([0-9]*)) .*',
                l)
            if m is not None:
                ip_ver = int(m['ip_ver'])
                line = int(m['line'])
                if ip_ver == 6:
                    line -= ngroups // 2
                width = int(m['width'])
                prefix = int(m['prefix'], 16)
                group = int(m['group'])
                core = int(m['core'])
                distributer = v4_distributer if (ip_ver == 4) else v6_distributer
                distributer[line] = {'key': prefix, 'width': width, 'payload': group}
                group_to_core[group] = core

    print('v4 Distributer')
    for k, v in v4_distributer.items():
        print('TCAM line %d: (Key 0x%x Width %d Payload 0x%x)' % (k, v['key'], v['width'], v['payload']))

    print('v6 Distributer')
    for k, v in v6_distributer.items():
        print('TCAM line %d: (Key 0x%x Width %d Payload 0x%x)' % (k, v['key'], v['width'], v['payload']))

    for i in range(ngroups):
        print('group[%d] -> core %d' % (i, group_to_core[i]))


def main():
    if sys.version_info[0] < 3:
        print('Must use python3')
        sys.exit(1)

    if len(sys.argv) < 2:
        print('usage: %s <report fname>' % sys.argv[0])
        sys.exit(1)

    report_fname = sys.argv[1]

    convert_report_to_lpm_state(report_fname)


if __name__ == '__main__':
    main()
