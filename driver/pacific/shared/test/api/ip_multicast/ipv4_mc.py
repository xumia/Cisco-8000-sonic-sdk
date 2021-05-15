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

import sim_utils
import topology as T
from leaba import sdk
from mc_base import *


class ipv4_mc:
    SIP = T.ipv4_addr('12.10.12.10')
    SIP_DCFAIL = T.ipv4_addr('22.20.22.20')
    SIP_FEC = T.ipv4_addr('32.30.32.30')

    @staticmethod
    def get_mc_sa_addr_str(ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        sa_addr_str = '01:00:5e'
        sa_addr_str += ':%02x' % (0x7f & int(octets[1]))
        for o in octets[2:]:
            sa_addr_str += ':%02x' % (int(o))
        return sa_addr_str

    @staticmethod
    def get_mc_sa_addr(ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        sa_addr_upper = 0x01005e << 24
        sa_addr_middle = (0x7f & int(octets[1])) << 16
        sa_addr_lower = (int(octets[2]) << 8 | int(octets[3]))
        sa_addr = sa_addr_upper | sa_addr_middle | sa_addr_lower
        mc_dst_mac = sdk.la_mac_addr_t()
        mc_dst_mac.flat = sa_addr
        return mc_dst_mac
