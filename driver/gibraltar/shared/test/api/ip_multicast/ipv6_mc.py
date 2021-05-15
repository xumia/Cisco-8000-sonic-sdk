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


class ipv6_mc:
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    SIP3 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:3333')
    SIP_DCFAIL = T.ipv6_addr('3333:0db8:0a0b:12f0:0000:0000:0000:2222')
    SIP_FEC = T.ipv6_addr('4444:0db8:0a0b:12f0:0000:0000:0000:2222')

    @staticmethod
    def get_mc_sa_addr_str(ip_addr):
        # https://tools.ietf.org/html/rfc2464#section-7
        shorts = ip_addr.addr_str.split(':')
        assert(len(shorts) == T.ipv6_addr.NUM_OF_SHORTS)
        sa_addr_str = '33:33'
        for s in shorts[-2:]:
            sl = int(s, 16) & 0xff
            sh = (int(s, 16) >> 8) & 0xff
            sa_addr_str += ':%02x:%02x' % (sh, sl)
        return sa_addr_str
