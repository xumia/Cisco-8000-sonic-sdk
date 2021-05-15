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

from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import decor
import time
from vxlan_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class sda_encap(vxlan_l2_single_port):
    underlay_ip_impl = ip_test_base.ipv6_test_base
    OVL_DIP = '1111:0db8:0a0b:12f0:0000:0000:0000:1111'
    OVL_DIP_ROUTE = T.ipv6_addr(OVL_DIP)

    OVL_DIP_1 = '1112:0db8:0a0b:12f0:0000:0000:0000:1111'
    OVL_DIP_ROUTE_1 = T.ipv6_addr(OVL_DIP_1)

    OVL_SIP = '2222:0db8:0a0b:12f0:0000:0000:0000:2222'
    OVL_SIP_ROUTE = T.ipv6_addr(OVL_SIP)

    L3VXLAN_IP_PACKET = \
        S.IPv6(dst=OVL_DIP_1,
               src=OVL_SIP,
               hlim=vxlan_base.INNER_TTL,
               plen=40) / \
        S.TCP()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_sda_encap(self):
        self.create_recycle_ac_port()
        self.single_port_setup()
        self.sda_setup()
        self._test_vxlan_sda_encap()
        self.sda_destroy()
        self.single_port_destroy()
        self.destroy_recycle_ac_port()


if __name__ == '__main__':
    unittest.main()
