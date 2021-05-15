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

import decor
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import decor
import time
from security_group_acl_vxlan_base import *


class test_l3_vxlan_decap_ipv4_security_group_acl_monitor(vxlan_l2_single_port):
    underlay_ip_impl = ip_test_base.ipv4_test_base
    OVL_SIPv4 = '21.1.1.1'
    OVL_SIP_ROUTE = T.ipv4_addr(OVL_SIPv4)

    OVL_DIPv4 = '10.1.1.1'
    OVL_DIP_ROUTE = T.ipv4_addr(OVL_DIPv4)

    OVL_DIPv4_1 = '31.1.1.1'
    OVL_DIP_ROUTE_1 = T.ipv4_addr(OVL_DIPv4_1)

    L3VXLAN_IP_PACKET = \
        S.IP(dst=OVL_DIPv4,
             src=OVL_SIPv4,
             id=0,
             flags=2,
             ttl=security_group_acl_vxlan_base.TTL) / \
        S.TCP()

    @unittest.skipIf(not decor.is_gibraltar(), "Run only on GB")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_l3_vxlan_decap_ipv4_security_group_acl_monitor(self):
        self.create_recycle_ac_port()
        self.single_port_setup()
        self.sda_setup()
        self.set_l3_sgacl(True, True, True, False)  # monitor, drop, is_ipv4, is_encap
        self._test_vxlan_sda_decap()
        self.destroy_sgacl()
        self.sda_destroy()
        self.single_port_destroy()
        self.destroy_recycle_ac_port()


if __name__ == '__main__':
    unittest.main()
