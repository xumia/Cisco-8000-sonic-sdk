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
import ip_test_base
import decor
from security_group_acl_vxlan_base import *


class test_l2_vxlan_decap_ipv6_security_group_acl_monitor(vxlan_l2_single_port):
    underlay_ip_impl = ip_test_base.ipv6_test_base

    OVL_DIPv6 = '1112:0db8:0a0b:12f0:0000:0000:0000:1111'
    OVL_SIPv6 = '2222:0db8:0a0b:12f0:0000:0000:0000:2222'

    VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = \
        S.Ether(dst=vxlan_l2_single_port.L2_DST_MAC.addr_str,
                src=vxlan_l2_single_port.L2_SRC_MAC.addr_str) / \
        S.IPv6(dst=OVL_DIPv6,
               src=OVL_SIPv6,
               hlim=security_group_acl_vxlan_base.TTL,
               plen=40) / \
        S.TCP()

    # Temporarily disabled on HW, till DGT corruption is fixed.
    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(not decor.is_gibraltar(), "Run only on GB")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_l2_vxlan_decap_ipv6_security_group_acl_monitor(self):
        self.single_port_setup()
        self.set_l2_sgacl(True, True, False, False)  # monitor, drop, is_ipv4, is_encap
        self._test_vxlan_l2_decap()
        self.destroy_sgacl()
        self.single_port_destroy()


if __name__ == '__main__':
    unittest.main()
