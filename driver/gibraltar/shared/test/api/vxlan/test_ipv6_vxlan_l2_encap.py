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
import ip_test_base
from vxlan_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class vxlan_l2_encap(vxlan_l2_single_port):
    underlay_ip_impl = ip_test_base.ipv6_test_base
    VXLAN_L2_ENCAP_INPUT_PACKET_1 = \
        S.Ether(dst=vxlan_l2_single_port.VXLAN_DST_MAC.addr_str,
                src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str) / \
        S.IPv6() / \
        S.TCP()

    VXLAN_L2_ENCAP_INPUT_PACKET_2 = \
        S.Ether(dst=vxlan_l2_single_port.VXLAN_DST_MAC.addr_str,
                src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str,
                type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IPv6() / \
        S.TCP()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_l2_encap(self):
        self.single_port_setup()
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV6_UC)
        self.single_port_destroy()


if __name__ == '__main__':
    unittest.main()
