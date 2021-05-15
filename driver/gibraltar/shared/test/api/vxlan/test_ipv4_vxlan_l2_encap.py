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
import ip_test_base
from vxlan_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class vxlan_l2_encap(vxlan_l2_single_port):
    underlay_ip_impl = ip_test_base.ipv4_test_base
    if(decor.is_asic4()):
        VXLAN_L2_ENCAP_INPUT_PACKET_1 = \
            S.Ether(dst=vxlan_l2_single_port.VXLAN_DST_MAC.addr_str,
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str) / \
            S.IP(dst='192.168.1.2',
                 src='192.168.1.1') / \
            S.TCP()

        VXLAN_L2_ENCAP_INPUT_PACKET_2 = \
            S.Ether(dst=vxlan_l2_single_port.VXLAN_DST_MAC.addr_str,
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(dst='192.168.1.2',
                 src='192.168.1.1') / \
            S.TCP()
    else:
        VXLAN_L2_ENCAP_INPUT_PACKET_1 = \
            S.Ether(dst=vxlan_l2_single_port.VXLAN_DST_MAC.addr_str,
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str) / \
            S.IP() / \
            S.TCP()

        VXLAN_L2_ENCAP_INPUT_PACKET_2 = \
            S.Ether(dst=vxlan_l2_single_port.VXLAN_DST_MAC.addr_str,
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP() / \
            S.TCP()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_l2_encap(self):
        self.single_port_setup()
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV4_UC)
        self.single_port_destroy()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_l2_encap_ucast_encap_decap(self):
        self.set_vxlan_dip(self.VXLAN_UC_DIP.addr_str)
        self.single_port_setup(tunnel_mode.ENCAP_DECAP)
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV4_UC)
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_l2_encap_ucast_encap_only(self):
        self.set_vxlan_dip(self.VXLAN_UC_DIP.addr_str)
        self.single_port_setup(tunnel_mode.ENCAP_ONLY)
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV4_UC)
        self.single_port_destroy(tunnel_mode.ENCAP_ONLY)

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l2_encap_mcast_her_encap_decap(self):
        self.single_port_setup(tunnel_mode.ENCAP_DECAP)
        self.l2_mcast_group_ovl(False)
        self.setup_snoop()
        self.set_l2_multicast(True)
        self._test_vxlan_l2_mcast_encap_her()
        self.set_l2_multicast(False)
        self._test_vxlan_l2_mcast_encap_arp_her()
        self._test_vxlan_l2_mcast_encap_ucast_her()
        self.snoop_destroy()
        self.destroy_l2_mcast_group_ovl(False)
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l2_encap_mcast_her_encap_only(self):
        self.single_port_setup(tunnel_mode.ENCAP_ONLY)
        self.l2_mcast_group_ovl(False)
        self.setup_snoop()
        self.set_l2_multicast(True)
        self._test_vxlan_l2_mcast_encap_her()
        self.set_l2_multicast(False)
        self._test_vxlan_l2_mcast_encap_arp_her()
        self._test_vxlan_l2_mcast_encap_ucast_her()
        self.snoop_destroy()
        self.destroy_l2_mcast_group_ovl(False)
        self.single_port_destroy(tunnel_mode.ENCAP_ONLY)

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l2_mcast_encap_ulay_encap_only(self):
        self.create_recycle_ac_port()
        self.set_vxlan_dip(self.UND_MC_GROUP_ADDR.addr_str)
        self.single_port_setup(tunnel_mode.ENCAP_ONLY, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, False)
        self.l2_mcast_group_ovl(True)
        self.set_l2_multicast(True)
        self._test_vxlan_l2_mcast_encap_und()
        self.destroy_l2_mcast_group_ovl(True)
        self.single_port_destroy(tunnel_mode.ENCAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(True, "Skip until the bug is fixed")
    def test_vxlan_l2_mcast_encap_ulay_encap_only_with_ir(self):
        self.create_recycle_ac_port()
        self.set_vxlan_dip(self.UND_MC_GROUP_ADDR.addr_str)
        self.single_port_setup(tunnel_mode.ENCAP_ONLY, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, False)
        self.set_ingress_rep(True)
        self.l2_mcast_group_ovl(True)
        self._test_vxlan_l2_mcast_encap_und()
        self.destroy_l2_mcast_group_ovl(True)
        self.single_port_destroy(tunnel_mode.ENCAP_ONLY)
        self.destroy_recycle_ac_port()


if __name__ == '__main__':
    unittest.main()
