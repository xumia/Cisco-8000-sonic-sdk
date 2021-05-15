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
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class vxlan_l3_encap(vxlan_l2_single_port):
    underlay_ip_impl = ip_test_base.ipv4_test_base
    OVL_DIP = '21.1.1.1'
    OVL_DIP_ROUTE = T.ipv4_addr(OVL_DIP)

    OVL_DIP_1 = '31.1.1.1'
    OVL_DIP_ROUTE_1 = T.ipv4_addr(OVL_DIP_1)

    OVL_SIP = '10.1.1.1'
    OVL_SIP_ROUTE = T.ipv4_addr(OVL_SIP)

    L3VXLAN_IP_PACKET = \
        S.IP(dst=OVL_DIP_1,
             src=OVL_SIP,
             id=0,
             flags=2,
             ttl=vxlan_base.INNER_TTL) / \
        S.TCP()

    if decor.is_asic4():
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
    def test_vxlan_l3_encap(self):
        self.create_recycle_ac_port()
        self.single_port_setup()
        self.l3vxlan_setup()
        self._test_vxlan_l3_encap()
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV4_UC)
        self.setup_ecmp()
        self._test_vxlan_l3_encap()
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV4_UC)
        self.l3vxlan_destroy()
        self.single_port_destroy()
        self.destroy_recycle_ac_port()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_l3_encap_ucast_encap_decap(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.ENCAP_DECAP)
        self.l3vxlan_setup()
        self._test_vxlan_l3_encap()
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV4_UC)
        self.setup_ecmp()
        self._test_vxlan_l3_encap()
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV4_UC)
        self.l3vxlan_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_l3_encap_ucast_encap_only(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.ENCAP_ONLY)
        self.l3vxlan_setup()
        self._test_vxlan_l3_encap()
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV4_UC)
        self.setup_ecmp()
        self._test_vxlan_l3_encap()
        self._test_vxlan_l2_encap(sdk.la_l3_protocol_e_IPV4_UC)
        self.l3vxlan_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l3_mcast_encap_her_encap_decap(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.ENCAP_DECAP, True)
        self.l3vxlan_setup()
        self.l3_mcast_group_ovl(False)
        self._test_vxlan_l3_mcast_encap_her()
        self._test_vxlan_l3_mcast_encap_her_collapsed_mc()
        self.destroy_l3_mcast_group_ovl(False)
        self.l3vxlan_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l3_mcast_encap_her_encap_decap_with_ir(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.ENCAP_DECAP, True)
        self.l3vxlan_setup()
        self.set_ingress_rep(True)
        self.l3_mcast_group_ovl(False)
        self._test_vxlan_l3_mcast_encap_her()
        self._test_vxlan_l3_mcast_encap_her_collapsed_mc()
        self.destroy_l3_mcast_group_ovl(False)
        self.l3vxlan_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l3_mcast_encap_her_encap_only(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.ENCAP_ONLY, True)
        self.l3vxlan_setup()
        self.l3_mcast_group_ovl(False)
        self._test_vxlan_l3_mcast_encap_her()
        self._test_vxlan_l3_mcast_encap_her_collapsed_mc()
        self.destroy_l3_mcast_group_ovl(False)
        self.l3vxlan_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l3_mcast_encap_her_encap_only_with_ir(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.ENCAP_ONLY, True)
        self.l3vxlan_setup()
        self.set_ingress_rep(True)
        self.l3_mcast_group_ovl(False)
        self._test_vxlan_l3_mcast_encap_her()
        self._test_vxlan_l3_mcast_encap_her_collapsed_mc()
        self.destroy_l3_mcast_group_ovl(False)
        self.l3vxlan_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l3_mcast_encap_ulay_encap_only(self):
        self.create_recycle_ac_port()
        self.set_vxlan_dip(self.UND_MC_GROUP_ADDR.addr_str)
        self.single_port_setup(tunnel_mode.ENCAP_ONLY, True)
        self.l3vxlan_setup()
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, False)
        self.l3_mcast_group_ovl(True)
        self._test_vxlan_l3_mcast_encap_und_collapsed_mc()
        self.destroy_l3_mcast_group_ovl(True)
        self.l3vxlan_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l3_mcast_encap_ulay_encap_only_with_ir(self):
        self.create_recycle_ac_port()
        self.set_vxlan_dip(self.UND_MC_GROUP_ADDR.addr_str)
        self.single_port_setup(tunnel_mode.ENCAP_ONLY, True)
        self.l3vxlan_setup()
        self.set_ingress_rep(True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, False)
        self.l3_mcast_group_ovl(True)
        self._test_vxlan_l3_mcast_encap_und_collapsed_mc()
        self.destroy_l3_mcast_group_ovl(True)
        self.l3vxlan_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_ONLY)
        self.destroy_recycle_ac_port()


if __name__ == '__main__':
    unittest.main()
