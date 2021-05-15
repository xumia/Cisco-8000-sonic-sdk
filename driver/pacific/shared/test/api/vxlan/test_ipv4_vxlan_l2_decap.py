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
from vxlan_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class vxlan_l2_decap(vxlan_l2_single_port):
    underlay_ip_impl = ip_test_base.ipv4_test_base
    # packet comes in at tx_l3_ac_def and goes out at tx_l2_ac_port_def
    VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = \
        S.Ether(dst=vxlan_l2_single_port.L2_DST_MAC.addr_str,
                src=vxlan_l2_single_port.L2_SRC_MAC.addr_str) / \
        S.IP() / \
        S.TCP()

    VXLAN_L2_BCAST_DECAP_EXPECTED_OUTPUT_PACKET = \
        S.Ether(dst=vxlan_l2_single_port.L2_BCAST_MAC.addr_str,
                src=vxlan_l2_single_port.L2_SRC_MAC.addr_str,
                type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=0) / \
        S.ARP(op='who-has')

    VXLAN_L2_UCAST_DECAP_EXPECTED_OUTPUT_PACKET = \
        S.Ether(dst=vxlan_l2_single_port.L2_UCAST_MAC.addr_str,
                src=vxlan_l2_single_port.L2_SRC_MAC.addr_str) / \
        S.IP() / \
        S.TCP()

    VXLAN_L2_MCAST_DECAP_EXPECTED_OUTPUT_PACKET = \
        S.Ether(dst=vxlan_l2_single_port.L2_MCAST_MAC.addr_str,
                src=vxlan_l2_single_port.L2_SRC_MAC.addr_str) / \
        S.IP() / \
        S.TCP()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_l2_decap(self):
        self.single_port_setup()
        self._test_vxlan_l2_decap()
        self.create_overlay_l2_mc_group()
        self.setup_snoop()
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = self.VXLAN_L2_BCAST_DECAP_EXPECTED_OUTPUT_PACKET
        self._test_vxlan_l2_decap_bcast()
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = self.VXLAN_L2_UCAST_DECAP_EXPECTED_OUTPUT_PACKET
        self._test_vxlan_l2_decap_ucast()
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = self.VXLAN_L2_MCAST_DECAP_EXPECTED_OUTPUT_PACKET
        self._test_vxlan_l2_decap_mcast()
        self.snoop_destroy()
        self.destroy_overlay_l2_mc_group()
        self.single_port_destroy()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_l2_decap_ucast_encap_decap(self):
        self.single_port_setup(tunnel_mode.ENCAP_DECAP)
        self._test_vxlan_l2_decap()
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_l2_decap_ucast_decap_only(self):
        self.single_port_setup(tunnel_mode.DECAP_ONLY)
        self.set_vxlan_dip(self.VXLAN_DIP_ANY.addr_str)
        self._test_vxlan_l2_decap()
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l2_decap_bum_her_encap_decap(self):
        self.single_port_setup(tunnel_mode.ENCAP_DECAP)
        self.l2_mcast_group_ovl(False)
        self.setup_snoop()
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = self.VXLAN_L2_BCAST_DECAP_EXPECTED_OUTPUT_PACKET
        # need to set filter group on vxlan port to pass
        self._test_vxlan_l2_decap_bcast()
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = self.VXLAN_L2_UCAST_DECAP_EXPECTED_OUTPUT_PACKET
        self._test_vxlan_l2_decap_ucast()
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = self.VXLAN_L2_MCAST_DECAP_EXPECTED_OUTPUT_PACKET
        self._test_vxlan_l2_decap_mcast()
        self.snoop_destroy()
        self.destroy_l2_mcast_group_ovl(False)
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l2_decap_bum_her_decap_only(self):
        self.single_port_setup(tunnel_mode.DECAP_ONLY)
        self.l2_mcast_group_ovl(False)
        self.setup_snoop()
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = self.VXLAN_L2_BCAST_DECAP_EXPECTED_OUTPUT_PACKET
        self._test_vxlan_l2_decap_bcast()
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = self.VXLAN_L2_UCAST_DECAP_EXPECTED_OUTPUT_PACKET
        self._test_vxlan_l2_decap_ucast()
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET = self.VXLAN_L2_MCAST_DECAP_EXPECTED_OUTPUT_PACKET
        self._test_vxlan_l2_decap_mcast()
        self.snoop_destroy()
        self.destroy_l2_mcast_group_ovl(False)
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l2_mcast_decap_ulay_decap_only_with_flooding(self):
        self.create_recycle_ac_port()
        self.set_vxlan_sip_prefix(vxlan_l2_single_port.VXLAN_MCAST_DIP.addr_str, 4)
        self.single_port_setup(tunnel_mode.DECAP_ONLY, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.l2_mcast_group_ovl(True)
        self.setup_snoop()
        self._test_vxlan_l2_mcast_decap_und()
        self._test_vxlan_l2_mcast_decap_und_bcast()
        self.snoop_destroy()
        self.destroy_l2_mcast_group_ovl(True)
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l2_mcast_decap_ulay_decap_only_with_mrouter(self):
        self.create_recycle_ac_port()
        self.set_vxlan_sip_prefix(vxlan_l2_single_port.VXLAN_MCAST_DIP.addr_str, 4)
        self.single_port_setup(tunnel_mode.DECAP_ONLY, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.set_l2_multicast(True)
        self.set_ingress_rep(False)
        self.l2_mcast_group_ovl(True)
        self.setup_snoop()
        self._test_vxlan_l2_mcast_decap_und()
        self._test_vxlan_l2_mcast_decap_und_bcast()
        self.snoop_destroy()
        self.destroy_l2_mcast_group_ovl(True)
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_l2_mcast_decap_ulay_decap_only_with_snooping(self):
        self.create_recycle_ac_port()
        self.set_vxlan_sip_prefix(vxlan_l2_single_port.VXLAN_MCAST_DIP.addr_str, 4)
        self.single_port_setup(tunnel_mode.DECAP_ONLY, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.set_l2_multicast(True)
        self.set_ingress_rep(False)
        self.l2_mcast_group_ovl(True)
        self.setup_snoop()
        self._test_vxlan_l2_mcast_decap_und()
        self._test_vxlan_l2_mcast_decap_und_bcast()
        self.snoop_destroy()
        self.destroy_l2_mcast_group_ovl(True)
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_vxlan_l2_mcast_decap_ulay_decap_only_with_ir(self):
        self.create_recycle_ac_port()
        self.set_vxlan_sip_prefix(vxlan_l2_single_port.VXLAN_MCAST_DIP.addr_str, 4)
        self.single_port_setup(tunnel_mode.DECAP_ONLY, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.set_ingress_rep(True)
        self.l2_mcast_group_ovl(True)
        self.setup_snoop()
        self._test_vxlan_l2_mcast_decap_und()
        self._test_vxlan_l2_mcast_decap_und_bcast()
        self.snoop_destroy()
        self.destroy_l2_mcast_group_ovl(True)
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)
        self.destroy_recycle_ac_port()


if __name__ == '__main__':
    unittest.main()
