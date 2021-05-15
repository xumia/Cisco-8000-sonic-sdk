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
from vxlan_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class sda_decap(vxlan_l2_single_port):
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

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_sda_decap_ucast(self):
        self.create_recycle_ac_port()
        self.single_port_setup()
        self.sda_setup()
        self._test_vxlan_sda_decap()
        self.sda_destroy()
        self.single_port_destroy()
        self.destroy_recycle_ac_port()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_sda_decap_ucast_encap_decap(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.ENCAP_DECAP)
        self.sda_setup()
        self._test_vxlan_sda_decap()
        self.sda_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_sda_decap_ucast_decap_only(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.DECAP_ONLY)
        self.set_vxlan_dip(self.VXLAN_DIP_ANY.addr_str)
        self.sda_setup()
        self._test_vxlan_sda_decap()
        self.sda_destroy()
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_sda_decap_mcast_her_encap_decap(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.ENCAP_DECAP, True)
        self.sda_setup()
        self.l3_mcast_group_ovl(False)
        self.setup_snoop()
        # This needs split horizon config on RCY L3 AC
        self._test_vxlan_l3_mcast_decap_her()
        self.snoop_destroy()
        self.destroy_l3_mcast_group_ovl(False)
        self.sda_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_sda_decap_mcast_her_encap_decap_with_ir(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.ENCAP_DECAP, True)
        self.sda_setup()
        self.set_ingress_rep(True)
        self.l3_mcast_group_ovl(False)
        self.setup_snoop()
        # need split horizon fix - phase2
        # self._test_vxlan_l3_mcast_decap_her()
        self.snoop_destroy()
        self.destroy_l3_mcast_group_ovl(False)
        self.sda_destroy()
        self.single_port_destroy(tunnel_mode.ENCAP_DECAP)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_sda_decap_mcast_her_decap_only(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.DECAP_ONLY, True)
        self.set_vxlan_dip(self.VXLAN_DIP_ANY.addr_str)
        self.sda_setup()
        self.l3_mcast_group_ovl(False)
        self.setup_snoop()
        self._test_vxlan_l3_mcast_decap_her()
        self.snoop_destroy()
        self.destroy_l3_mcast_group_ovl(False)
        self.sda_destroy()
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_sda_decap_mcast_her_decap_only_with_ir(self):
        self.create_recycle_ac_port()
        self.single_port_setup(tunnel_mode.DECAP_ONLY, True)
        self.set_vxlan_dip(self.VXLAN_DIP_ANY.addr_str)
        self.sda_setup()
        self.set_ingress_rep(True)
        self.l3_mcast_group_ovl(False)
        self.setup_snoop()
        self._test_vxlan_l3_mcast_decap_her()
        self.snoop_destroy()
        self.destroy_l3_mcast_group_ovl(False)
        self.sda_destroy()
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_sda_mcast_decap_ulay_decap_only(self):
        self.create_recycle_ac_port()
        self.set_vxlan_sip_prefix(self.L3MC_GROUP_ADDR.addr_str, 32)
        self.single_port_setup(tunnel_mode.DECAP_ONLY, True)
        self.sda_setup()
        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.l3_mcast_group_ovl(True)
        self._test_vxlan_l3_mcast_decap_und()
        self.destroy_l3_mcast_group_ovl(True)
        self.sda_destroy()
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic4()), "Run only on GB and PL")
    def test_vxlan_sda_mcast_decap_ulay_decap_only_with_ir(self):
        self.create_recycle_ac_port()
        self.set_vxlan_sip_prefix(self.L3MC_GROUP_ADDR.addr_str, 32)
        self.single_port_setup(tunnel_mode.DECAP_ONLY, True)
        self.sda_setup()
        self.set_ingress_rep(True)
        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_MC_TUNNEL_DECAP, True)
        self.l3_mcast_group_ovl(True)
        self._test_vxlan_l3_mcast_decap_und()
        self.destroy_l3_mcast_group_ovl(True)
        self.sda_destroy()
        self.single_port_destroy(tunnel_mode.DECAP_ONLY)
        self.destroy_recycle_ac_port()

    @unittest.skipIf(True, "Skipping now, as on GB WB its failing, will add later.")
    @unittest.skipIf(not decor.is_gibraltar(), "Test is enabled only on GB")
    def test_vxlan_sda_decap_with_ip_inactivity(self):
        self.create_recycle_ac_port()
        self.single_port_setup()
        self.sda_setup()
        self.setup_snoop()
        self._test_vxlan_sda_decap_with_ip_inactivity()
        self.snoop_destroy()
        self.sda_destroy()
        self.single_port_destroy()
        self.destroy_recycle_ac_port()


if __name__ == '__main__':
    unittest.main()
