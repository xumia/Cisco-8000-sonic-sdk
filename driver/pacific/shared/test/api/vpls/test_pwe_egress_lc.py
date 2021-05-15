#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from packet_test_utils import *
from scapy.all import *
from pwe_lc_base import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import nplapicli as nplapi


@unittest.skipIf(decor.is_hw_device(), "LC tests don't work on hardware.")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class egress_lc_pwe_vpls(pwe_vpls_lc_base):

    PREFIX1_GID = 0x691

    PWE_TTL = 0xff  # Set by the SDK

    LDP_LABEL = sdk.la_mpls_label()
    LDP_LABEL.label = 0x64

    PWE_LOCAL_LABEL = sdk.la_mpls_label()
    PWE_LOCAL_LABEL.label = 0x62
    PWE_REMOTE_LABEL = sdk.la_mpls_label()
    PWE_REMOTE_LABEL.label = 0x63

    PWE_PORT_GID = 0x4000
    PWE_GID = 0x25

    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

    RCY_LABEL = sdk.la_mpls_label()
    RCY_LABEL.label = 0xf0065

    RECYCLE_PORT_MAC = T.mac_addr('00:11:22:33:44:55')
    RCY_DST_MAC = T.mac_addr('07:66:77:88:99:aa')

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_lc_pwe_mac_forwarding(self):

        self.create_packets()

        vrf = T.vrf(self, self.device, VRF_GID)

        sw = T.switch(self, self.device, SWITCH_GID)
        ac_profile = T.ac_profile(self, self.device)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        dest_mac = T.mac_addr(DST_MAC)

        # Create rx fabric port
        out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)
        out_rx_fabric_port = T.fabric_port(self, self.device, out_rx_fabric_mac_port)

        # Create tx network port
        out_tx_eth_port = T.ethernet_port(
            self,
            self.device,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_SYS_PORT_GID,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)
        out_tx_eth_port.set_ac_profile(ac_profile)

        # Create l3 AC port
        l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        l3_ac = T.l3_ac_port(self, self.device,
                             GID_BASE + 1,
                             out_tx_eth_port,
                             vrf,
                             l3_port_mac,
                             T.RX_L3_AC_PORT_VID1,
                             T.RX_L3_AC_PORT_VID2)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        nh_l3_ac_reg = T.next_hop(self, self.device, GID_BASE + 2, T.NH_L3_AC_REG_MAC, l3_ac)

        pfx_obj_vpls = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_l3_ac_reg.hld_obj)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)
        pfx_obj_vpls.hld_obj.set_nh_lsp_properties(nh_l3_ac_reg.hld_obj,
                                                   lsp_labels,
                                                   None,
                                                   sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        pwe_port = T.l2_pwe_port(self, self.device, self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                 self.PWE_REMOTE_LABEL, self.PWE_GID, pfx_obj_vpls.hld_obj)
        pwe_port.hld_obj.set_ac_profile_for_pwe(ac_profile.hld_obj)
        pwe_port.hld_obj.attach_to_switch(sw.hld_obj)
        sw.hld_obj.set_mac_entry(dest_mac.hld_obj, pwe_port.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        run_and_compare(
            self,
            self.device,
            self.egress_rx_pkt,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            self.egress_tx_pkt,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_lc_pwe_flood(self):

        self.create_packets_flood()

        vrf = T.vrf(self, self.device, VRF_GID)

        sw = T.switch(self, self.device, SWITCH_GID)
        ac_profile = T.ac_profile(self, self.device)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        dest_mac = T.mac_addr(DST_MAC)

        # Create rx fabric port
        out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)
        out_rx_fabric_port = T.fabric_port(self, self.device, out_rx_fabric_mac_port)

        # Create Recycle Port
        default_slice = T.get_device_slice(1)
        slice_for_recycle = T.choose_active_slices(self.device, default_slice, [1, 3, 5])
        self.recycle_sys_port = self.topology.recycle_ports[slice_for_recycle].sys_port.hld_obj

        self.recycle_eth_port = self.device.create_ethernet_port(
            self.recycle_sys_port,
            sdk.la_ethernet_port.port_type_e_AC)
        self.recycle_eth_port.set_ac_profile(self.topology.ac_profile_def.hld_obj)

        self.recycle_l3_ac_port = self.device.create_l3_ac_port(
            T.RX_L3_AC_GID + 0x200,
            self.recycle_eth_port,
            0x567,
            0,
            self.RECYCLE_PORT_MAC.hld_obj,
            vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        self.recycle_nh = self.device.create_next_hop(
            T.NH_L3_AC_REG_GID + 0x100,
            self.RECYCLE_PORT_MAC.hld_obj,
            self.recycle_l3_ac_port,
            sdk.la_next_hop.nh_type_e_NORMAL)
        # self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = 0x567

        self.recycle_l3_ac_port.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        # Create tx network port
        out_tx_eth_port = T.ethernet_port(
            self,
            self.device,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_SYS_PORT_GID,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)
        out_tx_eth_port.set_ac_profile(ac_profile)

        # Create L3 AC
        l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        l3_ac = T.l3_ac_port(self, self.device,
                             GID_BASE + 1,
                             out_tx_eth_port,
                             vrf,
                             l3_port_mac,
                             T.RX_L3_AC_PORT_VID1,
                             T.RX_L3_AC_PORT_VID2)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        nh_l3_ac_reg = T.next_hop(self, self.device, GID_BASE + 2, T.NH_L3_AC_REG_MAC, l3_ac)

        pfx_obj_vpls = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_l3_ac_reg.hld_obj)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)
        pfx_obj_vpls.hld_obj.set_nh_lsp_properties(nh_l3_ac_reg.hld_obj,
                                                   lsp_labels,
                                                   None,
                                                   sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsp_labels = []
        lsp_labels.append(self.RCY_LABEL)

        pfx_obj_vpls.hld_obj.set_nh_lsp_properties(self.recycle_nh,
                                                   lsp_labels,
                                                   None,
                                                   sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.lsr = self.device.get_lsr()
        self.lsr.add_route(self.RCY_LABEL, vrf.hld_obj, pfx_obj_vpls.hld_obj, self.PRIVATE_DATA)

        pwe_port = T.l2_pwe_port(self, self.device, self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                 self.PWE_REMOTE_LABEL, self.PWE_GID, pfx_obj_vpls.hld_obj)
        pwe_port.hld_obj.set_ac_profile_for_pwe(ac_profile.hld_obj)
        pwe_port.hld_obj.set_pwe_multicast_recycle_lsp_properties(self.RCY_LABEL, self.recycle_nh)
        pwe_port.hld_obj.attach_to_switch(sw.hld_obj)

        mc_group = self.device.create_l2_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)

        sw.hld_obj.set_flood_destination(mc_group)
        mc_group.add(pwe_port.hld_obj, self.recycle_sys_port)

        run_and_compare(
            self,
            self.device,
            self.egress_rx_pkt,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            self.egress_tx_pkt,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST)


if __name__ == '__main__':
    unittest.main()
