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
class ingress_lc_pwe_vpls(pwe_vpls_lc_base):

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

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_lc_pwe_mac_forwarding(self):

        self.create_packets()

        vrf = T.vrf(self, self.device, VRF_GID)

        sw = T.switch(self, self.device, SWITCH_GID)
        ac_profile = T.ac_profile(self, self.device)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        dest_mac = T.mac_addr(DST_MAC)

        in_rx_eth_port = T.ethernet_port(
            self,
            self.device,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            SYS_PORT_GID_BASE,
            INGRESS_RX_SERDES_FIRST,
            INGRESS_RX_SERDES_LAST)
        in_rx_eth_port.set_ac_profile(ac_profile)
        in_rx_ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            sw,
            in_rx_eth_port,
            None,
            VLAN,
            0x0)

        # Create fabric port
        in_tx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            INGRESS_TX_SERDES_LAST)
        in_tx_fabric_port = T.fabric_port(self, self.device, in_tx_fabric_mac_port)

        # Manually set reachability to egress device
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)
        reachable_devices = []
        reachable_devices.append(EGRESS_DEVICE_ID)
        in_tx_fabric_port.hld_obj.set_reachable_lc_devices(reachable_devices)

        # Create remote port
        remote_port = T.remote_port(
            self,
            self.device,
            EGRESS_DEVICE_ID,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)

        # Create remote system port above the remote port
        remote_sys_port = T.system_port(self, self.device, EGRESS_SYS_PORT_GID, remote_port)

        # Create remote ethernet port above the remote system port
        remote_eth_port = T.sa_ethernet_port(self, self.device, remote_sys_port, ac_profile)

        # Create remote AC port above the remote ethernet
        remote_l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        remote_l3_ac = T.l3_ac_port(self, self.device,
                                    GID_BASE + 1,
                                    remote_eth_port,
                                    vrf,
                                    remote_l3_port_mac)
        remote_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        remote_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        remote_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        nh_l3_ac_reg = T.next_hop(self, self.device, GID_BASE + 2, T.NH_L3_AC_REG_MAC, remote_l3_ac)

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
            self.ingress_rx_pkt,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            INGRESS_RX_SERDES_FIRST,
            self.ingress_tx_pkt,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            TS_PLB)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_lc_pwe_flood(self):

        self.create_packets_flood()

        vrf = T.vrf(self, self.device, VRF_GID)

        sw = T.switch(self, self.device, SWITCH_GID)
        ac_profile = T.ac_profile(self, self.device)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        dest_mac = T.mac_addr(DST_MAC)

        in_rx_eth_port = T.ethernet_port(
            self,
            self.device,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            SYS_PORT_GID_BASE,
            INGRESS_RX_SERDES_FIRST,
            INGRESS_RX_SERDES_LAST)
        in_rx_eth_port.set_ac_profile(ac_profile)
        in_rx_ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            sw,
            in_rx_eth_port,
            None,
            VLAN,
            0x0)

        # Create fabric port
        in_tx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            INGRESS_TX_SERDES_LAST)
        in_tx_fabric_port = T.fabric_port(self, self.device, in_tx_fabric_mac_port)

        # Manually set reachability to egress device
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)
        reachable_devices = []
        reachable_devices.append(EGRESS_DEVICE_ID)
        in_tx_fabric_port.hld_obj.set_reachable_lc_devices(reachable_devices)

        # Create remote port
        remote_port = T.remote_port(
            self,
            self.device,
            EGRESS_DEVICE_ID,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)

        # Create remote system port above the remote port
        remote_sys_port = T.system_port(self, self.device, EGRESS_SYS_PORT_GID, remote_port)

        # Create remote ethernet port above the remote system port
        remote_eth_port = T.sa_ethernet_port(self, self.device, remote_sys_port, ac_profile)

        # Create remote AC port above the remote ethernet
        remote_l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        remote_l3_ac = T.l3_ac_port(self, self.device,
                                    GID_BASE + 1,
                                    remote_eth_port,
                                    vrf,
                                    remote_l3_port_mac)
        remote_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        remote_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        remote_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        nh_l3_ac_reg = T.next_hop(self, self.device, GID_BASE + 2, T.NH_L3_AC_REG_MAC, remote_l3_ac)

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

        mc_group = self.device.create_l2_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)
        sw.hld_obj.set_flood_destination(mc_group)

        run_and_compare(
            self,
            self.device,
            self.ingress_rx_pkt,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            INGRESS_RX_SERDES_FIRST,
            self.ingress_tx_pkt,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            TS_PLB)


if __name__ == '__main__':
    unittest.main()
