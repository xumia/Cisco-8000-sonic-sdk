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

from packet_test_utils import *
import decor
from scapy.all import *
from erspan_lc_base import *
import unittest
from leaba import sdk
import ip_test_base
import topology as T


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class ingress_erspan_lc(erspan_lc_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_erspan_lc(self):
        ip_impl = ip_test_base.ipv4_test_base()
        vrf = T.vrf(self, self.device, VRF_GID)
        ac_profile = T.ac_profile(self, self.device)

        in_rx_eth_port = T.ethernet_port(
            self,
            self.device,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            SYS_PORT_GID_BASE,
            INGRESS_RX_SERDES_FIRST,
            INGRESS_RX_SERDES_LAST)
        in_rx_eth_port.set_ac_profile(ac_profile)

        in_l3_port_mac = T.mac_addr(IN_L3_AC_PORT_MAC)
        self.in_l3_ac = T.l3_ac_port(self, self.device,
                                     GID_BASE,
                                     in_rx_eth_port,
                                     vrf,
                                     in_l3_port_mac,
                                     T.RX_L3_AC_PORT_VID1,
                                     T.RX_L3_AC_PORT_VID2)
        self.in_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.in_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

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

        nh_l3_ac_reg = T.next_hop(self, self.device, GID_BASE + 2, T.NH_L3_AC_REG_MAC, remote_l3_ac)

        prefix = ip_impl.build_prefix(DIP, length=16)
        ip_impl.add_route(vrf, prefix, nh_l3_ac_reg, PRIVATE_DATA)

        erspan_counter = self.device.create_counter(1)
        mirror_cmd = T.erspan_mirror_command(
            self,
            self.device, MIRROR_CMD_INGRESS_GID,
            SESSION_ID,
            T.NH_L3_AC_REG_MAC.addr_str,
            TUNNEL_DEST,
            TUNNEL_SOURCE,
            TUNNEL_TTL,
            TUNNEL_DSCP,
            TRAFFIC_CLASS,
            remote_l3_ac.hld_obj,
            None,
            remote_sys_port.hld_obj)
        mirror_cmd.hld_obj.set_counter(erspan_counter)

        self.in_packet = {
            'data': self.ingress_rx_pkt,
            'slice': INGRESS_RX_SLICE,
            'ifg': INGRESS_RX_IFG,
            'pif': INGRESS_RX_SERDES_FIRST}

        self.out_packet_data = {
            'data': self.ingress_tx_pkt,
            'slice': INGRESS_TX_SLICE,
            'ifg': INGRESS_TX_IFG,
            'pif': INGRESS_TX_SERDES_FIRST}

        self.span_packet_data = {
            'data': self.ingress_tx_erspan_pkt,
            'slice': INGRESS_TX_SLICE,
            'ifg': INGRESS_TX_IFG,
            'pif': INGRESS_TX_SERDES_FIRST}

        self.in_l3_ac.hld_obj.set_ingress_mirror_command(mirror_cmd.hld_obj, is_acl_conditioned=False)
        run_and_compare_list(self, self.device, self.in_packet, [self.out_packet_data, self.span_packet_data], TS_PLB)


if __name__ == '__main__':
    unittest.main()
