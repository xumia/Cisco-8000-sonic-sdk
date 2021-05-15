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
import packet_test_utils as U
import sim_utils
from scapy.all import *
from l2_mirror_lc_base import *
import unittest
from leaba import sdk
import ip_test_base
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class egress_l2_mirror_lc(l2_mirror_lc_base):

    @unittest.skipIf(decor.is_hw_device(), "Test cannot work on HW device")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_l2_mirror_lc(self):
        ip_impl = ip_test_base.ipv4_test_base()
        vrf = T.vrf(self, self.device, VRF_GID)
        ac_profile = T.ac_profile(self, self.device)

        # Create rx fabric port
        out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)
        out_rx_fabric_port = T.fabric_port(self, self.device, out_rx_fabric_mac_port)

        # Create tx mac port
        out_tx_mac_port = T.mac_port(
            self,
            self.device,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)

        # Create tx system port above the mac port
        out_tx_sys_port = T.system_port(self, self.device, EGRESS_SYS_PORT_GID, out_tx_mac_port)

        # Create tx ethernet port above the system port
        out_tx_eth_port = T.sa_ethernet_port(self, self.device, out_tx_sys_port, ac_profile)

        out_l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        out_l3_ac = T.l3_ac_port(self, self.device,
                                 GID_BASE + 1,
                                 out_tx_eth_port,
                                 vrf,
                                 out_l3_port_mac)
        out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        nh_l3_ac_reg = T.next_hop(self, self.device, GID_BASE + 2, T.NH_L3_AC_REG_MAC, out_l3_ac)

        prefix = ip_impl.build_prefix(DIP, length=16)
        ip_impl.add_route(vrf, prefix, nh_l3_ac_reg, PRIVATE_DATA)

        l2_mirror_counter = self.device.create_counter(1)
        mirror_cmd = self.device.create_l2_mirror_command(
            MIRROR_CMD_EGRESS_GID,
            out_tx_eth_port.hld_obj,
            out_tx_sys_port.hld_obj,
            TRAFFIC_CLASS,
            1)
        mirror_cmd.set_counter(l2_mirror_counter)

        # ingress
        # mirror_cmd = self.device.create_l2_mirror_command(
        #     MIRROR_CMD_INGRESS_GID,
        #     out_tx_eth_port.hld_obj,
        #     out_tx_sys_port.hld_obj,
        #     TRAFFIC_CLASS,
        #     1)

        # Only here to test all the "transmitted" packets by the equivalent LC ingress test
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

        run_and_compare(
            self,
            self.device,
            self.egress_rx_l2_mirror_pkt,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            self.egress_tx_l2_mirror_pkt,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST)

        packet_count, byte_count = l2_mirror_counter.read(0, True, True)
        mirror_cmd.set_counter(None)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.ingress_rx_pkt, byte_count)


if __name__ == '__main__':
    unittest.main()
