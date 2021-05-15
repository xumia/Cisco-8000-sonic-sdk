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
from scapy.all import *
from lc_multicast_base import *
import unittest
from leaba import sdk
import ip_test_base
import topology as T
import time
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class egress_lc_multicast(lc_multicast_base):

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_lc_multicast(self):
        vrf = T.vrf(self, self.device, 0)
        ac_profile = T.ac_profile(self, self.device)

        # Create rx fabric port
        out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            5,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)

        out_rx_fabric_mac_port.hld_obj.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_PMA_CORE_CLK)
        out_rx_fabric_mac_port.hld_obj.activate()
        time.sleep(2)

        out_rx_fabric_port = T.fabric_port(self, self.device, out_rx_fabric_mac_port)
        # needed for running on stingray
#        out_rx_fabric_port.hld_obj.activate(sdk.la_fabric_port.link_protocol_e_PEER_DISCOVERY)
#        out_rx_fabric_port.hld_obj.activate(sdk.la_fabric_port.link_protocol_e_LINK_KEEPALIVE)
        out_rx_fabric_port.hld_obj.set_reachable_lc_devices([self.device.device.get_id()])

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

        out_l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        out_l3_ac = T.l3_ac_port(self, self.device,
                                 GID_BASE + 1,
                                 out_tx_eth_port,
                                 vrf,
                                 out_l3_port_mac)
        out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        self.device.set_int_property(sdk.la_device_property_e_MULTICAST_MCID_SCALE_THRESHOLD, MC_TEST_THRESHOLD)

        # create the multicast group
        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(out_l3_ac.hld_obj, None, out_tx_eth_port.sys_port.hld_obj)

        # add the multicast route
        vrf.hld_obj.add_ipv4_multicast_route(
            self.mc_sip.hld_obj, self.mc_group_addr.hld_obj, self.mc_group, None, False, False, None)

        run_and_compare(
            self,
            self.device,
            self.egress_rx_pkt,
            5,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            self.egress_tx_pkt,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST)


if __name__ == '__main__':
    unittest.main()
