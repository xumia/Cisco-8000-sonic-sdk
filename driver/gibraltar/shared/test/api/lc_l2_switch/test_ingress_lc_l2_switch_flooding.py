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
from lc_l2_switch_mc_base import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import nplapicli as nplapi


@unittest.skipIf(decor.is_hw_device() or decor.is_gibraltar(),
                 "LC tests don't work on hardware. Distributed MC on GB is not yet implemented for NSIM.")
class ingress_lc_l2_switch_flooding(lc_l2_switch_mc_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_lc_l2_switch_flooding(self):
        sw = T.switch(self, self.device, SWITCH_GID)
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
        in_tx_fabric_port.hld_obj.set_reachable_lc_devices([EGRESS_DEVICE_ID])

        mc_group = self.device.create_l2_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)
        sw.hld_obj.set_flood_destination(mc_group)

        # No need to add ports to MC group. The packets will automatically be sent into the fabric

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
