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
class egress_lc_l2_switch_flooding(lc_l2_switch_mc_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_lc_l2_switch_flooding(self):
        sw = T.switch(self, self.device, SWITCH_GID)
        ac_profile = T.ac_profile(self, self.device)

        # Create fabric port
        out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)
        out_rx_fabric_port = T.fabric_port(self, self.device, out_rx_fabric_mac_port)

        out_tx_eth_port = T.ethernet_port(
            self,
            self.device,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            SYS_PORT_GID_BASE,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)
        out_tx_eth_port.set_ac_profile(ac_profile)
        out_tx_ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            sw,
            out_tx_eth_port,
            None,
            VLAN,
            0x0)

        mc_group = self.device.create_l2_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)
        mc_group.add(out_tx_ac_port.hld_obj, out_tx_eth_port.sys_port.hld_obj)

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
            EGRESS_TX_SERDES_FIRST,
            Ether)


if __name__ == '__main__':
    unittest.main()
