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
from vlan_vlan_with_fallback_base import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class no_fallback(vlan_vlan_with_fallback_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_no_fallback(self):
        INPUT_PACKET_BASE = Ether(dst=self.DST_MAC, src=self.SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(prio=2, id=1, vlan=self.RX_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=self.RX_AC_PORT_VID2) / \
            IP() / TCP()

        EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=self.DST_MAC, src=self.SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(prio=2, id=1, vlan=self.RX_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=self.RX_AC_PORT_VID2) / \
            IP() / TCP()

        INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

        rx_ac_port = T.l2_ac_port(
            self,
            self.device,
            self.RX_AC_PORT_GID,
            self.topology.filter_group_def,
            None,
            self.rx_eth_port,
            None,
            self.RX_AC_PORT_VID1,
            self.RX_AC_PORT_VID2)

        rx_ac_port.hld_obj.set_destination(self.topology.tx_l2_ac_port_reg.hld_obj)

        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, self.RX_SERDES_FIRST,
                        EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_SVI_REG)


if __name__ == '__main__':
    unittest.main()
