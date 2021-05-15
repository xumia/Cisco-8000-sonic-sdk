#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import pdb
from pfc_base import *
import unittest
import decor
from pfc_remote import *
from pfc_common import *

INGRESS_TX_SLICE = 4
INGRESS_TX_IFG = 1
INGRESS_TX_SERDES_FIRST = 2
INGRESS_TX_SERDES_LAST = INGRESS_TX_SERDES_FIRST + 1

EGRESS_TX_SLICE = 2
EGRESS_TX_IFG = 0
EGRESS_TX_SERDES_FIRST = 16
EGRESS_TX_SERDES_LAST = EGRESS_TX_SERDES_FIRST + 1


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class pfc_remote_ipv4_pfc(pfc_remote, pfc_base, pfc_common):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pfc_remote(self):
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

        # Test the 1st pass for Measurement packet. Rxpp - Fabric
        # Inject the packet and test outputs
        ingress_packet = {
            'data': self.INPUT_REMOTE_PACKET,
            'slice': self.s_rx_slice,
            'ifg': self.s_rx_ifg,
            'pif': self.s_first_serdes_p1}
        expected_packets = []
        expected_packets.append({'data': self.INPUT_REMOTE_OVER_FABRIC, 'slice': INGRESS_TX_SLICE,
                                 'ifg': INGRESS_TX_IFG, 'pif': INGRESS_TX_SERDES_FIRST})
        expected_packets.append({'data': self.SAMPLED_PKT_OVER_FABRIC, 'slice': INGRESS_TX_SLICE,
                                 'ifg': INGRESS_TX_IFG, 'pif': INGRESS_TX_SERDES_FIRST})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, TS_PLB)


if __name__ == '__main__':
    unittest.main()
