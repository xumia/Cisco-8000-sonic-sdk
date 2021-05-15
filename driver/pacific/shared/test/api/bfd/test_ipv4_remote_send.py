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

import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
from bfd_base import *
from bfd_remote import *
import decor
import topology as T
import ip_test_base

INGRESS_TX_SLICE = T.get_device_slice(4)
INGRESS_TX_IFG = T.get_device_ifg(1)
INGRESS_TX_SERDES_FIRST = T.get_device_first_serdes(2)
INGRESS_TX_SERDES_LAST = INGRESS_TX_SERDES_FIRST + 1

EGRESS_TX_SLICE = T.get_device_slice(2)
EGRESS_TX_IFG = 0
EGRESS_TX_SERDES_FIRST = T.get_device_next_first_serdes(16)
EGRESS_TX_SERDES_LAST = EGRESS_TX_SERDES_FIRST + 1


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class bfd_remote_send(bfd_remote, bfd_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bfd_remote_send(self):
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

        if self.device.get_ll_device().is_gibraltar():
            self.IPV4_MH_OVER_FABRIC.encap = 0x800e00020000fee06

        run_and_compare(
            self,
            self.device,
            self.INPUT_IPV4_REMOTE_MULTIHOP_PACKET,
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_first_serdes_p2,
            self.IPV4_MH_OVER_FABRIC,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            TS_PLB)


if __name__ == '__main__':
    unittest.main()
