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
from bfd_distributed_local_send import *
import decor
import topology as T
import ip_test_base

EGRESS_RX_SLICE = T.get_device_slice(4)
EGRESS_RX_IFG = T.get_device_ifg(1)
EGRESS_RX_SERDES_FIRST = 2
EGRESS_RX_SERDES_LAST = EGRESS_RX_SERDES_FIRST + 1


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class bfd_remote_rx(bfd_init_flags, bfd_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bfd_remote_rx(self):
        # Create rx fabric port
        out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)
        out_rx_fabric_port = T.fabric_port(self, self.device, out_rx_fabric_mac_port)

        run_and_compare(
            self,
            self.device,
            self.IPV4_MH_OVER_FABRIC,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            self.PUNT_PACKET_IPV4_REMOTE_MH_FLAG_CHANGE,
            INJECT_SLICE,
            T.PI_IFG,
            self.device.get_pci_serdes())


if __name__ == '__main__':
    unittest.main()
