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

EGRESS_RX_SLICE = 4
EGRESS_RX_IFG = 1
EGRESS_RX_SERDES_FIRST = 2
EGRESS_RX_SERDES_LAST = EGRESS_RX_SERDES_FIRST + 1


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class pfc_ipv4_from_fabric(pfc_remote, pfc_base, pfc_common):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pfc_ipv4_from_fabric(self):
        # Create rx fabric port
        out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)
        out_rx_fabric_port = T.fabric_port(self, self.device, out_rx_fabric_mac_port)

        # Manually set reachability to egress device
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)
        reachable_devices = []
        reachable_devices.append(EGRESS_DEVICE_ID)
        out_rx_fabric_port.hld_obj.set_reachable_lc_devices(reachable_devices)

        if self.device.get_ll_device().is_gibraltar():
            self.device.set_bool_property(sdk.la_device_property_e_PACIFIC_PFC_HBM_ENABLED, True)
            self.P3_SAMPLED_PKT_OVER_FABRIC.dest_oq = self.device.get_oq_num(self.PI_IFG, self.device.get_pci_serdes())
            self.P3_SAMPLED_PKT_OVER_FABRIC.unparsed_0 = 0x4000000
        # This packet path is from Fabric - TxPP - Recycle - RxPP - Fabric
        run_and_compare(
            self,
            self.device,
            self.P2_SAMPLED_PKT_OVER_FABRIC,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            self.P3_SAMPLED_PKT_OVER_FABRIC,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            TS_PLB)


if __name__ == '__main__':
    unittest.main()
