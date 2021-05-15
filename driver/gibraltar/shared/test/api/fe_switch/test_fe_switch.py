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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import decor
import sim_utils
import topology as T
from sdk_test_case_base import *

FE_DEVICE_ID = 280
FE_RX_SLICE = 2
FE_RX_IFG = 0
FE_RX_SERDES_FIRST = 4
FE_RX_SERDES_LAST = FE_RX_SERDES_FIRST + 1

FE_TX_SLICE = 4
FE_TX_IFG = 1
FE_TX_SERDES_FIRST = 2
FE_TX_SERDES_LAST = FE_TX_SERDES_FIRST + 1

INGRESS_DEVICE_ID = 1
INGRESS_RX_SLICE = 2

EGRESS_DEVICE_ID = 10
EGRESS_TX_SLICE = 2
EGRESS_TX_IFG = 0
EGRESS_TX_SERDES_FIRST = 16


DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9


@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "WB fails for FE mode")
@unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
@unittest.skipIf(decor.is_asic3(), "FE mode is not supported on GR")
class test_fe_switch(sdk_test_case_base):
    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            for sid in range(T.NUM_SLICES_PER_DEVICE):
                device.set_fabric_slice_clos_direction(sid, sdk.la_clos_direction_e_DOWN)

    @classmethod
    def setUpClass(cls):
        super(test_fe_switch, cls).setUpClass(slice_modes=sim_utils.FABRIC_ELEMENT_DEV,
                                              device_config_func=test_fe_switch.device_config_func)

    def setUp(self):
        super().setUp(create_default_topology=False)
        self.create_packets()

    def tearDown(self):
        self.device.clear_device()

    def create_packets(self):
        self.fe_rx_pkt = \
            TS_PLB(header_type="ONE_PKT_TS3",
                   link_fc=0,
                   fcn=0,
                   plb_context="UC_L",
                   ts3=[0, 0, 0],  # In TS3 mode, this list MUST be of size 3. There is no scapy enforcing of it.
                   src_device=INGRESS_DEVICE_ID,
                   src_slice=INGRESS_RX_SLICE,
                   reserved=0) / \
            TM(header_type="UUU_DD",
               vce=0,
               tc=0,
               dp=0,
               reserved=0,
               dest_device=EGRESS_DEVICE_ID,
               dest_slice=EGRESS_TX_SLICE,
               dest_oq=T.topology.get_oq_num(EGRESS_TX_IFG, EGRESS_TX_SERDES_FIRST)) / \
            NPU_Header(unparsed_0=0x1000000000000400,   # The NPU header data is arbitrary
                       unparsed_1=0xda83f2008000b000,
                       unparsed_2=0x0,
                       unparsed_3=0x648000a04000) / \
            Ether(dst=DST_MAC,
                  src=SRC_MAC,
                  type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IP() / TCP()

        self.fe_tx_pkt = self.fe_rx_pkt

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fe_min_fabric_links_for_connectivity(self):
        # Validate the default
        ret_val = self.device.get_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY)
        self.assertEqual(ret_val, 1)

        # Write new value and validate
        new_val = 3
        self.device.set_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY, new_val)
        ret_val = self.device.get_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY)
        self.assertEqual(ret_val, new_val)

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "FE mode is not supported on PL")
    def test_fe_switch_plb_forwarding(self):
        # Create rx fabric port
        rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            FE_RX_SLICE,
            FE_RX_IFG,
            FE_RX_SERDES_FIRST,
            FE_RX_SERDES_LAST)
        rx_fabric_port = T.fabric_port(self, self.device, rx_fabric_mac_port)

        # Create tx fabric port
        tx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            FE_TX_SLICE,
            FE_TX_IFG,
            FE_TX_SERDES_FIRST,
            FE_TX_SERDES_LAST)
        tx_fabric_port = T.fabric_port(self, self.device, tx_fabric_mac_port)

        # Manually set reachability to egress device
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)
        reachable_devices = []
        reachable_devices.append(EGRESS_DEVICE_ID)
        tx_fabric_port.hld_obj.set_reachable_lc_devices(reachable_devices)

        run_and_compare(
            self,
            self.device,
            self.fe_rx_pkt,
            FE_RX_SLICE,
            FE_RX_IFG,
            FE_RX_SERDES_FIRST,
            self.fe_tx_pkt,
            FE_TX_SLICE,
            FE_TX_IFG,
            FE_TX_SERDES_FIRST,
            TS_PLB)


if __name__ == '__main__':
    unittest.main()
