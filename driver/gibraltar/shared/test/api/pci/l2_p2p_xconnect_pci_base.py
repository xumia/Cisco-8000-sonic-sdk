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
import unittest
from leaba import sdk
import sim_utils
import topology as T


IN_SLICE = 2
IN_PCI_SLICE = 2  # PCI ports can be created only on even slices
IN_IFG = 0
IN_SERDES = 4
INJECT_SERDES = IN_SERDES + 2
OUT_SLICE = 0
OUT_IFG = 0
PCI_SERDES = 18
RCY_SERDES = 19


RX_SYS_PORT_GID_BASE = 0x111
TX_SYS_PORT_GID_BASE = RX_SYS_PORT_GID_BASE + 4
AC_PORT_GID_BASE = 10

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0x123
INJECT_PORT_BASE_GID = 1200


class l2_p2p_xconnect_unit_test(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device, create_default_topology=False)

    def tearDown(self):
        self.device.tearDown()

    def do_test_l2_p2p_xconnect(self, input_packet, expected_output_packet):
        #        sdk.la_set_logging_level(1, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)

        # Input ports
        in_rcy_slice = IN_PCI_SLICE + 1
        rcy_sys_port = T.recycle_sys_port(
            self,
            self.device,
            in_rcy_slice,
            IN_IFG,
            RX_SYS_PORT_GID_BASE)  # Needed by the PCI port

        in_pci_port = T.punt_inject_pci_port(
            self,
            self.device,
            IN_PCI_SLICE,
            IN_IFG,
            INJECT_PORT_BASE_GID,
            PUNT_INJECT_PORT_MAC_ADDR)
        eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, RX_SYS_PORT_GID_BASE + 1, IN_SERDES, IN_SERDES)
        eth_port1.set_ac_profile(self.topology.ac_profile_def)
        ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            eth_port1,
            None,
            VLAN,
            0x0)

        input_packet[2].ifg_id = IN_IFG
        input_packet[2].pif_id = IN_SERDES

        # Output punt port
        rcy_sys_port2 = T.recycle_sys_port(
            self,
            self.device,
            OUT_SLICE + 1,
            OUT_IFG,
            RX_SYS_PORT_GID_BASE +
            2)  # Needed by the PCI port
        pci_port = T.pci_port(self, self.device, OUT_SLICE, OUT_IFG)
        sys_port2 = T.system_port(self, self.device, TX_SYS_PORT_GID_BASE, pci_port)
        eth_port2 = T.sa_ethernet_port(self, self.device, sys_port2)
        eth_port2.set_ac_profile(self.topology.ac_profile_def)
        ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                1, self.topology.filter_group_def, None, eth_port2, None, VLAN, 0x0)

        expected_output_packet[0].ifg_id = 0  # IFG of the RCY port, which is on slice 5, so no flip
        expected_output_packet[0].pif_id = RCY_SERDES

        # Input-port --> output-port P2P connection
        ac_port1.hld_obj.set_destination(ac_port2.hld_obj)

        # Inject a packet
        run_and_compare(
            self,
            self.device,
            input_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            expected_output_packet,
            OUT_SLICE,
            OUT_IFG,
            PCI_SERDES)

    def do_test(self, raw_load):

        input_packet_base = \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP() / Raw(load=raw_load)

        output_packet_base = \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP() / Raw(load=raw_load)

        input_packet, output_packet = pad_input_and_output_packets(input_packet_base, output_packet_base)

        self.do_test_l2_p2p_xconnect(input_packet, output_packet)
