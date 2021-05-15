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
import decor
import topology as T


IN_SLICE = 2
IN_IFG = 0
IN_SERDES = 4
INJECT_SERDES = IN_SERDES + 2
OUT_SLICE = 4
OUT_IFG = 0
PCI_SERDES = 18


RX_SYS_PORT_GID_BASE = 0x111
TX_SYS_PORT_GID_BASE = RX_SYS_PORT_GID_BASE + 4
AC_PORT_GID_BASE = 10

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0x123


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
class l2_p2p_xconnect_unit_test(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        import sim_utils
        self.device = sim_utils.create_test_device('/dev/testdev', 1)

        self.topology = T.topology(self, self.device, create_default_topology=False)

    def tearDown(self):
        self.device.tearDown()

    def do_test_l2_p2p_xconnect(self, input_packet, expected_output_packet):
        #        sdk.la_set_logging_level(1, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)

        # Input ports
        eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, RX_SYS_PORT_GID_BASE, IN_SERDES, IN_SERDES)
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
        rcy_sys_port1 = T.recycle_port(self, self.device, IN_SLICE, T.PI_IFG)
        sys_port1 = T.system_port(self, self.device, RX_SYS_PORT_GID_BASE + 1, rcy_sys_port1)
        pi_port = T.punt_inject_pci_port(
            self,
            self.device,
            IN_SLICE,
            T.PI_IFG,
            RX_SYS_PORT_GID_BASE + 2,
            PUNT_INJECT_PORT_MAC_ADDR)

        # Output punt port
        rcy_sys_port2 = T.recycle_sys_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            RX_SYS_PORT_GID_BASE +
            3)  # Needed by the PCI port
        pci_port = T.pci_port(self, self.device, OUT_SLICE, OUT_IFG)
        sys_port2 = T.system_port(self, self.device, TX_SYS_PORT_GID_BASE, pci_port)
        eth_port2 = T.sa_ethernet_port(self, self.device, sys_port2)
        eth_port2.set_ac_profile(self.topology.ac_profile_def)
        ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                1, self.topology.filter_group_def, None, eth_port2, None, VLAN, 0x0)

        # Slice 4 IFG is opposite
        expected_output_packet[0].ifg_id = 1
        expected_output_packet[0].pif_id = PCI_SERDES + 1

        # Input-port --> output-port P2P connection
        ac_port1.hld_obj.set_destination(ac_port2.hld_obj)

        # Inject a packet
        run_and_compare(
            self,
            self.device,
            input_packet,
            IN_SLICE,
            T.PI_IFG,
            T.PI_PIF,
            expected_output_packet,
            OUT_SLICE,
            OUT_IFG,
            PCI_SERDES)

    def do_test(self, raw_load):

        input_packet = \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectUpStd(ifg_id=0, pif_id=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP() / Raw(load=raw_load)

        bare_output_packet = \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP() / Raw(load=raw_load)

        output_packet_with_wa_header_8 = \
            PacketDmaWaHeader8() / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP() / Raw(load=raw_load)

        output_packet_with_wa_header_16 = \
            PacketDmaWaHeader16() / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP() / Raw(load=raw_load)

        if (len(bare_output_packet) % 16) in [0, 9, 10, 11, 12, 13, 14, 15]:
            expected_output_packet = output_packet_with_wa_header_16
        else:
            expected_output_packet = output_packet_with_wa_header_8

        self.do_test_l2_p2p_xconnect(input_packet, expected_output_packet)
