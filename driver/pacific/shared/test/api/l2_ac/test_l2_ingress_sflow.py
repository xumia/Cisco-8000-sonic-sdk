#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import unittest
from leaba import sdk
from sdk_test_case_base import *
import sim_utils
import topology as T


IN_SLICE = T.get_device_slice(3)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(5)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_out_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
MIRROR_CMD_GID = 9
MIRROR_VLAN = 0xA12
PUNT_SLICE = T.get_device_slice(2)  # must be even numbered slice
PUNT_IFG = 0
PUNT_PIF_FIRST = 8

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_ingress_sflow(sdk_test_case_base):

    def setUp(self):
        super().setUp()

        # MATILDA_SAVE -- need review
        global IN_SLICE, OUT_SLICE, PUNT_SLICE
        if (IN_SLICE not in self.device.get_used_slices()):
            IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [3, 2])
        if (OUT_SLICE not in self.device.get_used_slices()):
            OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [5, 0])
        PUNT_SLICE = T.choose_active_slices(self.device, PUNT_SLICE, [2, 4])

        self.create_ports()
        self.create_packets()
        self.create_mirror()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()
        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        snoop_packet = Ether(dst=HOST_MAC_ADDR,
                             src=PUNT_INJECT_PORT_MAC_ADDR,
                             type=U.Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                   id=0,
                                                                   vlan=MIRROR_VLAN,
                                                                   type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                         fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                         next_header_offset=0,
                                                                                                         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                         code=MIRROR_CMD_INGRESS_GID,
                                                                                                         source_sp=SYS_PORT_GID_BASE,
                                                                                                         destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                         source_lp=0,
                                                                                                         destination_lp=AC_PORT_GID_BASE + 1,
                                                                                                         reserved2=1,
                                                                                                         relay_id=0,
                                                                                                         lpts_flow_type=0) / self.in_packet

        self.ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        self.expected_packets_no_sflow = [{'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}]
        self.expected_packets_disable = [{'data': snoop_packet, 'slice': PUNT_SLICE, 'ifg': 0, 'pif': self.device.get_pci_serdes()}]

        self.expected_packets = [{'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}]
        self.expected_packets.append({'data': snoop_packet, 'slice': PUNT_SLICE, 'ifg': 0, 'pif': self.device.get_pci_serdes()})

    def create_ports(self):
        self.ac_profile = T.ac_profile(self, self.device)

        self.eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            self.eth_port1,
            None,
            VLAN,
            0x0)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     1, self.topology.filter_group_def, None, self.eth_port2, None, VLAN, 0x0)

        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)

    def create_mirror(self):
        sampling_rate = 1.0
        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID,
            self.topology.inject_ports[PUNT_SLICE],
            HOST_MAC_ADDR,
            MIRROR_VLAN,
            sampling_rate)
        priority = 0

        # Clear trap and set snoop -> packet will go out and another packet with punt header will be generated.
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR)
        self.device.set_snoop_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR, priority, False, False, self.mirror_cmd)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_ingress_sflow(self):
        run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets_no_sflow)
        self.ac_port1.hld_obj.set_ingress_sflow_enabled(True)
        run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets)
        self.ac_port1.hld_obj.set_ingress_sflow_enabled(False)
        run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets_no_sflow)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_disable_rx(self):
        run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets_no_sflow)

        self.ac_port1.hld_obj.set_ingress_sflow_enabled(True)
        run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets)

        self.ac_port1.hld_obj.disable()
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        self.ac_port1.hld_obj.set_ingress_sflow_enabled(False)
        self.ac_port1.hld_obj.set_destination(None)
        self.device.destroy(self.ac_port1.hld_obj)
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        self.device.destroy(self.ac_port2.hld_obj)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_disable_tx(self):
        run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets_no_sflow)

        self.ac_port1.hld_obj.set_ingress_sflow_enabled(True)
        run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets)

        self.ac_port2.hld_obj.disable()
        # run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)
        run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets_disable)

        self.ac_port1.hld_obj.set_ingress_sflow_enabled(False)
        self.ac_port1.hld_obj.set_destination(None)
        self.device.destroy(self.ac_port2.hld_obj)
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        self.device.destroy(self.ac_port1.hld_obj)


if __name__ == '__main__':
    unittest.main()
