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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor

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

#############################################################################################################################
PUNT_INJECT_SLICE = 0
PUNT_INJECT_IFG = 0
PUNT_INJECT_PIF_FIRST = 8
PUNT_INJECT_SP_GID = 43
PUNT_INJECT_PORT_MAC_ADDR = "ca:fe:ba:be:ca:fe"
HOST_MAC_ADDR = "ba:be:ca:fe:ba:be"
MIRROR_CMD_GID = 20

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET


MIRROR_VLAN = 0xA12
#############################################################################################################################


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
class mirror_pci_counter_unit_test(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)
        # MATILDA_SAVE -- need review
        self.IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [3, 1, 4])
        self.OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [5, 2])

        self.topology = T.topology(self, self.device, create_default_topology=False)
        self.topology.create_default_profiles()
        self.topology.create_inject_ports()
        # remove the pi-port so the sys-port over pci in slice 2 can be attached to an ethernet port
        self.sys_pci_port_slice2 = self.topology.inject_ports[2].sys_port
        self.device.device.destroy(self.topology.inject_ports[2].hld_obj)
        self.topology.inject_ports[2] = None

        self.create_packets()
        self.create_ports()

    def tearDown(self):
        self.device.tearDown()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        self.ingress_punt_packet_pi_pci = \
            Ether(dst=HOST_MAC_ADDR, src=T.INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
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
                 lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(len=42, chksum=0x7ccb) / TCP(chksum=0x917a, options={}) / Raw(load='\x00\x00')

        self.ingress_punt_packet_pi_mac = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                 code =MIRROR_CMD_INGRESS_GID + 1,
                 source_sp=SYS_PORT_GID_BASE,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=0,
                 destination_lp=AC_PORT_GID_BASE + 1,
                 relay_id=0,
                 lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(len=42, chksum=0x7ccb) / TCP(chksum=0x917a, options={}) / Raw(load='\x00\x00')

        self.ingress_punt_packet_sys_mac = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                 code =MIRROR_CMD_INGRESS_GID + 1,
                 source_sp=SYS_PORT_GID_BASE,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=0,
                 destination_lp=AC_PORT_GID_BASE + 1,
                 relay_id=0,
                 lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(len=42, chksum=0x7ccb) / TCP(chksum=0x917a, options={}) / Raw(load='\x00\x00')

    def create_ports(self):
        self.ac_profile = T.ac_profile(self, self.device)

        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            self.IN_SLICE,
            IN_IFG,
            SYS_PORT_GID_BASE,
            IN_SERDES_FIRST,
            IN_SERDES_LAST)
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
            self.OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     1, self.topology.filter_group_def, None, self.eth_port2, None, VLAN, 0x0)

        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)

        self.mirror_counter = self.device.create_counter(1)

        # mirror command over punt-inject port over pci
        self.mirror_cmd_pi_pci = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID,
            self.topology.inject_ports[0],
            HOST_MAC_ADDR,
            MIRROR_VLAN)
        self.mirror_cmd_pi_pci.set_counter(self.mirror_counter)

        # mirror command over punt-inject port over mac
        self.punt_mac = T.punt_inject_port(
            self,
            self.device,
            PUNT_INJECT_SLICE,
            PUNT_INJECT_IFG,
            SYS_PORT_GID_BASE + 2,
            PUNT_INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)
        self.mirror_cmd_pi_mac = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID + 1,
            self.punt_mac,
            HOST_MAC_ADDR,
            MIRROR_VLAN)
        self.mirror_cmd_pi_mac.set_counter(self.mirror_counter)

        # mirror command over sys-port over mac
        self.mirror_cmd_sys_mac = self.device.device.create_l2_mirror_command(
            MIRROR_CMD_INGRESS_GID + 2,
            self.eth_port2.hld_obj,
            self.eth_port2.sys_port.hld_obj,
            0,  # voq_offset
            1.0)  # probablity
        self.mirror_cmd_sys_mac.set_counter(self.mirror_counter)

        # mirror command over sys-port over pci
        self.eth_port_pci = T.sa_ethernet_port(self, self.device, self.sys_pci_port_slice2)
        self.mirror_cmd_sys_pci = self.device.device.create_l2_mirror_command(
            MIRROR_CMD_INGRESS_GID + 3,
            self.eth_port_pci.hld_obj,
            self.sys_pci_port_slice2.hld_obj,
            0,  # voq_offset
            1.0)  # probablity
        self.mirror_cmd_sys_pci.set_counter(self.mirror_counter)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_mirror_counter_pi_pci(self):
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.mirror_cmd_pi_pci, is_acl_conditioned=False)
        self.in_packet_data = {'data': self.in_packet, 'slice': self.IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        self.out_packet_data = {'data': self.out_packet, 'slice': self.OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}
        self.ingress_punt_packet_data = {'data': self.ingress_punt_packet_pi_pci,
                                         'slice': PUNT_INJECT_SLICE, 'ifg': PUNT_INJECT_IFG, 'pif': self.device.get_pci_serdes()}
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.ingress_punt_packet_data])
        p, b = self.mirror_counter.read(0, True, True)
        self.assertEqual(p, 1)

    @unittest.skip('counter is not being read in tx_punt_macro, only in rx_outbound_mirror_macro. pending the fix of CSCvv24817 which recycles all punted packets, not only those targeted at the cpu')
    def test_mirror_counter_pi_mac(self):
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.mirror_cmd_pi_mac, is_acl_conditioned=False)
        self.in_packet_data = {'data': self.in_packet, 'slice': self.IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        self.out_packet_data = {'data': self.out_packet, 'slice': self.OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}
        self.ingress_punt_packet_data = {'data': self.ingress_punt_packet_pi_mac,
                                         'slice': PUNT_INJECT_SLICE, 'ifg': PUNT_INJECT_IFG, 'pif': PUNT_INJECT_PIF_FIRST}
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.ingress_punt_packet_data])
        p, b = self.mirror_counter.read(0, True, True)
        self.assertEqual(p, 1)

    @unittest.skipIf(decor.is_hw_device(), 'mirrored packet includes the inject-up header used for unit-testing')
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Mathilda models.")
    def test_mirror_counter_sys_mac(self):
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.mirror_cmd_sys_mac, is_acl_conditioned=False)
        self.in_packet_data = {'data': self.in_packet, 'slice': self.IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        self.out_packet_data = {'data': self.out_packet, 'slice': self.OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}
        self.ingress_punt_packet_data = {'data': self.ingress_punt_packet_sys_mac,
                                         'slice': self.OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.out_packet_data])
        p, b = self.mirror_counter.read(0, True, True)
        self.assertEqual(p, 1)

    @unittest.skipIf(decor.is_hw_device(), 'mirrored packet includes the inject-up header used for unit-testing')
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Mathilda models.")
    def test_mirror_counter_sys_pci(self):
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.mirror_cmd_sys_pci, is_acl_conditioned=False)
        self.in_packet_data = {'data': self.in_packet, 'slice': self.IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        self.out_packet_data = {'data': self.out_packet, 'slice': self.OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}
        self.ingress_punt_packet_data = {'data': self.out_packet, 'slice': 2, 'ifg': 0, 'pif': self.device.get_pci_serdes()}
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.ingress_punt_packet_data])
        p, b = self.mirror_counter.read(0, True, True)
        self.assertEqual(p, 1)


if __name__ == '__main__':
    unittest.main()
