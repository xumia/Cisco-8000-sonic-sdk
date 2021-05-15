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
from sdk_test_case_base import sdk_test_case_base


class l2_switch_base(sdk_test_case_base):

    IN_SLICE = T.get_device_slice(2)
    IN_IFG = 0
    IN_SERDES_FIRST = T.get_device_first_serdes(4)
    IN_SERDES_LAST = IN_SERDES_FIRST + 1
    OUT_SLICE = T.get_device_slice(4)
    OUT_IFG = T.get_device_ifg(1)
    OUT_SERDES_FIRST = T.get_device_next_first_serdes(8)
    OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

    SYS_PORT_GID_BASE = 23
    AC_PORT_GID_BASE = 10

    SWITCH_GID = 100

    SRC_MAC = "de:ad:de:ad:de:ad"
    UCAST_MAC = "ca:fe:ca:fe:ca:fe"
    MCAST_MAC = '01:00:5e:00:00:01'
    BCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    VLAN = 0xAB9
    VLAN2 = 0x123
    VLAN3 = 0x999

    AGE_INTERVAL = 2

    ARP_ETHER_TYPE = 0x0806

    def setUp(self):
        super().setUp(create_default_topology=False)

        # MATILDA_SAVE -- need review
        self.IN_SLICE = T.choose_active_slices(self.device, self.IN_SLICE, [2, 3])
        self.OUT_SLICE = T.choose_active_slices(self.device, self.OUT_SLICE, [4, 1])
        if hasattr(self, 'INJECT_SLICE'):
            self.INJECT_SLICE = T.choose_active_slices(self.device, self.INJECT_SLICE, [2, 3])

        self.topology.create_inject_ports()
        self._add_objects_to_keep()
        self.create_topology()
        self.copc_mac = self.device.create_copc(sdk.la_control_plane_classifier.type_e_MAC)

    def create_topology(self):
        self.sw1 = T.switch(self, self.device, self.SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            self.IN_SLICE,
            self.IN_IFG,
            self.SYS_PORT_GID_BASE,
            self.IN_SERDES_FIRST,
            self.IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            self.AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            None,
            self.VLAN,
            0x0)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            self.OUT_SLICE,
            self.OUT_IFG,
            self.SYS_PORT_GID_BASE + 1,
            self.OUT_SERDES_FIRST,
            self.OUT_SERDES_LAST)
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            self.AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            None,
            self.VLAN,
            0x0)

    def create_packets(self, src_mac, dest_mac, vlan, vlan2=0):
        if vlan2:
            in_packet_base = Ether(dst=dest_mac, src=src_mac, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=vlan, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vlan2) / \
                IP() / TCP()

            out_packet_base = Ether(dst=dest_mac, src=src_mac, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=vlan, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vlan2) / \
                IP() / TCP()
        else:
            in_packet_base = Ether(dst=dest_mac, src=src_mac, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vlan) / \
                IP() / TCP()

            out_packet_base = Ether(dst=dest_mac, src=src_mac, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vlan) / \
                IP() / TCP()

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)
        return in_packet, out_packet

    def generate_macs(self, starting_prefix, mac_addresses):
        self.macs = []
        self.mac_addr_start_prefix = starting_prefix
        num_256_entries = int(mac_addresses / 256) + 1
        num_32k_entries = 1
        if num_256_entries > 256:
            num_32k_entries = int(num_256_entries / 256) + 1
            num_256_entries = 256

        total_entries = 0
        # print("Generating {num_entries} packets with different SRC MAC...".format(num_entries=mac_addresses))
        for x, y, z in itertools.product(range(0, num_32k_entries), range(0, num_256_entries), range(0, 256)):
            current_mac_addr = "{prefix}:{x:02x}:{y:02x}:{z:02x}".format(prefix=self.mac_addr_start_prefix,
                                                                         x=x, y=y, z=z)
            self.macs.append(current_mac_addr)
            total_entries += 1
            if total_entries == mac_addresses:
                break

        return self.macs

    def install_mac(self, dst_mac):
        self.mac = T.mac_addr(dst_mac)
        self.sw1.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

    def set_flood_destination(self, is_ucast=True):
        if is_ucast:
            self.sw1.hld_obj.set_flood_destination(self.ac_port2.hld_obj)
        else:
            mc_group = self.device.create_l2_multicast_group(0x13, sdk.la_replication_paradigm_e_EGRESS)
            self.assertIsNotNone(mc_group)
            mc_group.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)
            self.sw1.hld_obj.set_flood_destination(mc_group)

    def create_l2_ingress_counter(self):
        counter_set_size = sdk.la_rate_limiters_packet_type_e_LAST
        l2_ingress_counter = self.device.create_counter(counter_set_size)
        self.ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, l2_ingress_counter)
        return l2_ingress_counter

    def run_and_compare_l2_ingress_counter(self, in_packet, out_packet, cnt_type, disable_rx=False, disable_tx=False):
        l2_ingress_counter = self.create_l2_ingress_counter()
        packets, byte_count = l2_ingress_counter.read(cnt_type, True, True)
        self.assertEqual(packets, 0)

        run_and_compare(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            out_packet,
            self.OUT_SLICE,
            self.OUT_IFG,
            self.OUT_SERDES_FIRST)

        packets, byte_count = l2_ingress_counter.read(cnt_type, True, True)
        self.assertEqual(packets, 1)
        assertPacketLengthIngress(self, in_packet, self.IN_SLICE, byte_count)

        if disable_rx:
            self.ac_port1.hld_obj.disable()
            run_and_drop(self, self.device, in_packet, self.IN_SLICE, self.IN_IFG, self.IN_SERDES_FIRST)

        if disable_tx:
            self.ac_port2.hld_obj.disable()
            run_and_drop(self, self.device, in_packet, self.IN_SLICE, self.IN_IFG, self.IN_SERDES_FIRST)

    def run_and_drop_unknown_bum(self, in_packet, out_packet, dst_mac):
        run_and_drop(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST)

        self.install_mac(dst_mac)

        run_and_compare(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            out_packet,
            self.OUT_SLICE,
            self.OUT_IFG,
            self.OUT_SERDES_FIRST)

    def delete_mac_entries(self, entries):
        total_entries = 0
        print("Deleting {num_entries} MAC entries...".format(num_entries=len(entries)))
        for x in range(0, len(entries)):
            dynamic_mac = entries[x]
            self.check1 = self.sw1.hld_obj.remove_mac_entry(dynamic_mac.hld_obj)
            total_entries += 1
            if total_entries == len(entries):
                break

    def install_mac_entries(self, max_switch_addresses, and_delete):
        self.mac_entries = []
        self.mac_addr_start_prefix = 'ab:cd:00'
        num_256_entries = int(max_switch_addresses / 256) + 1
        num_32k_entries = 1
        if num_256_entries > 256:
            num_32k_entries = int(num_256_entries / 256) + 1
            num_256_entries = 256

        total_entries = 0
        print("Installing {num_entries} MAC entries...".format(num_entries=max_switch_addresses))
        for x, y, z in itertools.product(range(0, num_32k_entries), range(0, num_256_entries), range(0, 256)):
            current_mac_addr = "{prefix}:{x:02x}:{y:02x}:{z:02x}".format(prefix=self.mac_addr_start_prefix,
                                                                         x=x, y=y, z=z)
            dynamic_mac = T.mac_addr(current_mac_addr)
            entry_inserted = True
            try:
                self.sw1.hld_obj.set_mac_entry(dynamic_mac.hld_obj, self.ac_port1.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

            except (sdk.ResourceException, AssertionError) as STATUS:
                if STATUS is not None:
                    print("set_mac_entry failed because table is full...")
                    entry_inserted = False
                pass

            if entry_inserted is True:
                self.mac_entries.append(dynamic_mac)
            total_entries += 1
            if total_entries == max_switch_addresses:
                break

        if and_delete is not True:
            return self.mac_entries

        self.delete_mac_entries(self.mac_entries)
        # total_entries = 0
        # print("Deleting {num_entries} MAC entries...".format(num_entries=max_switch_addresses))
        # for x in range(0, max_switch_addresses):
        #     dynamic_mac = self.mac_entries[x]
        #     self.check1 = self.sw1.hld_obj.remove_mac_entry(dynamic_mac.hld_obj)
        #     total_entries += 1
        #     if total_entries == max_switch_addresses:
        #         break
        return self.mac_entries

    def install_an_entry_in_copc_mac_table(
            self,
            ether_value,
            ether_mask,
            mac_da_value,
            event,
            mac_da_mask=T.mac_addr('ff:ff:ff:ff:ff:ff'),
            npp_attribute=0x0,
            mac_lp_type_value=0x0,
            mac_lp_type_mask=0x0):
        key1 = []
        f1 = sdk.field()
        f1.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERNET_PROFILE_ID
        f1.val.mac.ethernet_profile_id = npp_attribute
        f1.mask.mac.ethernet_profile_id = npp_attribute
        key1.append(f1)

        f2 = sdk.field()
        f2.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_DA
        f2.val.mac.da = mac_da_value.hld_obj
        f2.mask.mac.da = mac_da_mask.hld_obj
        key1.append(f2)

        f3 = sdk.field()
        f3.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERTYPE
        f3.val.mac.ethertype = ether_value
        f3.mask.mac.ethertype = ether_mask
        key1.append(f3)

        f4 = sdk.field()
        f4.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_LP_TYPE
        f4.val.mac.lp_type = mac_lp_type_value
        f4.mask.mac.lp_type = mac_lp_type_mask
        key1.append(f4)

        result1 = sdk.result()
        result1.event = event

        self.copc_mac.append(key1, result1)

    def clear_entries_from_copc_mac_table(self):
        self.copc_mac.clear()
