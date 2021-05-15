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

import decor
from packet_test_utils import *
from collections import namedtuple
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import ip_test_base
import topology as T
from sdk_test_case_base import *
import nplapicli
import smart_slices_choise as ssch

load_contrib('mpls')

# This test assumes that MPLS bottom-of-stack label is followed by Ether
bind_layers(MPLS, Ether, s=1)


class pwe_learn_base(sdk_test_case_base):
    PREFIX1_GID = 0x691
    PREFIX2_GID = 0x692

    ip_impl_class = ip_test_base.ipv4_test_base

    DA = T.mac_addr('be:ef:5d:35:8b:46')
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    PWE_TTL = 0xff  # Set by the SDK

    LDP_LABEL = sdk.la_mpls_label()
    LDP_LABEL.label = 0x64

    PWE_LOCAL_LABEL = sdk.la_mpls_label()
    PWE_LOCAL_LABEL.label = 0x62
    PWE_REMOTE_LABEL = sdk.la_mpls_label()
    PWE_REMOTE_LABEL.label = 0x63

    AC_PORT_VID1 = 0xaaa

    PWE_PORT_GID = 0x4000
    PWE_GID = 0x25

    IN_SLICE = T.get_device_slice(2)
    IN_IFG = 0
    IN_SERDES_FIRST = T.get_device_first_serdes(4)
    IN_SERDES_LAST = IN_SERDES_FIRST + 1
    OUT_SLICE = T.get_device_slice(4)
    OUT_IFG = T.get_device_ifg(1)
    OUT_SERDES_FIRST = T.get_device_next_first_serdes(8)
    OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

    SYS_PORT_GID_BASE = 23
    AC_PORT_GID_BASE = 0x25

    SWITCH_GID = 100

    SRC_MAC = "de:ad:de:ad:de:ad"
    UCAST_MAC = "ca:fe:ca:fe:ca:fe"
    MCAST_MAC = '01:00:5e:00:00:01'
    BCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    VLAN = 0xAB9

    PUNT_VLAN = 0xA13
    MAC_LEARN_IN_SLICE = 0

    INJECT_SLICE = 2  # must be an even number
    INJECT_IFG = 0
    INJECT_PIF_FIRST = 8
    INJECT_PIF_LAST = INJECT_PIF_FIRST + 1
    INJECT_SP_GID = SYS_PORT_GID_BASE + 2
    NPUH_SP_GID = SYS_PORT_GID_BASE + 3

    LEARN_NOTIFICATION_SLICE = T.get_device_slice(4)  # must be an even number
    LEARN_NOTIFICATION_IFG = 0
    LEARN_NOTIFICATION_PIF_FIRST = 8
    LEARN_NOTIFICATION_PIF_LAST = LEARN_NOTIFICATION_PIF_FIRST + 1
    LEARN_NOTIFICATION_SP_GID = SYS_PORT_GID_BASE + 2

    PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
    INJECT_UP_DST_MAC = "12:34:56:78:9a:bd"
    INJECT_UP_SRC_MAC = "00:ca:fe:de:ad:00"
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    PUNT_PACKET_BASE_SINGLE = \
        Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             next_header_offset=35,
             code=sdk.LA_EVENT_ETHERNET_LEARN_PUNT, source_sp=T.RCY_SYS_PORT_GID_BASE,
             # destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
             destination_lp=sdk.LA_EVENT_ETHERNET_LEARN_PUNT,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID) / \
        Ether(dst=INJECT_UP_DST_MAC, src=INJECT_UP_SRC_MAC, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=0, type=Ethertype.Inject.value) / \
        InjectUp(type=sdk.la_packet_types.LA_PACKET_INJECT_TYPE_UP_LEARN_RECORD)

    PUNT_PACKET_BASE_MULTI = \
        Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             next_header_offset=35,
             code=sdk.LA_EVENT_ETHERNET_LEARN_PUNT, source_sp=T.RCY_SYS_PORT_GID_BASE,
             destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID) / \
        Ether(dst=INJECT_UP_DST_MAC, src=INJECT_UP_SRC_MAC, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=0, type=Ethertype.Inject.value) / \
        InjectUp(type=sdk.la_packet_types.LA_PACKET_INJECT_TYPE_UP_LEARN_RECORD)

    def create_ldp_mpls_nh(self):
        self.pfx_obj_vpls = T.prefix_object(self, self.device, self.PREFIX1_GID, self.nh_l3_ac.hld_obj)
        self.assertNotEqual(self.pfx_obj_vpls.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        self.pfx_obj_vpls.hld_obj.set_nh_lsp_properties(self.nh_l3_ac.hld_obj,
                                                        lsp_labels,
                                                        None,
                                                        sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def setUp(self):
        super().setUp(create_default_topology=False)

        # MATILDA_SAVE -- need review
        self.IN_SLICE = T.choose_active_slices(self.device, self.IN_SLICE, [2, 3])
        self.OUT_SLICE = T.choose_active_slices(self.device, self.OUT_SLICE, [4, 1])
        self.TX_SLICE_DEF = T.choose_active_slices(self.device, 1, [1, 4])
        if hasattr(self, 'INJECT_SLICE'):
            self.INJECT_SLICE = T.choose_active_slices(self.device, self.INJECT_SLICE, [2, 3])

        self.topology.create_inject_ports()
        self._add_objects_to_keep()

        self.create_topology()

        ssch.rechoose_even_inject_slice(self, self.device)

        self.set_trap()
        self.enable_learning_mode()

    def create_topology(self):
        self.ip_impl = self.ip_impl_class()
        self.ac_profile = T.ac_profile(self, self.device)

        self.LEARN_NOTIFICATION_SLICE = T.choose_active_slices(self.device, self.LEARN_NOTIFICATION_SLICE, [4, 1])

        # Create SW
        self.sw1 = T.switch(self, self.device, self.SWITCH_GID)

        # create VRF
        self.vrf = T.vrf(self, self.device, T.VRF_GID)

        # Create Ehternet ports
        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            self.MAC_LEARN_IN_SLICE,
            self.IN_IFG,
            self.SYS_PORT_GID_BASE,
            self.IN_SERDES_FIRST,
            self.IN_SERDES_LAST)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            self.OUT_SLICE,
            self.OUT_IFG,
            self.SYS_PORT_GID_BASE + 1,
            self.OUT_SERDES_FIRST,
            self.OUT_SERDES_LAST)

        self.eth_port3 = T.ethernet_port(
            self,
            self.device,
            self.TX_SLICE_DEF,
            1,
            0x26,
            2,
            3)

        # l3 rx ac and l3 tx ac and l2 tx ac
        # CREATE ACs
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.rx_l3_ac = T.l3_ac_port(self, self.device,
                                     self.AC_PORT_GID_BASE,
                                     self.eth_port1,
                                     self.vrf,
                                     T.RX_L3_AC_MAC,
                                     T.RX_L3_AC_PORT_VID1,
                                     T.RX_L3_AC_PORT_VID2)
        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        self.eth_port3.set_ac_profile(self.ac_profile)
        self.tx_l3_ac = T.l3_ac_port(
            self,
            self.device,
            T.TX_L3_AC_DEF_GID,
            self.eth_port3,
            self.vrf,
            T.TX_L3_AC_DEF_MAC)

        self.eth_port2.set_ac_profile(self.ac_profile)
        self.tx_l2_ac = T.l2_ac_port(
            self,
            self.device,
            self.AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            None,
            self.VLAN,
            0x0)

        self.nh_l3_ac = T.next_hop(self, self.device, T.NH_L3_AC_DEF_GID, T.NH_L3_AC_DEF_MAC, self.tx_l3_ac)
        self.add_default_route()

        # Create  PWE
        self.create_ldp_mpls_nh()

        self.pwe_port = T.l2_pwe_port(self, self.device, self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                      self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj)

        self.pwe_port.hld_obj.set_ac_profile_for_pwe(self.ac_profile.hld_obj)

        status = self.pwe_port.hld_obj.attach_to_switch(self.sw1.hld_obj)

        status = self.sw1.hld_obj.set_mac_entry(self.DA.hld_obj, self.tx_l2_ac.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.LEARN_NOTIFICATION_SLICE,
            self.LEARN_NOTIFICATION_IFG,
            self.LEARN_NOTIFICATION_SP_GID,
            self.LEARN_NOTIFICATION_PIF_FIRST,
            self.PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            self.PUNT_INJECT_PORT_MAC_ADDR,
            self.PUNT_VLAN)

        # NPUH port required for Learn Notification packets to work
        self.npu_host_port = T.npu_host_port(self, self.device, self.device.get_id(), False, self.NPUH_SP_GID)

    def set_trap(self):
        priority = 0
        counter = self.device.create_counter(1)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_LEARN_PUNT)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_LEARN_PUNT, priority,
                                           counter, self.punt_dest, False, False, True, 0)

    def enable_learning_mode(self):
        # Test set_stp_state and set_mac_learning_mode
        self.pwe_port.hld_obj.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
        self.pwe_port.hld_obj.set_mac_learning_mode(sdk.la_lp_mac_learning_mode_e_CPU)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.vrf, prefix, self.nh_l3_ac, self.PRIVATE_DATA_DEFAULT)

    def create_learn_notification_packets(self, mac_list, dst_mac):
        ingress_packets = []
        expected_packets = []
        learn_records = []
        learn_command = 0
        for tmp_mac in mac_list:
            # For each mac, construct input packet, learn record and add into lists
            in_packet = self.INPUT_PACKET
            out_packet = self.OUTPUT_PACKET
            tmp_src_mac = T.mac_addr(tmp_mac)
            learn_record = LearnRecord(
                command=learn_command,
                slp=0xC0025,
                relay_id=self.SWITCH_GID,
                mac_sa=tmp_src_mac.to_num(),
                mact_ldb=nplapicli.NPL_CENTRAL_EM_LDB_MAC_RELAY_DA)
            ingress_packets.append({
                'data': in_packet,
                'slice': self.MAC_LEARN_IN_SLICE,
                'ifg': self.IN_IFG,
                'pif': self.IN_SERDES_FIRST})
            expected_packets.append({
                'data': out_packet,
                'slice': self.OUT_SLICE,
                'ifg': self.OUT_IFG,
                'pif': self.OUT_SERDES_FIRST})
            learn_records.append(learn_record)

        current_learn_record = 0
        num_mac_to_test = len(mac_list)
        PUNT_PACKET_BASE = self.PUNT_PACKET_BASE_SINGLE if (num_mac_to_test == 1) else self.PUNT_PACKET_BASE_MULTI
        if not decor.is_hw_device():
            # NSIM today is sending only one notification packet with up to 11 learn records
            num_lr_records = 0
            if num_mac_to_test < self.MAX_LR_PER_PACKET:
                num_lr_records = num_mac_to_test
            else:
                num_lr_records = self.MAX_LR_PER_PACKET

            # Start with the common part plus the LearnRecordHeader
            PUNT_PACKET = PUNT_PACKET_BASE / \
                LearnRecordHeader(num_lr_records=num_lr_records)

            # Add each learn record
            for i in range(0, num_lr_records):
                PUNT_PACKET = PUNT_PACKET / \
                    learn_records[i]

            # The rest is empty
            for i in range(num_lr_records, self.MAX_LR_PER_PACKET):
                PUNT_PACKET = PUNT_PACKET / \
                    LearnRecord(command=0,
                                slp=0,
                                relay_id=0,
                                mac_sa=0,
                                mact_ldb=0)

            # Add trailer in the end
            PUNT_PACKET = PUNT_PACKET / \
                LearnRecordTrailer(trailer=0)

            # Append it to the expected packet list
            expected_packets.append({
                'data': PUNT_PACKET,
                'slice': self.LEARN_NOTIFICATION_SLICE,
                'ifg': self.LEARN_NOTIFICATION_IFG,
                'pif': self.LEARN_NOTIFICATION_PIF_FIRST})
        else:
            # HW would send the first notification with one learn record only
            # And it would then send notification with 10 learn records
            lr_per_notification_list = []
            lr_per_notification_list.append(1)
            num_of_packets_with_10_lr = int((num_mac_to_test - 1) / self.MAX_LR_PER_PACKET)
            for x in range(0, num_of_packets_with_10_lr):
                lr_per_notification_list.append(self.MAX_LR_PER_PACKET)

            num_learn_records_in_last_packet = (num_mac_to_test - 1) % self.MAX_LR_PER_PACKET
            if num_learn_records_in_last_packet is not 0:
                lr_per_notification_list.append(num_learn_records_in_last_packet)

            # Iterate through the list and generate notification packets
            for num_lr_records in lr_per_notification_list:
                # Start with the common part plus the LearnRecordHeader
                PUNT_PACKET = PUNT_PACKET_BASE / \
                    LearnRecordHeader(num_lr_records=num_lr_records)

                # Add all learn records
                for y in range(0, num_lr_records):
                    PUNT_PACKET = PUNT_PACKET / \
                        learn_records[current_learn_record]
                    current_learn_record += 1

                # The rest is empty
                for y in range(num_lr_records, self.MAX_LR_PER_PACKET):
                    PUNT_PACKET = PUNT_PACKET / \
                        LearnRecord(command=0,
                                    slp=0,
                                    relay_id=0,
                                    mac_sa=0,
                                    mact_ldb=0)

                # Add trailer in the end
                PUNT_PACKET = PUNT_PACKET / \
                    LearnRecordTrailer(trailer=0)

                # Append it to the expected packet list
                expected_packets.append({
                    'data': PUNT_PACKET,
                    'slice': self.LEARN_NOTIFICATION_SLICE,
                    'ifg': self.LEARN_NOTIFICATION_IFG,
                    'pif': self.LEARN_NOTIFICATION_PIF_FIRST})

            # Adjust the cfg_npu_host_lri_max_time field to MAX
            # to test multiple learn records in on notification packet
            if num_mac_to_test > 1:
                ll_device = self.sw1.device.device.get_ll_device()
                device_tree = sim_utils.get_device_tree(ll_device)
                ll_device.write_register(device_tree.npuh.host.cfg_lri, 0xFFFFFFFF00000000)

        return ingress_packets, expected_packets

    def compare_egress_packets(self, egress_packets, expected_packets):
        unmatched_packets = []
        for out_packet in egress_packets:
            index = 0
            found = False
            for exp_packet in expected_packets:
                if out_packet.slice == exp_packet['slice'] and \
                        out_packet.ifg == exp_packet['ifg'] and \
                        out_packet.pif == exp_packet['pif']:
                    exp_packet_hex = scapy_to_hex(exp_packet['data'])
                    found = True
                    break
                index += 1

            if found is True:
                del(expected_packets[index])
            else:
                unmatched_packets.append(out_packet)

        if len(unmatched_packets) is not 0:
            print("Unmatched packets received: {num_packets}".format(num_packets=len(unmatched_packets)))
            for packet in unmatched_packets:
                hex_to_scapy(packet.packet).show()
        if len(expected_packets) is not 0:
            print("Expected packets not yet received: {num_packets}".format(num_packets=len(expected_packets)))
            for packet in expected_packets:
                packet['data'].show()
