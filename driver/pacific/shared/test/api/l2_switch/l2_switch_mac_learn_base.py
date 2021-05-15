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

# #!/usr/bin/env python3

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from l2_switch_base import l2_switch_base
import nplapicli
import smart_slices_choise as ssch


class l2_switch_mac_learn_base(l2_switch_base):

    PUNT_VLAN = 0xA13
    MAC_LEARN_IN_SLICE = 0

    INJECT_SLICE = 2  # must be an even number
    INJECT_IFG = 0
    INJECT_PIF_FIRST = 8
    INJECT_PIF_LAST = INJECT_PIF_FIRST + 1
    INJECT_SP_GID = l2_switch_base.SYS_PORT_GID_BASE + 2
    NPUH_SP_GID = l2_switch_base.SYS_PORT_GID_BASE + 3

    LEARN_NOTIFICATION_SLICE = T.get_device_slice(4)  # must be an even number
    LEARN_NOTIFICATION_IFG = 0
    LEARN_NOTIFICATION_PIF_FIRST = 8
    LEARN_NOTIFICATION_PIF_LAST = LEARN_NOTIFICATION_PIF_FIRST + 1
    LEARN_NOTIFICATION_SP_GID = l2_switch_base.SYS_PORT_GID_BASE + 2

    PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
    INJECT_UP_DST_MAC = "12:34:56:78:9a:bd"
    INJECT_UP_SRC_MAC = "00:ca:fe:de:ad:00"

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

    def setUp(self):
        super().setUp()
        ssch.rechoose_even_inject_slice(self, self.device)

        self.set_trap()
        self.enable_learning_mode()

        self.dest_mac = T.mac_addr(self.UCAST_MAC)
        self.src_mac = T.mac_addr(self.SRC_MAC)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        self.sw1.hld_obj.set_mac_entry(self.dest_mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

    def create_topology(self):
        # MATILDA_SAVE -- need review
        self.LEARN_NOTIFICATION_SLICE = T.choose_active_slices(self.device, self.LEARN_NOTIFICATION_SLICE, [4, 1])
        self.sw1 = T.switch(self, self.device, self.SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            self.MAC_LEARN_IN_SLICE,
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
        self.ac_port1.hld_obj.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
        self.ac_port1.hld_obj.set_mac_learning_mode(sdk.la_lp_mac_learning_mode_e_CPU)

    def create_age_notification_packets(self, mac_addr):
        # Construct the packet till the first learn record
        AGE_NOTIFICATION_PACKET = self.PUNT_PACKET_BASE_SINGLE / \
            LearnRecordHeader(num_lr_records=1) / \
            LearnRecord(command=sdk.la_packet_types.LA_LEARN_NOTIFICATION_TYPE_REFRESH,
                        slp=0x8000a,
                        relay_id=self.SWITCH_GID,
                        mac_sa=mac_addr.to_num(),
                        mact_ldb=nplapicli.NPL_CENTRAL_EM_LDB_MAC_RELAY_DA)

        # The rest is empty
        for x in range(1, self.MAX_LR_PER_PACKET):
            AGE_NOTIFICATION_PACKET = AGE_NOTIFICATION_PACKET / \
                LearnRecord(command=0,
                            slp=0,
                            relay_id=0,
                            mac_sa=0,
                            mact_ldb=0)

        # Add trailer in the end
        AGE_NOTIFICATION_PACKET = AGE_NOTIFICATION_PACKET / \
            LearnRecordTrailer(trailer=0)

        expected_packets = []
        expected_packets.append({
            'data': AGE_NOTIFICATION_PACKET,
            'slice': self.LEARN_NOTIFICATION_SLICE,
            'ifg': self.LEARN_NOTIFICATION_IFG,
            'pif': self.LEARN_NOTIFICATION_PIF_FIRST})

        return expected_packets

    def create_learn_notification_packets(self, mac_list, dst_mac):
        ingress_packets = []
        expected_packets = []
        learn_records = []
        learn_command = 0
        for tmp_mac in mac_list:
            # For each mac, construct input packet, learn record and add into lists
            in_packet, out_packet = self.create_packets(src_mac=tmp_mac, dest_mac=dst_mac, vlan=self.VLAN)
            tmp_src_mac = T.mac_addr(tmp_mac)
            learn_record = LearnRecord(
                command=learn_command,
                slp=0x8000a,
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
