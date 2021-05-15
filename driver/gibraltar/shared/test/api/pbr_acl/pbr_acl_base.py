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
from enum import Enum
import sdk_test_case_base
import unittest
from leaba import sdk
from packet_test_utils import *
import decor
import sim_utils
import topology as T
from scapy.all import *
import ip_test_base
import ipaddress

NUM_OF_DEFAULT_ENTRIES = 6
MAX_IPV4_PBR_ACL_ENTRIES = 1512 - NUM_OF_DEFAULT_ENTRIES
MAX_IPV6_PBR_ACL_ENTRIES = 1024 - NUM_OF_DEFAULT_ENTRIES
DROP_COUNTER_OFFSET = 1
PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
TTL = 127
SPORT = 0x1234
DPORT = 0x2345
EXTRA_VRF_GID = 0x3ff if not decor.is_gibraltar() else 0xEFF
ECN = 0x0
DSCP = 0x5
DSCP_2 = 0x6
IP_TOT_LEN = 0x2a
OUT_DSCP_REMARK = 0x18
MAX_COUNTER_OFFSET = 8

SA = T.mac_addr('be:ef:5d:35:7a:35')
# IPv4
SIP_V4 = T.ipv4_addr('192.193.194.195')
DIP_V4 = T.ipv4_addr('208.209.210.211')
IP_V4_MASK = T.ipv4_addr('255.255.255.255')

# IPv6
SIP_V6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP_V6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
IP_V6_MASK = T.ipv6_addr('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')

###################################################################


class command_type(Enum):
    NOP = 0
    DROP = 1
    POLICE = 2
    REDIRECT_DEST = 3
    REMARK_DSCP = 4


class pbr_acl_base(sdk_test_case_base.sdk_test_case_base):
    # default slice mode settings. Can be changed inside each test
    slice_modes = sim_utils.STANDALONE_DEV

    def setUp(self):
        super().setUp()

        if self.is_svi:
            self.l3_port_impl = T.ip_svi_base(self.topology)
        else:
            self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.rx_port = self.l3_port_impl.rx_port

        if self.is_ipv4:
            self.ip_impl = ip_test_base.ipv4_test_base
            self.scapy_IP = scapy.layers.inet.IP
            self.PBR_ACL_FIELDS = [
                'ALL',
                'SIP',
                'DIP',
                'SPORT',
                'DPORT',
                'PROTOCOL',
                'IPV4_LENGTH',
                'TOS',
                'IPV4_FLAGS',
                'TCP_FLAGS',
                'MSG_TYPE',
                'VRF_GID']
            self.MAX_PBR_ENTRIES = MAX_IPV4_PBR_ACL_ENTRIES
            self.ipvx = 'v4'
            self.SIP = SIP_V4
            self.DIP = DIP_V4
            self.IP_MASK = IP_V4_MASK
        else:
            self.ip_impl = ip_test_base.ipv6_test_base
            self.scapy_IP = scapy.layers.inet6.IPv6
            self.PBR_ACL_FIELDS = ['ALL', 'SIP', 'DIP', 'SPORT', 'DPORT', 'PROTOCOL', 'TOS', 'TCP_FLAGS']
            self.MAX_PBR_ENTRIES = MAX_IPV6_PBR_ACL_ENTRIES
            self.ipvx = 'v6'
            self.SIP = SIP_V6
            self.DIP = DIP_V6
            self.IP_MASK = IP_V6_MASK

        self.in_tcp_packet, self.out_tcp_packet, self.in_icmp_packet, self.out_icmp_packet = self.create_packets()
        self.add_default_route()
        self.per_field_counters = {}  # key: pbr matching field, value: counter to count ACEs matching that field
        self.create_pbr_acl_key_profile()

    def tearDown(self):
        self.device.destroy(self.ipv4_pbr_acl_key_profile)
        self.device.destroy(self.ipv4_pbr_acl_command_profile)
        self.device.destroy(self.ipv6_pbr_acl_key_profile)
        self.device.destroy(self.ipv6_pbr_acl_command_profile)
        super().tearDown()

    def create_pbr_acl_key_profile(self):
        # Destroy topology based IPv4 & IPv6 ACL key profiles
        self.device.destroy(self.topology.ingress_acl_key_profile_ipv4_def)
        self.device.destroy(self.topology.ingress_acl_key_profile_ipv6_def)
        # Create UDK fields
        udf1 = sdk.la_acl_field_def()
        udf1.type = sdk.la_acl_field_type_e_IPV4_SIP
        udf2 = sdk.la_acl_field_def()
        udf2.type = sdk.la_acl_field_type_e_IPV4_DIP
        udf3 = sdk.la_acl_field_def()
        udf3.type = sdk.la_acl_field_type_e_SPORT
        udf4 = sdk.la_acl_field_def()
        udf4.type = sdk.la_acl_field_type_e_DPORT
        udf5 = sdk.la_acl_field_def()
        udf5.type = sdk.la_acl_field_type_e_PROTOCOL
        udf6 = sdk.la_acl_field_def()
        udf6.type = sdk.la_acl_field_type_e_IPV4_LENGTH
        udf7 = sdk.la_acl_field_def()
        udf7.type = sdk.la_acl_field_type_e_TOS
        udf8 = sdk.la_acl_field_def()
        udf8.type = sdk.la_acl_field_type_e_IPV4_FLAGS
        udf9 = sdk.la_acl_field_def()
        udf9.type = sdk.la_acl_field_type_e_TCP_FLAGS
        udf10 = sdk.la_acl_field_def()
        udf10.type = sdk.la_acl_field_type_e_MSG_TYPE
        udf11 = sdk.la_acl_field_def()
        udf11.type = sdk.la_acl_field_type_e_IPV6_SIP
        udf12 = sdk.la_acl_field_def()
        udf12.type = sdk.la_acl_field_type_e_IPV6_DIP
        udf13 = sdk.la_acl_field_def()
        udf13.type = sdk.la_acl_field_type_e_LAST_NEXT_HEADER
        udf14 = sdk.la_acl_field_def()
        udf14.type = sdk.la_acl_field_type_e_VRF_GID
        ipv4_udk = [udf1, udf2, udf3, udf4, udf5, udf6, udf7, udf8, udf9, udf10, udf14]
        ipv6_udk = [udf11, udf12, udf3, udf4, udf13, udf7, udf9]
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        # IPv4 PBR ACL key profile
        key_type = sdk.la_acl_key_type_e_IPV4
        key_def = ipv4_udk
        cmd_def = sdk.LA_ACL_COMMAND
        self.ipv4_pbr_acl_key_profile = self.device.create_acl_key_profile(key_type, direction, key_def, tcam_pool_id)
        self.ipv4_pbr_acl_command_profile = self.device.create_acl_command_profile(cmd_def)
        # IPv6 PBR ACL key profile
        key_type = sdk.la_acl_key_type_e_IPV6
        key_def = ipv6_udk
        self.ipv6_pbr_acl_key_profile = self.device.create_acl_key_profile(key_type, direction, key_def, tcam_pool_id)
        self.ipv6_pbr_acl_command_profile = self.device.create_acl_command_profile(cmd_def)
        self.ipv4_pbr_acl_list = []
        self.ipv4_pbr_acl_group_list = []
        self.ipv6_pbr_acl_list = []
        self.ipv6_pbr_acl_group_list = []

    def create_pbr_acl(self, vrf):
        if (self.is_ipv4):
            ipv4_pbr_acl = self.device.create_acl(self.ipv4_pbr_acl_key_profile, self.ipv4_pbr_acl_command_profile)
            ipv4_pbr_acl_group = self.device.create_acl_group()
            self.ipv4_pbr_acl_list.append((vrf, ipv4_pbr_acl))
            self.ipv4_pbr_acl_group_list.append((vrf, ipv4_pbr_acl_group))
        else:
            ipv6_pbr_acl = self.device.create_acl(self.ipv6_pbr_acl_key_profile, self.ipv6_pbr_acl_command_profile)
            ipv6_pbr_acl_group = self.device.create_acl_group()
            self.ipv6_pbr_acl_list.append((vrf, ipv6_pbr_acl))
            self.ipv6_pbr_acl_group_list.append((vrf, ipv6_pbr_acl_group))

    def destroy_pbr_acl(self, vrf):
        acl = self.get_pbr_acl(vrf)
        acl_group = self.get_pbr_acl_group(vrf)
        self.device.destroy(acl_group)
        self.device.destroy(acl)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, PRIVATE_DATA_DEFAULT)

    def create_packets(self):
        rx_port_mac_str = T.mac_addr.mac_num_to_str(self.l3_port_impl.rx_port.hld_obj.get_mac().flat)
        tx_port_mac_str = T.mac_addr.mac_num_to_str(self.l3_port_impl.tx_port.hld_obj.get_mac().flat)
        nh_mac_str = self.l3_port_impl.reg_nh.mac_addr.addr_str
        vid1 = T.RX_L3_AC_PORT_VID1
        vid2 = T.RX_L3_AC_PORT_VID2

        if self.is_svi:
            vid1 = T.RX_L2_AC_PORT_VID1
            INPUT_TCP_PACKET_BASE = \
                Ether(dst=rx_port_mac_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vid1) / \
                IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL, dscp=DSCP, ecn=ECN) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")
            INPUT_ICMP_PACKET_BASE = \
                Ether(dst=rx_port_mac_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vid1) / \
                IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL, dscp=DSCP, ecn=ECN) / \
                ICMP()
        else:
            INPUT_TCP_PACKET_BASE = \
                Ether(dst=rx_port_mac_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=vid1, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vid2) / \
                IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL, dscp=DSCP, ecn=ECN) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")

            INPUT_ICMP_PACKET_BASE = \
                Ether(dst=rx_port_mac_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=vid1, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vid2) / \
                IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL, dscp=DSCP, ecn=ECN) / \
                ICMP()

        EXPECTED_OUTPUT_TCP_PACKET_BASE = \
            Ether(dst=nh_mac_str, src=tx_port_mac_str) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL - 1, dscp=DSCP, ecn=ECN) / \
            TCP(sport=SPORT, dport=DPORT, flags="SA")
        EXPECTED_OUTPUT_ICMP_PACKET_BASE = \
            Ether(dst=nh_mac_str, src=tx_port_mac_str) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL - 1, dscp=DSCP, ecn=ECN) / \
            ICMP()

        if self.is_ipv4:
            INPUT_TCP_PACKET_BASE[self.scapy_IP].len = IP_TOT_LEN
            INPUT_ICMP_PACKET_BASE[self.scapy_IP].len = IP_TOT_LEN
            EXPECTED_OUTPUT_TCP_PACKET_BASE[self.scapy_IP].len = IP_TOT_LEN
            EXPECTED_OUTPUT_ICMP_PACKET_BASE[self.scapy_IP].len = IP_TOT_LEN

        INPUT_TCP_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_TCP_PACKET_BASE)
        EXPECTED_OUTPUT_TCP_PACKET = add_payload(EXPECTED_OUTPUT_TCP_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
        INPUT_TCP_PACKET = add_payload(INPUT_TCP_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
        INPUT_ICMP_PACKET = add_payload(INPUT_ICMP_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
        EXPECTED_OUTPUT_ICMP_PACKET = add_payload(EXPECTED_OUTPUT_ICMP_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)

        return INPUT_TCP_PACKET, EXPECTED_OUTPUT_TCP_PACKET, INPUT_ICMP_PACKET, EXPECTED_OUTPUT_ICMP_PACKET

    ########## TEST CASES ##########
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_getters(self):
        self.create_pbr_acl(self.topology.vrf)
        acl = self.get_pbr_acl(self.topology.vrf)
        self.assertNotEqual(acl, None)

        count = acl.get_count()
        self.assertEqual(count, 0)

        profile = acl.get_acl_key_profile()
        self.assertNotEqual(profile, None)

        key_type = profile.get_key_type()
        if self.is_ipv4:
            self.assertEqual(key_type, sdk.la_acl_key_type_e_IPV4)
        else:
            self.assertEqual(key_type, sdk.la_acl_key_type_e_IPV6)

        direction = profile.get_direction()
        self.assertEqual(direction, sdk.la_acl_direction_e_INGRESS)

        tcam_pool_id = profile.get_key_tcam_pool_id()
        self.assertEqual(tcam_pool_id, 0)

        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_drop(self):
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(self.topology.vrf, command_type=command_type.DROP)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_police(self):
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(self.topology.vrf, command_type=command_type.POLICE)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_redirect(self):
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(self.topology.vrf, command_type=command_type.REDIRECT_DEST, is_verify_counter=False)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_remark(self):
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(self.topology.vrf, command_type=command_type.REMARK_DSCP, is_verify_counter=False)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_nop(self):
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(self.topology.vrf, command_type=command_type.NOP)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_multi_vrfs(self):
        # verify no interference between multiple VRFs
        # configure extra vrf with police PBR commands
        vrf = T.vrf(self, self.device, EXTRA_VRF_GID)
        self.create_pbr_acl(vrf)
        acl = self.get_pbr_acl(vrf)

        vrf_gid = EXTRA_VRF_GID
        self.add_aces(acl, vrf_gid, command_type=command_type.POLICE)

        # run drop test expecting it work although the extra vrf is set to police
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(self.topology.vrf, command_type=command_type.DROP)

        self.destroy_pbr_acl(vrf)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_acl_set_get(self):
        # run drop test
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(self.topology.vrf, command_type=command_type.DROP, skip_acl_detach=True)

        # create new counter to set (override) in the existing PBR ACEs
        for f in self.PBR_ACL_FIELDS:
            self.per_field_counters[f] = self.device.create_counter(MAX_COUNTER_OFFSET)

        # set the counters in the existing ACEs
        self.acl = self.get_pbr_acl(self.topology.vrf)
        for i in range(self.acl.get_count()):
            entry = self.acl.get(i)
            type = entry.key_val[0].type

            if len(entry.key_val) > 2:  # special entry of all fields
                entry.cmd_actions[1].data.counter = self.per_field_counters['ALL']
            elif type in [sdk.la_acl_field_type_e_IPV4_SIP, sdk.la_acl_field_type_e_IPV6_SIP]:
                entry.cmd_actions[1].data.counter = self.per_field_counters['SIP']
            elif type in [sdk.la_acl_field_type_e_IPV4_DIP, sdk.la_acl_field_type_e_IPV6_DIP]:
                entry.cmd_actions[1].data.counter = self.per_field_counters['DIP']
            elif type == sdk.la_acl_field_type_e_SPORT:
                entry.cmd_actions[1].data.counter = self.per_field_counters['SPORT']
            elif type == sdk.la_acl_field_type_e_DPORT:
                entry.cmd_actions[1].data.counter = self.per_field_counters['DPORT']
            elif type in [sdk.la_acl_field_type_e_PROTOCOL, sdk.la_acl_field_type_e_LAST_NEXT_HEADER]:
                entry.cmd_actions[1].data.counter = self.per_field_counters['PROTOCOL']
            elif type == sdk.la_acl_field_type_e_TOS:
                entry.cmd_actions[1].data.counter = self.per_field_counters['TOS']
            elif type == sdk.la_acl_field_type_e_IPV4_FLAGS:
                entry.cmd_actions[1].data.counter = self.per_field_counters['IPV4_FLAGS']
            elif type == sdk.la_acl_field_type_e_VRF_GID:
                entry.cmd_actions[1].data.counter = self.per_field_counters['VRF_GID']
            elif type == sdk.la_acl_field_type_e_TCP_FLAGS:
                entry.cmd_actions[1].data.counter = self.per_field_counters['TCP_FLAGS']
            elif type == sdk.la_acl_field_type_e_IPV4_LENGTH:
                entry.cmd_actions[1].data.counter = self.per_field_counters['IPV4_LENGTH']
            elif type == sdk.la_acl_field_type_e_MSG_TYPE:
                entry.cmd_actions[1].data.counter = self.per_field_counters['MSG_TYPE']
            else:
                self.assertTrue(False)

            key_val = entry.key_val
            cmd_actions = list(entry.cmd_actions)
            self.acl.set(i, key_val, cmd_actions)

        # verify that the newly set counters are working
        self._test_all_acl_fields(self.topology.vrf, command_type.DROP, skip_add_ace=True, skip_acl_attach=True)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_acl_clear(self):
        port_counter = self.device.create_counter(1)
        self.rx_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)

        self.rx_port.hld_obj.set_pbr_enabled(True)
        self.create_pbr_acl(self.topology.vrf)
        acl = self.get_pbr_acl(self.topology.vrf)
        acl_group = self.get_pbr_acl_group(self.topology.vrf)

        if self.is_ipv4:
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl])
            self.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        else:
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl])
            self.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # first verify packet is dropped
        vrf_gid = T.VRF_GID
        self.add_aces(acl, vrf_gid, command_type.DROP)
        run_and_drop(self, self.device, self.in_tcp_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        packet_count, byte_count = port_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        # second clear PBR and verify that packet is forwarded
        acl.clear()
        run_and_compare(self, self.device,
                        self.in_tcp_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.out_tcp_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = port_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.rx_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_shared_drop_counter(self):
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(
            self.topology.vrf,
            command_type=command_type.DROP,
            is_shared_counter=True,
            is_verify_counter=False)

        # verify any counter in per_field_counters (they all point to the same counter)
        packet_count, byte_count = self.per_field_counters['ALL'].read(DROP_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, len(self.PBR_ACL_FIELDS))
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_shared_meter(self):
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(
            self.topology.vrf,
            command_type=command_type.POLICE,
            is_shared_counter=True,
            is_verify_counter=False)

        # verify any meter in per_field_counters (they all point to the same meter)
        g_packet_count, g_byte_count = self.per_field_counters['ALL'].read(0, True, True, sdk.la_qos_color_e_GREEN)
        y_packet_count, y_byte_count = self.per_field_counters['ALL'].read(0, True, True, sdk.la_qos_color_e_YELLOW)
        r_packet_count, r_byte_count = self.per_field_counters['ALL'].read(0, True, True, sdk.la_qos_color_e_RED)

        self.assertEqual(g_packet_count, len(self.PBR_ACL_FIELDS))
        self.assertEqual(y_packet_count, 0)
        self.assertEqual(r_packet_count, 0)
        self.assertEqual(y_byte_count, 0)
        self.assertEqual(r_byte_count, 0)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_port_enable_disable(self):
        # Enable PBR on the RX l3_port and verify - packets should be dropped
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(self.topology.vrf, command_type=command_type.DROP, enable_pbr=True)
        self.destroy_pbr_acl(self.topology.vrf)

        # Disable PBR on the RX l3_port and verify - should have no effect on packets flow
        self.create_pbr_acl(self.topology.vrf)
        self._test_all_acl_fields(self.topology.vrf, command_type=command_type.DROP, enable_pbr=False, skip_add_ace=True)
        self.destroy_pbr_acl(self.topology.vrf)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_scale(self):
        self.create_pbr_acl(self.topology.vrf)
        acl = self.get_pbr_acl(self.topology.vrf)
        acl_group = self.get_pbr_acl_group(self.topology.vrf)

        if self.is_ipv4:
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl])
            self.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        else:
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl])
            self.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        k = []
        f = sdk.la_acl_field()
        if self.is_ipv4:
            # ACE to catch DPORT
            f.type = sdk.la_acl_field_type_e_DPORT
            f.val.dport = DPORT
            f.mask.dport = 0xffff
        else:
            # ACE to catch PROTOCOL
            f.type = sdk.la_acl_field_type_e_LAST_NEXT_HEADER
            f.val.last_next_header = sdk.la_l4_protocol_e_TCP
            f.mask.last_next_header = 0xff
        k.append(f)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = True
        commands.append(action1)

        for i in range(self.MAX_PBR_ENTRIES):
            count_pre = acl.get_count()
            acl.append(k, commands)
            count_post = acl.get_count()
            self.assertEqual(count_post, count_pre + 1)

        count = acl.get_count()
        self.assertEqual(count, self.MAX_PBR_ENTRIES)
        acl.clear()
        self.rx_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.destroy_pbr_acl(self.topology.vrf)

    ########## Helper Methods ##########
    def _test_all_acl_fields(
            self,
            vrf,
            command_type,
            skip_add_ace=False,
            is_shared_counter=False,
            is_verify_counter=True,
            enable_pbr=True,
            skip_acl_attach=False,
            skip_acl_detach=False):
        port_counter = self.device.create_counter(1)
        self.rx_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.rx_port.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, DROP_COUNTER_OFFSET)
        self.acl = self.get_pbr_acl(vrf)
        self.acl_group = self.get_pbr_acl_group(vrf)

        # If requested, enable PBR at l3_port level
        if enable_pbr:
            self.rx_port.hld_obj.set_pbr_enabled(True)
        else:
            self.rx_port.hld_obj.set_pbr_enabled(False)

        if not skip_add_ace:
            # Install ACE per PBR matching rule
            # Also, installs a special ACE to match all PBR matching fields (called 'ALL')
            vrf_gid = T.VRF_GID
            self.add_aces(self.acl, vrf_gid, command_type, is_shared_counter)

        if not skip_acl_attach:
            if self.is_ipv4:
                self.acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [self.acl])
                self.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, self.acl_group)
            else:
                self.acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [self.acl])
                self.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, self.acl_group)

        # Create packet per PBR matching field dictionary:
        #      packets[PBR matching field] -> packet that matches that field and only that field
        # For each PBR supported matching field, send a packet matching that field and:
        #   1- Verify packet is dropped/forwarded depedning on the given command_type
        #   2- Verify the corresponding ACE is hit by examining its counter/meter set
        packets = self.create_match_packet_per_field()
        for f in self.PBR_ACL_FIELDS:
            if command_type == command_type.DROP and enable_pbr:
                run_and_drop(self, self.device, packets[f]['input'], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            elif command_type == command_type.REDIRECT_DEST and enable_pbr:
                run_and_compare(self, self.device,
                                packets[f]['input'], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                packets[f]['output_redirect'], T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3)
            elif command_type == command_type.REMARK_DSCP and enable_pbr:
                run_and_compare(self, self.device,
                                packets[f]['input'], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                packets[f]['output_remark'], T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
            else:
                run_and_compare(self, self.device,
                                packets[f]['input'], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                packets[f]['output'], T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

            if is_verify_counter:
                if not enable_pbr:
                    command_type = command_type.NOP
                self.verify_acl_counters(f, command_type, port_counter)

        if not skip_acl_detach:
            self.rx_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def get_pbr_acl(self, vrf):
        acl = []
        if self.is_ipv4:
            for ipv4_pbr_acl in self.ipv4_pbr_acl_list:
                if (ipv4_pbr_acl[0] == vrf):
                    acl = ipv4_pbr_acl[1]
        else:
            for ipv6_pbr_acl in self.ipv6_pbr_acl_list:
                if (ipv6_pbr_acl[0] == vrf):
                    acl = ipv6_pbr_acl[1]
        return acl

    def get_pbr_acl_group(self, vrf):
        acl_group = []
        if self.is_ipv4:
            for ipv4_pbr_acl_group in self.ipv4_pbr_acl_group_list:
                if (ipv4_pbr_acl_group[0] == vrf):
                    acl_group = ipv4_pbr_acl_group[1]
        else:
            for ipv6_pbr_acl_group in self.ipv6_pbr_acl_group_list:
                if (ipv6_pbr_acl_group[0] == vrf):
                    acl_group = ipv6_pbr_acl_group[1]
        return acl_group

    def create_match_packet_per_field(self):
        packets = {}

        for f in self.PBR_ACL_FIELDS:
            if f != 'MSG_TYPE':
                out_packet = self.out_tcp_packet.copy()
                p = self.in_tcp_packet.copy()
            else:
                out_packet = self.out_icmp_packet.copy()
                p = self.in_icmp_packet.copy()

            # Poison all fields other than the requested one
            if f != 'ALL':
                if f is not 'SIP':
                    p[self.scapy_IP].src = ipaddress.ip_address(self.SIP.to_num() + 1).exploded

                if f is not 'DIP':
                    p[self.scapy_IP].dst = ipaddress.ip_address(self.DIP.to_num() + 1).exploded

                if self.is_ipv4:
                    if f is not 'IPV4_FLAGS':
                        p[self.scapy_IP].frag = 1

                    if f is not 'IPV4_LENGTH':
                        p[self.scapy_IP].len = IP_TOT_LEN + 1

                if f is not 'TOS':
                    if self.is_ipv4:
                        p[self.scapy_IP].tos = DSCP_2 << 2 | ECN
                    else:
                        p[self.scapy_IP].tc = DSCP_2 << 2 | ECN

                if f is not 'MSG_TYPE':
                    if f is not 'SPORT':
                        p[TCP].sport = p[TCP].sport + 1

                    if f is not 'DPORT':
                        p[TCP].dport = p[TCP].dport + 1

                    if f is not 'PROTOCOL' and f is not 'TCP_FLAGS':
                        if self.is_ipv4:
                            p[self.scapy_IP].proto = socket.IPPROTO_UDP
                        else:
                            p[self.scapy_IP].nh = socket.IPPROTO_UDP
                    else:
                        if f is not 'TCP_FLAGS':
                            p[TCP].flags = "S"

            out_packet[self.scapy_IP] = p[self.scapy_IP].copy()
            if self.is_ipv4:
                out_packet[self.scapy_IP].ttl = out_packet[self.scapy_IP].ttl - 1
            else:
                out_packet[self.scapy_IP].hlim = out_packet[self.scapy_IP].hlim - 1

            out_packet_redirect  = out_packet.copy()
            out_packet_redirect[Ether].dst = T.NH_L3_AC_EXT_MAC.addr_str
            out_packet_redirect[Ether].src = T.TX_L3_AC_EXT_MAC.addr_str

            out_packet_remark_dscp = out_packet.copy()
            if self.is_ipv4:
                out_packet_remark_dscp[self.scapy_IP].tos = OUT_DSCP_REMARK << 2 | ECN
            else:
                out_packet_remark_dscp[self.scapy_IP].tc = OUT_DSCP_REMARK << 2 | ECN

            packets[f] = {
                'input': p,
                'output': out_packet,
                'output_redirect': out_packet_redirect,
                'output_remark': out_packet_remark_dscp}

        return packets

    def verify_acl_counters(self, field_name, command_type, port_counter):
        if command_type == command_type.NOP:
            # In case of NOP no PBR hit thus port counter is expected to advance.
            packet_count, byte_count = port_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)

        elif command_type == command_type.DROP:
            # Each supported PBR packet field has its own ACE and drop counter installed by add_aces()
            # verify that only that counter has ticked at the offset of DROP_COUNTER_OFFSET.
            for f, c in self.per_field_counters.items():
                for i in range(MAX_COUNTER_OFFSET):
                    packet_count, byte_count = c.read(i, True, True)
                    if f == field_name and i == DROP_COUNTER_OFFSET:
                        self.assertEqual(packet_count, 1, f)
                    else:
                        self.assertEqual(packet_count, 0, f)
                        self.assertEqual(byte_count, 0, f)

        else:
            # Each supported PBR packet field has its own ACE and meter installed by add_aces()
            # verify that only that meter's green counter has ticked.
            for f, m in self.per_field_counters.items():
                g_packet_count, g_byte_count = m.read(0, True, True, sdk.la_qos_color_e_GREEN)
                y_packet_count, y_byte_count = m.read(0, True, True, sdk.la_qos_color_e_YELLOW)
                r_packet_count, r_byte_count = m.read(0, True, True, sdk.la_qos_color_e_RED)

                if f == field_name:
                    self.assertEqual(g_packet_count, 1, f)
                    self.assertEqual(y_packet_count, 0, f)
                    self.assertEqual(r_packet_count, 0, f)

                    self.assertEqual(y_byte_count, 0, f)
                    self.assertEqual(r_byte_count, 0, f)
                else:
                    self.assertEqual(g_packet_count, 0, f)
                    self.assertEqual(y_packet_count, 0, f)
                    self.assertEqual(r_packet_count, 0, f)

                    self.assertEqual(g_byte_count, 0, f)
                    self.assertEqual(y_byte_count, 0, f)
                    self.assertEqual(r_byte_count, 0, f)

    def set_counter_or_meter(self, commands, command_type, counter):
        if command_type == command_type.DROP:
            action1 = sdk.la_acl_command_action()
            action1.type = sdk.la_acl_action_type_e_DROP
            action1.data.drop = True
            commands.append(action1)
            action2 = sdk.la_acl_command_action()
            action2.type = sdk.la_acl_action_type_e_COUNTER
            action2.data.counter = counter
            commands.append(action2)
        if command_type == command_type.NOP:
            action1 = sdk.la_acl_command_action()
            action1.type = sdk.la_acl_action_type_e_DROP
            action1.data.drop = False
            commands.append(action1)
            action2 = sdk.la_acl_command_action()
            action2.type = sdk.la_acl_action_type_e_COUNTER
            action2.data.counter = counter
            commands.append(action2)
        elif command_type == command_type.POLICE:
            action1 = sdk.la_acl_command_action()
            action1.type = sdk.la_acl_action_type_e_COUNTER_TYPE
            action1.data.counter_type = sdk.la_acl_counter_type_e_OVERRIDE_METERING_PTR
            commands.append(action1)
            action2 = sdk.la_acl_command_action()
            action2.type = sdk.la_acl_action_type_e_METER
            action2.data.meter = counter
            commands.append(action2)
        elif command_type == command_type.REDIRECT_DEST:
            action = sdk.la_acl_command_action()
            action.type = sdk.la_acl_action_type_e_L3_DESTINATION
            action.data.l3_dest = self.topology.fec_l3_ac_ext.hld_obj
            commands.append(action)
        elif command_type == command_type.REMARK_DSCP:
            action1 = sdk.la_acl_command_action()
            action1.type = sdk.la_acl_action_type_e_COUNTER_TYPE
            action1.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
            commands.append(action1)

            action2 = sdk.la_acl_command_action()
            action2.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
            action2.data.qos_offset = 0
            commands.append(action2)

            action3 = sdk.la_acl_command_action()
            action3.type = sdk.la_acl_action_type_e_REMARK_FWD
            action3.data.remark_fwd = OUT_DSCP_REMARK
            commands.append(action3)

            action4 = sdk.la_acl_command_action()
            action4.type = sdk.la_acl_action_type_e_ENCAP_EXP
            action4.data.encap_exp = 0
            commands.append(action4)

            action5 = sdk.la_acl_command_action()
            action5.type = sdk.la_acl_action_type_e_REMARK_GROUP
            action5.data.remark_group = 0
            commands.append(action5)

    def add_aces(self, acl, vrf_gid, command_type, is_shared_counter=False):
        count = acl.get_count()
        self.assertEqual(count, 0)

        if is_shared_counter:
            if command_type == command_type.DROP:
                shared_counter = self.device.create_counter(MAX_COUNTER_OFFSET)
            elif command_type == command_type.POLICE:
                shared_meter = T.create_meter_set(self, self.device, set_size=1, is_aggregate=True)

        for f in self.PBR_ACL_FIELDS:
            if command_type == command_type.DROP:
                self.per_field_counters[f] = shared_counter if is_shared_counter else self.device.create_counter(
                    MAX_COUNTER_OFFSET)
            elif command_type == command_type.POLICE:
                self.per_field_counters[f] = shared_meter if is_shared_counter else T.create_meter_set(
                    self, self.device, set_size=1, is_aggregate=True)
            else:
                self.per_field_counters[f] = None

        k_all = []
        # ACE to catch VRF_GID
        if self.is_ipv4:
            k = []
            f = sdk.la_acl_field()
            f.type = sdk.la_acl_field_type_e_VRF_GID
            f.val.vrf_gid = vrf_gid
            f.mask.vrf_gid = 0x7FF
            k.append(f)
            k_all.append(f)
            commands = []
            self.set_counter_or_meter(commands, command_type, self.per_field_counters['VRF_GID'])
            count_pre = acl.get_count()
            acl.insert(0, k, commands)
            count_post = acl.get_count()
            self.assertEqual(count_post, count_pre + 1)

        # ACE to catch SIP
        k = []
        f = sdk.la_acl_field()
        if self.is_ipv4:
            f.type = sdk.la_acl_field_type_e_IPV4_SIP
            f.val.ipv4_sip.s_addr = self.SIP.to_num()
            f.mask.ipv4_sip.s_addr = self.IP_MASK.to_num()
        else:
            f.type = sdk.la_acl_field_type_e_IPV6_SIP
            f.val.ipv6_sip = self.SIP.hld_obj
            f.mask.ipv6_sip = self.IP_MASK.hld_obj
        k.append(f)
        k_all.append(f)
        commands = []
        self.set_counter_or_meter(commands, command_type, self.per_field_counters['SIP'])
        count_pre = acl.get_count()
        acl.insert(0, k, commands)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        # ACE to catch DIP
        k = []
        f = sdk.la_acl_field()
        if self.is_ipv4:
            f.type = sdk.la_acl_field_type_e_IPV4_DIP
            f.val.ipv4_dip.s_addr = DIP_V4.to_num()
            f.mask.ipv4_dip.s_addr = 0xffffffff
        else:
            f.type = sdk.la_acl_field_type_e_IPV6_DIP
            f.val.ipv6_dip = self.DIP.hld_obj
            f.mask.ipv6_dip = self.IP_MASK.hld_obj
        k.append(f)
        k_all.append(f)
        commands = []
        self.set_counter_or_meter(commands, command_type, self.per_field_counters['DIP'])
        count_pre = acl.get_count()
        acl.insert(0, k, commands)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        # ACE to catch SPORT
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_SPORT
        f.val.sport = SPORT
        f.mask.sport = 0xffff
        k.append(f)
        k_all.append(f)
        commands = []
        self.set_counter_or_meter(commands, command_type, self.per_field_counters['SPORT'])
        count_pre = acl.get_count()
        acl.insert(0, k, commands)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        # ACE to catch DPORT
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_DPORT
        f.val.dport = DPORT
        f.mask.dport = 0xffff
        k.append(f)
        k_all.append(f)
        commands = []
        self.set_counter_or_meter(commands, command_type, self.per_field_counters['DPORT'])
        count_pre = acl.get_count()
        acl.insert(0, k, commands)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        # ACE to catch PROTOCOL
        k = []
        f = sdk.la_acl_field()
        if self.is_ipv4:
            f.type = sdk.la_acl_field_type_e_PROTOCOL
            f.val.protocol = sdk.la_l4_protocol_e_TCP
            f.mask.protocol = 0xff
        else:
            f.type = sdk.la_acl_field_type_e_LAST_NEXT_HEADER
            f.val.last_next_header = sdk.la_l4_protocol_e_TCP
            f.mask.last_next_header = 0xff
        k.append(f)
        k_all.append(f)
        commands = []
        self.set_counter_or_meter(commands, command_type, self.per_field_counters['PROTOCOL'])
        count_pre = acl.get_count()
        acl.insert(0, k, commands)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        # ACE to catch TCP Flags
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_TCP_FLAGS
        f.val.tcp_flags.fields.syn = 1
        f.val.tcp_flags.fields.ack = 1
        f.mask.tcp_flags.flat = 0x3f
        k.append(f)
        k_all.append(f)
        f = sdk.la_acl_field()
        if self.is_ipv4:
            f.type = sdk.la_acl_field_type_e_PROTOCOL
            f.val.protocol = sdk.la_l4_protocol_e_TCP
            f.mask.protocol = 0xff
        else:
            f.type = sdk.la_acl_field_type_e_LAST_NEXT_HEADER
            f.val.last_next_header = sdk.la_l4_protocol_e_TCP
            f.mask.last_next_header = 0xff
        k.append(f)
        commands = []
        self.set_counter_or_meter(commands, command_type, self.per_field_counters['TCP_FLAGS'])
        count_pre = acl.get_count()
        acl.insert(0, k, commands)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        # ACE to catch TOS
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_TOS
        f.val.tos.fields.ecn = ECN
        f.val.tos.fields.dscp = DSCP
        f.mask.tos.flat = 0xff
        k.append(f)
        k_all.append(f)
        commands = []
        self.set_counter_or_meter(commands, command_type, self.per_field_counters['TOS'])
        count_pre = acl.get_count()
        acl.insert(0, k, commands)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        if self.is_ipv4:
            # ACE to catch IPV4 first fragment
            k = []
            f = sdk.la_acl_field()
            f.type = sdk.la_acl_field_type_e_IPV4_FLAGS
            f.val.ipv4_flags.fragment = 0
            f.mask.ipv4_flags.fragment = 1
            k.append(f)
            k_all.append(f)
            commands = []
            self.set_counter_or_meter(commands, command_type, self.per_field_counters['IPV4_FLAGS'])
            count_pre = acl.get_count()
            acl.insert(0, k, commands)
            count_post = acl.get_count()
            self.assertEqual(count_post, count_pre + 1)

            # ACE to catch IPV4 total length
            k = []
            f = sdk.la_acl_field()
            f.type = sdk.la_acl_field_type_e_IPV4_LENGTH
            f.val.ipv4_length = IP_TOT_LEN
            f.mask.ipv4_length = 0xffff
            k.append(f)
            k_all.append(f)
            commands = []
            self.set_counter_or_meter(commands, command_type, self.per_field_counters['IPV4_LENGTH'])
            count_pre = acl.get_count()
            acl.insert(0, k, commands)
            count_post = acl.get_count()
            self.assertEqual(count_post, count_pre + 1)

            # ACE to match on ICMP msg type
            k = []
            f = sdk.la_acl_field()
            f.type = sdk.la_acl_field_type_e_MSG_TYPE
            f.val.mtype = 0x8
            f.mask.mtype = 0xff
            k.append(f)
            commands = []
            self.set_counter_or_meter(commands, command_type, self.per_field_counters['MSG_TYPE'])
            count_pre = acl.get_count()
            acl.insert(0, k, commands)
            count_post = acl.get_count()
            self.assertEqual(count_post, count_pre + 1)

        # ACE to catch all fields
        commands = []
        self.set_counter_or_meter(commands, command_type, self.per_field_counters['ALL'])
        count_pre = acl.get_count()
        acl.insert(0, k_all, commands)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        # Make sure number of ACEs is equal to PBR_ACL_FIELDS tested fields
        count = acl.get_count()
        self.assertEqual(count, len(self.PBR_ACL_FIELDS))
