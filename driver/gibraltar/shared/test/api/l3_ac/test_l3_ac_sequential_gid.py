#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import ip_test_base
import topology as T
from sdk_test_case_base import *
import nplapicli
import decor

TX_SLICE = T.get_device_slice(1)
TX_IFG = 0
TX_SERDES_DEF = 1
TX_SERDES_REG = 2

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

SIP = T.ipv4_addr('192.193.194.195')
DIP = T.ipv4_addr('208.209.210.211')

TTL = 127

INPUT_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    ICMP()

EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()

INPUT_PACKET, PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)

# DLP mapping 1:1 ACL ids on egress


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
class l3_ac_sequential_gid(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp(create_default_topology=False)
        self.create_network_topology()
        self.topology.create_inject_ports()
        self.inserted_drop_counter = None

    def tearDown(self):
        super().tearDown()

    def create_network_topology(self):
        # Create L2 objects
        self.rx_eth_port = T.ethernet_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            T.RX_SYS_PORT_GID,
            T.FIRST_SERDES,
            T.LAST_SERDES)
        self.tx_l3_ac_eth_port_reg = T.ethernet_port(
            self,
            self.device,
            TX_SLICE,
            TX_IFG,
            T.TX_L3_AC_SYS_PORT_REG_GID,
            TX_SERDES_REG,
            TX_SERDES_REG)
        self.tx_l3_ac_eth_port_def = T.ethernet_port(
            self,
            self.device,
            TX_SLICE,
            TX_IFG,
            T.TX_L3_AC_SYS_PORT_DEF_GID,
            TX_SERDES_DEF,
            TX_SERDES_DEF)

        # Create VRF
        self.vrf = T.vrf(self, self.device, T.VRF_GID)

        # Create L3 objects
        self.rx_l3_ac = T.l3_ac_port(self, self.device,
                                     T.RX_L3_AC_GID,
                                     self.rx_eth_port,
                                     self.vrf,
                                     T.RX_L3_AC_MAC,
                                     T.RX_L3_AC_PORT_VID1,
                                     T.RX_L3_AC_PORT_VID2)
        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        self.tx_l3_ac_reg = T.l3_ac_port(
            self,
            self.device,
            T.TX_L3_AC_REG_GID,
            self.tx_l3_ac_eth_port_reg,
            self.vrf,
            T.TX_L3_AC_REG_MAC)
        self.tx_l3_ac_def = T.l3_ac_port(
            self,
            self.device,
            T.TX_L3_AC_REG_GID + 1,
            self.tx_l3_ac_eth_port_def,
            self.vrf,
            T.TX_L3_AC_DEF_MAC)

        # Create L3 destinations
        self.nh_l3_ac_reg = T.next_hop(self, self.device, T.NH_L3_AC_REG_GID, T.NH_L3_AC_REG_MAC, self.tx_l3_ac_reg)
        self.nh_l3_ac_def = T.next_hop(self, self.device, T.NH_L3_AC_DEF_GID, T.NH_L3_AC_DEF_MAC, self.tx_l3_ac_def)

    def add_route(self, next_hop):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0

        self.vrf.hld_obj.add_ipv4_route(prefix, next_hop.hld_obj, self.PRIVATE_DATA, False)

    def destroy_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.vrf.hld_obj.delete_ipv4_route(prefix)

    def do_test_route_default(self):
        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_PACKET, TX_SLICE, TX_IFG, TX_SERDES_DEF)

    def do_test_route_regular(self):
        run_and_drop(self, self.device,
                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def create_empty_acl(self):
        ''' Create empty ACL. '''

        acl = self.device.create_acl(self.topology.egress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl, None)

        count = acl.get_count()
        self.assertEqual(count, 0)

        return acl

    def insert_ace(self, acl, is_drop):
        ''' Insert ACE that catch all traffic and result in drop if is_drop True. '''

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = SIP.to_num()
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k1.append(f1)

        acl_cmd = []
        drop_action = sdk.la_acl_command_action()
        drop_action.type = sdk.la_acl_action_type_e_DROP
        drop_action.data.drop = is_drop
        acl_cmd.append(drop_action)

        if (is_drop):
            if self.inserted_drop_counter is None:
                counter = self.device.create_counter(8)
                counter_cmd_action = sdk.la_acl_command_action()
                counter_cmd_action.type = sdk.la_acl_action_type_e_COUNTER
                counter_cmd_action.data.counter = counter
                acl_cmd.append(counter_cmd_action)
                self.inserted_drop_counter = counter

        count_pre = acl.get_count()

        acl.insert(0, k1, acl_cmd)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

    def insert_drop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop.'''
        self.insert_ace(acl, True)

    def insert_nop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in NOP. '''
        self.insert_ace(acl, False)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "RTF is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_l3_ac_sequential_gid(self):

        acl_nop = self.create_empty_acl()
        self.insert_nop_ace(acl_nop)

        acl_drop = self.create_empty_acl()
        self.insert_drop_ace(acl_drop)

        acl_group_nop = self.device.create_acl_group()
        acl_group_nop.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl_nop])

        acl_group_drop = self.device.create_acl_group()
        acl_group_drop.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl_drop])

        self.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group_nop)
        self.tx_l3_ac_reg.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group_drop)

        self.add_route(self.nh_l3_ac_def)
        self.do_test_route_default()
        self.destroy_route()

        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        self.add_route(self.nh_l3_ac_reg)
        self.do_test_route_regular()
        self.destroy_route()

        # Check counter
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)


if __name__ == '__main__':
    unittest.main()
