# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import unittest
from unified_table_test_case_base import *
import decor
import logging
import topology as T
from packet_test_utils import *

#
# Overall description for tests involving packet behavior:
#
#   - fill a table with all empty entries, except three special entries (drop/nop/redirect)
#   - erase certain number of entries from that table that are not special
#   - fill a table from another group, so that TCAM reallocation is triggered
#   - throughout the test, check if the packet behaves as expected with respect to dropping
#
# Relative order of special entries determines packet pehavior, and this order
# should remain the same after TCAM reallocation as it was before.
#
# Individual tests differ from each other by the choice of tables and
# the pattern of insertion of special entries.
#

# In order to see logging messages, uncomment next line:
# logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

#
# common constants for functions in this file
#

SIP_IPV4 = T.ipv4_addr('192.193.194.195')
DIP_IPV4 = T.ipv4_addr('208.209.210.211')

SIP_IPV6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP_IPV6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

SA = T.mac_addr('be:ef:5d:35:7a:35')
TTL = 127


@unittest.skipUnless(decor.is_hw_pacific() or decor.is_hw_gibraltar(), "Requires HW Pacific or Gb device")
class test_packet_behavior(unified_table_test_case_base):

    def _get_ipv4_key(self):
        key = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV4_DIP
        f.val.ipv4_dip.s_addr = DIP_IPV4.to_num()
        f.mask.ipv4_dip.s_addr = 0xffffffff
        key.append(f)
        return key

    def _get_ipv6_key(self):
        key = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV6_DIP
        q0 = sdk.get_ipv6_addr_q0(DIP_IPV6.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(DIP_IPV6.hld_obj)
        sdk.set_ipv6_addr(f.val.ipv6_dip, q0, q1)
        sdk.set_ipv6_addr(f.mask.ipv6_dip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(f)
        return key

    def _create_ipv4_input_packet(self):

        input_packet_base = \
            Ether(dst=RX_L3_AC_MAC2.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=SIP_IPV4.addr_str, dst=DIP_IPV4.addr_str, ttl=TTL) / \
            ICMP()

        input_packet, input_packet_payload_size = enlarge_packet_to_min_length(input_packet_base)

        return input_packet

    def _create_ipv6_input_packet(self):

        input_packet_base = \
            Ether(dst=RX_L3_AC_MAC2.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=SIP_IPV6.addr_str, dst=DIP_IPV6.addr_str, hlim=TTL) / \
            TCP()

        input_packet_svi_base = \
            Ether(dst=RX_L3_AC_MAC2.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IPv6(src=SIP_IPV6.addr_str, dst=DIP_IPV6.addr_str, hlim=TTL) / \
            TCP()

        input_packet_svi, input_packet_payload_size = enlarge_packet_to_min_length(input_packet_svi_base)
        input_packet = add_payload(input_packet_base, input_packet_payload_size)

        return input_packet

    # \brief Inserts entry for NOP operation.
    # \param self
    # \param is_ipv6    False for ipv4, True for ipv6 entry.
    # \param table_name Table name.
    # \param table      Table object reference.
    # \param generator  Generator object reference.
    def insert_nop_entry(self, is_ipv6, table_name, table, generator):

        before_insert_count = table.do_get_count()
        logging.info("Inserting nop entry into " + table_name +
                     " - entry count before: " + str(before_insert_count))

        cmd = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_action_type_e_DROP
        action.data.drop = False
        cmd.append(action)

        key = self._get_ipv6_key() if is_ipv6 else self._get_ipv4_key()

        table.do_append(generator.construct_entry(key, cmd))

        after_insert_count = table.do_get_count()
        logging.info("Entry count after: " + str(after_insert_count))
        self.assertEqual(after_insert_count, before_insert_count + 1)

    # \brief Inserts entry for REDIRECT operation.
    # \param self
    # \param is_ipv6    False for ipv4, True for ipv6 entry.
    # \param table_name Table name.
    # \param table      Table object reference.
    # \param generator  Generator object reference.
    def insert_redirect_entry(self, is_ipv6, table_name, table, generator):

        before_insert_count = table.do_get_count()
        logging.info("Inserting redirect entry into " + table_name +
                     " - entry count before: " + str(before_insert_count))

        cmd = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action.data.l3_dest = self.topology.fec_l3_ac_ext.hld_obj
        cmd.append(action)

        key = self._get_ipv6_key() if is_ipv6 else self._get_ipv4_key()

        table.do_append(generator.construct_entry(key, cmd))

        after_insert_count = table.do_get_count()
        logging.info("Entry count after: " + str(after_insert_count))
        self.assertEqual(after_insert_count, before_insert_count + 1)

    # \brief Inserts entry for DROP operation.
    # \param self
    # \param is_ipv6    False for ipv4, True for ipv6 entry.
    # \param table_name Table name.
    # \param table      Table object reference.
    # \param generator  Generator object reference.
    def insert_drop_entry(self, is_ipv6, table_name, table, generator):

        before_insert_count = table.do_get_count()
        logging.info("Inserting drop entry into " + table_name +
                     " - entry count before: " + str(before_insert_count))

        cmd = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_action_type_e_DROP
        action.data.drop = True
        cmd.append(action)

        key = self._get_ipv6_key() if is_ipv6 else self._get_ipv4_key()

        table.do_append(generator.construct_entry(key, cmd))

        after_insert_count = table.do_get_count()
        logging.info("Entry count after: " + str(after_insert_count))
        self.assertEqual(after_insert_count, before_insert_count + 1)

    # \brief Runs an IPv4 security packet and checkes if it is not dropped.
    # \param self
    # \param is_ipv6    False for ipv4, True for ipv6 entry.
    def do_test_entry_not_drop(self, is_ipv6):

        logging.info("Check if the packet is NOT dropped.")

        input_packet = self._create_ipv6_input_packet() if is_ipv6 else self._create_ipv4_input_packet()

        try:
            run_and_drop(self, self.device, input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)
            logging.info("Packet dropped.")
            self.fail("Packet unexpectedly dropped.")
        except BaseException:
            logging.info("Packet NOT dropped.")

    # \brief Runs an IPv4 security packet and checkes if it is dropped.
    # \param self
    # \param is_ipv6    False for ipv4, True for ipv6 entry.
    def do_test_entry_drop(self, is_ipv6):

        logging.info("Check if the packet is dropped.")

        input_packet = self._create_ipv6_input_packet() if is_ipv6 else self._create_ipv4_input_packet()

        # no need to catch or raise exceptions, run_and_drop() will raise an exception on packet not dropping
        run_and_drop(self, self.device, input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)
        logging.info("Packet dropped.")

    def run_packet_behavior_scenario(self, is_ipv6, table_1_name, table_2_name, pattern):

        table_1_ref = table_factory.create_table(self, self.device, self.topology, table_1_name, 0)
        table_1_gen = gen_factory.create_gen(self, self.device, table_1_name)
        table_1_ref.attach_default()

        table_2_ref = table_factory.create_table(self, self.device, self.topology, table_2_name, 0)
        table_2_gen = gen_factory.create_gen(self, self.device, table_2_name)
        table_2_ref.attach_default()

        offset_short = 30
        offset_long = 800
        erase_start = 100
        erase_step = 1
        erase_count = 512

        offset1, offset2, offset3 = {
            1: (offset_short, offset_short, offset_short),
            2: (offset_short, offset_short, offset_long),
            3: (offset_short, offset_long, offset_short),
            4: (offset_long, offset_short, offset_short)
        }[pattern]

        self.do_test_entry_not_drop(is_ipv6)

        self.insert_entries(table_1_name, table_1_ref, table_1_gen, offset1)
        self.do_test_entry_not_drop(is_ipv6)

        self.insert_drop_entry(is_ipv6, table_1_name, table_1_ref, table_1_gen)
        self.do_test_entry_drop(is_ipv6)

        self.insert_entries(table_1_name, table_1_ref, table_1_gen, offset2)
        self.do_test_entry_drop(is_ipv6)

        self.insert_redirect_entry(is_ipv6, table_1_name, table_1_ref, table_1_gen)
        self.do_test_entry_drop(is_ipv6)

        self.insert_entries(table_1_name, table_1_ref, table_1_gen, offset3)
        self.do_test_entry_drop(is_ipv6)

        self.insert_nop_entry(is_ipv6, table_1_name, table_1_ref, table_1_gen)
        self.do_test_entry_drop(is_ipv6)

        self.fill_table(table_1_name, table_1_ref, table_1_gen)
        self.do_test_entry_drop(is_ipv6)

        self.erase_entries_regular(table_1_name, table_1_ref, erase_start, erase_step, erase_count)
        self.do_test_entry_drop(is_ipv6)

        self.fill_table(table_2_name, table_2_ref, table_2_gen)
        self.do_test_entry_drop(is_ipv6)

        table_1_ref.detach_default()
        table_2_ref.detach_default()

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_packet_behavior_nn_1(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = False,
            table_1_name="INGRESS_IPV4_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            pattern=1)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_packet_behavior_nn_2(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = False,
            table_1_name="INGRESS_IPV4_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            pattern=2)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_packet_behavior_nn_3(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = False,
            table_1_name="INGRESS_IPV4_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            pattern=3)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_packet_behavior_nn_4(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = False,
            table_1_name="INGRESS_IPV4_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            pattern=4)

    def test_packet_behavior_wn_1(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = True,
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            pattern=1)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_packet_behavior_wn_2(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = True,
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            pattern=2)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_packet_behavior_wn_3(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = True,
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            pattern=3)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_packet_behavior_wn_4(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = True,
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            pattern=4)

    def test_packet_behavior_ww_1(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = True,
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV6_SEC_TABLE",
            pattern=1)

    def test_packet_behavior_ww_2(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = True,
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV6_SEC_TABLE",
            pattern=2)

    def test_packet_behavior_ww_3(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = True,
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV6_SEC_TABLE",
            pattern=3)

    def test_packet_behavior_ww_4(self):
        self.run_packet_behavior_scenario(
            is_ipv6 = True,
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV6_SEC_TABLE",
            pattern=4)


if __name__ == '__main__':
    unittest.main()
