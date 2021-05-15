#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from sdk_test_case_base import *
import sim_utils
import topology as T
from leaba.debug_tools.debug_utils import ctm_db
import random
import ipaddress
from collections import namedtuple
import warm_boot_test_utils as wb
import decor

wb.support_warm_boot()


validation_context = namedtuple("validation_context", "acl_oid values entry_validation_func")


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class test_warm_boot_ctm(sdk_test_case_base):

    def setUp(self):
        super().setUp()
        # debug_utils object for getting hw_content
        self.ctm = ctm_db(self.device.device)
        # Counter for warm boots triggered during particular test

        # number of entries will be inserted during single-table tests
        self.NUM_ENTRIES_SINGE_TABLE = 2540
        # number of ipv6 entries will be inserted during multiple-table tests
        self.IPV6_NUM_ENTRIES = 1200
        # number of ipv4 entries will be inserted during multiple-table tests
        self.IPV4_NUM_ENTRIES = 1340
        self.NUM_WARM_BOOTS = 5

    @unittest.skip("Test is skipped because of slow performance with dynamic allocation")
    def test_warm_boot_after_filling_single_acl(self):
        acl = self._create_and_attach_ingress_acl(is_ipv4=True)

        # Fill acl with entries that have consequent key values and saving all info needed for validation
        context = self._fill_acl_and_save_context(acl, num_entries=self.NUM_ENTRIES_SINGE_TABLE)

        # Trigger warm boot
        wb.warm_boot(self.device.device)

        # Checking ACL's content didn't change
        self._validate_acl(context)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skip("Test is skipped because of slow performance with dynamic allocation")
    def test_warm_boot_after_filling_two_overlaping_acls(self):
        ipv6_ingress_acl = self._create_and_attach_ingress_acl(is_ipv4=False)
        ipv4_ingress_acl = self._create_and_attach_ingress_acl(is_ipv4=True)

        # Insert entries, save values and object ids
        ipv6_context = self._fill_acl_and_save_context(ipv6_ingress_acl, num_entries=self.IPV6_NUM_ENTRIES, is_ipv4=False)
        ipv4_context = self._fill_acl_and_save_context(ipv4_ingress_acl, num_entries=self.IPV4_NUM_ENTRIES, is_ipv4=True)

        # Trigger warm boot
        wb.warm_boot(self.device.device)

        # Make checks
        self._validate_acl(ipv6_context)
        self._validate_acl(ipv4_context)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skip("Test is skipped because of slow performance with dynamic allocation")
    def test_warm_boot_filling_single_acl_hw_validation(self):
        acl = self._create_and_attach_ingress_acl(is_ipv4=True)

        # Insert entries, save values and object ids
        context = self._fill_acl_and_save_context(acl, num_entries=self.NUM_ENTRIES_SINGE_TABLE)
        # Saving state of hw without warm boot
        hw_content_without_wb = self.ctm._read_tcam_content()
        acl.clear()

        # Fill ACL the same way, but having possibility of sporadic warm boot after every insertion
        values_with_wb = self._fill_acl_having_sporadic_warmboots(
            acl,
            self._create_and_insert_ipv4_ingress_ace,
            self.NUM_ENTRIES_SINGE_TABLE,
            start_position=0,
            num_warm_boots=self.NUM_WARM_BOOTS)

        self._validate_acl(context)
        # Comparing HW content with and without warm boot
        hw_content_with_wb = self.ctm._read_tcam_content()
        self._compare_hw_content(hw_content_without_wb, hw_content_with_wb)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skip("Test is skipped because of slow performance with dynamic allocation")
    def test_warm_boot_filling_two_overlaping_acls_hw_validation(self):
        ipv6_ingress_acl = self._create_and_attach_ingress_acl(is_ipv4=False)
        ipv4_ingress_acl = self._create_and_attach_ingress_acl(is_ipv4=True)

        # Insert entries, save values and object ids
        ipv6_context = self._fill_acl_and_save_context(ipv6_ingress_acl, num_entries=self.IPV6_NUM_ENTRIES, is_ipv4=False)
        ipv4_context = self._fill_acl_and_save_context(ipv4_ingress_acl, num_entries=self.IPV4_NUM_ENTRIES, is_ipv4=True)

        # Saving hw state of acl without warm boot
        hw_content_without_wb = self.ctm._read_tcam_content()
        ipv6_ingress_acl.clear()
        ipv4_ingress_acl.clear()

        # Fill ACLs the same way, but having possibility of sporadic warm boot after every insertion
        ipv6_values_with_wb = self._fill_acl_having_sporadic_warmboots(
            ipv6_ingress_acl,
            self._create_and_insert_ipv6_ingress_ace,
            self.IPV6_NUM_ENTRIES,
            start_position=0,
            num_warm_boots=self.NUM_WARM_BOOTS)

        ipv4_values_with_wb = self._fill_acl_having_sporadic_warmboots(
            ipv4_ingress_acl,
            self._create_and_insert_ipv4_ingress_ace,
            self.IPV4_NUM_ENTRIES,
            start_position=0,
            num_warm_boots=self.NUM_WARM_BOOTS)

        # Check that insetred entries are the same in both cases
        self.assertEqual(ipv6_context.values, ipv6_values_with_wb)
        self.assertEqual(ipv4_context.values, ipv4_values_with_wb)
        # Validating ACL from SDK API level
        self._validate_acl(ipv6_context)
        self._validate_acl(ipv4_context)
        # Comparing HW content with and without warm boot
        hw_content_with_wb = self.ctm._read_tcam_content()
        self._compare_hw_content(hw_content_without_wb, hw_content_with_wb)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def _create_and_attach_ingress_acl(self, is_ipv4=True):
        profile = None
        if is_ipv4:
            profile = self.topology.ingress_acl_key_profile_ipv4_def
        else:
            profile = self.topology.ingress_acl_key_profile_ipv6_def
        acl0 = self.device.create_acl(profile, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)
        count = acl0.get_count()
        self.assertEqual(count, 0)

        acl_group = self.device.create_acl_group()
        if is_ipv4:
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl0])
        else:
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl0])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        return acl0

    def _create_and_insert_ipv4_ingress_ace(self, acl, val, position):
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = val
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k1.append(f1)
        cmd_nop = []
        acl.insert(position, k1, cmd_nop)

    def _create_and_insert_ipv6_ingress_ace(self, acl, val, position):
        ip_str = str(ipaddress.IPv6Address(val))
        ip = T.ipv6_addr(ip_str)
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(ip.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(ip.hld_obj)
        sdk.set_ipv6_addr(f1.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(f1.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        k1.append(f1)
        cmd_nop = []
        acl.insert(position, k1, cmd_nop)

    # @brief Make warm boot with given chance (from 0.0 to 1.0)
    def _make_sporadic_warm_boot(self, chance_to_make):
        current_chance = random.random()
        is_making_warm_boot = current_chance < chance_to_make if chance_to_make < 1.0 else True
        if is_making_warm_boot:
            wb.warm_boot(self.device.device)
        return is_making_warm_boot

    def _fill_acl_and_save_context(self, acl_to_fill, num_entries, is_ipv4=True, start_position=0, num_warm_boots=0):
        ace_func = None
        entry_validation_func = None
        if is_ipv4:
            ace_func = self._create_and_insert_ipv4_ingress_ace
            entry_validation_func = self._validate_ingress_ipv4_entry
        else:
            ace_func = self._create_and_insert_ipv6_ingress_ace
            entry_validation_func = self._validate_ingress_ipv6_entry
        values = self._fill_acl_having_sporadic_warmboots(acl_to_fill, ace_func, num_entries, start_position, num_warm_boots)
        return validation_context(acl_to_fill.oid(), values, entry_validation_func)

    # @brief Fill ACLs with consequent entries, having possibility of sporadic warm boot after every insertion
    # @param acl_to_fill - ACL table to be fille dwith entries
    # @param ace_func - function object creating and inserting ACE to ACL (either self._create_and_insert_ipv4_ingress_ace or
    # self._create_and_insert_ipv6_ingress_ace)
    # @param num_entries - number of entries to be inserted
    # @param start_position - first index, from which insertion starts
    # @param num_warm_boots - number of warm boots to be done during insertion
    # @return list of values, which were inserted as a part of each entry key (for further validation)
    def _fill_acl_having_sporadic_warmboots(self, acl_to_fill, ace_func, num_entries, start_position=0, num_warm_boots=0):
        val_list = []
        create_and_insert_ace = ace_func
        insertion_range = range(start_position, start_position + num_entries)
        warm_boot_iterations = sorted(random.sample(insertion_range, num_warm_boots))
        acl_oid = acl_to_fill.oid()
        count_before_insertion = acl_to_fill.get_count()
        for i in insertion_range:
            current_val = i + 1
            create_and_insert_ace(acl_to_fill, val=current_val, position=i)
            if i in warm_boot_iterations:
                wb.warm_boot(self.device.device)
                acl_to_fill = self.device.device.get_object(acl_oid)
            val_list.append(current_val)
        count_after_insertion = acl_to_fill.get_count()
        self.assertEqual(count_after_insertion, count_before_insertion + num_entries)
        return val_list

    # @brief Fill ACLs with consequent entries without having possibility of warm boot
    # @param acl_to_fill - ACL table to be fille dwith entries
    # @param ace_func - function object creating and inserting ACE to ACL (either self._create_and_insert_ipv4_ingress_ace or
    #                   self._create_and_insert_ipv6_ingress_ace)
    # @param num_entries - number of entries to be inserted
    # @param start_position - first index, from which insertion starts
    # @return list of values, which were inserted as a part of each entry key (for further validation)
    def _fill_acl_without_warm_boots(self, acl_to_fill, ace_func, num_entries, start_position=0):
        return self._fill_acl_having_sporadic_warmboots(
            acl_to_fill, ace_func, num_entries, start_position, num_warm_boots=0)

    def _validate_ingress_ipv4_entry(self, entry, expected_val):
        k = entry.key_val
        f = k[0]
        real_val = f.val.ipv4_sip.s_addr
        self.assertEqual(real_val, expected_val)

    def _validate_ingress_ipv6_entry(self, entry, expected_val):
        k = entry.key_val
        f = k[0]
        real_val = f.val.ipv6_sip.s_addr
        self.assertEqual(real_val, expected_val)

    def _validate_acl(self, context):
        # After warm boot all underlying cpp SDK objects are desroyed, so new objects should be gained from restored device
        acl = self.device.device.get_object(context.acl_oid)
        expected_values = context.values
        entry_validation_func = context.entry_validation_func
        self._do_validate_acl(acl, expected_values, entry_validation_func)

    # @brief Consequently compare particular part of each ACE's key with previously saved list of values
    # @param acl - ACL object to be validated
    # @param expected_values - list of values, which was saved during filling the ACL
    def _do_validate_acl(self, acl, expected_values, entry_validation_func):
        expected_count = len(expected_values)
        real_count = acl.get_count()
        self.assertEqual(real_count, expected_count)
        validate_entry = entry_validation_func
        for i in range(expected_count):
            entry = acl.get(i)
            expected_val = expected_values[i]
            validate_entry(entry, expected_val)

    def _compare_hw_content(self, hw_content1, hw_content2):
        # Compare number of entries
        len1 = len(hw_content1)
        len2 = len(hw_content2)
        self.assertEqual(len1, len2)
        # Compare every entry
        for entry1, entry2 in zip(hw_content1, hw_content2):
            for key in entry1.keys():
                self.assertEqual(entry1[key], entry2[key])


if __name__ == '__main__':
    unittest.main()
