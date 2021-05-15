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

import os

import unittest
from leaba import sdk
from leaba.debug_tools import debug_utils
import hw_tablescli as hw_tables
import nplapicli as nplapi
import test_racli as ra

import hld_sim_utils

import tempfile

# @brief Unit test for hld/debug_utils
#
# Calls each one of the reports to make sure nothing is broken
# It's impractical to check the content, since the reports work properly only with real device.


class debug_utils_unit_test(unittest.TestCase):

    # Fixture
    device = None

    @classmethod
    def setUpClass(cls):
        cls.device = hld_sim_utils.create_ra_device('/dev/testdev/rtl', 1, False, 0, create_sim=True)

        VRF_GID = 555
        V4_IP_ADDR = 0xc403e101
        V6_IP_ADDR = 0x1234567890abcd

        tables = cls.device.get_device_tables()
        ipv4_lpm_table = tables.ipv4_lpm_table[0]
        ipv6_lpm_table = tables.ipv6_lpm_table[0]

        k4 = nplapi.npl_ipv4_lpm_table_key_t()
        k4.l3_relay_id.id = VRF_GID
        k4.ipv4_ip_address_address = V4_IP_ADDR

        v4 = nplapi.npl_ipv4_lpm_table_value_t()
        v4.unpack(0x12345)

        ipv4_lpm_table.insert(k4, 28, v4, 0, False)

        k6 = nplapi.npl_ipv6_lpm_table_key_t()
        k6.l3_relay_id.id = VRF_GID
        k6.ipv6_ip_address_address = V6_IP_ADDR

        v6 = nplapi.npl_ipv6_lpm_table_value_t()
        v6.unpack(0xabcde)

        ipv6_lpm_table.insert(k6, 120, v6, 0, True)

    def setUp(self):
        self.device = debug_utils_unit_test.device
        self.debug_device = debug_utils.debug_device(self.device)

        self.ll_device = self.device.get_ll_device()
        self.tree = self.ll_device.get_pacific_tree()

        self.tables = self.device.get_device_tables()
        self.ipv4_lpm_table = self.tables.ipv4_lpm_table[0]
        self.ipv6_lpm_table = self.tables.ipv6_lpm_table[0]

    @classmethod
    def tearDownClass(cls):
        cls.device.tearDown()

    def test_debug_device(self):
        self.debug_device.cem_age_table_dump()

    def test_arc_counters(self):
        ac = debug_utils.arc_counters(self.device.device)
        ac.report_debug_counters()
        ac.reset_debug_counters()
        ac.report_group_counters()
        ac.report_core_counters()
        ac.report_mac_relay_counters()
        ac.report_ac_port_counters()
        ac.read_dccm(0, 10)

    def test_cem_db(self):
        tmpfile = tempfile.mktemp()

        cem = debug_utils.cem_db(self.device.device)
        cem.report([0], cam=True, filename=tmpfile)
        cem.report_summary()
        os.remove(tmpfile)

    def test_ctm_db(self):
        tmpfile = tempfile.mktemp()

        ctm = debug_utils.ctm_db(self.device.device)
        ctm.report()
        ctm.report_hw_usage()
        ctm.read_and_dump(filename=tmpfile)
        os.remove(tmpfile)

    def test_lpm_db(self):
        tmpfile = tempfile.mktemp()

        lpm = debug_utils.lpm_db(self.device.device)
        for k, l, v in self.ipv4_lpm_table.entries(0):
            s, d, t, l1, l2 = lpm.find_ipv4_entry(k, l)

        for k, l, v in self.ipv6_lpm_table.entries(0):
            s, d, t, l1, l2 = lpm.find_ipv6_entry(k, l)

        lpm.report(filename=tmpfile)
        os.remove(tmpfile)

        lpm.report_distributer_in_hw(filename=tmpfile)
        os.remove(tmpfile)

        lpm.report_memory_content(0, filename=tmpfile)
        os.remove(tmpfile)

        lpm.check_entries_in_lpm(self.ipv4_lpm_table.entries(0), is_ipv6=False)
        lpm.check_entries_in_lpm(self.ipv6_lpm_table.entries(0), is_ipv6=True)

        lpm.check_entries_in_hw(self.ipv4_lpm_table.entries(0), is_ipv6=False)
        lpm.check_entries_in_hw(self.ipv6_lpm_table.entries(0), is_ipv6=True)

        lpm.report_lpm_hbm_channel_bank_utilization(count_entries=False, filename=tmpfile)
        os.remove(tmpfile)

        lpm.report_lpm_hbm_channel_bank_utilization(count_entries=True, filename=tmpfile)
        os.remove(tmpfile)

        hbm_caching_params = lpm.get_hbm_caching_params()
        lpm.set_hbm_caching_params(hbm_caching_params)
        lpm.print_hbm_caching_params(hbm_caching_params)

        lpm.report_hbm_caching_statistics(filename=tmpfile)
        os.remove(tmpfile)

        lpm.print_hbm_caching_histograms(filename=tmpfile)
        os.remove(tmpfile)

    def test_cdb_helper(self):
        tmpfile = tempfile.mktemp()

        he = debug_utils.cdb_helper(self.device.device)
        he.read_cem_mem([0], [0, 1], filename=tmpfile)
        os.remove(tmpfile)

        he.read_lpm_mem([0], [0, 1], filename=tmpfile)
        os.remove(tmpfile)


if __name__ == '__main__':
    unittest.main()
