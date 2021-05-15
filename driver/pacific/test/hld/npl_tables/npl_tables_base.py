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

import unittest
from leaba import sdk
import sim_utils


class npl_tables_base(unittest.TestCase):

    def setUp(self):

        self.device_name = '/dev/testdev'
        self.device = sim_utils.create_test_device(self.device_name, 1)

    def tearDown(self):
        self.device.tearDown()

    def exact_table_interface_check(self, table, k, v):

        # Make sure table is empty before test begins
        self.assertEqual(0, table.size())

        # Check that all inserts succeed
        for idx in range(10):
            k.unpack(idx)
            v.unpack(idx + 10)
            table.insert(k, v)

        # Ensure insert fails for existing entries
        k.unpack(0)
        v.unpack('beef')
        try:
            table.insert(k, v)
            self.fail()
        except sdk.BaseException:
            pass

        # Ensure set succeeds for existing entries
        table.set(k, v)

        # Erase entry 5
        k.unpack(5)
        table.erase(k)

        # Lookup entry 5 - fails
        try:
            ret = table.lookup(k)
            self.fail
        except sdk.BaseException:
            pass

        # Lookup entry 0 - success
        k.unpack(0)
        ret = table.lookup(k)
        self.assertEqual(hex(ret[1].pack())[-4:], 'beef')

        # Retrieve all entries - check one of them
        entries = table.entries(0)
        self.assertEqual(9, table.size())
        self.assertEqual(len(entries), table.size())
        k, v = entries[0]
        self.assertEqual(hex(v.pack())[-4:], 'beef')

    def ternary_table_interface_check(self, table, k, m, v):

        # At device init, the mac_da_table is populated with 2 MC MAC address (IPv4/6),
        # and 2 ISIS MAC ranges ranges, LACP and CDP mac addreses. The list can keep
        # changing in the future. From now on those entries are inserted at the end
        # of table starting from index 16 so that it does not collide with the sa rewite index.
        table_size = table.size()
        base_idx = 0

        # Check that all inserts succeed
        keys = ['0', '1', '2', '3', '4']
        m.unpack('ff')
        for idx in range(len(keys)):
            k.unpack('cafe' + keys[idx])
            v.unpack(idx)
            table.insert(idx + base_idx, k, m, v)

        # Ensure insert fail on existing entry
        k.unpack('face3')
        v.unpack('5')
        try:
            table.insert(4, k, m, v)
            self.fail()
        except sdk.BaseException:
            pass

        # Ensure set_value succeeds on existing entry
        v.unpack('7')
        table.set(4, k, m, v)

        # Push new entry to line 0
        k.unpack('face5')
        v.unpack('6')
        table.push(0, k, m, v)

        # Erase line 1
        table.erase(1)

        # Erase line 1 again - failure
        try:
            table.erase(1)
            self.fail()
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_NOTFOUND)

        # Pop line one - not implemented for RA
        table.pop(3)

        # Current table status
        print()
        for e in table.entries(0):
            l, k, m, v = e
            print("[%d] %x (%x) -> %s" % (l, k.pack(), m.pack(), v.pack()))

        # Locate free entry - line 1 was removed before - should return 1
        loc = table.locate_first_free_entry()
        self.assertEqual(loc, 1)

        # Locate free entry starting line - started inserting 5 keys, cleared
        # 1,pushed 0 poped 3 leaving us with entry 1 empty followed by 5.
        loc = table.locate_free_entry(3)
        self.assertEqual(loc, 5)

        # Find key face5 - stored at line 0
        k.unpack('face5')
        m.unpack('ff')
        loc = table.find(k, m)
        self.assertEqual(loc, 0)

        # Find key race5 - should fail, although mask is set only to 8 LSB
        k.unpack('race5')
        try:
            loc = table.find(k, m)
            self.fail
        except sdk.BaseException:
            pass

        # Lookup key race5 - should succeed since mask is set only to 8 LSB
        ret = table.lookup(k)
        self.assertEqual(hex(ret[3].pack())[-1:], '6')

        # Lookup for key that does not exist - should fail
        k.unpack('beef')
        try:
            ret = table.lookup(k)
            self.fail
        except sdk.BaseException:
            pass

        # Retrieve all entries - check one of them
        entries = table.entries(0)
        self.assertEqual(table_size + 4, table.size())
        self.assertEqual(len(entries), table.size())
        e = entries[0]
        self.assertEqual(hex(e[1].pack())[-5:], 'face5')

    def lpm_table_interface_check(self, table, k, v):

        # Make sure table is empty before test begins
        self.assertEqual(0, table.size())

        k.unpack('abcd')
        v.unpack('cafe')
        length = 10

        # Insert succeeds
        table.insert(k, length, v, 123, False)

        # Find succeeds
        ret = table.find(k, length)
        self.assertEqual(hex(ret[0].pack())[-4:], 'abcd')

        # Lookup succeeds
        ret = table.lookup(k)
        self.assertEqual(hex(ret[0].pack())[-4:], 'abcd')

        # Retrieve all entries (one)
        entries = table.entries(0)
        self.assertEqual(1, table.size())
        self.assertEqual(len(entries), table.size())

        # Erase existing entry - should succeed.
        table.erase(k, length)
