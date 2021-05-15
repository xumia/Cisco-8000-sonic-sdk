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

import unittest
import lldcli
import test_lldcli
import re
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_pacific_tree(unittest.TestCase):

    def setUp(self):
        self.pt_a0 = lldcli.pacific_tree.create(lldcli.la_device_revision_e_PACIFIC_A0)
        self.pt_b0 = lldcli.pacific_tree.create(lldcli.la_device_revision_e_PACIFIC_B0)

    def tearDown(self):
        pass

    def test_get_revision(self):
        self.assertEqual(self.pt_a0.get_revision(), 1)
        self.assertEqual(self.pt_b0.get_revision(), 2)

    # Check that get_registers() and get_memories() return a container of only valid registers/memories
    def test_list_is_valid(self):
        for lbr_tree in [self.pt_a0, self.pt_b0]:
            invalid_registers = [r.get_desc().name for b in lbr_tree.get_leaf_blocks()
                                 for r in b.get_registers() if not r.is_valid()]
            self.assertEqual(len(invalid_registers), 0)

            invalid_memories = [m.get_desc().name for b in lbr_tree.get_leaf_blocks() for m in b.get_memories() if not m.is_valid()]
            self.assertEqual(len(invalid_memories), 0)

    # Check that registers that appear only in B0 are "invalid" in A0
    def test_b0_only_registers(self):
        registers_b0_only = ['rx_port0_cgm_sop_cfg',
                             'rx_port8_cgm_sop_cfg',
                             'pacific_rev2_ifgb_fix_en_reg',
                             'oobi_shaper_reg[0]']
        for name in registers_b0_only:
            self.assertFalse(eval('self.pt_a0.slice[0].ifg[0].ifgb.' + name).is_valid())
            self.assertTrue(eval('self.pt_b0.slice[0].ifg[0].ifgb.' + name).is_valid())

    def test_registers_descriptors(self):
        registers_a0 = [r for b in self.pt_a0.get_leaf_blocks() for r in b.get_registers()]
        registers_b0_list = [r for b in self.pt_b0.get_leaf_blocks() for r in b.get_registers()]

        # Organize B0 in a dict for fast lookup by name
        registers_b0 = {}
        for r in registers_b0_list:
            registers_b0[r.get_name()] = r

        # B0 has more registers than A0
        self.assertTrue(len(registers_a0) < len(registers_b0))

        # Compare addresses and sizes.
        # All registers that exist in A0, also exist in B0, with same size.
        # In ifgb, many registers have different addresses, but sizes still match.
        for r1 in registers_a0:
            r2 = registers_b0[r1.get_name()]

            # check if same size
            self.assertEqual(r1.get_desc().width_in_bits, r2.get_desc().width_in_bits)

            # addresses may not match in 'ifgb' block, others must match
            if 'ifgb.' not in r1.get_name():
                self.assertEqual(r1.get_desc().addr, r2.get_desc().addr)

    def test_memories(self):
        # These 3 memory templates must have different width
        mem_diff = [r'cdb.top.key_mem\[\d+\]',
                    r'cdb.top.lpm_key_mem\[\d+\]',
                    r'cdb.top.em_payload_mem\[\d+\]']

        # All the rest are identical
        memories_a0 = [m for b in self.pt_a0.get_leaf_blocks() for m in b.get_memories()]
        memories_b0 = [m for b in self.pt_b0.get_leaf_blocks() for m in b.get_memories()]

        # Both revisions have same memories.
        self.assertEqual(len(memories_a0), len(memories_b0))

        # Compare addresses, size of entry, number of entries and "validness"
        for m1, m2 in zip(memories_a0, memories_b0):
            self.assertTrue(m1.is_valid())
            self.assertTrue(m2.is_valid())
            self.assertEqual(m1.get_name(), m2.get_name())
            self.assertEqual(m1.get_desc().addr, m2.get_desc().addr)

            match = [pattern for pattern in mem_diff if re.match(pattern, m1.get_name())]
            if match == []:
                self.assertEqual(m1.get_desc().width_total_bits, m2.get_desc().width_total_bits)
                self.assertEqual(m1.get_desc().entries, m2.get_desc().entries)
            else:
                self.assertNotEqual(m1.get_desc().width_total_bits, m2.get_desc().width_total_bits)
                self.assertNotEqual(m1.get_desc().entries, m2.get_desc().entries)

    def test_register_fields(self):
        # Pacific B0 only
        reg = self.pt_b0.slice[0].ifg[0].ifgb.rx_port0_cgm_sop_cfg
        self.do_test_fields(reg,
                            [
                                'p0_tc0_sop_drop_th',
                                'p0_tc1_sop_drop_th',
                                'p0_tc2_sop_drop_th',
                                'p0_tc3_sop_drop_th',
                            ])

        # Pacific A0/B0
        reg = self.pt_a0.slice[0].ifg[0].ifgb.rx_port18_cgm_cfg
        self.do_test_fields(reg,
                            [
                                'p18_drop_th',
                                'p18_xon_th',
                                'p18_xoff_th',
                            ])

    def test_memory_fields(self):
        mem = self.pt_b0.cdb.top.slb_or_plb_egress_flow_table_cam[0]
        self.do_test_fields(mem,
                            [
                                'slb_or_plb_egress_flow_table_cam_payload',
                                'slb_or_plb_egress_flow_table_cam_key',
                                'slb_or_plb_egress_flow_table_cam_valid',
                            ])

    def do_test_fields(self, regmem, field_names):
        fields = regmem.get_desc().fields
        self.assertEqual(len(fields), len(field_names))
        self.assertEqual([f.name for f in fields], field_names)

        field = regmem.get_field(0)
        for name in field_names:
            # This field
            self.assertEqual(field.name, name)
            # Still this field
            field = regmem.get_field(field.lsb + field.width_in_bits - 1)
            self.assertEqual(field.name, name)
            # Next field
            field = regmem.get_field(field.lsb + field.width_in_bits)

        self.assertEqual(field.name, '')


if __name__ == '__main__':
    unittest.main()
