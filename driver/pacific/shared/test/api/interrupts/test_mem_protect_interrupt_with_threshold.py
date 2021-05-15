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

import unittest
from leaba import sdk
import decor
import interrupt_utils
import lldcli
import time

verbose = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class mem_protect_with_threshold(unittest.TestCase):

    def setUp(self):
        device_id = 0
        import sim_utils
        self.device = sim_utils.create_device(device_id)
        self.critical_fd, self.normal_fd = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        self.ldev = self.device.get_ll_device()
        if self.ldev.is_pacific():
            self.tree = self.ldev.get_pacific_tree()
        else:
            self.tree = self.ldev.get_gibraltar_tree()

    def tearDown(self):
        self.device.close_notification_fds()
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_config_mem_with_threshold(self):
        # memory is CONFIG and ECC protected
        block = self.tree.slice[0].pdoq.top
        mem = block.oq_ifc_mapping
        mem_entry = 0
        bad_bits = 1

        threshold = 100
        times_to_cross = 3
        for i in range(threshold * times_to_cross):
            self.generate_mem_protect_error_using_bypass(block, mem, mem_entry, bad_bits)
            time.sleep(0.05)

        crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .1)
        crit = [d for d in crit if d.type == sdk.la_notification_type_e_MEM_PROTECT]
        norm = [d for d in norm if d.type == sdk.la_notification_type_e_MEM_PROTECT]

        # First 99 notifications are "normal", the rest are "critical"
        expected_all = threshold * times_to_cross
        expected_normal = threshold - 1
        expected_critical = expected_all - expected_normal

        self.assertEqual(len(crit) + len(norm), expected_all)
        self.assertEqual(len(norm), expected_normal)
        self.assertEqual(len(crit), expected_critical)

        if verbose >= 1:
            for i, desc in enumerate(crit):
                block_name = self.tree.get_block(desc.block_id).get_name()
                s = '%d: la_notification_desc={id=%d, type=%d, req_action=%d, action_threshold=%d, block=%s' % (
                    i, desc.id, desc.type, desc.requested_action, desc.action_threshold, block_name)
                s += ', u.mem_protect={'
                s += 'error=%d,' % desc.u.mem_protect.error
                s += 'instance_addr=0x%x,' % desc.u.mem_protect.instance_addr
                s += 'entry=0x%x' % desc.u.mem_protect.entry
                s += '}}'
                print(s)

    def generate_mem_protect_error_using_bypass(self, block, mem, mem_entry, bad_bits):
        ldev = self.ldev
        block_id = mem.get_block_id()
        addr = mem.get_desc().addr + mem_entry
        width_total_bits = mem.get_desc().width_total_bits

        # For CONFIG memories, reads are terminated in shadow and do not reach the HW.
        # For DYNAMIC memories, reads bypass the shadow and go directly to HW.
        #
        # Since mem_protect error is generated on HW read, we use read_memory_raw() to reach the HW both
        # for CONFIG and DYNAMIC memories

        # Read the initial value with ECC/Parity
        val_initial = ldev.read_memory_raw(block_id, addr, width_total_bits)
        if verbose >= 2:
            print('generate_mem_protect_error_using_bypass: val_initial=%x' % val_initial)

        # Write a value with known good ECC/Parity and a payload with deliberately corrupted 'bad_bits' bits
        # Set/clear CifProtGenBypass bit to disable/enable HW ECC/Parity generation - ECC/Parity and payload are written by host
        ldev.write_register(block.memory_prot_bypass, 0x2)
        ldev.write_memory_raw(block_id, addr, width_total_bits, val_initial ^ ((1 << bad_bits) - 1))
        ldev.write_register(block.memory_prot_bypass, 0x0)

        if verbose >= 2:
            print('generate_mem_protect_error_using_bypass: val_corrupted=%x' % (val_initial ^ ((1 << bad_bits) - 1)))

        # The 1st read_memory_raw should generate a mem_protect error, which is expected to be fixed by SDK if the memory is CONFIG
        # The 2nd read_memory_raw should only generate a mem_protect error for non-CONFIG memory

        val_read_1 = None
        val_read_2 = None
        err_1 = sdk.la_status_e_SUCCESS
        err_2 = sdk.la_status_e_SUCCESS

        try:
            val_read_1 = ldev.read_memory_raw(block_id, addr, width_total_bits)
        except sdk.BaseException as e:
            err_1 = int(str(e))
        time.sleep(0.01)

        try:
            val_read_2 = ldev.read_memory_raw(block_id, addr, width_total_bits)
        except sdk.BaseException as e:
            err_2 = int(str(e))

        time.sleep(0.01)

        return {'initial': val_initial, 'err_1': err_1, 'read_1': val_read_1, 'err_2': err_2, 'read_2': val_read_2}


if __name__ == '__main__':
    unittest.main()
