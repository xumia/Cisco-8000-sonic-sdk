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
from leaba import debug
import decor
import interrupt_utils
import lldcli
import time
import re
import topology as T

verbose = 0
counters = {'OK': 0, 'ERROR': 0, 'SKIP': 0, 'MASKED-OFF': 0}

# Skip sbif - because sbif interrupts are ignored by SDK
# Skip mem-protect, mac-pool - because setting a test bit is not enough to trigger a notification.
SKIP_REGISTERS_REGEXP = re.compile(r'mem_protect_interrupt|sbif.|.mac_pool')

# Skip interrupts that are terminated internally in SDK. Same list for GB and Pacific.
# Format: 'full.path.to.block.register.bit_name'
# Use regex syntax wherever applicable.
SKIP_BITS = [
    r'counters.bank_.*\[\d+\].interrupt_reg\[\d+\].max_counter_crossed_threshold',
    r'csms.csms_interrupt_reg.credit_gnt_dest_dev_unreachable',
    r'slice\[\d+\].ics.general_interrupt_register.queue_aged_out_intr',
    r'mmu.general_interrupt_register.mmu_has_error_buffer_interrupt',
]

SKIP_BITS_REGEXP = re.compile('|'.join(SKIP_BITS))

if decor.is_gibraltar():
    NON_WIRED_BLOCKS = [
        r'slice\[\d+\].npu.rxpp_term.fi_eng\[\d+\]',
        r'slice\[\d+\].npu.rxpp_term.fi_stage',
        r'slice\[\d+\].npu.rxpp_term.sna',
        r'npuh.fi',
    ]
else:
    NON_WIRED_BLOCKS = [
        r'slice\[\d+\].npu.rxpp_term.fi_eng\[\d+\]',
        r'slice\[\d+\].npu.rxpp_term.fi_stage',
        r'slice\[\d+\].npu.sna',
        r'npuh.fi',
        r'mmu_buff',
    ]

NON_WIRED_BLOCKS_REGEXP = re.compile('|'.join(NON_WIRED_BLOCKS))


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class all_leafs(unittest.TestCase):

    def setUp(self):
        device_id = 0
        import sim_utils
        if verbose >= 2:
            sdk.la_set_logging_level(device_id, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_XDEBUG)
        self.device = sim_utils.create_device(device_id)
        self.critical_fd, self.normal_fd = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        self.ldev = self.device.get_ll_device()
        self.dd = debug.debug_device(self.device)

    def tearDown(self):
        self.device.close_notification_fds()
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_all_leafs(self):
        global counters
        if T.is_matilda_model(self.device) and decor.is_hw_device():
            self.skipTest("on matilda the interupt tree is partially not accessible, and the test is adapted to that. ")
            return

        def node_cb(node, unused):
            reg_name = node['status']['name']
            # Skip sbif - because sbif interrupts are ignored by SDK
            # Skip mem-protect, mac-pool - because setting a test bit is not enough to trigger a notification.
            if re.findall(SKIP_REGISTERS_REGEXP, reg_name):
                if verbose >= 1:
                    print('SKIP:', reg_name)
                counters['SKIP'] += 1
                return

            reg = eval('self.dd.device_tree.' + reg_name)
            for bit_i in node['bits']:
                full_bit_name = reg_name + '.' + reg.get_field(int(bit_i)).name
                if re.findall(SKIP_BITS_REGEXP, full_bit_name):
                    if verbose >= 1:
                        print('SKIP: bit={}'.format(full_bit_name))
                    counters['SKIP'] += 1
                    continue

                bit = node['bits'][bit_i]
                is_leaf = bit['children'] is None
                self.assertEqual(reg.get_field(int(bit_i)).name, bit['name'])
                if is_leaf:
                    self.do_test_leaf(reg, int(bit_i))

        def bit_cb(node, bit, bit_i, unused):
            pass

        self.dd.traverse_interrupt_tree(self.dd.interrupt_tree, node_cb, None, bit_cb, None)

        print('End-of-test summary:\n', counters)

    def do_test_leaf(self, reg, bit_i):
        assert reg.get_desc().type == lldcli.lld_register_type_e_INTERRUPT

        bit_name = reg.get_field(bit_i).name
        block = reg.get_block()

        addr = reg.get_desc().addr + reg.get_desc().instances
        reg_m = block.get_register(addr)
        assert reg_m.get_desc().type == lldcli.lld_register_type_e_INTERRUPT_MASK

        addr = reg.get_desc().addr + 2 * reg.get_desc().instances
        reg_t = block.get_register(addr)
        assert reg_t.get_desc().type == lldcli.lld_register_type_e_INTERRUPT_TEST

        interrupt_enabled = True
        if reg_m:
            interrupt_enabled = self.is_interrupt_enabled(reg_m, bit_i)

        global counters

        if not interrupt_enabled:
            status = "MASKED-OFF"
            counters[status] += 1
            if verbose >= 1:
                print('{}: progress={}, reg={}, bit_i={}, bit_name={}'.format(status, counters, reg.get_name(), bit_i, bit_name))
        else:
            self.ldev.write_register(reg_t, 0)
            self.ldev.write_register(reg_t, 1 << bit_i)
            self.ldev.write_register(reg_t, 0)

            is_non_wired = self.is_non_wired(reg)
            if is_non_wired:
                # non-wired interrupts are polled with POLL_INTERVAL_SLOW
                sleep_seconds = 1.0
                max_retry = 2
            elif self.device.POLL_MSI:
                # If enabled, MSI is polled with POLL_INTERVAL_FAST
                sleep_seconds = 0.1
                max_retry = 20
            else:
                # Normal case: MSI polling is disabled (default) and interrupt is wired
                sleep_seconds = 0
                max_retry = 1

            for retry in range(max_retry):
                time.sleep(sleep_seconds)
                crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .05)
                if len(crit) + len(norm) > 0:
                    break

            status = 'OK' if len(crit) + len(norm) == 1 else 'ERROR'
            counters[status] += 1

            reg_val = self.ldev.read_register(reg)
            msi_val = self.ldev.read_register(self.dd.device_tree.sbif.msi_master_interrupt_reg)
            msi_mask = self.ldev.read_register(self.dd.device_tree.sbif.msi_master_interrupt_reg_mask)
            msg = '{}: progress={}, retry={}/{}, reg={}, reg_val={}, bit_i={}, bit_val={}, bit_name={}, msi_val={}, msi_mask={}, len(crit)={}, len(norm)={}, is_non_wired={}'.format(
                status, counters, retry, max_retry, reg.get_name(), hex(reg_val), bit_i, (reg_val >> bit_i) & 1, bit_name, hex(msi_val), hex(msi_mask), len(crit), len(norm), is_non_wired)

            if verbose >= 1:
                print(msg)
                if verbose >= 2:
                    for d in crit + norm:
                        print('{}, bit_name={}'.format(self.dd.notification_to_string(d), bit_name))

            if status == 'ERROR':
                self.fail(msg)

    def is_non_wired(self, reg):
        return re.findall(NON_WIRED_BLOCKS_REGEXP, reg.get_name())

    def is_interrupt_enabled(self, reg_m, bit_i):
        self.assertEqual(reg_m.get_desc().type, lldcli.lld_register_type_e_INTERRUPT_MASK)

        val = 1 << bit_i
        mask = self.ldev.read_register(reg_m)

        if decor.is_hw_gibraltar():
            # On GB, all masks are active low
            is_active_low = True
        else:
            # On Pacific, SBIF masks are active high, the rest are active low
            is_sbif = reg_m.get_block().get_block_id() == self.dd.device_tree.sbif.get_block_id()
            is_active_low = not is_sbif

        if is_active_low:
            return ((~mask) & val) != 0

        return (mask & val) != 0


if __name__ == '__main__':
    unittest.main()
