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


from leaba import sdk
import hw_tablescli
import lldcli
import test_hldcli as sdk_debug
import unittest
import random
import os
import sim_utils
import decor
import warm_boot_test_utils as wb


wb.support_warm_boot()


SINGLE_ENTRY_KEYS = 10

IPV4_KEY_WIDTH = 32
PAYLOAD_WIDTH = 20

IS_HW_PACIFIC_OR_GB_DEVICE = decor.is_hw_pacific() or decor.is_hw_gibraltar()


def create_em_payload(value, width):
    return hw_tablescli.em_payload(hex(value)[2:], width)


def create_em_key(value, width):
    return hw_tablescli.em_key(hex(value)[2:], width)


@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(IS_HW_PACIFIC_OR_GB_DEVICE, "Requires HW Pacific or Gb device")
class test_cem_warm_boot(unittest.TestCase):
    def setUp(self):
        self.device = sim_utils.create_device(1)
        assert self.device is not None, "create_device failed"

        self.ll_device = self.device.get_ll_device()
        self.rm = sdk_debug.la_device_get_resource_manager(self.device)
        self.cem = self.rm.get_cem()
        assert self.cem is not None, "get_cem failed"

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic4(), "Warm boot not supported on PL")
    @unittest.skipIf(decor.is_asic3(), "Warm boot not supported on GR")
    def test_main(self):
        single_keys = set()
        single_entries_to_insert = []

        for i in range(SINGLE_ENTRY_KEYS):
            payload = create_em_payload(random.getrandbits(PAYLOAD_WIDTH), PAYLOAD_WIDTH)
            key = create_em_key(random.getrandbits(IPV4_KEY_WIDTH) * 16, IPV4_KEY_WIDTH + 4)
            while key.get_value() in single_keys:
                key = create_em_key(random.getrandbits(IPV4_KEY_WIDTH) * 16, IPV4_KEY_WIDTH + 4)
            single_keys.add(key.get_value())
            single_entries_to_insert.append((key, payload))

        for i in range(SINGLE_ENTRY_KEYS):
            key, payload = single_entries_to_insert[i]
            self.device.acquire_device_lock(True)
            try:
                self.cem.insert_table_single_entry(key, payload)
            except BaseException:
                self.device.release_device_lock()
                raise
            self.device.release_device_lock()

        # perform warm boot here
        wb.warm_boot(self.device.device)

        for i in range(SINGLE_ENTRY_KEYS):
            key, payload = single_entries_to_insert[i]
            self.device.acquire_device_lock(True)
            try:
                self.cem.lookup(key, payload)
                self.cem.erase_table_single_entry(key)
            except BaseException:
                self.device.release_device_lock()
                raise
            self.device.release_device_lock()

        for i in range(SINGLE_ENTRY_KEYS):
            key, payload = single_entries_to_insert[i]
            self.device.acquire_device_lock(True)
            try:
                self.cem.insert_table_single_entry(key, payload)
            except BaseException:
                self.device.release_device_lock()
                raise
            self.device.release_device_lock()
            cem = None

        pass


if __name__ == '__main__':
    unittest.main()
