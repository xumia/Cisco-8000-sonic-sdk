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

from packet_test_utils import *
import os
import unittest
from leaba import sdk
import topology as T
import time
import json
from sdk_test_case_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class save_state_tester(sdk_test_case_base):

    def setUp(self):
        super().setUp()
        self.options = sdk.save_state_options()

    def _save_path(self, filename):
        return os.path.join(os.environ['BASE_OUTPUT_DIR'], filename)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_counters_dump(self):
        self.options.include_counters = True
        self._started_at = time.time()
        self.device.save_state(self.options, self._save_path("counters.gz"))
        elapsed = time.time() - self._started_at
        print('{} ({}s)'.format(self.id(), round(elapsed, 4)))

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_status_dump(self):
        self.options.include_status = True
        self._started_at = time.time()
        self.device.save_state(self.options, self._save_path("status.gz"))
        elapsed = time.time() - self._started_at
        print('{} ({}s)'.format(self.id(), round(elapsed, 4)))

    def _test_json_dump(self):
        self.options.include_counters = True
        self.options.return_json = True
        self._started_at = time.time()
        root = self.device.save_state(self.options)
        elapsed = time.time() - self._started_at
        print('{} ({}s)'.format(self.id(), round(elapsed, 4)))

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_counters_dump_text(self):
        self.options.include_counters = True
        self._started_at = time.time()
        self.device.save_state(self.options, self._save_path("counters.txt"))
        elapsed = time.time() - self._started_at
        print('{} ({}s)'.format(self.id(), round(elapsed, 4)))

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_config_dump(self):
        self.options.include_config = True
        self._started_at = time.time()
        self.device.save_state(self.options, self._save_path("config.gz"))
        elapsed = time.time() - self._started_at
        print('{} ({}s)'.format(self.id(), round(elapsed, 4)))

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_config_mac_port_serdes_dump_text(self):
        self.options.include_config = True
        self.options.include_mac_port_serdes = True
        self._started_at = time.time()
        self.device.save_state(self.options, self._save_path("config_mp_serdes.txt"))
        elapsed = time.time() - self._started_at
        print('{} ({}s)'.format(self.id(), round(elapsed, 4)))

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_interrupt_counters_dump_text(self):
        self.options.include_interrupt_counters = True
        self._started_at = time.time()
        self.device.save_state(self.options, self._save_path("interrupt_counters.txt"))
        elapsed = time.time() - self._started_at
        print('{} ({}s)'.format(self.id(), round(elapsed, 4)))

    def _test_volatile_dump(self):
        self.options.include_volatile = True
        self.device.save_state(self.options, self._save_path("volatile.gz"))

    def _test_all_dump(self):
        self.options.include_all = True
        self.device.save_state(self.options, self._save_path("volatile.gz"))

    def _test_all_dump(self):
        self.options.include_all = True
        self.device.save_state(self.options, self._save_path("all.gz"))

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_expanded_fields(self):
        PACIFIC_PART_NUMBER = 0x451
        GIBRALTAR_PART_NUMBER = 0x485
        ASIC4_PART_NUMBER = 0x485
        ASIC5_PART_NUMBER = 0x485
        self.options.include_status = True
        file = self._save_path("status.json")
        self.device.save_state(self.options, file)
        with open(file) as fp:
            self.status = json.load(fp)
        if self.device.get_ll_device().is_pacific():
            self.assertEqual(self.status['pacific_tree']['sbif']['device_id_status_reg']['device_id_part_num'], PACIFIC_PART_NUMBER)
        elif self.device.get_ll_device().is_gibraltar():
            self.assertIn(self.status['gibraltar_tree']['top']['chip_id_reg']['part_number_code'], [GIBRALTAR_PART_NUMBER, 0, 1])
        elif self.device.get_ll_device().is_asic4():
            self.assertIn(self.status['asic4_tree']['top']['chip_id_reg']['part_number_code'], [ASIC4_PART_NUMBER, 0, 1])
        elif self.device.get_ll_device().is_asic5():
            self.assertIn(self.status['asic5_tree']['top']['chip_id_reg']['part_number_code'], [ASIC5_PART_NUMBER, 0, 1])
        else:
            assert(False)


if __name__ == '__main__':
    unittest.main()
