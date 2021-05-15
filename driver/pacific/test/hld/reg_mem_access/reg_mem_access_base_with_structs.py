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
from leaba import debug
import sim_utils


class reg_mem_access_base_with_structs(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.device_name = '/dev/testdev'

        self.device = sim_utils.create_test_device(self.device_name, 1)

        self.ll_device = self.device.get_ll_device()
        self.pacific_tree = self.ll_device.get_pacific_tree()
        self.debug_device = debug.debug_device(self.device)

    def tearDown(self):
        self.device.tearDown()

    # Registers

    def register_write_read(self):
        self.debug_device.write_register(self.REG, self.REG_VALUE.flat)

        read_value = self.debug_device.read_register(self.REG)
        self.compare_data(read_value, self.REG_VALUE)

    # Memories

    def memory_write_read(self, index):
        self.debug_device.write_memory(self.MEM, index, self.MEM_VALUE.flat)

        read_value = self.debug_device.read_memory(self.MEM, index)
        self.compare_data(read_value, self.MEM_VALUE)

    # Comparator

    def compare_data(self, x1, x2):
        for attr in [attr for attr in dir(x1) if not attr.startswith('__') and not attr == 'this']:
            self.assertEqual(getattr(x1, attr), getattr(x2, attr))
