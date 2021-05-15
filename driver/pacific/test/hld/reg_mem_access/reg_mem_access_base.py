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

import sys
import unittest
from leaba import sdk
import scapy.all as S
import topology as T
import sim_utils

import lldcli


class reg_mem_access_base(unittest.TestCase):
    REG_VALUE = 0x1234

    # array write/read works in 4B alignment, so each value is 4B wide.
    REG_ARR_VALUE = 0x000000a1_000000b2_000000c3_000000d4

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.device_name = '/dev/testdev'

        self.device = sim_utils.create_test_device(self.device_name, 1)

        self.ll_device = self.device.get_ll_device()
        self.pacific_tree = self.ll_device.get_pacific_tree()

    def tearDown(self):
        self.device.tearDown()

    # Registers

    def register_write_read(self, reg):
        self.ll_device.write_register(reg, self.REG_VALUE)

        read_value = self.ll_device.read_register(reg)
        self.assertEqual(read_value, self.REG_VALUE)

    # Memories

    def memory_write_read(self, mem, index, value):
        self.ll_device.write_memory(mem, index, value)

        read_value = self.ll_device.read_memory(mem, index)
        self.assertEqual(read_value, value)
