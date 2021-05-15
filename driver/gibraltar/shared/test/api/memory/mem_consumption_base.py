#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import resource
from leaba import sdk
from leaba import debug
import sim_utils
import logging


class mem_consumption_base(unittest.TestCase):

    def _test_mem(self, slice_modes, max_mem):
        device_id = 0

        mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        device = sim_utils.create_device(device_id, slice_modes=slice_modes)
        mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - mem_before

        logging.getLogger().info('RU: ', mem_usage)
        self.assertLess(mem_usage, max_mem)
        self.assertGreater(mem_usage, max_mem * 0.8)

        device.tearDown()
