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
import sim_utils
from logging_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class log_config(logging_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_log_config(self):
        aapl_level = sdk.la_get_logging_level(self.device_id, sdk.la_logger_component_e_AAPL)
        self.assertEqual(aapl_level, sdk.la_logger_level_e_INFO)

        sdk.la_set_logging_level(self.device_id, sdk.la_logger_level_e_DEBUG)

        aapl_level = sdk.la_get_logging_level(self.device_id, sdk.la_logger_component_e_AAPL)
        self.assertEqual(aapl_level, sdk.la_logger_level_e_DEBUG)
        ra_level = sdk.la_get_logging_level(self.device_id, sdk.la_logger_component_e_RA)
        self.assertEqual(ra_level, sdk.la_logger_level_e_DEBUG)

        sdk.la_set_logging_level(self.device_id, sdk.la_logger_component_e_RA, sdk.la_logger_level_e_ERROR)

        aapl_level = sdk.la_get_logging_level(self.device_id, sdk.la_logger_component_e_AAPL)
        self.assertEqual(aapl_level, sdk.la_logger_level_e_DEBUG)
        ra_level = sdk.la_get_logging_level(self.device_id, sdk.la_logger_component_e_RA)
        self.assertEqual(ra_level, sdk.la_logger_level_e_ERROR)

        sdk.la_set_logging_level(self.device_id, sdk.la_logger_level_e_INFO)

        flush_period_set = 120
        sdk.la_set_log_flush_period(flush_period_set)
        flush_period_read = sdk.la_get_log_flush_period()
        self.assertEqual(
            flush_period_set,
            flush_period_read,
            "Error ocurred while testing the api for the logger flush period configuration.")

        self.device = sim_utils.create_device(self.device_id)

    def tearDown(self):
        self.device.tearDown()


if __name__ == '__main__':
    unittest.main()
