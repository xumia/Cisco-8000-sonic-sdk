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

import decor
from leaba import sdk
import unittest
from resource_management.resource_handler_base import *
import topology as T

L2_PROTECTION_GROUP_GID = 0x20


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class stage1_protection_monitor(resource_handler_base):

    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_stage1_protection_monitor(self):
        rd_def = sdk.la_resource_descriptor()
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_STAGE1_PROTECTION_MONITOR
        resource_init_status = self.device.get_resource_usage(rd_def)

        protection_monitor = self.device.create_protection_monitor()
        self.assertNotEqual(protection_monitor, None)

        self.m_l2_protection_group = self.device.create_l2_protection_group(
            L2_PROTECTION_GROUP_GID, self.topology.tx_l2_ac_port_reg.hld_obj,
            self.topology.tx_l2_ac_port_def.hld_obj, protection_monitor)

        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, resource_init_status.used + 1)


if __name__ == '__main__':
    unittest.main()
