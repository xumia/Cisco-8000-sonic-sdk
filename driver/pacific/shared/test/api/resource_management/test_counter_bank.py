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

import decor
from resource_handler_base import *

import decor
import unittest
from leaba import sdk
import topology as T

NUM_COUNTER_DIRECTIONS = 2  # Ingress and Egress.


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class counter_bank(resource_handler_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_counter_bank(self):
        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_COUNTER_BANK
        res = self.device.get_resource_usage(rd)
        # clear a counter.
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

        res = self.device.get_resource_usage(rd)
        banks_allocated_during_device_init = res.used

        # set the same drop counter. aggregate counter 1 for each slice*ifg*direction
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, 0, counter, None, False, False, True, 0)

        res = self.device.get_resource_usage(rd)
        # trap counters use the same banks as internal-error counters, which are allocated at device initialization
        self.assertEqual(res.used, banks_allocated_during_device_init)

        # clear counter.
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, banks_allocated_during_device_init)


if __name__ == '__main__':
    unittest.main()
