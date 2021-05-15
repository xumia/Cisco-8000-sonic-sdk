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
from resource_handler_base import *
import unittest
import decor
from ipv4_lpts.ipv4_lpts_base import *
from ipv6_lpts.ipv6_lpts_base import *
import interrupt_utils

THRESHOLD_FOR_LPTS = 0.2
# NETWORK_SLICES = 6


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Auto restoring of notification pipes after WB not supported.")
class lpts_tcam_notifications(ipv4_lpts_base, ipv6_lpts_base, resource_handler_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lpts_tcam_notifications(self):
        # Open file descriptors for monitoring LPTS critical usage notifications
        fd_critical, fd_resource = self.device.open_notification_fds(1 << sdk.la_notification_type_e_RESOURCE_MONITOR)

        ts = sdk.la_resource_thresholds()
        ts.low_watermark = THRESHOLD_FOR_LPTS - 0.1
        ts.high_watermark = THRESHOLD_FOR_LPTS
        ts_vec = [ts]
        self.device.set_resource_notification_thresholds(sdk.la_resource_descriptor.type_e_IPV4_LPTS, ts_vec)
        self.device.set_resource_notification_thresholds(sdk.la_resource_descriptor.type_e_IPV6_LPTS, ts_vec)

        lpts_v4 = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
        lpts_v6 = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)

        r_desc_in = sdk.la_resource_descriptor()
        # Get the size of ipv4 and ipv6 lpts table
        r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_IPV4_LPTS
        r_desc_in.m_index.slice_id = 0
        r_desc_out = self.device.get_resource_usage(r_desc_in)
        max_ipv4_entries = r_desc_out.total

        r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_IPV6_LPTS
        r_desc_out = self.device.get_resource_usage(r_desc_in)
        max_ipv6_entries = r_desc_out.total

        # Set the entries to create so that notification is generated
        add_ipv4_entries = int(max_ipv4_entries * THRESHOLD_FOR_LPTS + 1)
        add_ipv6_entries = int(max_ipv6_entries * THRESHOLD_FOR_LPTS + 1)

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = 6
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED

        k2 = sdk.la_lpts_key()
        k2.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k2.val.ipv6.protocol = 255
        k2.mask.ipv6.protocol = 0

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.dest = self.punt_dest2
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)

        for i in range(0, add_ipv4_entries):
            self.push_lpts_entry(lpts_v4, i, k1, result)

        # Read ipv4 lpts notifications that correspond to critical usage
        crit, norm = interrupt_utils.read_notifications(fd_critical, fd_resource, .1)
        desc_list = crit + norm
        num_network_slices = len(self.device.get_used_slices())
        self.assertEqual(len(desc_list), num_network_slices)

        desc = desc_list[0]
        self.assertEqual(desc.type, sdk.la_notification_type_e_RESOURCE_MONITOR)
        self.assertEqual(desc.u.resource_monitor.resource_usage.desc.m_resource_type, sdk.la_resource_descriptor.type_e_IPV4_LPTS)
        self.assertEqual(desc.u.resource_monitor.resource_usage.used, add_ipv4_entries)
        self.assertEqual(desc.u.resource_monitor.resource_usage.total, max_ipv4_entries)

        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)
        for i in range(0, add_ipv6_entries):
            self.push_lpts_entry(lpts_v6, i, k2, result)

        # Read ipv6 lpts notifications that correspond to critical usage
        crit, norm = interrupt_utils.read_notifications(fd_critical, fd_resource, .1)
        desc_list = crit + norm

        self.assertEqual(len(desc_list), num_network_slices)

        desc = desc_list[0]
        self.assertEqual(desc.type, sdk.la_notification_type_e_RESOURCE_MONITOR)
        self.assertEqual(desc.u.resource_monitor.resource_usage.desc.m_resource_type, sdk.la_resource_descriptor.type_e_IPV6_LPTS)
        self.assertEqual(desc.u.resource_monitor.resource_usage.used, add_ipv6_entries)
        self.assertEqual(desc.u.resource_monitor.resource_usage.total, max_ipv6_entries)

        for i in range(0, add_ipv4_entries):
            self.trim_lpts(lpts_v4)

        for i in range(0, add_ipv6_entries):
            self.trim_lpts(lpts_v6)

        self.device.close_notification_fds()


if __name__ == '__main__':
    unittest.main()
