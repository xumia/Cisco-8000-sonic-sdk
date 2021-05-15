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


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class vector_getters(resource_handler_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vector_getters(self):
        rd = sdk.la_resource_descriptor()
        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_METER_PROFILE)
        self.assertEqual(len(res), 12)  # NUM IFG-s in the device

        for slice_id in self.device.get_used_slices():
            for ifg_id in range(T.NUM_IFGS_PER_SLICE):
                ifg = slice_id * T.NUM_IFGS_PER_SLICE + ifg_id
                record = res[ifg]
                self.assertEqual(record.desc.m_index.slice_ifg_id.slice, slice_id)
                self.assertEqual(record.desc.m_index.slice_ifg_id.ifg, ifg_id)

        # calculate the NUM ACL_ID in the device, that are not on disabled slices
        num_ACL_ID_in_device = 3
        # for i in self.device.get_used_slice_pairs():
        #     num_ACL_ID_in_device+=1

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_ETH_NARROW_DB1_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_ETH_NARROW_DB2_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV4_NARROW_DB1_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV4_NARROW_DB2_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV4_NARROW_DB3_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV4_NARROW_DB4_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV4_WIDE_DB1_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV4_WIDE_DB2_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV4_WIDE_DB3_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV4_WIDE_DB4_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV6_NARROW_DB1_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV6_NARROW_DB2_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV6_NARROW_DB3_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV6_NARROW_DB4_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV6_WIDE_DB1_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV6_WIDE_DB2_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV6_WIDE_DB3_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_INGRESS_IPV6_WIDE_DB4_INTERFACE0_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_EGRESS_IPV4_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device

        res = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_EGRESS_IPV6_ACL)
        self.assertEqual(len(res), num_ACL_ID_in_device)  # NUM ACL_ID in the device


if __name__ == '__main__':
    unittest.main()
