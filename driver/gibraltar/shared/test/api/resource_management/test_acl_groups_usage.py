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
import decor
import topology as T


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class acl_groups_usage(resource_handler_base):

    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)

    def test_acl_groups_usage(self):

        # get acl-groups resource initial usage
        rd_def = sdk.la_resource_descriptor()
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_ACL_GROUP
        initial_acl_groups_usage = self.device.get_resource_usage(rd_def)

        # create new acl group
        ipv4_acls = []
        acl_group = self.device.create_acl_group()
        self.assertNotEqual(acl_group, None)
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_svi.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # verify usage
        create_acl_group_usage = self.device.get_resource_usage(rd_def)
        self.assertEqual(create_acl_group_usage.used, initial_acl_groups_usage.used + 1)

        # destroy acl group
        self.topology.rx_svi.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.device.destroy(acl_group)

        # verify usage
        destroy_acl_group_usage = self.device.get_resource_usage(rd_def)
        self.assertEqual(destroy_acl_group_usage.used, create_acl_group_usage.used - 1)


if __name__ == '__main__':
    unittest.main()
