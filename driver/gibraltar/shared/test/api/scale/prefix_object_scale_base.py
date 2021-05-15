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

from scapy.all import *
from scale_base import *
import sys
import unittest
from leaba import sdk
import ip_test_base
import sim_utils
import topology as T
import packet_test_utils as U

U.parse_ip_after_mpls()


class prefix_object_scale_base(scale_base):

    def _test_prefix_object_scale(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        # Supported Prefix Object scale is 64K. Create one with GID 0 and the
        # other with GID 64K-1 to test the min and max GIDs.
        pfx_obj_min = T.prefix_object(self, self.device, 0, nh_ecmp)
        max_pfx_objs = self.device.get_limit(sdk.limit_type_e_DEVICE__MAX_PREFIX_OBJECT_GIDS)
        pfx_obj_max = T.prefix_object(self, self.device, max_pfx_objs - 1, nh_ecmp)

        pfx_obj_min.destroy()
        pfx_obj_max.destroy()
        self.device.destroy(nh_ecmp)
