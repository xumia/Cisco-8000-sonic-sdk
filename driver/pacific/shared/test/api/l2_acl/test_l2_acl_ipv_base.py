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
from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import nplapicli as nplapi
from sdk_test_case_base import *
import ip_test_base
import uut_provider
from binascii import hexlify, unhexlify


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_l2_acl_ipv_base(sdk_test_case_base):
    IN_SLICE = 5
    OUT_SLICE = 2
    ACL_SLICE = 3
    # needed only for  ipv4_160_with_class_id2
    PUNT_INJECT_SLICE = 3
    MIRROR_DEST_SLICE = 3
    PUNT_INJECT_IFG = 0
    MIRROR_DEST_IFG = 0

    def setUp(self, create_default_topology=False):
        super().setUp(create_default_topology=create_default_topology)
        # MATILDA_SAVE -- need review
        self.IN_SLICE = T.choose_active_slices(self.device, self.IN_SLICE, [5, 0])
        self.OUT_SLICE = T.choose_active_slices(self.device, self.OUT_SLICE, [2, 4])
        self.ACL_SLICE = T.choose_active_slices(self.device, self.ACL_SLICE, [3, 1])

        self.PUNT_INJECT_SLICE = T.choose_active_slices(self.device, self.PUNT_INJECT_SLICE, [3, 1])
        self.MIRROR_DEST_SLICE = self.PUNT_INJECT_SLICE


if __name__ == '__main__':
    unittest.main()
