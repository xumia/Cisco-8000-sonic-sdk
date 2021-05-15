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

from copy import deepcopy
import sys
import unittest
from leaba import sdk
from scapy.all import *
import topology as T
import packet_test_utils as U
import sim_utils
from sdk_test_case_base import *


class sdk_multi_test_case_base(sdk_test_case_base):
    @classmethod
    def initialize(
            cls,
            *,
            device_id=1,
            slice_modes=sim_utils.STANDALONE_DEV,
            device_config_func=None):
        super().setUpClass(device_config_func=device_config_func)

    @classmethod
    def destroy(cls):
        super().tearDownClass()

    @classmethod
    def setUpClass(
            cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self, ** Karg):
        # print("sdk_multi_test_case_base:setUp")
        super().setUp(** Karg)
        # MATILDA_SAVE -- need review
        if hasattr(self, 'PUNT_SLICE'):
            #print('sdk_multi_test_case_base:: self.PUNT_SLICE=',self.PUNT_SLICE)
            if (self.PUNT_SLICE not in self.device.get_used_slices()):
                self.PUNT_SLICE = T.choose_active_slices(self.device, self.PUNT_SLICE, [4, 2])
