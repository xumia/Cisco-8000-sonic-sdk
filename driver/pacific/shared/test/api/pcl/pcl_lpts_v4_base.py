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

import unittest
from leaba import sdk
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
import ip_test_base

# IPv4
# 0xc0c1c2c3
SIP = T.ipv4_addr('192.193.194.195')
SBINCODE = 0xdead
SIP1 = T.ipv4_addr('10.1.1.2')
SBINCODE1 = 0xbeef
SIP2 = T.ipv4_addr('20.1.1.2')
SBINCODE2 = 0xfeed
SIP_NO_PCL = T.ipv4_addr('101.1.1.2')
SBINCODE3 = 0xdeaf


class pcl_lpts_v4_base(unittest.TestCase):
    # default slice mode settings. Can be changed inside each test
    slice_modes = sim_utils.STANDALONE_DEV

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_int_property(sdk.la_device_property_e_MAX_NUM_PCL_GIDS, 32)

    def setUp(self):
        self.maxDiff = None
        self.device = sim_utils.create_device(1, True, self.slice_modes, self.device_config_func)
        self.topology = T.topology(self, self.device)

    def tearDown(self):
        self.device.tearDown()

    def create_pcl_instance(self):
        pcl = self.create_pcl()
        self.assertNotEqual(pcl, None)
        return pcl

    def create_pcl(self):
        src_pclEntryVec = sdk.pcl_v4_vector()

        src_pclEntry1 = sdk.la_pcl_v4()
        src_pclEntry1.prefix.addr.s_addr = SIP.to_num()
        src_pclEntry1.prefix.length = 32
        src_pclEntry1.bincode = SBINCODE
        src_pclEntryVec.append(src_pclEntry1)

        src_pclEntry2 = sdk.la_pcl_v4()
        src_pclEntry2.prefix.addr.s_addr = SIP1.to_num()
        src_pclEntry2.prefix.length = 32
        src_pclEntry2.bincode = SBINCODE1
        src_pclEntryVec.append(src_pclEntry2)

        src_pclEntry3 = sdk.la_pcl_v4()
        src_pclEntry3.prefix.addr.s_addr = 0
        src_pclEntry3.prefix.length = 0
        src_pclEntry3.bincode = SBINCODE2
        src_pclEntryVec.append(src_pclEntry3)

        src_pcl = self.device.create_pcl(src_pclEntryVec, sdk.pcl_feature_type_e_LPTS)
        self.assertNotEqual(src_pcl, None)
        return src_pcl
