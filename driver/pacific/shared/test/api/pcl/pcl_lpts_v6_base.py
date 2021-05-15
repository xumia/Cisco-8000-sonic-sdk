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
SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
SBINCODE = 0xdead
SIP1 = T.ipv6_addr('1000:0db8:0a0b:12f0:0000:0000:0000:2')
SBINCODE1 = 0xbeef
SIP2 = T.ipv6_addr('2000:0db8:0a0b:12f0:0000:0000:0000:2')
SBINCODE2 = 0xfeed
SIP_NO_PCL = T.ipv6_addr('2020:0db8:0a0b:12f0:0000:0000:0000:1')
SBINCODE3 = 0xdeaf
DEFAULT = T.ipv6_addr('0000:0000:0000:0000:0000:0000:0000:0000')


class pcl_lpts_v6_base(unittest.TestCase):
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

    def b_prefix(self, dip, length):
        prefix = sdk.la_ipv6_prefix_t()
        q0 = sdk.get_ipv6_addr_q0(dip.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(dip.hld_obj)
        masked_q0, masked_q1 = ip_test_base.ipv6_test_base.apply_prefix_mask(q0, q1, length)
        sdk.set_ipv6_addr(prefix.addr, masked_q0, masked_q1)
        prefix.length = length
        return prefix

    def create_pcl(self):
        src_pclEntryVec = sdk.pcl_v6_vector()
        src_pclEntry1 = sdk.la_pcl_v6()
        src_pclEntry1.prefix = self.b_prefix(SIP, 128)
        src_pclEntry1.bincode = SBINCODE
        src_pclEntryVec.append(src_pclEntry1)

        src_pclEntry2 = sdk.la_pcl_v6()
        src_pclEntry2.prefix = self.b_prefix(SIP1, 128)
        src_pclEntry2.bincode = SBINCODE1
        src_pclEntryVec.append(src_pclEntry2)

        src_pclEntry3 = sdk.la_pcl_v6()
        src_pclEntry3.prefix = self.b_prefix(DEFAULT, 0)
        src_pclEntry3.bincode = SBINCODE2
        src_pclEntryVec.append(src_pclEntry3)

        src_pcl = self.device.create_pcl(src_pclEntryVec, sdk.pcl_feature_type_e_LPTS)
        self.assertNotEqual(src_pcl, None)
        return src_pcl
