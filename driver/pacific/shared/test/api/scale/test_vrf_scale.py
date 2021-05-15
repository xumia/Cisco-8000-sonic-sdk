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


import sys
import unittest
from leaba import sdk
from scapy.all import *
from prefix_object_scale_base import *
import sim_utils
import topology as T
import decor

SLICE = T.get_device_slice(2)
IFG = T.get_device_ifg(1)
FIRST_SERDES = T.get_device_first_serdes(10)
LAST_SERDES = T.get_device_last_serdes(11)


@unittest.skipIf(not decor.is_gibraltar(), "Test is enabled only on GB")
class test_vrf_scale(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device, create_default_topology=False)

        self.mac_port = T.mac_port(self, self.device, SLICE, IFG, FIRST_SERDES, LAST_SERDES)

    def tearDown(self):
        self.mac_port.destroy()

        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vrf_creation(self):
        MIN_VRF_GID = 0
        MAX_VRF_GID = (1 << 12) - 1

        # Create a VRF using the min GID
        min_vrf = T.vrf(self, self.device, MIN_VRF_GID)
        # Cleanup
        min_vrf.destroy()

        # Create a system port using the maximal GID
        max_vrf = T.vrf(self, self.device, MAX_VRF_GID)
        # Cleanup
        max_vrf.destroy()

        # Create a system port using an invalid GID
        invalid_gid = MAX_VRF_GID + 1
        with self.assertRaises(sdk.InvalException):
            T.vrf(self, self.device, invalid_gid)
        vrf = []

        # Create 4K VRFs
        for vrf_gid in range(MAX_VRF_GID + 1):
            vrf.append(T.vrf(self, self.device, vrf_gid))

        # Cleanup
        for vrf_gid in range(MAX_VRF_GID + 1):
            vrf[vrf_gid].destroy()


if __name__ == '__main__':
    unittest.main()
