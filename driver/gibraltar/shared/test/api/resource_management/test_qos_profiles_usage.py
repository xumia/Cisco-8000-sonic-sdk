#!/usr/bin/env python3
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

from leaba import sdk
import unittest
from resource_management.resource_handler_base import *
import decor
import topology as T

IFG = T.get_device_ifg(1)
FIRST_SERDES = T.get_device_first_serdes(10)
LAST_SERDES = T.get_device_last_serdes(11)
SYS_PORT_GID = 1000
L3_AC_QOS_VID1_START = 10
L3_AC_GID = 0x210


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class qos_profiles_usage(resource_handler_base):

    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)
        self.vrf = self.topology.vrf

        prefered_slices = [0, 2, 4]
        self.slice = []
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            chosen_slice = prefered_slices[slice_pair_id]
            if chosen_slice not in self.device.get_used_slices():
                chosen_slice += 1
            self.slice.append(chosen_slice)

        self.eth_port = []
        for slice_pair_id in self.device.get_used_slice_pairs():
            self.eth_port.append(T.ethernet_port(self, self.device,
                                                 self.slice[slice_pair_id],
                                                 IFG,
                                                 (SYS_PORT_GID + slice_pair_id),
                                                 FIRST_SERDES,
                                                 LAST_SERDES))

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_qos_profiles_usage(self):
        num_ingress_qos_profiles_at_init = [0, 0, 0]
        num_egress_qos_profiles_at_init = [0, 0, 0]
        rd_def = sdk.la_resource_descriptor()

        for slice_pair_id in self.device.get_used_slice_pairs():
            rd_def.m_index.slice_pair_id = slice_pair_id
            rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_INGRESS_QOS_PROFILES
            num_ingress_qos_profiles_at_init[slice_pair_id] = self.device.get_resource_usage(rd_def).used
            rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_QOS_PROFILES
            num_egress_qos_profiles_at_init[slice_pair_id] = self.device.get_resource_usage(rd_def).used

        # create l3ac with ingress and egress profiles on every slice_pair
        in_profile = T.ingress_qos_profile(self, self.device)
        out_profile = T.egress_qos_profile(self, self.device)

        for slice_pair_id in self.device.get_used_slice_pairs():
            T.l3_ac_port(self, self.device,
                         L3_AC_GID + slice_pair_id,
                         self.eth_port[slice_pair_id],
                         self.vrf,
                         T.RX_L3_AC_MAC,
                         (L3_AC_QOS_VID1_START + slice_pair_id),
                         (L3_AC_QOS_VID1_START + slice_pair_id),
                         ingress_qos_profile=in_profile,
                         egress_qos_profile=out_profile)

        for slice_pair_id in self.device.get_used_slice_pairs():
            rd_def.m_index.slice_pair_id = slice_pair_id
            # Check ingress_qos_profiles usage.
            rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_INGRESS_QOS_PROFILES
            res = self.device.get_resource_usage(rd_def)
            self.assertEqual(res.used, (num_ingress_qos_profiles_at_init[slice_pair_id] + 1))

            # Check egress_qos_profiles usage.
            rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_QOS_PROFILES
            res = self.device.get_resource_usage(rd_def)
            self.assertEqual(res.used, (num_egress_qos_profiles_at_init[slice_pair_id] + 1))


if __name__ == '__main__':
    unittest.main()
