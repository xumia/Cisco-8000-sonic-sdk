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

import sys
import unittest
from leaba import sdk
from scapy.all import *
from npu_getters_base import *
import sim_utils
import topology as T
import packet_test_utils as U
import decor

PFX_OBJ_GID = 53


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class mpls_multicast_group(npu_getters_base, unittest.TestCase):

    def setUp(self):
        self.device = U.sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)

        self.mc_group = self.device.create_mpls_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)

        group_size = self.mc_group.get_size()
        self.assertEqual(group_size, 0)

        label = sdk.la_mpls_label()
        label.label = 500
        labels = []
        labels.append(label)
        self.prefix_object = self.device.create_prefix_object(
            PFX_OBJ_GID, self.topology.nh_l3_ac_reg.hld_obj, sdk.la_prefix_object.prefix_type_e_NORMAL)
        self.prefix_object.set_nh_lsp_properties(self.topology.nh_l3_ac_reg.hld_obj, labels,
                                                 None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.dsp = self.topology.tx_l3_ac_reg.hld_obj.get_ethernet_port().get_system_port()
        self.mc_group.add(self.prefix_object, self.dsp)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mpls_mc_group_set_get(self):
        # Check get_member
        size = self.mc_group.get_size()
        self.assertEqual(size, 1)

        out_member = self.mc_group.get_member(0)
        self.assertEqual(out_member.prefix_object.this, self.prefix_object.this)

        try:
            self.mc_group.get_member(5)
            self.assertFail()
        except BaseException:
            pass

        # Check get_replication_paradigm
        res_replication_paradigm = self.mc_group.get_replication_paradigm()
        self.assertEqual(res_replication_paradigm, sdk.la_replication_paradigm_e_EGRESS)

        # DSP
        dsp = self.mc_group.get_destination_system_port(self.prefix_object)
        self.assertEqual(dsp.this, self.dsp.this)

#        # Check get multicast group
#        mc_group2 = self.device.get_l2_multicast_group(MC_GROUP_GID)
#        self.assertEqual(mc_group2.this, self.mc_group.this)


if __name__ == '__main__':
    unittest.main()
