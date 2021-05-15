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

import unittest
from leaba import sdk
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *
import decor

SLICE = T.get_device_slice(T.RX_SLICE)
IFG = T.get_device_ifg(T.RX_IFG)
PIF = T.get_device_first_serdes(4)
SYSPORT_GID = 50
SPA_GID = 60
L3AC_GID = 70
VRF_GID = 80 if not decor.is_gibraltar() else 0xF00
L3AC_MAC = T.mac_addr('36:35:34:33:32:31')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class meter_pair_config(sdk_test_case_base):

    CBS0 = 2048
    CBS1 = 1024
    EBS = 1024

    def init(self, is_aggregate):
        # MATILDA_SAVE -- need review
        global SLICE
        T.RX_SLICE = T.choose_active_slices(self.device, T.RX_SLICE, [5, 0])
        SLICE = T.RX_SLICE

        # Create a meter-set with set-size 2
        meter_set_type = sdk.la_meter_set.type_e_EXACT if (not is_aggregate) else sdk.la_meter_set.type_e_PER_IFG_EXACT
        self.meter_set = self.device.create_meter(meter_set_type, 2)

        slice_ifg = sdk.la_slice_ifg()
        slice_ifg.slice = T.RX_SLICE
        slice_ifg.ifg = T.RX_IFG

        # Create 2 different meter-profiles
        self.meter_profile0 = self.device.create_meter_profile(
            sdk.la_meter_profile.type_e_GLOBAL if (not is_aggregate) else sdk.la_meter_profile.type_e_PER_IFG,
            sdk.la_meter_profile.meter_measure_mode_e_BYTES,
            sdk.la_meter_profile.meter_rate_mode_e_TR_TCM,
            sdk.la_meter_profile.color_awareness_mode_e_AWARE)
        if is_aggregate:
            self.meter_profile0.set_cbs(slice_ifg, self.CBS0)
            self.meter_profile0.set_ebs_or_pbs(slice_ifg, self.EBS)
        else:
            self.meter_profile0.set_cbs(self.CBS0)
            self.meter_profile0.set_ebs_or_pbs(self.EBS)

        self.meter_profile1 = self.device.create_meter_profile(
            sdk.la_meter_profile.type_e_GLOBAL if (not is_aggregate) else sdk.la_meter_profile.type_e_PER_IFG,
            sdk.la_meter_profile.meter_measure_mode_e_BYTES,
            sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
            sdk.la_meter_profile.color_awareness_mode_e_AWARE)
        if is_aggregate:
            self.meter_profile1.set_cbs(slice_ifg, self.CBS1)
            self.meter_profile1.set_ebs_or_pbs(slice_ifg, self.EBS)
        else:
            self.meter_profile1.set_cbs(self.CBS1)
            self.meter_profile1.set_ebs_or_pbs(self.EBS)

        # Create 2 different meter-actio-profiles
        self.meter_action_profile0 = self.device.create_meter_action_profile()
        self.meter_action_profile1 = self.device.create_meter_action_profile()

        # Set different profile to each meter in the meter-set
        self.meter_set.set_committed_bucket_coupling_mode(0, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
        self.meter_set.set_committed_bucket_coupling_mode(1, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
        self.meter_set.set_meter_profile(0, self.meter_profile0)
        self.meter_set.set_meter_profile(1, self.meter_profile1)
        self.meter_set.set_meter_action_profile(0, self.meter_action_profile0)
        self.meter_set.set_meter_action_profile(1, self.meter_action_profile1)

    def do_test_meter_pair_config(self):
        # Verify the different config
        mp0 = self.meter_set.get_meter_profile(0)
        rate_mode0 = mp0.get_meter_rate_mode()
        self.assertEqual(rate_mode0, sdk.la_meter_profile.meter_rate_mode_e_TR_TCM)

        mp1 = self.meter_set.get_meter_profile(1)
        rate_mode1 = mp1.get_meter_rate_mode()
        self.assertEqual(rate_mode1, sdk.la_meter_profile.meter_rate_mode_e_SR_TCM)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_meter_pair_config_aggregate(self):
        self.init(is_aggregate=True)
        self.mp = T.mac_port(self, self.device, SLICE, IFG, PIF, PIF + 1)
        self.sp = T.system_port(self, self.device, SYSPORT_GID, self.mp)
        self.spa = T.spa_port(self, self.device, SPA_GID)
        self.spa.add(self.sp)
        self.eth = T.sa_ethernet_port(self, self.device, self.spa)
        self.vrf = T.vrf(self, self.device, VRF_GID)
        self.l3ac = T.l3_ac_port(self, self.device, L3AC_GID, self.eth, self.vrf, L3AC_MAC)
        # Attach the meter to an existing port
        self.l3ac.hld_obj.set_meter(self.meter_set)
        self.do_test_meter_pair_config()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_meter_pair_config_non_aggregate(self):
        self.init(is_aggregate=False)
        self.topology.rx_l3_ac.hld_obj.set_meter(self.meter_set)
        self.do_test_meter_pair_config()


if __name__ == '__main__':
    unittest.main()
