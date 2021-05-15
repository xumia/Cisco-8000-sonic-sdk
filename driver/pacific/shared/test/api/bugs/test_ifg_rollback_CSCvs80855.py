#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from sdk_test_case_base import *
from leaba import sdk
import sim_utils
import topology as T
import decor

CBS = 1024000
ZERO_PBS = 0
PBS = 1024000
CIR = 5000000000
NUM_METERS = 8
L3AC_GID = 0x99
NUM_METER_ACTION_PROFILES = 4
VLAN = 0x10


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class meter_action_profile_scale_tester(sdk_test_case_base):

    def create_meter_action_profile(self):
        map = self.device.create_meter_action_profile()
        map.set_action(sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_GREEN, False,
                       False, sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_GREEN)
        map.set_action(sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, False,
                       False, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_GREEN)
        map.set_action(
            sdk.la_qos_color_e_GREEN,
            sdk.la_qos_color_e_RED,
            False,
            False,
            sdk.la_qos_color_e_YELLOW,
            sdk.la_qos_color_e_GREEN)
        map.set_action(sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_GREEN, True,
                       False, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_GREEN)
        map.set_action(sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_YELLOW, True,
                       False, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_GREEN)
        map.set_action(sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_RED, True,
                       False, sdk.la_qos_color_e_RED, sdk.la_qos_color_e_GREEN)
        map.set_action(sdk.la_qos_color_e_RED, sdk.la_qos_color_e_GREEN, True,
                       False, sdk.la_qos_color_e_RED, sdk.la_qos_color_e_GREEN)
        map.set_action(sdk.la_qos_color_e_RED, sdk.la_qos_color_e_YELLOW, True,
                       False, sdk.la_qos_color_e_RED, sdk.la_qos_color_e_GREEN)
        map.set_action(
            sdk.la_qos_color_e_RED,
            sdk.la_qos_color_e_RED,
            True,
            False,
            sdk.la_qos_color_e_RED,
            sdk.la_qos_color_e_GREEN)
        return map

    def create_meter_profile(self):
        mp = self.device.create_meter_profile(
            sdk.la_meter_profile.type_e_GLOBAL,
            sdk.la_meter_profile.meter_measure_mode_e_BYTES,
            sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
            sdk.la_meter_profile.color_awareness_mode_e_AWARE)
        mp.set_meter_measure_mode(sdk.la_meter_profile.meter_measure_mode_e_BYTES)
        mp.set_meter_rate_mode(sdk.la_meter_profile.meter_rate_mode_e_SR_TCM)
        mp.set_color_awareness_mode(sdk.la_meter_profile.color_awareness_mode_e_AWARE)
        mp.set_cbs(CBS)
        mp.set_ebs_or_pbs(PBS)
        return mp

    def create_meter(self, num_maps=1):
        meter = self.device.create_meter(sdk.la_meter_set.type_e_EXACT, NUM_METERS)
        maps = []
        for i in range(num_maps):
            maps.append(self.create_meter_action_profile())
        mp = self.create_meter_profile()

        for i in range(NUM_METERS):
            meter.set_committed_bucket_coupling_mode(i, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
            meter.set_meter_profile(i, mp)
            meter.set_meter_action_profile(i, maps[int(i % num_maps)])
            meter.set_cir(i, CIR)
            meter.set_eir(i, PBS)
        return meter

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_rollback(self):
        ''' Verify meter action profiles allocation is rolled back on error
        '''
        # use 1 meter action profile as test
        meter = self.create_meter()
        l3ac = self.device.create_l3_ac_port(
            L3AC_GID,
            self.topology.tx_l3_ac_eth_port_def.hld_obj,
            VLAN,
            VLAN,
            T.RX_L3_AC_MAC.hld_obj,
            self.topology.vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)
        l3ac.set_meter(meter)

        # create a meter with 4 meter action profiles. Should fail and rollback.
        meter = self.create_meter(NUM_METER_ACTION_PROFILES)
        with self.assertRaises(sdk.ResourceException):
            self.topology.tx_l3_ac_def.hld_obj.set_meter(meter)

        # prev rollback should have been a success. try again with 3 profiles
        meter = self.create_meter(NUM_METER_ACTION_PROFILES - 1)
        self.topology.tx_l3_ac_def.hld_obj.set_meter(meter)


if __name__ == '__main__':
    unittest.main()
