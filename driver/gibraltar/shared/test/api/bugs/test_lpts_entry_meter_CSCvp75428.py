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

import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
import decor
import topology as T
from ipv4_lpts.ipv4_lpts_base import *
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class lpts_entry_meter_CSCvp75428(ipv4_lpts_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lpts_entry_meter(self):
        # Enable MAC aging
        self.device.set_mac_aging_interval(1)

        METER_SET_SIZE = 1

        meter1 = self.device.create_meter(sdk.la_meter_set.type_e_PER_IFG_EXACT, METER_SET_SIZE)
        meter2 = self.device.create_meter(sdk.la_meter_set.type_e_PER_IFG_EXACT, METER_SET_SIZE)
        meter3 = self.device.create_meter(sdk.la_meter_set.type_e_PER_IFG_EXACT, METER_SET_SIZE)

        meter_action_profile = self.device.create_meter_action_profile()

        #                               exact-meter result          rate-limiter result        drop   ecn    out-packet color            rx-cgm color
        #                               ------------------          --------------
        meter_action_profile.set_action(sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_GREEN, False,
                                        False, sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_GREEN)

        meter_profile = self.device.create_meter_profile(
            sdk.la_meter_profile.type_e_PER_IFG,
            sdk.la_meter_profile.meter_measure_mode_e_BYTES,
            sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
            sdk.la_meter_profile.color_awareness_mode_e_AWARE)

        slice_ifg = sdk.la_slice_ifg()
        for s in range(T.NUM_SLICES_PER_DEVICE):
            for i in range(T.NUM_IFGS_PER_SLICE):
                slice_ifg.slice = s
                slice_ifg.ifg = i
                max_bs = self.device.get_limit(sdk.limit_type_e_METER_PROFILE__MAX_BURST_SIZE)
                meter_profile.set_cbs(slice_ifg, max_bs)
                meter_profile.set_ebs_or_pbs(slice_ifg, max_bs)

        for s in range(T.NUM_SLICES_PER_DEVICE):
            for i in range(T.NUM_IFGS_PER_SLICE):
                slice_ifg.slice = s
                slice_ifg.ifg = i
                for meter_index in range(METER_SET_SIZE):
                    for meter in [meter1, meter2, meter3]:
                        meter.set_committed_bucket_coupling_mode(meter_index, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
                        meter.set_meter_profile(meter_index, meter_profile)
                        meter.set_meter_action_profile(meter_index, meter_action_profile)
                        meter.set_cir(meter_index, slice_ifg, 90)
                        meter.set_eir(meter_index, slice_ifg, 180)

        lpts = self.create_lpts_instance(meter1, meter2, meter3, True)
        self.setup_forus_dest()

        ingress_counter = self.device.create_counter(1)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_counter)

        # lpts_em_2nd_lookup_table uses CEM, if entries got aged out, test would fail
        time.sleep(2)

        run_and_compare(self, self.device,
                        INPUT_PACKET_UC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_UC, PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST)

        (p, b) = ingress_counter.read(0, True, True)
        self.assertEqual(p, 1)

        (p, b) = meter2.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(p, 1)

        run_and_compare(self, self.device,
                        INPUT_PACKET_MC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_MC, PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST)

        (p, b) = meter3.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(p, 1)


if __name__ == '__main__':
    unittest.main()
