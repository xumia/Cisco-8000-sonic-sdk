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

# This test creates ingress and egress profiles.
# Creates l3ac using these profiles. ingress slices (0, 2, 4). Egress slices (1, 3, 5)
# MAX_SLICE_PAIRS, MAX_QOS_PROFILES_PER_SLICE_PAIR drives the scale.

import unittest
from leaba import sdk
from packet_test_utils import sim_utils
import topology as T
import logging
from sdk_test_case_base import *
import decor

MAX_QOS_PROFILES_PER_SLICE_PAIR = 15
# 1 profile used for default
MAX_QOS_PROFILES_PER_SLICE_PAIR_USABLE = MAX_QOS_PROFILES_PER_SLICE_PAIR - 1
#NUM_SLICES_PER_DEVICE = 6

IFG = T.get_device_ifg(1)
OTHER_IFG = 0
VRF_GID = 0
FIRST_SERDES = 10
LAST_SERDES = 11
RX_SYS_PORT_GID = 1000
TX_SYS_PORT_GID = 1100
L3_AC_QOS_VID1_START = 10
RX_L3_AC_GID = 0x210
TX_L3_AC_GID = 0x310


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class qos_profile_scale(sdk_test_case_base):

    def setUp(self):
        super().setUp(create_default_topology=False)

    def choose_slices(self):
        self.rx_slice_ifgs = []
        self.tx_slices_ifgs = []
        for slice_pair in self.device.get_used_slice_pairs():
            even_slice = 2 * slice_pair
            odd_slice = 2 * slice_pair + 1
            if even_slice in self.device.get_used_slices():
                self.rx_slice_ifgs.append([even_slice, IFG])
            else:
                self.rx_slice_ifgs.append([odd_slice, OTHER_IFG])

            if odd_slice in self.device.get_used_slices():
                self.tx_slices_ifgs.append([odd_slice, IFG])
            else:
                self.tx_slices_ifgs.append([even_slice, OTHER_IFG])

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_qos_profile_scale(self):
        self.choose_slices()

        ingress_l3_ac = []
        egress_l3_ac = []
        rx_eth_port = []
        tx_eth_port = []
        ingress_profiles = []
        egress_profiles = []

        vrf = T.vrf(self, self.device, VRF_GID)

        for slice_pair in self.device.get_used_slice_pairs():
            # create ethports
            rx_slice, rx_ifg = self.rx_slice_ifgs[slice_pair]
            tx_slice, tx_ifg = self.tx_slices_ifgs[slice_pair]

            rx_eth_port.append(T.ethernet_port(self, self.device,
                                               rx_slice,
                                               rx_ifg,
                                               (RX_SYS_PORT_GID + slice_pair),
                                               FIRST_SERDES,
                                               LAST_SERDES))
            if decor.is_asic5():  # SERDES number needs to be different as Asic5 has only 1 slice and 1 IFG
                tx_eth_port.append(T.ethernet_port(self, self.device,
                                                   tx_slice,
                                                   tx_ifg,
                                                   (TX_SYS_PORT_GID + slice_pair),
                                                   FIRST_SERDES + 2,
                                                   LAST_SERDES + 2))
            else:
                tx_eth_port.append(T.ethernet_port(self, self.device,
                                                   tx_slice,
                                                   tx_ifg,
                                                   (TX_SYS_PORT_GID + slice_pair),
                                                   FIRST_SERDES,
                                                   LAST_SERDES))
            in_profiles = []
            out_profiles = []
            for id in range(0, MAX_QOS_PROFILES_PER_SLICE_PAIR_USABLE):
                in_profiles.append(T.ingress_qos_profile(self, self.device))
                out_profiles.append(T.egress_qos_profile(self, self.device))
            ingress_profiles.append(in_profiles)
            egress_profiles.append(out_profiles)
        for slice_pair in self.device.get_used_slice_pairs():
            in_l3_ac = []
            out_l3_ac = []
            for id in range(0, MAX_QOS_PROFILES_PER_SLICE_PAIR_USABLE):
                # create ingress l3ac
                in_l3_ac.append(T.l3_ac_port(self, self.device,
                                             RX_L3_AC_GID + id + (slice_pair * MAX_QOS_PROFILES_PER_SLICE_PAIR_USABLE),
                                             rx_eth_port[slice_pair],
                                             vrf,
                                             T.RX_L3_AC_MAC,
                                             (L3_AC_QOS_VID1_START + id),
                                             (L3_AC_QOS_VID1_START + id),
                                             ingress_qos_profile=ingress_profiles[slice_pair][id],
                                             egress_qos_profile=None))

                # create egress l3ac
                out_l3_ac.append(T.l3_ac_port(self, self.device,
                                              TX_L3_AC_GID + id + (slice_pair * MAX_QOS_PROFILES_PER_SLICE_PAIR_USABLE),
                                              tx_eth_port[slice_pair],
                                              vrf,
                                              T.RX_L3_AC_MAC,
                                              (L3_AC_QOS_VID1_START + id),
                                              (L3_AC_QOS_VID1_START + id),
                                              ingress_qos_profile=None,
                                              egress_qos_profile=egress_profiles[slice_pair][id]))
            ingress_l3_ac.append(in_l3_ac)
            egress_l3_ac.append(out_l3_ac)


if __name__ == '__main__':
    unittest.main()
