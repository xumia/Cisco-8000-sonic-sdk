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
import topology as T
import sim_utils
from leaba import sdk
from leaba import hldcli


SLICE0 = 3
SLICE1 = 5
IFG = 0
SERDES = 4
VID1 = 5
VID2 = 6

SYS_GID = T.MIN_SYSTEM_PORT_GID
SPA_GID = 2
L3AC_GID = 3
TUNNEL_GID = 4
NH_GID = 5
VRF_GID = 6


class unit_test(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device, create_default_topology=False)

        vrf = T.vrf(self, self.device, VRF_GID)
        mac0 = T.mac_port(self, self.device, SLICE0, IFG, SERDES, SERDES)
        self.sys0 = T.system_port(self, self.device, SYS_GID, mac0)
        mac1 = T.mac_port(self, self.device, SLICE1, IFG, SERDES, SERDES)
        self.sys1 = T.system_port(self, self.device, SYS_GID + 1, mac1)
        self.spa = T.spa_port(self, self.device, SPA_GID)
        self.spa.add(self.sys0)
        eth = T.sa_ethernet_port(self, self.device, self.spa)
        l3ac = T.l3_ac_port(self, self.device, L3AC_GID, eth, vrf, T.RX_L3_AC_MAC, VID1, VID2)
        self.nh = T.next_hop(self, self.device, NH_GID, T.RX_L3_AC_MAC, l3ac)
        lsp_labels = []
        self.tunnel = T.te_tunnel(self, self.device, TUNNEL_GID, self.nh.hld_obj)
        lsp_counter = self.device.create_counter(1)
        self.tunnel.hld_obj.set_nh_lsp_properties(self.nh.hld_obj, lsp_labels, lsp_counter)

    def tearDown(self):
        self.device.tearDown()

    def test_te_tunnel_spa_counters(self):
        (labels, counter) = self.tunnel.hld_obj.get_nh_lsp_properties(self.nh.hld_obj)
        counter_impl = counter.imp()

        # check a single system port
        pair_idx0 = SLICE0 // 2
        for pi in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            # counter should have allocations only on slice-pairs that the tunnel's next-hop has access to
            if pi != pair_idx0:
                with self.assertRaises(sdk.NotFoundException):
                    alloc = counter_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)
            else:
                alloc = counter_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)

        # add another system port
        self.spa.add(self.sys1)
        pair_idx1 = SLICE1 // 2
        for pi in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            if pi != pair_idx0 and pi != pair_idx1:
                with self.assertRaises(sdk.NotFoundException):
                    alloc = counter_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)
            else:
                alloc = counter_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)

        # remove a system port
        self.spa.remove(self.sys0)
        for pi in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            if pi != pair_idx1:
                with self.assertRaises(sdk.NotFoundException):
                    alloc = counter_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)
            else:
                alloc = counter_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)

        ############# change the counter and check again ###################
        counter1 = self.device.create_counter(1)
        self.tunnel.hld_obj.set_nh_lsp_properties(self.nh.hld_obj, labels, counter1)
        counter1_impl = counter1.imp()

        # check allocations of new counter
        for pi in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            if pi != pair_idx1:
                with self.assertRaises(sdk.NotFoundException):
                    alloc = counter1_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)
            else:
                alloc = counter1_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)

        # add system port
        self.spa.add(self.sys0)
        pair_idx1 = SLICE1 // 2
        for pi in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            if pi != pair_idx0 and pi != pair_idx1:
                with self.assertRaises(sdk.NotFoundException):
                    alloc = counter1_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)
            else:
                alloc = counter1_impl.get_allocation(pi * 2, hldcli.COUNTER_DIRECTION_EGRESS)


if __name__ == '__main__':
    unittest.main()
