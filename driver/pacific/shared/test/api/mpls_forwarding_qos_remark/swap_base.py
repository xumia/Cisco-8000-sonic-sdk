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
from mpls_forwarding_qos_remark_base import *
import sim_utils
import topology as T
import packet_test_utils as U

load_contrib('mpls')


class swap_base(mpls_forwarding_qos_remark_base):

    def _test_swap(self):
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)

        lsr = self.device.get_lsr()

        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(self.EGRESS_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)

        lsr.delete_route(self.INPUT_LABEL)

        self.device.destroy(nhlfe)
