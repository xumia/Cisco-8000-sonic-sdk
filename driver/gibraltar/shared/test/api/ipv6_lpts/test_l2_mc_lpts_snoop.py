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
from ipv6_lpts_base import *
from scapy.all import *
import sim_utils
import decor
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_mc_lpts(ipv6_lpts_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_mc_snoop_lpts(self):
        lpts = self.create_lpts_instance()
        self.setup_forus_dest()

        run_and_compare(self, self.device,
                        INPUT_PACKET_ND_UC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_ND_UC, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        run_and_compare(self, self.device,
                        INPUT_PACKET_ND_MC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_ND_MC, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        run_and_compare(self, self.device,
                        INPUT_PACKET_ND_UC_SVI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_ND_UC_SVI, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        run_and_compare(self, self.device,
                        INPUT_PACKET_ND_MC_SVI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_ND_MC_SVI, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        self.setup_l2_mc_snoop(False)

        run_and_compare(self, self.device,
                        INPUT_PACKET_ND_UC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_ND_UC, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        run_and_compare(self, self.device,
                        INPUT_PACKET_ND_MC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_ND_MC, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        run_and_compare(self, self.device,
                        INPUT_PACKET_ND_UC_SVI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_ND_UC_SVI, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        ingress_packet = {'data': INPUT_PACKET_ND_MC_SVI, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': PUNT_PACKET_ND_MC_SVI_SNOOP, 'slice': self.INJECT_SLICE,
                                 'ifg': self.INJECT_IFG, 'pif': self.INJECT_PIF_FIRST})
        expected_packets.append({'data': INPUT_PACKET_ND_MC_SVI, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)


if __name__ == '__main__':
    unittest.main()
