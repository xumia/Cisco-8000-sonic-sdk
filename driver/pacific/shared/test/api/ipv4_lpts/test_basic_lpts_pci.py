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

import decor
import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
from ipv4_lpts_base_pci import *
import sim_utils
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class basic_lpts(ipv4_lpts_base_pci):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_basic_lpts(self):
        lpts = self.create_lpts_instance()
        self.setup_forus_dest()

        pi_pif = self.device.get_pci_serdes()

        run_and_compare(self, self.device,
                        INPUT_PACKET_UC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_UC, PUNT_SLICE, T.PI_IFG, pi_pif)

        run_and_compare(self, self.device,
                        INPUT_PACKET_MC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_MC, PUNT_SLICE, T.PI_IFG, pi_pif)

        self.trim_lpts_invalid(lpts)
        self.trim_lpts(lpts)

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = 6
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.meter = T.create_meter_set(self, self.device, is_statistical=True, set_size=1)
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)
        result.dest = self.punt_dest2

        self.push_lpts_entry(lpts, 0, k1, result)
        self.update_lpts_entry(lpts, 2)

        lpts.clear()

        count = lpts.get_count()
        self.assertEqual(count, 0)


if __name__ == '__main__':
    unittest.main()
