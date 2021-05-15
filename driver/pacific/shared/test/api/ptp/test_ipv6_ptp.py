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

import decor
from leaba import sdk
import unittest
import packet_test_utils as U
import packet_test_defs as P
import scapy.all as S
import decor
import topology as T
from ip_routing.ip_routing_base import *
from ip_routing.ipv6_l3_ac_routing_base import *


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class test_ipv6_ptp(ipv6_l3_ac_routing_base):
    # PTP transparent disabled for rx port. Expecting packet to go out unchanged

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_transient(self):
        self.topology.rx_eth_port.hld_obj.set_transparent_ptp_enabled(False)
        self.INPUT_PACKET_BASE /= S.UDP(sport=2048) / P.PTPv2(correction_field=0x1122334455667788) / \
            P.PTPDelayReq(origin_time_stamp=0xaabbccddeeff112233)
        self.EXPECTED_OUTPUT_PACKET_BASE /= S.UDP(sport=2048) / P.PTPv2(correction_field=0x1122334455667788) / \
            P.PTPDelayReq(origin_time_stamp=0xaabbccddeeff112233)
        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(
            self.INPUT_PACKET_BASE, self.EXPECTED_OUTPUT_PACKET_BASE)

        self._test_route_single_nh()

    # PTP transparent enabled for rx port. Expecting stamping on PTP correction field

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_transparent(self):
        self.topology.rx_eth_port.hld_obj.set_transparent_ptp_enabled(True)
        self.INPUT_PACKET_BASE /= S.UDP(sport=2048, chksum=0) / P.PTPv2() / P.PTPSync()
        self.EXPECTED_OUTPUT_PACKET_BASE /= S.UDP(sport=2048, chksum=0) / P.PTPv2(correction_field=0x1112131415161721) / P.PTPSync()
        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(
            self.INPUT_PACKET_BASE, self.EXPECTED_OUTPUT_PACKET_BASE)
        self._test_route_single_nh()


if __name__ == '__main__':
    unittest.main()
