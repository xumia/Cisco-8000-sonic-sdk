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

import decor
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import decor
import topology as T

from traps_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class traps_rx_drop_dsp(TrapsTest):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_traps_rx_drop_dsp(self):
        '''
            Inject a packet that should hit the no-service-mapping trap, with the trap configured to drop.
            1. Validate the packet is dropped.
            2. Validate its VOQ counter works.
        '''
        # Save current trap configuration
        prev_trap_config = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        # Configure trap to superior priority and to drop
        destination = None
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, 0, None, destination, False, False, True, 0)

        NO_SERVICE_MAPPING_VID = T.RX_L2_AC_PORT_VID1 + 1
        INPUT_PACKET_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=NO_SERVICE_MAPPING_VID) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        rx_drop_voq_counter = self.device.get_forwarding_drop_counter()

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0,    # ENQUEUE counter
                                                                            True,  # force_update
                                                                            True)  # clear_on_read
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1,      # DROP counter
                                                                      True,   # force_update
                                                                      True)   # clear_on_read
        # Verify the counter is empty.
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

        U.run_and_drop(self, self.device, INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0, True, True)
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1, True, True)

        # The packets should be dropped, so verify that the ENQUEUE counter is empty
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)

        expected_packet_size = U.get_injected_packet_len(self.device, INPUT_PACKET, T.RX_SLICE)
        self.assertEqual(drop_packet_count, 1)
        self.assertEqual(drop_byte_count, expected_packet_size)

        # Restore trap configuration
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, *prev_trap_config)


if __name__ == '__main__':
    unittest.main()
