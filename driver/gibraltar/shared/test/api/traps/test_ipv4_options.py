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

from ipv4_traps_base import *
import unittest
import sim_utils
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_options(ipv4_traps_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_options(self):

        in_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL, options=IPOption(b'\x83\x03\x10')) / \
            TCP()
        in_packet, __ = enlarge_packet_to_min_length(in_packet_base)

        punt_packet = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                 next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                 code=sdk.LA_EVENT_IPV4_OPTIONS_EXIST,
                 source_sp=T.RX_SYS_PORT_GID,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=T.RX_L3_AC_GID,
                 # destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
                 destination_lp=sdk.LA_EVENT_IPV4_OPTIONS_EXIST,
                 relay_id=self.PUNT_RELAY_ID, lpts_flow_type=0) / \
            in_packet

        # Use per-ifg exact meter set as counting meter in case of Pacific and GB.
        if decor.is_pacific() or decor.is_gibraltar():
            self.device.set_bool_property(sdk.la_device_property_e_STATISTICAL_METER_COUNTING, False)

        # Create a statistical meter and configure trap with it.
        self.stat_meter = T.create_meter_set(self, self.device, is_statistical=True, set_size=1)

        priority = 1
        self.device.set_trap_configuration(
            sdk.LA_EVENT_IPV4_OPTIONS_EXIST,
            priority,
            self.stat_meter,
            self.punt_dest,
            False,
            False,
            True,
            0)

        self.do_run_test(in_packet, punt_packet)

        if decor.is_pacific() or decor.is_gibraltar():
            (p, b) = self.stat_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
            self.assertEqual(p, 1)


if __name__ == '__main__':
    unittest.main()
