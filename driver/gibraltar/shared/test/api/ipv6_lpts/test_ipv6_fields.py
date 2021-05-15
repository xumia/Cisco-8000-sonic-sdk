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
from ipv6_lpts_base import *
from scapy.all import *
import sim_utils
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv6_fields(ipv6_lpts_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_fields(self):
        # Set trap for hop_by_hop to default, which is punt
        self.device.clear_trap_configuration(sdk.LA_EVENT_IPV6_HOP_BY_HOP)
        lpts = self.create_lpts_instance()
        self.setup_forus_dest()
        key_list = []

        # Create a list with lpts key and a modified packet that will match the key

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[IPv6].nh = 17
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[IPv6].nh = 17
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.protocol = 17
        k1.mask.ipv6.protocol = sdk.la_l4_protocol_e_RESERVED
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        out_packet = PUNT_PACKET_UC.copy()
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.protocol = in_packet[IPv6].nh
        k1.mask.ipv6.protocol = sdk.la_l4_protocol_e_RESERVED
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[IPv6].hlim = 1
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[IPv6].hlim = 1
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.protocol = in_packet[IPv6].nh
        k1.mask.ipv6.protocol = sdk.la_l4_protocol_e_RESERVED
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[TCP].sport = 0xab12
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[TCP].sport = 0xab12
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.ports.sport = in_packet[TCP].sport
        k1.mask.ipv6.ports.sport = 0xffff
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[TCP].dport = 0xfa34
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[TCP].dport = 0xfa34
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.ports.dport = in_packet[TCP].dport
        k1.mask.ipv6.ports.dport = 0xffff
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        out_packet = PUNT_PACKET_UC.copy()
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.ip_length = 80
        k1.mask.ipv6.ip_length = 0xffff
        key_list.append((k1, in_packet, out_packet))

        # remove existing entries
        lpts.pop(5)
        lpts.pop(4)
        lpts.pop(3)
        lpts.pop(2)
        lpts.pop(1)
        lpts.pop(0)

        in_packet = INPUT_PACKET_UC_HOP_BY_HOP.copy()
        in_packet[IPv6].nh = 0
        out_packet = PUNT_PACKET_UC_HOP_BY_HOP.copy()
        out_packet[IPv6].nh = 0
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.protocol = 0
        k1.mask.ipv6.protocol = sdk.la_l4_protocol_e_RESERVED
        key_list.append((k1, in_packet, out_packet))

        # For every tuple of key-packet in the list
        for key_packet in key_list:
            self.verify_packet_fields(lpts, key_packet[0], key_packet[1], key_packet[2])

        lpts.clear()

        count = lpts.get_count()
        self.assertEqual(count, 0)


if __name__ == '__main__':
    unittest.main()
