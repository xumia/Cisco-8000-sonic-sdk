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
from ipv4_lpts_base import *
import sim_utils
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_fields(ipv4_lpts_base):

    #@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_fields(self):
        lpts = self.create_lpts_instance()
        self.setup_forus_dest()
        key_list = []

        # Create a list with lpts key and a modified packet that will match the key

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[IP].proto = 17
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[IP].proto = 17
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = 17
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[IP].frag = 4
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[IP].frag = 4
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.fragment = 0x1
        k1.mask.ipv4.fragment = 0x1
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[IP].frag = 4
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[IP].frag = 4
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.fragment_info.fields.frag_offset = 0x004
        k1.mask.ipv4.fragment_info.fields.frag_offset = 0xfff
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[IP].flags = "DF"
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[IP].flags = "DF"
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.fragment_info.fields.df = 1
        k1.mask.ipv4.fragment_info.fields.df = 1
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[IP].flags = "MF"
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[IP].flags = "MF"
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.fragment_info.fields.mf = 1
        k1.mask.ipv4.fragment_info.fields.mf = 1
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        out_packet = PUNT_PACKET_UC.copy()
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.ip_length = 40
        k1.mask.ipv4.ip_length = 0xffff
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        out_packet = PUNT_PACKET_UC.copy()
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = in_packet[IP].proto
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[IP].ttl = 1
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[IP].ttl = 1
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = in_packet[IP].proto
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[TCP].sport = 0xab12
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[TCP].sport = 0xab12
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.ports.sport = in_packet[TCP].sport
        k1.mask.ipv4.ports.sport = 0xffff
        key_list.append((k1, in_packet, out_packet))

        in_packet = INPUT_PACKET_UC.copy()
        in_packet[TCP].dport = 0xfa34
        out_packet = PUNT_PACKET_UC.copy()
        out_packet[TCP].dport = 0xfa34
        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.ports.dport = in_packet[TCP].dport
        k1.mask.ipv4.ports.dport = 0xffff
        key_list.append((k1, in_packet, out_packet))

        # remove existing entries
        lpts.pop(2)
        lpts.pop(1)
        lpts.pop(0)

        # For every tuple of key-packet in the list
        for key_packet in key_list:
            self.verify_packet_fields(lpts, key_packet[0], key_packet[1], key_packet[2])

        lpts.clear()

        count = lpts.get_count()
        self.assertEqual(count, 0)


if __name__ == '__main__':
    unittest.main()
