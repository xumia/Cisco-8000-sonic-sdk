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
import unittest
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from ipv6_ingress_acl_udk_320_base2 import *
import decor
import topology as T


class udf_data:

    NUM_OF_SHORTS = 8
    BITS_IN_SHORT = 16
    BITS_IN_QWORD = 64

    def __init__(self, data_str):
        self.data_str = data_str
        self.hld_obj = sdk.la_acl_udf_data()
        q0 = self.to_num() & ((1 << udf_data.BITS_IN_QWORD) - 1)
        q1 = (self.to_num() >> udf_data.BITS_IN_QWORD) & ((1 << udf_data.BITS_IN_QWORD) - 1)
        sdk.set_udf_data(self.hld_obj, q0, q1)

    def to_num(self):
        shorts = self.data_str.split(':')
        assert(len(shorts) == udf_data.NUM_OF_SHORTS)
        c = udf_data.NUM_OF_SHORTS - 1
        n = 0
        for s in shorts:
            if len(s) > 0:
                sn = int(s, 16)
                n += (1 << udf_data.BITS_IN_SHORT) ** c * sn
            c -= 1

        return n


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv6_fields_acl(ipv6_ingress_acl_udk_320_base2):

    @unittest.skipIf(decor.is_hw_device(), 'Skip on HW device')
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_fields_acl(self):
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        key_list = []

        # Create a list with special ACL key and modified packet that will be caught by the key

        # Inner IPv6 Hop-Limit
        k0 = []
        f0 = sdk.la_acl_field()
        f0.type = sdk.la_acl_field_type_e_UDF
        f0.udf_index = 2
        f0.val.ttl = 0x3f
        f0.mask.ttl = 0xff
        k0.append(f0)
        in_packet = self.INPUT_IP_IN_IP_PACKET.copy()
        in_packet[4].hlim = 0x3f
        key_list.append((k0, in_packet))

        # Inner IPv6 TCP dport
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_UDF
        f1.udf_index = 5
        f1.val.dport = 0xab12
        f1.mask.dport = 0xab12
        k1.append(f1)
        in_packet = self.INPUT_IP_IN_IP_PACKET.copy()
        in_packet[5].dport = 0xab12
        key_list.append((k1, in_packet))

        # For every tuple of key-packet in the list
        for key_packet in key_list:
            self.verify_key_packet_acl(acl1, key_packet[0], key_packet[1])

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()


if __name__ == '__main__':
    unittest.main()
