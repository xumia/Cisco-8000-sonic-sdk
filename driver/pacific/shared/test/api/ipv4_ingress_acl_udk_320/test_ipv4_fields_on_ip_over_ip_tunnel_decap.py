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
from ipv4_ingress_acl_udk_320_base2 import *
import sim_utils
import topology as T
import ip_test_base


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


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class ipv4_fields_acl(ipv4_ingress_acl_udk_320_base2):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")  # and RTF
    def test_ipv4_fields_acl(self):
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Create IP-over-IP tunnel
        ip_impl = ip_test_base.ipv4_test_base
        TUNNEL_PORT_GID1 = 0x521
        self.tunnel_dest = ip_impl.build_prefix(LOCAL_IP, length=16)
        self.ip_over_ip_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                               TUNNEL_PORT_GID1,
                                                               self.topology.vrf,
                                                               self.tunnel_dest,
                                                               REMOTE_IP,
                                                               self.topology.vrf)

        # Inherit port features
        self.ip_over_ip_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        key_list = []

        # Create a list with special ACL key and modified packet that will be caught by the key

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_PROTOCOL
        f1.val.protocol = 4  # Protocol IPinIP in outer
        f1.mask.protocol = 0xff
        k1.append(f1)
        in_packet = INPUT_IP_IN_IP_PACKET.copy()
        key_list.append((k1, in_packet))

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_TTL
        f2.val.ttl = 33
        f2.mask.ttl = 0xff
        k2.append(f2)
        in_packet = INPUT_IP_IN_IP_PACKET.copy()
        in_packet[IP].ttl = 33
        key_list.append((k2, in_packet))

        # Inner TCP sport
        k6 = []
        f6 = sdk.la_acl_field()
        f6.type = sdk.la_acl_field_type_e_UDF
        f6.udf_index = 3
        in_packet = INPUT_IP_IN_IP_PACKET.copy()
        in_packet[3].sport = 0xab12
        f6.val.sport = in_packet[3].sport
        f6.mask.sport = 0xffff
        k6.append(f6)
        key_list.append((k6, in_packet))

        # Inner TCP dport
        k7 = []
        f7 = sdk.la_acl_field()
        f7.type = sdk.la_acl_field_type_e_UDF
        f7.udf_index = 4
        in_packet = INPUT_IP_IN_IP_PACKET.copy()
        in_packet[3].dport = 0xfa34
        f7.val.dport = in_packet[3].dport
        f7.mask.dport = 0xffff
        k7.append(f7)
        key_list.append((k7, in_packet))

        # For every tuple of key-packet in the list
        for key_packet in key_list:
            self.verify_key_packet_acl(acl1, key_packet[0], key_packet[1])

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()


if __name__ == '__main__':
    unittest.main()
