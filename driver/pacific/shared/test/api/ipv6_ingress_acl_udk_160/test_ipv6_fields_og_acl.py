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

import unittest
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from ipv6_ingress_acl_og_160_base import *
import sim_utils
import topology as T
import decor


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
class ipv6_fields_og_acl(ipv6_ingress_acl_og_160_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_fields_og_acl(self):
        for key_list_num in range(2):
            if (key_list_num == 0):
                acl1 = self.create_simple_sec_acl(False, True, True)
            else:
                acl1 = self.create_simple_sec_acl(True, False, True)

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

            k0 = []
            f0 = sdk.la_acl_field()
            f0.type = sdk.la_acl_field_type_e_TOS
            f0.val.tos.fields.dscp = 0x3f
            f0.mask.tos.fields.dscp = 0x3f
            k0.append(f0)
            in_packet = self.INPUT_PACKET.copy()
            in_packet[IPv6].tc = 0xfc
            key_list.append((k0, in_packet))

            k2 = []
            f2 = sdk.la_acl_field()
            f2.type = sdk.la_acl_field_type_e_SPORT
            f2.val.sport = 0xab12
            f2.mask.sport = 0xffff
            k2.append(f2)
            in_packet = self.INPUT_PACKET.copy()
            in_packet[TCP].sport = 0xab12
            key_list.append((k2, in_packet))

            # Not-first fragment
            k3 = []
            f3 = sdk.la_acl_field()
            f3.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
            f3.udf_index = 1
            f3.val.ipv6_fragment.fragment = 0x1
            f3.mask.ipv6_fragment.fragment = 0x1
            k3.append(f3)
            in_packet = self.INPUT_PACKET_WITH_EH.copy()
            in_packet[4].offset = 4
            key_list.append((k3, in_packet))

            # First fragment
            k4 = []
            f4 = sdk.la_acl_field()
            f4.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
            f4.udf_index = 1
            f4.val.ipv6_fragment.fragment = 0x0
            f4.mask.ipv6_fragment.fragment = 0x1
            k4.append(f4)
            # Adding TOS also, so that packet input for testing default-route does not hit this TCAM entry
            f5 = sdk.la_acl_field()
            f5.type = sdk.la_acl_field_type_e_TOS
            f5.val.tos.fields.dscp = 0x3f
            f5.mask.tos.fields.dscp = 0x3f
            k4.append(f5)
            in_packet = self.INPUT_PACKET_WITH_EH.copy()
            in_packet[4].m = 0x1
            in_packet[IPv6].tc = 0xfc
            key_list.append((k4, in_packet))

            # For every tuple of key-packet in the list
            for key_packet in key_list:
                self.verify_key_packet_acl(acl1, key_packet[0], key_packet[1])
            key_list = []

            # Create a list with special ACL key and modified packet that will be caught by the key
            # this list is the same as before, however the src and dst bincode fields have also been
            # added to each entry
            k0 = []
            f0 = sdk.la_acl_field()
            f0.type = sdk.la_acl_field_type_e_TOS
            f0.val.tos.fields.dscp = 0x3f
            f0.mask.tos.fields.dscp = 0x3f
            k0.append(f0)

            fspcl = sdk.la_acl_field()
            fspcl.type = sdk.la_acl_field_type_e_SRC_PCL_BINCODE
            if (key_list_num == 0):
                fspcl.val.src_pcl_bincode = self.SBINCODE1
            else:
                fspcl.val.src_pcl_bincode = self.SBINCODE2
            fspcl.mask.src_pcl_bincode = 0x7ffff
            k0.append(fspcl)

            fdpcl = sdk.la_acl_field()
            fdpcl.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
            if (key_list_num == 0):
                fdpcl.val.dst_pcl_bincode = self.DBINCODE1
            else:
                fdpcl.val.dst_pcl_bincode = self.DBINCODE2
            fdpcl.mask.dst_pcl_bincode = 0x7ffff
            k0.append(fdpcl)

            in_packet = self.INPUT_PACKET.copy()
            in_packet[IPv6].tc = 0xfc
            key_list.append((k0, in_packet))

            k2 = []
            f2 = sdk.la_acl_field()
            f2.type = sdk.la_acl_field_type_e_SPORT
            f2.val.sport = 0xab12
            f2.mask.sport = 0xffff
            k2.append(f2)
            k2.append(fspcl)
            k2.append(fdpcl)
            in_packet = self.INPUT_PACKET.copy()
            in_packet[TCP].sport = 0xab12
            key_list.append((k2, in_packet))

            # Not-first fragment
            k3 = []
            f3 = sdk.la_acl_field()
            f3.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
            f3.udf_index = 1
            f3.val.ipv6_fragment.fragment = 0x1
            f3.mask.ipv6_fragment.fragment = 0x1
            k3.append(f3)
            k3.append(fspcl)
            k3.append(fdpcl)
            in_packet = self.INPUT_PACKET_WITH_EH.copy()
            in_packet[4].offset = 4
            key_list.append((k3, in_packet))

            # First fragment
            k4 = []
            f4 = sdk.la_acl_field()
            f4.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
            f4.udf_index = 1
            f4.val.ipv6_fragment.fragment = 0x0
            f4.mask.ipv6_fragment.fragment = 0x1
            k4.append(f4)
            k4.append(fspcl)
            k4.append(fdpcl)
            # Adding TOS also, so that packet input for testing default-route does not hit this TCAM entry
            f5 = sdk.la_acl_field()
            f5.type = sdk.la_acl_field_type_e_TOS
            f5.val.tos.fields.dscp = 0x3f
            f5.mask.tos.fields.dscp = 0x3f
            k4.append(f5)
            in_packet = self.INPUT_PACKET_WITH_EH.copy()
            in_packet[4].m = 0x1
            in_packet[IPv6].tc = 0xfc
            key_list.append((k4, in_packet))

            if (key_list_num == 1):
                k5 = []
                f5 = sdk.la_acl_field()
                f5.type = sdk.la_acl_field_type_e_DPORT
                f5.val.dport = 0x1122
                f5.mask.dport = 0xffff
                k5.append(f5)
                k5.append(fspcl)
                k5.append(fdpcl)
                in_packet = self.INPUT_PACKET.copy()
                in_packet[TCP].dport = f5.val.dport
                key_list.append((k5, in_packet))

                k6 = []
                f6 = sdk.la_acl_field()
                f6.type = sdk.la_acl_field_type_e_IPV6_LENGTH
                in_packet = self.INPUT_PACKET.copy()
                f6.val.ipv6_length = len(in_packet[TCP])
                f6.mask.ipv6_length = 0x0ffff
                k6.append(f6)
                k6.append(fspcl)
                k6.append(fdpcl)
                f6b = sdk.la_acl_field()
                f6b.type = sdk.la_acl_field_type_e_TOS
                f6b.val.tos.fields.dscp = 0x11
                f6b.mask.tos.fields.dscp = 0x3f
                k6.append(f6b)
                in_packet[IPv6].tc = 0x44
                key_list.append((k6, in_packet))

                k7 = []
                f7 = sdk.la_acl_field()
                f7.type = sdk.la_acl_field_type_e_HOP_LIMIT
                f7.val.ttl = 223
                f7.mask.ttl = 0xff
                k7.append(f7)
                k7.append(fspcl)
                k7.append(fdpcl)
                in_packet = self.INPUT_PACKET.copy()
                in_packet[IPv6].hlim = f7.val.ttl
                key_list.append((k7, in_packet))

                k8 = []
                f8 = sdk.la_acl_field()
                f8.type = sdk.la_acl_field_type_e_TCP_FLAGS
                in_packet = self.INPUT_PACKET.copy()
                in_packet[TCP].flags = "SA"
                f8.val.tcp_flags.fields.syn = 1
                f8.val.tcp_flags.fields.ack = 1
                f8.mask.tcp_flags.flat = 0x3f
                k8.append(f8)
                key_list.append((k8, in_packet))

            # For every tuple of key-packet in the list
            for key_packet in key_list:
                self.verify_key_packet_acl(acl1, key_packet[0], key_packet[1])

            # Detach ACL
            self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
            self.device.destroy(acl_group)
            self.device.destroy(acl1)

            # Test default route
            self.do_test_route_default()


if __name__ == '__main__':
    unittest.main()
