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
from ipv4_ingress_acl_og_160_base import *
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


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class ipv4_fields_og_acl(ipv4_ingress_acl_og_160_base):

    def configure_key_list1(self, is_svi=False):
        key_list = []

        # Create a list with special ACL key and modified packet that will be caught by the key
        k0 = []
        f0 = sdk.la_acl_field()
        f0.type = sdk.la_acl_field_type_e_TOS
        f0.val.tos.fields.dscp = 0x3f
        f0.mask.tos.fields.dscp = 0x3f
        k0.append(f0)
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        in_packet[IP].tos = 0xfc
        key_list.append((k0, in_packet))

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_PROTOCOL
        f1.val.protocol = 17
        f1.mask.protocol = 0xff
        k1.append(f1)
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        in_packet[IP].proto = 17
        key_list.append((k1, in_packet))

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV4_FLAGS
        f3.val.ipv4_flags.fragment = 0x1
        f3.mask.ipv4_flags.fragment = 0x1
        k3.append(f3)
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        in_packet[IP].frag = 4
        key_list.append((k3, in_packet))

        k4 = []
        f4 = sdk.la_acl_field()
        f4.type = sdk.la_acl_field_type_e_PROTOCOL
        in_packet = self.INPUT_PACKET_TCP_SVI.copy() if is_svi else self.INPUT_PACKET_TCP.copy()
        f4.val.protocol = in_packet[IP].proto
        f4.mask.protocol = 0xff
        k4.append(f4)
        key_list.append((k4, in_packet))

        k5 = []
        f5 = sdk.la_acl_field()
        f5.type = sdk.la_acl_field_type_e_TCP_FLAGS
        in_packet = self.INPUT_PACKET_TCP_SVI.copy() if is_svi else self.INPUT_PACKET_TCP.copy()
        in_packet[TCP].flags = "SA"
        f5.val.tcp_flags.fields.syn = 1
        f5.val.tcp_flags.fields.ack = 1
        f5.mask.tcp_flags.flat = 0x3f
        k5.append(f5)
        key_list.append((k5, in_packet))

        k6 = []
        f6 = sdk.la_acl_field()
        f6.type = sdk.la_acl_field_type_e_SPORT
        in_packet = self.INPUT_PACKET_TCP_SVI.copy() if is_svi else self.INPUT_PACKET_TCP.copy()
        in_packet[TCP].sport = 0xab12
        f6.val.sport = in_packet[TCP].sport
        f6.mask.sport = 0xffff
        k6.append(f6)
        key_list.append((k6, in_packet))

        k7 = []
        f7 = sdk.la_acl_field()
        f7.type = sdk.la_acl_field_type_e_DPORT
        in_packet = self.INPUT_PACKET_TCP_SVI.copy() if is_svi else self.INPUT_PACKET_TCP.copy()
        in_packet[TCP].dport = 0xfa34
        f7.val.dport = in_packet[TCP].dport
        f7.mask.dport = 0xffff
        k7.append(f7)
        key_list.append((k7, in_packet))

        k8 = []
        f8 = sdk.la_acl_field()
        f8.type = sdk.la_acl_field_type_e_MSG_TYPE
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        in_packet[ICMP].type = 8
        in_packet[ICMP].code = 23
        f8.val.mtype = in_packet[ICMP].type
        f8.mask.mtype = 0xff
        k8.append(f8)
        f9 = sdk.la_acl_field()
        f9.type = sdk.la_acl_field_type_e_MSG_CODE
        f9.val.mcode = in_packet[ICMP].code
        f9.mask.mcode = 0xff
        k8.append(f9)
        #key_list.append((k8, in_packet))

        return key_list

    def configure_key_list2(self, is_svi=False):
        key_list = []

        # Create a list with special ACL key and modified packet that will be caught by the key
        k0 = []
        f0 = sdk.la_acl_field()
        f0.type = sdk.la_acl_field_type_e_TOS
        f0.val.tos.fields.dscp = 0x3f
        f0.mask.tos.fields.dscp = 0x3f
        k0.append(f0)
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        in_packet[IP].tos = 0xfc
        key_list.append((k0, in_packet))

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_PROTOCOL
        f1.val.protocol = 17
        f1.mask.protocol = 0xff
        k1.append(f1)
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        in_packet[IP].proto = 17
        key_list.append((k1, in_packet))

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV4_FLAGS
        f2.val.ipv4_flags.fragment = 0x1
        f2.mask.ipv4_flags.fragment = 0x1
        k2.append(f2)
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        in_packet[IP].frag = 4
        key_list.append((k2, in_packet))

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_PROTOCOL
        in_packet = self.INPUT_PACKET_TCP_SVI.copy() if is_svi else self.INPUT_PACKET_TCP.copy()
        f3.val.protocol = in_packet[IP].proto
        f3.mask.protocol = 0xff
        k3.append(f3)
        key_list.append((k3, in_packet))

        k4 = []
        f4 = sdk.la_acl_field()
        f4.type = sdk.la_acl_field_type_e_TCP_FLAGS
        in_packet = self.INPUT_PACKET_TCP_SVI.copy() if is_svi else self.INPUT_PACKET_TCP.copy()
        in_packet[TCP].flags = "SA"
        f4.val.tcp_flags.fields.syn = 1
        f4.val.tcp_flags.fields.ack = 1
        f4.mask.tcp_flags.flat = 0x3f
        k4.append(f4)
        key_list.append((k4, in_packet))

        k5 = []
        f5 = sdk.la_acl_field()
        f5.type = sdk.la_acl_field_type_e_SPORT
        in_packet = self.INPUT_PACKET_TCP_SVI.copy() if is_svi else self.INPUT_PACKET_TCP.copy()
        in_packet[TCP].sport = 0xab12
        f5.val.sport = in_packet[TCP].sport
        f5.mask.sport = 0xffff
        k5.append(f5)
        key_list.append((k5, in_packet))

        k6 = []
        f6 = sdk.la_acl_field()
        f6.type = sdk.la_acl_field_type_e_DPORT
        in_packet = self.INPUT_PACKET_TCP_SVI.copy() if is_svi else self.INPUT_PACKET_TCP.copy()
        in_packet[TCP].dport = 0xfa34
        f6.val.dport = in_packet[TCP].dport
        f6.mask.dport = 0xffff
        k6.append(f6)
        key_list.append((k6, in_packet))

        k7 = []
        f7 = sdk.la_acl_field()
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        f7.type = sdk.la_acl_field_type_e_IPV4_LENGTH
        f7.val.ipv4_length = len(in_packet[IP])
        f7.mask.ipv4_length = 0x0ffff
        k7.append(f7)
        f7b = sdk.la_acl_field()
        f7b.type = sdk.la_acl_field_type_e_TOS
        f7b.val.tos.fields.dscp = 0x33
        f7b.mask.tos.fields.dscp = 0x3f
        k7.append(f7b)
        in_packet[IP].tos = 0xcc
        key_list.append((k7, in_packet))

        k8 = []
        f8 = sdk.la_acl_field()
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        f8.type = sdk.la_acl_field_type_e_TTL
        f8.val.ttl = 0xf
        f8.mask.ttl = 0xff
        in_packet[IP].ttl = 0xf
        k8.append(f8)
        f8b = sdk.la_acl_field()
        f8b.type = sdk.la_acl_field_type_e_TOS
        f8b.val.tos.fields.dscp = 0x33
        f8b.mask.tos.fields.dscp = 0x3f
        k8.append(f8b)
        in_packet[IP].tos = 0xcc
        key_list.append((k8, in_packet))

        k9 = []
        f9 = sdk.la_acl_field()
        f9.type = sdk.la_acl_field_type_e_SRC_PCL_BINCODE
        f9.val.src_pcl_bincode = self.SBINCODE
        f9.mask.src_pcl_bincode = 0x7ffff
        k9.append(f9)
        f9b = sdk.la_acl_field()
        f9b.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
        f9b.val.dst_pcl_bincode = self.DBINCODE
        f9b.mask.dst_pcl_bincode = 0x7ffff
        k9.append(f9b)
        f9c = sdk.la_acl_field()
        f9c.type = sdk.la_acl_field_type_e_TOS
        f9c.val.tos.fields.dscp = 0x11
        f9c.mask.tos.fields.dscp = 0x3f
        k9.append(f9c)
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        in_packet[IP].tos = 0x44
        key_list.append((k9, in_packet))

        k10 = []
        f10 = sdk.la_acl_field()
        in_packet = self.INPUT_PACKET_SVI.copy() if is_svi else self.INPUT_PACKET.copy()
        f10.type = sdk.la_acl_field_type_e_IPV4_FRAG_OFFSET
        f10.val.ipv4_fragment.fields.frag_offset = 0xeee
        f10.mask.ipv4_fragment.fields.frag_offset = 0xffff
        in_packet[IP].frag = 0xeee
        k10.append(f10)
        f10b = sdk.la_acl_field()
        f10b.type = sdk.la_acl_field_type_e_TOS
        f10b.val.tos.fields.dscp = 0x22
        f10b.mask.tos.fields.dscp = 0x3f
        k10.append(f10b)
        in_packet[IP].tos = 0x88
        key_list.append((k10, in_packet))
        return key_list

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_fields_og_acl(self):
        # Normal port
        self._test_ipv4_fields_og_acl()

        # SVI port
        self._test_ipv4_fields_og_acl(True)

    def _test_ipv4_fields_og_acl(self, is_svi=False):
        if (is_svi):
            self.delete_default_route()
            self.add_default_route(is_svi)

        l3_port = self.topology.rx_svi.hld_obj if is_svi else self.topology.rx_l3_ac.hld_obj
        acl1 = self.create_simple_sec_acl(True, is_svi)

        for key_list_num in range(2):
            # Test default route
            self.do_test_route_default(is_svi)
            ipv4_acls = []
            ipv4_acls.append(acl1)
            acl_group = []
            acl_group = self.device.create_acl_group()
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
            l3_port.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
            self.do_test_route_default_with_acl(is_svi)

            if key_list_num == 0:
                key_list = self.configure_key_list1(is_svi)
            else:
                key_list = self.configure_key_list2(is_svi)

            # For every tuple of key-packet in the list
            for key_packet in key_list:
                self.verify_key_packet_acl(acl1, key_packet[0], key_packet[1], is_svi)

            # Detach ACL
            l3_port.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

            # Test default route
            self.do_test_route_default(is_svi)

    # change TEST_MAX_PCL_ID to reflect the real supported max pcl id
    # when CSCvx70714 is fixed
    def test_ipv4_pcl_max(self):
        # create max number of PCLs
        for idx in range(0, TEST_MAX_PCL_ID):
            src_pcl = self.create_src_pcl()

        # exceed the limit by creating one more
        with self.assertRaises(sdk.ResourceException):
            src_pcl2 = self.create_src_pcl()


if __name__ == '__main__':
    unittest.main()
