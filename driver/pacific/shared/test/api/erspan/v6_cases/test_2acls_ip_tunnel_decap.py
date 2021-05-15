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

#from erspan_acl_base import *
from ipv4_l3_ac_erspan_base import *
import decor


# class test_2acls_ip_tunnel_decap(erspan_acl_base):
@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_2acls_ip_tunnel_decap(ipv4_l3_ac_erspan_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_2acls_ip_tunnel_decap1(self):
        self.create_ip_over_ip_tunnel_ports()
        self.add_2_acls(is_drop=True)

        self.topology.rx_l3_ac.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_tunl_packet_data, [self.span_tunl_packet_data])

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        # U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.clear_l3_acls()
        self.destroy_ip_over_ip_tunnel_ports()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_2acls_ip_tunnel_decap2(self):
        self.create_ip_over_ip_tunnel_ports()
        self.add_2_acls(is_drop=False)

        self.topology.rx_l3_ac.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_tunl_packet_data, [self.out_tunl_packet_data, self.span_tunl_packet_data])

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        # U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.clear_l3_acls()
        self.destroy_ip_over_ip_tunnel_ports()


if __name__ == '__main__':
    unittest.main()
