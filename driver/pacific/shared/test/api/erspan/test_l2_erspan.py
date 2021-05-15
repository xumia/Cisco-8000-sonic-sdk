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

from l2_erspan_base import *
import decor

OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_first_serdes(8)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_l2_erspan(l2_erspan_base):

    def test_erspan(self):
        self.create_l2_topology()
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.span_packet_data])
        mirror_cmd, is_acl_conditioned = self.ac_port1.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.mirror_cmd.hld_obj.get_gid())
        self.assertFalse(is_acl_conditioned)

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.mirror_cmd.hld_obj.set_counter(None)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.ac_port1.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=False)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])

        self.ac_port1.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_l2_muticast_erspan(self):
        self.create_l2_muticast_topology()
        self._test_l2_multicast_erspan()


if __name__ == '__main__':
    unittest.main()
