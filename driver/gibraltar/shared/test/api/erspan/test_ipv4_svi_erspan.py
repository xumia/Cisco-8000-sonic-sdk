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

from ipv4_svi_erspan_base import *
import mtu.mtu_test_utils as MTU
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv4_svi_erspan(ipv4_svi_erspan_base):

    def test_erspan_without_acl(self):
        self._test_erspan_without_acl()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "RTF is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_erspan_without_acl(self):
        self._test_l3_erspan_without_acl()

    def test_multicast_erspan(self):
        self._test_ip_multicast_erspan()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mirroring_with_acl(self):
        self._test_mirroring_with_acl()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mirroring_with_acl_mtu(self):
        self.add_l3_acl()
        self.topology.rx_svi.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)
        self.span_packet_data['ingress_mirror_pi_port_pkt'] = True
        MTU.run_mtu_tests(self, self.device, self.in_packet_data, [self.out_packet_data, self.span_packet_data])
        self.clear_l3_acls()
        self.add_l3_acl(is_mirror=False, is_drop=False)


if __name__ == '__main__':
    unittest.main()
