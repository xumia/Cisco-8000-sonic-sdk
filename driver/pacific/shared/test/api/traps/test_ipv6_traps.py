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


from ipv6_traps_base import *
import unittest
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv6_traps(ipv6_traps_base):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_empty_payload(self):
        sip = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
        dip = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
        input_packet = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=sip.addr_str, dst=dip.addr_str, hlim=self.TTL)

        self.do_test_legall_packet(input_packet)

    # These depend on FI programming to identify upper 16 bits as zeros, which has been removed.
    #
    # @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    # def test_ipv6_sip_0(self):
    #     sip = T.ipv6_addr('0000:0000:0000:0000:0000:0000:0000:0000')
    #     self.do_test_legall_sip_drop(sip)

    # @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    # def test_ipv6_sip_1(self):
    #     sip = T.ipv6_addr('0000:0000:0000:0000:0000:0000:0000:0001')
    #     self.do_test_legall_sip_drop(sip)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_sip_mc(self):
        sip = T.ipv6_addr('ff00:0000:0000:0000:0000:0000:0000:0001')
        self.do_test_legall_sip_drop(sip)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_ttl_0(self):
        self.do_test_ttl_drop()


if __name__ == '__main__':
    unittest.main()
