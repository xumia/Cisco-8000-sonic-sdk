#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
import sim_utils
import warm_boot_test_utils as wb
import ip_test_base
import os
import decor

SA = T.mac_addr('be:ef:5d:35:7a:35')
SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')
PRIVATE_DATA = 0x1234567890abcdef
TTL = 128


wb.support_warm_boot()
wb.enable_leaba_kernel_module_reload()


@unittest.skipIf(decor.is_hw_asic3(), "WB is not supported on GR-HW")
class warm_boot_l3_ac_routing_kernel_module_reload(sdk_test_case_base):

    @unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
    @unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
    @unittest.skipUnless(decor.is_set_leaba_kernel_module_path(), "Env variable LEABA_KERNEL_MODULE_PATH is not set!")
    @unittest.skipIf(decor.is_pacific(), "WB is not supported on PAC")
    @unittest.skipIf(decor.is_asic4(), "WB is not supported on PL")
    @unittest.skipIf(decor.is_asic3(), "WB is not supported on GR")
    @unittest.skipIf(decor.is_asic5(), "WB is not supported on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Disabled because of problems with resetting packet-DMA on Blacktip")
    def test_warm_boot_l3_ac_routing_kernel_module_reload(self):
        l3_port_impl_class = T.ip_l3_ac_base
        l3_port_impl = l3_port_impl_class(self.topology)

        ip_impl = ip_test_base.ipv4_test_base
        subnet = ip_impl.build_prefix(DIP, length=16)

        # wb.warm_boot(self.device.device)
        ip_impl.add_subnet(l3_port_impl.tx_port, subnet)
        # wb.warm_boot(self.device.device)
        ip_impl.add_host(l3_port_impl.tx_port, DIP, l3_port_impl.reg_nh.mac_addr)

        input_packet_base = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str)

        output_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str)

        input_packet, output_packet = U.pad_input_and_output_packets(input_packet_base, output_packet_base)

        for i in range(5):
            if i != 0:
                wb.warm_boot(self.device.device)

            ttl = TTL - 2 * i
            input_packet[S.IP].ttl = ttl
            output_packet[S.IP].ttl = ttl - 1

            U.run_and_compare(
                self,
                self.device,
                input_packet,
                T.RX_SLICE,
                T.RX_IFG,
                T.FIRST_SERDES,
                output_packet,
                T.TX_SLICE_REG,
                T.TX_IFG_REG,
                l3_port_impl.serdes_reg)


if __name__ == '__main__':
    unittest.main()
