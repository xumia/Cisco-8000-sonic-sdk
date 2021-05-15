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
import warm_boot_test_utils as wb
import os
import tempfile
import decor


wb.support_warm_boot()


@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_basic_l2_p2p_sdk_down_kernel_module_up(sdk_test_case_base):

    SA = T.mac_addr('be:ef:5d:35:7a:35')
    DA = T.mac_addr('02:02:02:02:02:02')

    def setUp(self):
        super().setUp()
        self.warm_boot_file_name = wb.get_warm_boot_file_name()

    def tearDown(self):
        if os.path.exists(self.warm_boot_file_name):
            os.remove(self.warm_boot_file_name)

    def test_warm_boot_basic_l2_p2p_sdk_down_kernel_module_up(self):
        # ports
        rx_ac_port = self.topology.rx_l2_ac_port
        tx_ac_port = self.topology.tx_l2_ac_port_reg

        rx_ac_port.hld_obj.detach()
        wb.warm_boot(self.device.device)
        rx_ac_port.hld_obj.set_destination(tx_ac_port.hld_obj)
        wb.warm_boot(self.device.device)

        # create packets
        in_packet_base = S.Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP() / S.TCP()

        out_packet_base = S.Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP() / S.TCP()

        in_packet, out_packet = U.pad_input_and_output_packets(in_packet_base, out_packet_base)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_compare(
            self,
            self.device,
            in_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            out_packet,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            T.FIRST_SERDES_SVI)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)


if __name__ == '__main__':
    unittest.main()
