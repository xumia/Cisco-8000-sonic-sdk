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

import decor
from packet_test_utils import *
from scapy.all import *
from punt_inject_port.punt_inject_port_base import *
import unittest
from leaba import sdk
import ip_test_base
import decor
import topology as T


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class inject_up_ptp(punt_inject_port_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_inject_up_ptp(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        dest_id = sdk.la_get_destination_id_from_gid(sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP, OUT_SP_GID)

        inject_packet_base = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectUp(ssp_gid=IN_SP_GID, ts_opcode=1, ts_offset=54) / \
            InjectTimeExt(cpu_time=0x11335577) / \
            Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / UDP(sport=2048, chksum=0) / PTPv2() / PTPSync()

        out_packet_base = Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / UDP(sport=2048, chksum=0) / PTPv2(correction_field=0x1112131415161721) / PTPSync()

        self.inject_packet, self.out_packet = pad_input_and_output_packets(inject_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            self.inject_packet,
            self.IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_PIF_FIRST,
            self.out_packet,
            self.OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        pi_port.destroy()


if __name__ == '__main__':
    unittest.main()
