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
from pfc_base import *
import unittest
import decor
from pfc_local import *
import nplapicli


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class ipv4_pfc(pfc_local, pfc_base, pfc_common):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pfc(self):
        self.init_common()
        # Add an entry in the congestion table
        self.set_pfc_congestion_table(DEST_VALUE_REMOTE, TC_VALUE, True, self.s_rx_slice)

        npu_host_dest = sdk.la_get_destination_id_from_gid(sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP, NPUH_SP_GID)
        self.inject_down_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=1, type=Ethertype.Inject.value) / \
            InjectDown(dest=npu_host_dest, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            NPU_host_ext(first_npe_macro_id=nplapicli.NPL_PFC_AA_RECEIVE_MACRO,
                         first_fi_macro_id=nplapicli.NPL_FI_MACRO_ID_OAMP,
                         ether_type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_NPUH,
                 code=0,
                 source_sp=self.s_sys_p1_gid,
                 source_lp=T.RX_L3_AC_GID, destination_lp=self.destination_remote,
                 relay_id=T.VRF_GID, lpts_flow_type=0, time_stamp=0x1234) / \
            self.INPUT_TEST_PACKET

        # This path tests inject from the recycle path - RxPP - TxPP - NPUhost - RxPP - TxPP - PFC packet
        run_and_compare(
            self,
            self.device,
            self.inject_down_packet,
            self.PI_SLICE,
            self.PI_IFG,
            self.PI_PIF_FIRST,
            self.pfc_packet,
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_first_serdes_p1,
            Ether)


if __name__ == '__main__':
    unittest.main()
