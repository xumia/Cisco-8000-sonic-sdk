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

# Description
#
#-----------
# Egress profile based remarking for DSCP


from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import scapy.all as S
import packet_test_utils as U
import ip_test_base
from sdk_test_case_base import *
import decor

# Helper class


SLICE = T.get_device_slice(3)
IFG = 0

FIRST_SERDES1 = T.get_device_first_serdes(4)
LAST_SERDES1 = T.get_device_last_serdes(5)

IN_DSCP_VAL = 0
OUT_DSCP_VAL = 8
OUT_TOS = (OUT_DSCP_VAL << 2)

VRF_GID = 0x2bc if not decor.is_gibraltar() else 0xabc


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_l3_ac_on_spa(sdk_test_case_base):

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=SA.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1, tos=OUT_TOS)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_port_on_spa(self):

        # MATILDA_SAVE -- need review
        global SLICE
        SLICE = T.choose_active_slices(self.device, SLICE, [1, 3, 4])
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            SLICE,
            IFG,
            FIRST_SERDES1,
            LAST_SERDES1)
        sys_port_member_1 = T.system_port(self, self.device, 100, mac_port_member_1)

        mac_port_member_1.activate()

        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(sys_port_member_1)
        vrf = T.vrf(self, self.device, VRF_GID)

        # Update QoS Profile
        IN_DSCP = sdk.la_ip_dscp()
        IN_DSCP.value = IN_DSCP_VAL
        OUT_DSCP = sdk.la_ip_dscp()
        OUT_DSCP.value = OUT_DSCP_VAL

        # Encapsulating headers. Dummy. Egress is Untagged. Still Needed by API's :(
        OUT_PCPDEI = sdk.la_vlan_pcpdei()
        OUT_PCPDEI.fields.pcp = 3
        OUT_PCPDEI.fields.dei = 1
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        encap_qos_values.pcpdei = OUT_PCPDEI

        egress_qos_profile_def = self.topology.egress_qos_profile_def
        egress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(IN_DSCP, OUT_DSCP, encap_qos_values)

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        l3_ac = T.l3_ac_port(
            self,
            self.device,
            T.TX_L3_AC_REG_SPA_GID,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC)

        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        # add route
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(self.DIP.to_num(), 16)
        prefix.length = 16
        vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj, self.PRIVATE_DATA, False)

        # send packet SPA New member -> DEF NH
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE, IFG, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        l3_ac.destroy()
        eth_port.destroy()


if __name__ == '__main__':
    unittest.main()
