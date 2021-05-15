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

import sys
import unittest
from enum import Enum
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
import packet_test_defs as P
import ip_test_base
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU
from gre.test_gre_qos_mpls_base import *
import decor

S.load_contrib('mpls')


class qos_mode(Enum):
    Default = 1
    QoS_Marking = 2
    QoS_ACL = 3


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_gre_qos_mpls_ipv6(test_gre_qos_mpls_base):

    protocol = sdk.la_l3_protocol_e_IPV6_UC

    OVL_DIP_ROUTE = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:0000')
    OVL_SIP_ROUTE = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:0000')

    OVL_IP_PACKET_DIP = '1111:0db8:0a0b:12f0:0000:0000:0000:1111'
    OVL_IP_PACKET_SIP = '2222:0db8:0a0b:12f0:0000:0000:0000:2222'

    GRE_HEADER = S.GRE(proto=0x86DD)

    GRE_MPLS_DECAP_TERM_INPUT = S.IPv6(dst=OVL_IP_PACKET_SIP,
                                       src=OVL_IP_PACKET_DIP,
                                       hlim=test_gre_qos_mpls_base.OVL_IP_TTL, plen=40)
    GRE_MPLS_ENCAP_TERM_INPUT = S.IPv6(dst=OVL_IP_PACKET_DIP,
                                       src=OVL_IP_PACKET_SIP,
                                       hlim=test_gre_qos_mpls_base.OVL_IP_TTL, plen=40)

    GRE_MPLS_DECAP_TERM_OUT_PIPE = S.IPv6(dst=OVL_IP_PACKET_SIP,
                                          src=OVL_IP_PACKET_DIP,
                                          hlim=test_gre_qos_mpls_base.OVL_IP_TTL - 1, plen=40)

    GRE_MPLS_DECAP_TERM_OUT_UNIFORM = S.IPv6(dst=OVL_IP_PACKET_SIP,
                                             src=OVL_IP_PACKET_DIP,
                                             hlim=test_gre_qos_mpls_base.IP_TTL - 1, plen=40)

    GRE_MPLS_DECAP_PHP_PIPE_ZERO_TC = S.IPv6(dst=OVL_IP_PACKET_SIP,
                                             src=OVL_IP_PACKET_DIP,
                                             hlim=test_gre_qos_mpls_base.MPLS_TTL - 1,
                                             plen=40,
                                             tc=0)

    GRE_MPLS_DECAP_PHP_PIPE_DSCP_TC = S.IPv6(dst=OVL_IP_PACKET_SIP,
                                             src=OVL_IP_PACKET_DIP,
                                             hlim=test_gre_qos_mpls_base.MPLS_TTL - 1,
                                             plen=40,
                                             tc=test_gre_qos_mpls_base.OUT_TOS.flat)

    GRE_MPLS_DECAP_PHP_PIPE_PIPE_ZERO_TC = S.IPv6(dst=OVL_IP_PACKET_SIP,
                                                  src=OVL_IP_PACKET_DIP,
                                                  hlim=test_gre_qos_mpls_base.OVL_IP_TTL,
                                                  plen=40,
                                                  tc=0)

    GRE_MPLS_DECAP_PHP_PIPE_PIPE_DSCP_TC = S.IPv6(dst=OVL_IP_PACKET_SIP,
                                                  src=OVL_IP_PACKET_DIP,
                                                  hlim=test_gre_qos_mpls_base.OVL_IP_TTL,
                                                  plen=40,
                                                  tc=test_gre_qos_mpls_base.OUT_TOS.flat)

    GRE_MPLS_DECAP_PHP_UNIFORM_ZERO_TC = S.IPv6(dst=OVL_IP_PACKET_SIP,
                                                src=OVL_IP_PACKET_DIP,
                                                hlim=test_gre_qos_mpls_base.IP_TTL - 1,
                                                plen=40,
                                                tc=0)

    GRE_MPLS_DECAP_PHP_UNIFORM_DSCP_TC = S.IPv6(dst=OVL_IP_PACKET_SIP,
                                                src=OVL_IP_PACKET_DIP,
                                                hlim=test_gre_qos_mpls_base.IP_TTL - 1,
                                                plen=40,
                                                tc=test_gre_qos_mpls_base.OUT_TOS.flat)

    EXPLICIT_NULL_LABEL = sdk.la_mpls_label()
    EXPLICIT_NULL_LABEL.label = sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6

    MPLS_OVER_GRE_PACKET_BASE = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                src=test_gre_qos_mpls_base.UNL_IP_PACKET_SMAC) / \
        S.IP(dst=test_gre_qos_mpls_base.GRE_SIP.addr_str,
             src=test_gre_qos_mpls_base.GRE_DIP.addr_str,
             id=0,
             flags=2,
             ttl=test_gre_qos_mpls_base.IP_TTL,
             tos=test_gre_qos_mpls_base.IN_TOS.flat) / \
        S.GRE(proto=U.Ethertype.MPLS.value) / \
        MPLS(label=test_gre_qos_mpls_base.DST_LABEL.label,
             ttl=test_gre_qos_mpls_base.MPLS_TTL) / \
        S.IPv6(dst=OVL_IP_PACKET_SIP,
               src=OVL_IP_PACKET_DIP,
               hlim=test_gre_qos_mpls_base.OVL_IP_TTL, plen=40) / \
        S.TCP()

    MPLS_OVER_GRE_PACKET_DOUBLE_LABEL_BASE = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                src=test_gre_qos_mpls_base.UNL_IP_PACKET_SMAC) / \
        S.IP(dst=test_gre_qos_mpls_base.GRE_SIP.addr_str,
             src=test_gre_qos_mpls_base.GRE_DIP.addr_str,
             id=0,
             flags=2,
             ttl=test_gre_qos_mpls_base.IP_TTL,
             tos=test_gre_qos_mpls_base.IN_TOS.flat) / \
        S.GRE(proto=U.Ethertype.MPLS.value) / \
        MPLS(label=test_gre_qos_mpls_base.DST_LABEL.label,
             ttl=test_gre_qos_mpls_base.MPLS_TTL - 2,
             s=0) / \
        MPLS(label=test_gre_qos_mpls_base.DST_LABEL1.label,
             ttl=test_gre_qos_mpls_base.MPLS_TTL) / \
        S.IPv6(dst=OVL_IP_PACKET_SIP,
               src=OVL_IP_PACKET_DIP,
               hlim=test_gre_qos_mpls_base.OVL_IP_TTL, plen=40) / \
        S.TCP()

    def _test_gre_decap_mpls_route_create(self):
        self.ovl_sip_prefix = self.ipv6_impl.build_prefix(self.OVL_SIP_ROUTE, length=64)
        self.ipv6_impl.add_route(self.topology.vrf,
                                 self.ovl_sip_prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA)

    def _test_gre_decap_mpls_route_delete(self):
        self.ipv6_impl.delete_route(self.topology.vrf, self.ovl_sip_prefix)

    def _test_gre_decap_mpls_encap_add_route(self, pfx_obj):
        self.ovl_sip_prefix = self.ipv6_impl.build_prefix(self.OVL_SIP_ROUTE, length=64)
        self.topology.vrf.hld_obj.add_ipv6_route(
            self.ovl_sip_prefix, pfx_obj.hld_obj, self.PRIVATE_DATA, False)

    def _test_gre_decap_mpls_encap_delete_route(self):
        self.topology.vrf.hld_obj.delete_ipv6_route(self.ovl_sip_prefix)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_swap(self):
        '''
        GRE DECAP followed by MPLS swap
        '''
        self.gre_port_single_path()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        self._test_gre_decap_mpls_swap()

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_swap_uniform(self):
        '''
        GRE DECAP followed by MPLS swap with UNIFORM ttl
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_swap(ttl_pipe_mode=False)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_swap_qos(self):
        '''
        GRE DECAP followed by MPLS swap with QoS Mapping
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_swap(ttl_pipe_mode=False, test_qos=qos_mode.QoS_Marking)

        self._test_gre_decap_mpls_swap(test_qos=qos_mode.QoS_Marking)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_swap_qos_acl(self):
        '''
        GRE DECAP followed by MPLS swap with QoS ACL
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_swap(ttl_pipe_mode=False, test_qos=qos_mode.QoS_ACL)

        self._test_gre_decap_mpls_swap(test_qos=qos_mode.QoS_ACL)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_swap_double_label(self):
        '''
        GRE DECAP followed by MPLS swap double-label
        '''
        self.gre_port_single_path()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        self._test_gre_decap_mpls_swap_double_label()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self._test_gre_decap_mpls_swap_double_label()

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_swap_double_label_uniform(self):
        '''
        GRE DECAP followed by MPLS swap with UNIFORM ttl
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_swap_double_label(ttl_pipe_mode=False)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_swap_double_label_qos(self):
        '''
        GRE DECAP followed by MPLS swap with QoS Mapping
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_swap_double_label(ttl_pipe_mode=False, test_qos=qos_mode.QoS_Marking)

        self._test_gre_decap_mpls_swap_double_label(test_qos=qos_mode.QoS_Marking)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_swap_double_label_qos_acl(self):
        '''
        GRE DECAP followed by MPLS swap with QoS ACL
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_swap_double_label(ttl_pipe_mode=False, test_qos=qos_mode.QoS_ACL)

        self._test_gre_decap_mpls_swap_double_label(test_qos=qos_mode.QoS_ACL)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_php(self):
        '''
        GRE DECAP followed by MPLS php
        '''
        self.gre_port_single_path()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        self._test_gre_decap_mpls_php()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self._test_gre_decap_mpls_php()

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        self._test_gre_decap_mpls_php(ttl_device_pipe_node=True)

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self._test_gre_decap_mpls_php(ttl_device_pipe_node=True)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_php_uniform(self):
        '''
        GRE DECAP followed by MPLS php with UNIFORM ttl
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_php(ttl_pipe_mode=False)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_php_qos(self):
        '''
        GRE DECAP followed by MPLS php with QoS Mapping
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_php(ttl_pipe_mode=False, test_qos=qos_mode.QoS_Marking)

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self._test_gre_decap_mpls_php(ttl_device_pipe_node=True, test_qos=qos_mode.QoS_Marking)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_php_qos_acl(self):
        '''
        GRE DECAP followed by MPLS php with QoS ACL
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_php(ttl_pipe_mode=False, test_qos=qos_mode.QoS_ACL)

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self._test_gre_decap_mpls_php(ttl_device_pipe_node=True, test_qos=qos_mode.QoS_ACL)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_pop_double_label(self):
        '''
        GRE DECAP followed by MPLS pop double label
        '''
        self.gre_port_single_path()

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        self._test_gre_decap_mpls_pop_double_label()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self._test_gre_decap_mpls_pop_double_label()

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_pop_double_label_uniform(self):
        '''
        GRE DECAP followed by MPLS pop double label with UNIFORM ttl
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_pop_double_label(ttl_pipe_mode=False)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_pop_double_label_qos(self):
        '''
        GRE DECAP followed by MPLS pop double label with QoS Mapping
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_pop_double_label(ttl_pipe_mode=False, test_qos=qos_mode.QoS_Marking)

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self._test_gre_decap_mpls_pop_double_label(test_qos=qos_mode.QoS_Marking)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_pop_double_label_qos_acl(self):
        '''
        GRE DECAP followed by MPLS pop double label with QoS ACL
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_pop_double_label(ttl_pipe_mode=False, test_qos=qos_mode.QoS_ACL)

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self._test_gre_decap_mpls_pop_double_label(test_qos=qos_mode.QoS_ACL)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_termination(self):
        '''
        GRE DECAP followed by MPLS termination
        '''
        self.gre_port_single_path()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        self._test_gre_decap_mpls_termination()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self._test_gre_decap_mpls_termination()

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_termination_uniform(self):
        '''
        GRE DECAP followed by MPLS termination with UNIFORM ttl
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_termination(ttl_pipe_mode=False)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_encap(self):
        '''
        GRE DECAP followed by MPLS ENCAP
        '''
        self.gre_port_single_path()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        self._test_gre_decap_mpls_encap()

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self._test_gre_decap_mpls_encap()

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        self._test_gre_decap_mpls_encap(ttl_device_pipe_mode=True)

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self._test_gre_decap_mpls_encap(ttl_device_pipe_mode=True)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_encap_uniform(self):
        '''
        GRE DECAP followed by MPLS ENCAP with UNIFORM ttl
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_encap(ttl_pipe_mode=False)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_encap_qos(self):
        '''
        GRE DECAP followed by MPLS ENCAP with QoS mapping
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_encap(ttl_pipe_mode=False, test_qos=qos_mode.QoS_Marking)

        self._test_gre_decap_mpls_encap(test_qos=qos_mode.QoS_Marking)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_encap_qos_acl(self):
        '''
        GRE DECAP followed by MPLS ENCAP with Qos ACL
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_encap(ttl_pipe_mode=False, test_qos=qos_mode.QoS_ACL)

        self._test_gre_decap_mpls_encap(test_qos=qos_mode.QoS_ACL)

        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mpls_decap_gre_encap_single_path(self):
        '''
        MPLS terminate then GRE ENCAP
        '''
        self.gre_port_single_path()
        self._test_mpls_decap_gre_encap_single_path()
        self.destroy_gre_port_single_path()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mpls_decap_gre_encap_multi_path(self):
        '''
        MPLS terminate then GRE ENCAP ECMP
        '''
        self.gre_port_multi_path()
        self._test_mpls_decap_gre_encap_multi_path()
        self.destroy_gre_port_multi_path()


if __name__ == '__main__':
    unittest.main()
