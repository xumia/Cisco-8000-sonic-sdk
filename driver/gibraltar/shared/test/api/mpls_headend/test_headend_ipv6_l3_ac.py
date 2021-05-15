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

from mpls_headend.mpls_headend_ipv6_l3_ac_base import *
import sim_utils
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac(mpls_headend_ipv6_l3_ac_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_prefix_nh_to_ip(self):
        self._test_ecmp_prefix_nh_to_ip_setup()
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_prefix_nh_to_ip_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_prefix_nh_to_mpls(self):
        self._test_ecmp_prefix_nh_to_mpls_setup()
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_prefix_nh_to_mpls_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_tenh_to_mpls(self):
        self._test_ecmp_tenh_to_mpls_setup()
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.te_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_tenh_to_mpls_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fec_prefix_nh_to_ip(self):
        self._test_fec_prefix_nh_to_ip_setup()
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.fec.hld_obj, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_fec_prefix_nh_to_ip_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fec_prefix_nh_to_mpls(self):
        self._test_fec_prefix_nh_to_mpls_setup()
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.fec.hld_obj, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_fec_prefix_nh_to_mpls_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ip6pe_ecmp_prefix_nh_to_mpls(self):
        self._test_ip6pe_ecmp_prefix_nh_to_mpls_setup()
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ip6pe_ecmp_prefix_nh_to_mpls_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ip6pe_ecmp_prefix_tenh_to_mpls(self):
        self._test_ip6pe_ecmp_prefix_tenh_to_mpls_setup()
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ip6pe_ecmp_prefix_tenh_to_mpls_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ip6pe_fec_prefix_nh_to_mpls(self):
        self._test_ip6pe_fec_prefix_nh_to_mpls_setup()
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.fec.hld_obj, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ip6pe_fec_prefix_nh_to_mpls_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_2(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_2()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_3(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_3()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_3_no_explicit_null(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_3(add_lsp_counter=False, v6_explicit_null=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_4(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_4()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_4_lsp_counter(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_4(False, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_4_both_counter(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_4(True, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_8(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_8()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_ip(self):
        self._test_prefix_ecmp_tenh_to_ip()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls(self):
        self._test_prefix_ecmp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label(is_v4 = False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label_4(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label_4(is_v4 = False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_3_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_3_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_4_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_4_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_5_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_5_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_6_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_6_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_7_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_7_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_8_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_8_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_to_ip(self):
        self._test_prefix_ecmp_to_ip()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_to_mpls(self):
        self._test_prefix_ecmp_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_to_mpls(self):
        self._test_prefix_global_ecmp_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_per_protocol_counters(self):
        self._test_sr_global_per_protocol_counters(sdk.la_mpls_sr_protocol_counter_e_IP_UC)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_update_destination(self):
        self._test_prefix_global_ecmp_update_destination()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_error_handling(self):
        self._test_prefix_global_error_handling()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_with_exp_null_config(self):
        self._test_sr_global_with_exp_null_config()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ldp_tenh_to_mpls(self):
        self._test_prefix_ldp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ldp_tenh_to_mpls_te_impl_null(self):
        self._test_prefix_ldp_tenh_to_mpls_te_impl_null()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_ip(self):
        self._test_prefix_nh_to_ip()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_ip_uniform(self):
        self._test_prefix_nh_to_ip_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_mpls(self):
        self._test_prefix_nh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_mpls_uniform(self):
        self._test_prefix_nh_to_mpls_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_mpls_update_label(self):
        self._test_prefix_nh_to_mpls_update_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_tenh_to_ip(self):
        self._test_prefix_tenh_to_ip()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_tenh_to_mpls(self):
        self._test_prefix_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_ecmp_ldp_tenh_to_mpls(self):
        self._test_swap_ecmp_ldp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_ecmp_ldp_tenh_to_mpls_double_label(self):
        self._test_swap_ecmp_ldp_tenh_to_mpls_double_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_with_vlan_ecmp_ldp_tenh_to_mpls(self):
        self._test_swap_with_vlan_ecmp_ldp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_no_ldp(self):
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(is_v4=False, enable_ldp=False, add_lsp_counter=True)
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_with_ldp(self):
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(is_v4=False, enable_ldp=True, add_lsp_counter=True)
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_ip_ecmp_dpe_ecmp_implicit_null_asbr_lsp_to_mpls_with_ldp(self):
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(
            is_v4=False, enable_ldp=True, add_lsp_counter=True, asbr_labels_null=True)
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=True, asbr_labels_null=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_dpe_vpn_properties(self):
        self._test_bgp_lu_dpe_vpn_properties()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_object_vpn_properties(self):
        self._test_prefix_object_vpn_properties()


if __name__ == '__main__':
    unittest.main()
