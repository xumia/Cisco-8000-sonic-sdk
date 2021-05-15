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

import sys
import unittest
from leaba import sdk
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *

IN_SLICE = T.get_device_slice(1)
IN_IFG = T.get_device_ifg(0)
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
VLAN = 0xAB9
SYS_PORT_GID_BASE = 23

# QoS remarking
# Ingress QoS fields
# Terminated headers
IN_PCPDEI = sdk.la_vlan_pcpdei()
IN_PCPDEI.fields.pcp = 2
IN_PCPDEI.fields.dei = 1

# Forwarding headers
IN_DSCP = sdk.la_ip_dscp()
IN_DSCP.value = 48

# Intermediate tags
TAG_IP_DSCP = sdk.la_ip_dscp()
TAG_IP_DSCP.value = 60

# Conditional markdown DSCP
MARKDOWN_DSCP = sdk.la_ip_dscp()
MARKDOWN_DSCP.value = 3

# Egress QoS fields
# Forwarding headers
OUT_DSCP = sdk.la_ip_dscp()
OUT_DSCP.value = 63

# Encapsulating headers
OUT_PCPDEI = sdk.la_vlan_pcpdei()
OUT_PCPDEI.fields.pcp = 5
OUT_PCPDEI.fields.dei = 1

# IP ECN field
IP_ECN = 2


class meter_getters_base(sdk_test_case_base):

    meter_profile_types = [sdk.la_meter_profile.type_e_GLOBAL, sdk.la_meter_profile.type_e_PER_IFG]
    meter_profile_measure_modes = [
        sdk.la_meter_profile.meter_measure_mode_e_BYTES,
        sdk.la_meter_profile.meter_measure_mode_e_PACKETS]
    meter_profile_rate_modes = [
        sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
        sdk.la_meter_profile.meter_rate_mode_e_TR_TCM]
    meter_profile_aware_modes = [
        sdk.la_meter_profile.color_awareness_mode_e_BLIND,
        sdk.la_meter_profile.color_awareness_mode_e_AWARE]

    meter_set_coupling_mode = [
        sdk.la_meter_set.coupling_mode_e_NOT_COUPLED,
        sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET]

    meter_set_types = [
        sdk.la_meter_set.type_e_EXACT,
        sdk.la_meter_set.type_e_PER_IFG_EXACT,
        sdk.la_meter_set.type_e_STATISTICAL]

    MIN_CBS = 1024
    MIN_EBS = 1024

    DEFAULT_BURST_SIZE = 0
    BURST_SIZE = MIN_CBS

    # Colors
    COLOR_LST = [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_RED]

    def _test_meter_markdown_mapping_dscp(self):
        # Configure meter markdown profile tables
        meter_markdown_gid = 0
        for profile in range(0, sdk.LA_NUM_METER_MARKDOWN_PROFILES):
            meter_markdown_profile = self.device.create_meter_markdown_profile(meter_markdown_gid)
            meter_markdown_gid += 1
            for color in self.COLOR_LST:
                for dscp in range(0, 64):
                    from_dscp_tag = sdk.la_ip_dscp()
                    from_dscp_tag.value = dscp
                    to_dscp_tag = sdk.la_ip_dscp()
                    to_dscp_tag.value = 63 - dscp
                    meter_markdown_profile.set_meter_markdown_mapping_dscp(
                        color, from_dscp_tag, to_dscp_tag)
                    dscp_tag = meter_markdown_profile.get_meter_markdown_mapping_dscp(
                        color, from_dscp_tag)
                    self.assertEqual(to_dscp_tag.value, dscp_tag.value)

        # Clean-up meter markdown profile tables
        meter_markdown_gid = 0
        for profile in range(0, sdk.LA_NUM_METER_MARKDOWN_PROFILES):
            meter_markdown_profile = self.device.get_meter_markdown_profile_by_id(meter_markdown_gid)
            meter_markdown_gid += 1
            self.device.destroy(meter_markdown_profile)

    def _test_meter_markdown_mapping_pcpdei(self):
        # Configure meter markdown profile tables
        meter_markdown_gid = 0
        for profile in range(0, sdk.LA_NUM_METER_MARKDOWN_PROFILES):
            meter_markdown_profile = self.device.create_meter_markdown_profile(meter_markdown_gid)
            meter_markdown_gid += 1
            for color in self.COLOR_LST:
                for dei in range(0, 2):
                    for pcp in range(0, 8):
                        from_pcpdei_tag = sdk.la_vlan_pcpdei()
                        from_pcpdei_tag.fields.pcp = pcp
                        from_pcpdei_tag.fields.dei = dei
                        to_pcpdei_tag = sdk.la_vlan_pcpdei()
                        to_pcpdei_tag.fields.pcp = 7 - pcp
                        to_pcpdei_tag.fields.dei = dei
                        meter_markdown_profile.set_meter_markdown_mapping_pcpdei(
                            color, from_pcpdei_tag, to_pcpdei_tag)
                        pcpdei_tag = meter_markdown_profile.get_meter_markdown_mapping_pcpdei(
                            color, from_pcpdei_tag)
                        self.assertEqual(to_pcpdei_tag.fields.pcp, pcpdei_tag.fields.pcp)
                        self.assertEqual(to_pcpdei_tag.fields.dei, pcpdei_tag.fields.dei)

        # Clean-up meter markdown profile tables
        meter_markdown_gid = 0
        for profile in range(0, sdk.LA_NUM_METER_MARKDOWN_PROFILES):
            meter_markdown_profile = self.device.get_meter_markdown_profile_by_id(meter_markdown_gid)
            meter_markdown_gid += 1
            self.device.destroy(meter_markdown_profile)

    def _test_meter_markdown_mapping_mpls_tc(self):
        # Configure meter markdown profile tables
        meter_markdown_gid = 0
        for profile in range(0, sdk.LA_NUM_METER_MARKDOWN_PROFILES):
            meter_markdown_profile = self.device.create_meter_markdown_profile(meter_markdown_gid)
            meter_markdown_gid += 1
            for color in self.COLOR_LST:
                for mpls_tc in range(0, 8):
                    from_mpls_tc_tag = sdk.la_mpls_tc()
                    from_mpls_tc_tag.value = mpls_tc
                    to_mpls_tc_tag = sdk.la_mpls_tc()
                    to_mpls_tc_tag.value = 7 - mpls_tc
                    meter_markdown_profile.set_meter_markdown_mapping_mpls_tc(
                        color, from_mpls_tc_tag, to_mpls_tc_tag)
                    mpls_tc_tag = meter_markdown_profile.get_meter_markdown_mapping_mpls_tc(
                        color, from_mpls_tc_tag)
                    self.assertEqual(to_mpls_tc_tag.value, mpls_tc_tag.value)
                    meter_markdown_profile.set_meter_markdown_mapping_mpls_tc_encap(
                        color, from_mpls_tc_tag, to_mpls_tc_tag)
                    mpls_tc_tag = meter_markdown_profile.get_meter_markdown_mapping_mpls_tc_encap(
                        color, from_mpls_tc_tag)
                    self.assertEqual(to_mpls_tc_tag.value, mpls_tc_tag.value)

        # Clean-up meter markdown profile tables
        meter_markdown_gid = 0
        for profile in range(0, sdk.LA_NUM_METER_MARKDOWN_PROFILES):
            meter_markdown_profile = self.device.get_meter_markdown_profile_by_id(meter_markdown_gid)
            meter_markdown_gid += 1
            self.device.destroy(meter_markdown_profile)

    def _test_meter_markdown_mapping_dscp_ext(self):
        # self.device.nsim_provider.set_logging(True)

        # Get the topology-assigned default ingress/egress qos profiles
        ingress_qos_profile_def = self.topology.ingress_qos_profile_def
        egress_qos_profile_def = self.topology.egress_qos_profile_def

        # Create new ingress/egress qos profiles
        ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)
        egress_qos_profile_new = T.egress_qos_profile(self, self.device)

        # Prepare remarking of IN_DSCP -> OUT_DSCP
        encap_qos_values_new = sdk.encapsulating_headers_qos_values()
        encap_qos_values_new.pcpdei = OUT_PCPDEI

        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, IN_DSCP, TAG_IP_DSCP)
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, IN_DSCP, TAG_IP_DSCP)

        # Assign new profiles
        rx_port = self.l3_port_impl.rx_one_tag_port
        rx_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile_new.hld_obj)

        tx_port = self.l3_port_impl.tx_port
        tx_port.hld_obj.set_egress_qos_profile(egress_qos_profile_new.hld_obj)

        # Conditional remarking
        meter_markdown_gid = 0
        for profile in range(0, 1):
            meter_markdown_profile = self.device.create_meter_markdown_profile(meter_markdown_gid)
            meter_markdown_gid += 1
            for color in self.COLOR_LST:
                ingress_qos_profile_new.hld_obj.set_color_mapping(sdk.la_ip_version_e_IPV4, IN_DSCP, color)
                ingress_qos_profile_new.hld_obj.set_color_mapping(sdk.la_ip_version_e_IPV6, IN_DSCP, color)
                for dscp in range(0, 64):
                    from_dscp_tag = sdk.la_ip_dscp()
                    from_dscp_tag.value = dscp
                    to_dscp_tag = sdk.la_ip_dscp()
                    to_dscp_tag.value = 63 - dscp
                    meter_markdown_profile.set_meter_markdown_mapping_dscp(
                        color, from_dscp_tag, to_dscp_tag)
                    dscp_tag = meter_markdown_profile.get_meter_markdown_mapping_dscp(
                        color, from_dscp_tag)
                    self.assertEqual(to_dscp_tag.value, dscp_tag.value)

                # Program meter profile selection table
                ingress_qos_profile_new.hld_obj.set_meter_markdown_profile(meter_markdown_profile)
                meter_markdown_profile_new = ingress_qos_profile_new.hld_obj.get_meter_markdown_profile()
                self.assertEqual(meter_markdown_profile.this, meter_markdown_profile_new.this)

                # Egress remarking
                egress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(MARKDOWN_DSCP,
                                                                        OUT_DSCP, encap_qos_values_new)

                # Test a packet using the QoS mapping
                self.route_single_fec()

        # Cleanup
        # Assign the previous profiles, in order to "un-use" the new ones.
        ingress_qos_profile_new.hld_obj.clear_meter_markdown_profile()
        self.device.destroy(meter_markdown_profile)
        rx_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile_def.hld_obj)
        tx_port.hld_obj.set_egress_qos_profile(egress_qos_profile_def.hld_obj)
        ingress_qos_profile_new.destroy()
        egress_qos_profile_new.destroy()
