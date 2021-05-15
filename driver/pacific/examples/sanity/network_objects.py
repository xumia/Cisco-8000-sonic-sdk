#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

###
# Wrapper around HLD network objects
###

import re

from leaba import sdk
from sanity_constants import *

ingress_qos_profile_def = None
egress_qos_profile_def = None
tc_profile_def = None
ac_profile_def = None
mc_voq_sets = None
uc_voq_cgm_profile_def = None
mc_voq_cgm_profile_def = None

VOQ_SET_SIZE = 8


class mac_addr:

    def __init__(self, addr_str):
        self.addr_str = addr_str
        self.hld_obj = sdk.la_mac_addr_t()
        self.hld_obj.flat = self.to_num()

    def to_num(self):
        addr_bytes = self.addr_str.split(':')
        assert(len(addr_bytes) == 6)  # 6 bytes
        for b in addr_bytes:
            assert(len(b) == 2)  # 2 digits for each byte

        hex_str = self.addr_str.replace(':', '')
        n = int(hex_str, 16)

        return n

    @staticmethod
    def to_str(n):
        sn = '%012x' % n
        ssn = re.sub(r'([0-9][0-9])', '\g<1>:', sn)
        s = ssn[:-1]

        return s

    def set_flat(self, n):
        self.hld_obj = sdk.la_mac_addr_t()
        self.hld_obj.flat = n
        self.addr_str = self.to_str(n)


class ipv4_addr:

    NUM_OF_BYTES = 4
    BITS_IN_BYTE = 8

    def __init__(self, addr_str):
        self.addr_str = addr_str
        self.hld_obj = sdk.la_ipv4_addr_t()
        self.hld_obj.s_addr = self.to_num()

    def to_num(self):
        addr_bytes = self.addr_str.split('.')
        assert(len(addr_bytes) == ipv4_addr.NUM_OF_BYTES)
        c = ipv4_addr.NUM_OF_BYTES - 1
        n = 0
        for b in addr_bytes:
            bn = int(b)
            assert(bn < (1 << ipv4_addr.BITS_IN_BYTE))
            n += (1 << ipv4_addr.BITS_IN_BYTE) ** c * bn
            c -= 1

        return n


class ingress_qos_profile:

    def __init__(self, la_dev):

        self.la_dev = la_dev
        profile = self.la_dev.create_ingress_qos_profile()
        profile.set_qos_tag_mapping_enabled(True)
        self.hld_obj = profile

    def set_default_values(self):
        # (PCP,DEI) mapping
        pcpdei = sdk.la_vlan_pcpdei()
        for pcp in range(0, 8):
            for dei in range(0, 2):
                pcpdei.fields.pcp = pcp
                pcpdei.fields.dei = dei
                self.hld_obj.set_qos_tag_mapping_pcpdei(pcpdei, pcpdei)

        # (DSCP) mapping for IPv4
        ip_dscp = sdk.la_ip_dscp()
        for dscp in range(0, 64):
            ip_dscp.value = dscp
            self.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, ip_dscp, ip_dscp)

        # (DSCP) mapping for IPv6
        ip_dscp = sdk.la_ip_dscp()
        for dscp in range(0, 64):
            ip_dscp.value = dscp
            self.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, ip_dscp, ip_dscp)

        # (MPLS_TC) mapping
        mpsl_tc = sdk.la_mpls_tc()
        for tc in range(0, 8):
            mpsl_tc.value = tc
            self.hld_obj.set_qos_tag_mapping_mpls_tc(mpsl_tc, mpsl_tc)

    def destroy(self):
        self.la_dev.destroy(self.hld_obj)
        self.hld_obj = None


class egress_qos_profile:

    def __init__(self, la_dev, marking_source=sdk.la_egress_qos_marking_source_e_QOS_TAG):
        self.la_dev = la_dev
        egress_qos_profile = self.la_dev.create_egress_qos_profile(marking_source)
        self.hld_obj = egress_qos_profile

    def set_default_values(self):
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        # mapping to (PCP,DEI)
        pcpdei = sdk.la_vlan_pcpdei()
        for pcp in range(0, 8):
            for dei in range(0, 2):
                pcpdei.fields.pcp = pcp
                pcpdei.fields.dei = dei
                self.hld_obj.set_qos_tag_mapping_pcpdei(pcpdei, pcpdei, encap_qos_values)

        # mapping to (DSCP)
        ip_dscp = sdk.la_ip_dscp()
        for dscp in range(0, 64):
            ip_dscp.value = dscp
            self.hld_obj.set_qos_tag_mapping_dscp(ip_dscp, ip_dscp, encap_qos_values)

        # mapping to (MPLS_TC)
        mpls_tc = sdk.la_mpls_tc()
        for tc in range(0, 8):
            mpls_tc.value = tc
            self.hld_obj.set_qos_tag_mapping_mpls_tc(mpls_tc, mpls_tc, encap_qos_values)

    def destroy(self):
        self.la_dev.destroy(self.hld_obj)
        self.hld_obj = None


class tc_profile:
    def __init__(self, la_dev):

        self.la_dev = la_dev
        profile = la_dev.create_tc_profile()
        self.hld_obj = profile

    def set_default_values(self):
        for tc in range(8):
            self.hld_obj.set_mapping(tc, tc)

    def destroy(self):
        # NYI       self.la_dev.destroy(self.hld_obj)
        self.hld_obj = None


class ac_profile:

    def __init__(self, la_dev, with_fallback=False):

        self.la_dev = la_dev
        profile = self.la_dev.create_ac_profile()

        # NO VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x0000
        pvf.tpid2 = 0x0000
        profile.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT)

        # PORT VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x8100
        pvf.tpid2 = 0x0000
        profile.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        # PORT VLAN VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x9100
        pvf.tpid2 = 0x8100

        if with_fallback:
            selector = sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN_WITH_FALLBACK
        else:
            selector = sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN

        profile.set_key_selector_per_format(pvf, selector)

        self.hld_obj = profile

    def destroy(self):
        # NYI   self.la_dev.destroy(self.hld_obj)
        pass


def create_default_profiles(la_dev):
    global ingress_qos_profile_def
    global egress_qos_profile_def
    global tc_profile_def
    global ac_profile_def
    global uc_voq_cgm_profile_def
    global mc_voq_cgm_profile_def

    # Default QOS profiles
    ingress_qos_profile_def = ingress_qos_profile(la_dev)
    ingress_qos_profile_def.set_default_values()

    egress_qos_profile_def = egress_qos_profile(la_dev)
    egress_qos_profile_def.set_default_values()

    # Default TC profile
    tc_profile_def = tc_profile(la_dev)
    tc_profile_def.set_default_values()

    # Default AC profile
    ac_profile_def = ac_profile(la_dev)

    # Default VOQ-CGM profile
    uc_voq_cgm_profile_def = la_dev.create_voq_cgm_profile()
    mc_voq_cgm_profile_def = la_dev.create_voq_cgm_profile()


def initialize(la_dev, voq_allocator):
    erm = sdk.get_error_mode()
    sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)
    global mc_voq_sets

    create_default_profiles(la_dev)
    mc_voq_sets = []
    for slice_id in range(ASIC_MAX_SLICES_PER_DEVICE_NUM):
        mc_voq_set = la_dev.get_egress_multicast_slice_replication_voq_set(slice_id)
        for voq in range(mc_voq_set.get_set_size()):
            mc_voq_set.set_cgm_profile(voq, mc_voq_cgm_profile_def)

        mc_voq_sets.append(mc_voq_set)

    sdk.set_error_mode(erm)


def teardown(la_dev):
    erm = sdk.get_error_mode()
    sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)
    global ingress_qos_profile_def
    global egress_qos_profile_def
    global tc_profile_def
    global ac_profile_def
    global mc_voq_sets
    global uc_voq_cgm_profile_def
    global mc_voq_cgm_profile_def

    ingress_qos_profile_def.destroy()
    egress_qos_profile_def.destroy()
    tc_profile_def.destroy()
    ac_profile_def.destroy()

    ingress_qos_profile_def = None
    egress_qos_profile_def = None
    tc_profile_def = None
    ac_profile_def = None
    mc_voq_sets = None
    uc_voq_cgm_profile_def = None
    mc_voq_cgm_profile_def = None

    sdk.set_error_mode(erm)
