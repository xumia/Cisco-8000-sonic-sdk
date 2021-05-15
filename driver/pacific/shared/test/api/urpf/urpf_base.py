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

import sys
import unittest
from leaba import sdk
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
from sdk_test_case_base import *


class urpf_base(sdk_test_case_base):

    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    NH_MAC = T.RX_MAC
    NH_GID = 0x691
    IPv4_ADDRESS_SIZE = T.ipv4_addr.NUM_OF_BYTES
    IPv6_ADDRESS_SIZE = T.ipv6_addr.NUM_OF_BYTES

    def setUp(self):

        self.maxDiff = None  # Show whole strings on failures (unittest variable)
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

    def tearDown(self):
        super().tearDown()

    def get_prefix_length(self, is_em):
        if is_em:
            if self.ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
                length = 128
            if self.ip_impl.BYTES_NUM_IN_ADDR == self.IPv4_ADDRESS_SIZE:
                length = 32
        else:
            length = 16
        return length

    def add_route_to_dest_in_lpm(self):
        dip_prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, dip_prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

    def add_default_route_to_source_in_lpm(self, is_fec):
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length=0)
        if is_fec:
            self.ip_impl.add_route(self.topology.vrf, sip_prefix, self.l3_port_impl.ext_fec, self.PRIVATE_DATA)
        else:
            self.ip_impl.add_route(self.topology.vrf, sip_prefix, self.l3_port_impl.ext_nh, self.PRIVATE_DATA)

    def add_route_to_source(self, is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict):
        if is_fec:
            if is_em:
                self.add_route_to_source_fec(is_em, is_em_strict)
            if is_lpm:
                self.add_route_to_source_fec(False, is_lpm_strict)
        else:
            if is_em:
                self.add_route_to_source_nh(is_em, is_em_strict)
            if is_lpm:
                self.add_route_to_source_nh(False, is_lpm_strict)

    def add_route_to_source_nh(self, is_em, is_strict):
        length = self.get_prefix_length(is_em)
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length)

        if is_strict:
            self.ip_impl.add_route(self.topology.vrf, sip_prefix, self.nh, self.PRIVATE_DATA)
        else:
            self.ip_impl.add_route(self.topology.vrf, sip_prefix, self.l3_port_impl.ext_nh, self.PRIVATE_DATA)

    def add_route_to_source_fec(self, is_em, is_strict):
        length = self.get_prefix_length(is_em)
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length)

        if is_strict:
            self.ip_impl.add_route(self.topology.vrf, sip_prefix, self.fec, self.PRIVATE_DATA)
        else:
            self.ip_impl.add_route(self.topology.vrf, sip_prefix, self.l3_port_impl.ext_fec, self.PRIVATE_DATA)

    def add_route_to_source_glean(self):
        sip_prefix = self.ip_impl.build_prefix(self.SIP, 32)
        self.ip_impl.add_route(self.topology.vrf, sip_prefix, self.l3_port_impl.glean_null_nh, self.PRIVATE_DATA)

    def modify_route_to_source(self, is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict):
        if is_fec:
            if is_em:
                self.modify_route_to_source_fec(True, is_em_strict)
            if is_lpm:
                self.modify_route_to_source_fec(False, is_lpm_strict)
        else:
            if is_em:
                self.modify_route_to_source_nh(True, is_em_strict)
            if is_lpm:
                self.modify_route_to_source_nh(False, is_lpm_strict)

    def modify_route_to_source_nh(self, is_em, is_strict):
        length = self.get_prefix_length(is_em)
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length)

        if is_strict:
            self.ip_impl.modify_route(self.topology.vrf, sip_prefix, self.nh)
        else:
            self.ip_impl.modify_route(self.topology.vrf, sip_prefix, self.l3_port_impl.ext_nh)

    def modify_route_to_source_fec(self, is_em, is_strict):
        length = self.get_prefix_length(is_em)
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length)

        if is_strict:
            self.ip_impl.modify_route(self.topology.vrf, sip_prefix, self.fec)
        else:
            self.ip_impl.modify_route(self.topology.vrf, sip_prefix, self.l3_port_impl.ext_fec)

    def _test_get_urpf_mode(self):
        mode = self.l3_port_impl.rx_port.hld_obj.get_urpf_mode()
        self.assertEqual(mode, sdk.la_l3_port.urpf_mode_e_NONE)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)
        mode = self.l3_port_impl.rx_port.hld_obj.get_urpf_mode()
        self.assertEqual(mode, sdk.la_l3_port.urpf_mode_e_LOOSE)

        # set strict rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_STRICT)
        mode = self.l3_port_impl.rx_port.hld_obj.get_urpf_mode()
        self.assertEqual(mode, sdk.la_l3_port.urpf_mode_e_STRICT)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_no_route_to_sender_rpf_loose(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        # setup a counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Test counter
        packets, bytes = counter.read(0,     # sub-counter index
                                      True,  # force_update
                                      True)  # clear on read
        self.assertEqual(packets, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_no_route_to_sender_rpf_loose_nh(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, self.PRIVATE_DATA)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        # set counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Test counter
        packets, bytes = counter.read(0,     # sub-counter index
                                      True,  # force_update
                                      True)  # clear on read
        self.assertEqual(packets, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_loose_route_to_sender_rpf_loose(self):
        dip_prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, dip_prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # add route to source
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, sip_prefix, self.l3_port_impl.ext_fec, self.PRIVATE_DATA)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, dip_prefix)

        self.ip_impl.delete_route(self.topology.vrf, sip_prefix)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_loose_route_to_sender_rpf_loose_em_prefix(self, is_em,
                                                        is_em_strict, is_lpm, is_lpm_strict, is_fec, default_route_in_lpm):
        self.add_route_to_dest_in_lpm()

        # add route to source
        self.add_route_to_source(is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict)

        if default_route_in_lpm:
            self.add_default_route_to_source_in_lpm(is_fec)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # modify route to source
        self.modify_route_to_source(not is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_loose_route_to_sender_rpf_strict(self):
        dip_prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, dip_prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # add route to source
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, sip_prefix, self.l3_port_impl.ext_fec, self.PRIVATE_DATA)

        # set strict rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_STRICT)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.ip_impl.delete_route(self.topology.vrf, dip_prefix)
        self.ip_impl.delete_route(self.topology.vrf, sip_prefix)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_loose_route_to_sender_rpf_strict_em_prefix(self, is_em,
                                                         is_em_strict, is_lpm, is_lpm_strict, is_fec, default_route_in_lpm):
        self.add_route_to_dest_in_lpm()

        # add route to source
        self.add_route_to_source(is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict)

        if default_route_in_lpm:
            self.add_default_route_to_source_in_lpm(is_fec)

        # set strict rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_STRICT)
        # set counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Test counter
        packets, bytes = counter.read(0,     # sub-counter index
                                      True,  # force update
                                      True)  # clear on read
        self.assertEqual(packets, 1)

        # modify route to source
        self.modify_route_to_source(not is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict)

        # set counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Test counter
        packets, bytes = counter.read(0,     # sub-counter index
                                      True,  # force update
                                      True)  # clear on read
        self.assertEqual(packets, 1)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_no_route_to_sender_rpf_none(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_no_route_to_sender_rpf_strict(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # set strict rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_STRICT)

        # setup counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Test counter
        packets, bytes = counter.read(0,     # sub-counter index
                                      True,  # force update
                                      True)  # clear on read
        self.assertEqual(packets, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_strict_route_to_sender_rpf_loose(self):

        nh = T.next_hop(self, self.device, self.NH_GID, self.NH_MAC, self.l3_port_impl.rx_port)
        fec = T.fec(self, self.device, nh)

        dip_prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, dip_prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # add route to source
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, sip_prefix, fec, self.PRIVATE_DATA)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, dip_prefix)
        self.ip_impl.delete_route(self.topology.vrf, sip_prefix)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_strict_route_to_sender_rpf_loose_em_prefix(self, is_em,
                                                         is_em_strict, is_lpm, is_lpm_strict, is_fec, default_route_in_lpm):

        self.nh = T.next_hop(self, self.device, self.NH_GID, self.NH_MAC, self.l3_port_impl.rx_port)
        self.fec = T.fec(self, self.device, self.nh)
        self.add_route_to_dest_in_lpm()

        # add route to source
        self.add_route_to_source(is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict)

        if default_route_in_lpm:
            self.add_default_route_to_source_in_lpm(is_fec)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # modify route to source
        self.modify_route_to_source(not is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_strict_route_to_sender_rpf_strict(self):

        nh = T.next_hop(self, self.device, self.NH_GID, self.NH_MAC, self.l3_port_impl.rx_port)
        fec = T.fec(self, self.device, nh)

        dip_prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, dip_prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # add route to source
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, sip_prefix, nh, self.PRIVATE_DATA)

        # set strict rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_STRICT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, sip_prefix)
        self.ip_impl.delete_route(self.topology.vrf, dip_prefix)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_strict_route_to_sender_rpf_strict_em_prefix(self, is_em,
                                                          is_em_strict, is_lpm, is_lpm_strict, is_fec, default_route_in_lpm):

        self.nh = T.next_hop(self, self.device, self.NH_GID, self.NH_MAC, self.l3_port_impl.rx_port)
        self.fec = T.fec(self, self.device, self.nh)
        self.add_route_to_dest_in_lpm()

        # add route to source
        self.add_route_to_source(is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict)

        if default_route_in_lpm:
            self.add_default_route_to_source_in_lpm(is_fec)

        # set strict rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_STRICT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # modify route to source
        self.modify_route_to_source(not is_fec, is_em, is_lpm, is_em_strict, is_lpm_strict)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_default_route_to_sender_rpf_loose(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)
        self.topology.vrf.hld_obj.set_urpf_allow_default(True)

        self.add_default_route_to_source_in_lpm(is_fec=False)
        self.topology.vrf.hld_obj.set_urpf_allow_default(False)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        # setup a counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Test counter
        packets, bytes = counter.read(0,     # sub-counter index
                                      True,  # force_update
                                      True)  # clear on read
        self.assertEqual(packets, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_default_route_to_sender_rpf_loose_allow_default(self):
        dip_prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, dip_prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        self.topology.vrf.hld_obj.set_urpf_allow_default(True)
        # add route to source
        self.add_default_route_to_source_in_lpm(is_fec=False)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, dip_prefix)

        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    # RTBH will allow drop with source IP lookup pointing to drop/null with urpf enabled
    def _test_default_route_to_sender_rpf_loose_rtbh(self):
        dip_prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, dip_prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        self.topology.vrf.hld_obj.set_urpf_allow_default(True)
        # add route to source
        self.m_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        # Add 1 members
        self.m_ecmp1.add_member(self.l3_port_impl.ext_nh.hld_obj)
        sip_prefix = self.ip_impl.build_prefix(self.SIP, length=0)
        self.topology.vrf.hld_obj.add_ipv4_route(sip_prefix, self.m_ecmp1, self.PRIVATE_DATA, False)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)
        self.topology.vrf.hld_obj.set_urpf_allow_default(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.topology.vrf.hld_obj.delete_ipv4_route(sip_prefix)
        self.m_ecmp1.remove_member(self.l3_port_impl.ext_nh.hld_obj)
        # Add 2 members
        members = []
        self.l3_port_impl.ext_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_DROP)
        members.append(self.l3_port_impl.def_nh.hld_obj)
        members.append(self.l3_port_impl.ext_nh.hld_obj)
        self.m_ecmp1.set_members(members)
        self.topology.vrf.hld_obj.add_ipv4_route(sip_prefix, self.m_ecmp1, self.PRIVATE_DATA, False)

        # setup a counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Test counter
        packets, bytes = counter.read(0,     # sub-counter index
                                      True,  # force_update
                                      True)  # clear on read
        self.assertEqual(packets, 1)
        self.topology.vrf.hld_obj.delete_ipv4_route(sip_prefix)

        self.m_ecmp1.remove_member(self.l3_port_impl.ext_nh.hld_obj)
        self.topology.vrf.hld_obj.add_ipv4_route(sip_prefix, self.m_ecmp1, self.PRIVATE_DATA, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_for_us_route_to_sender_rpf_loose(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        self.prefix_uc = self.ip_impl.build_prefix(self.SIP, length=24)
        self.ip_impl.add_route(self.topology.vrf, self.prefix_uc,
                               self.topology.forus_dest,
                               self.PRIVATE_DATA)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        # setup a counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Test counter
        packets, bytes = counter.read(0,     # sub-counter index
                                      True,  # force_update
                                      True)  # clear on read
        self.assertEqual(packets, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_NONE)

    def _test_no_route_to_sender_dest_for_us_rpf_loose(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.topology.forus_dest,
                               self.PRIVATE_DATA)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        # setup a counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Test counter
        packets, bytes = counter.read(0,     # sub-counter index
                                      True,  # force_update
                                      True)  # clear on read
        self.assertEqual(packets, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_default_route_to_sender_glean_rpf_loose(self):
        dip_prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, dip_prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        # setup a counter to check trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                                           0, counter, None, False, False, True, 0)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # add route to source
        self.add_route_to_source_glean()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
