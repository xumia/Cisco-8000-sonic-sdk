#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from leaba import sdk
try:
    import test_nsim_providercli as nsim
except BaseException:
    import test_packet_provider as nsim
import nplapicli as nplapi
import sim_utils
from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *
from binascii import hexlify, unhexlify
from copy import deepcopy
from enum import Enum
from io import StringIO
import gzip
import json
import lldcli
load_contrib('mpls')
from packet_test_defs import *
import os
import decor

CRC_HEADER_SIZE = 4
MIN_PKT_SIZE_WITHOUT_CRC = 60
PACIFIC_COMPATIBLE_TM_HEADERS_MODE = True
# Fabric load-balancing header - Time-stamp packet-load-balancing


class TS_PLB(Packet):
    name = "TS_PLB"
    header_type_dict = {
        2: "ONE_PKT_TS1",
        3: "TWO_PKT_TS1",
        4: "ONE_PKT_TS3",
        5: "TWO_PKT_TS3",
        # TODO - add rest of formats
    }
    plb_context_dict = {
        0: "UC_H",
        1: "UC_L",
        2: "MC"
    }

    fields_desc = [
        # Common fields
        BitEnumField("header_type", 0, 4, header_type_dict),
        BitField("link_fc", 0, 1),

        # ts_plb_fabric_header_start_t
        BitField("fcn", 0, 1),
        BitEnumField("plb_context", 0, 2, plb_context_dict),

        # Per-type specific fields
        # ONE_PKT_TS1 fields
        ConditionalField(
            BitField("ts1", 0, 24),  # inject_fabric_time
            lambda pkt: pkt.header_type in [2]),

        # ONE_PKT_TS3 fields
        ConditionalField(
            FieldListField("ts3", [0, 0, 0], BitField("ts", 0, 24), count_from=lambda pkt: 3),
            lambda pkt: pkt.header_type in [4]),

        # Common fields
        # ts_plb_fabric_header_body_t
        BitField("src_device", 0, 9),
        BitField("src_slice", 0, 3),

        # The reserved field is used for byte alignment
        # ONE_PKT_TS1
        ConditionalField(
            BitField("reserved", 0, 4),
            lambda pkt: pkt.header_type in [2, 4]),
        # If the header_type is not set to a supported size, then the whole packet
        # is not byte aligned and scapy shouts. So align it.
        ConditionalField(
            BitField("unsupported_reserved", 0, 4),
            lambda pkt: pkt.header_type not in [2, 3, 4, 5]),
    ]


class TM(Packet):
    name = "TM"
    header_type_dict = {
        0: "UUU_DD",    # Used in PLB
        1: "UUU_DSP",   # Used in FLB
        2: "MMM",
        3: "MUM",
    }

    fields_desc = [
        # Common fields
        BitEnumField("header_type", 0, 2, header_type_dict),
        BitField("vce", 0, 1),
        BitField("tc", 0, 3),
        BitField("dp", 0, 2),

        # The reserved field is used for byte alignment
        # UUU_DD
        ConditionalField(
            BitField("reserved", 0, 3),
            lambda pkt: pkt.header_type == 0),
        # UUU_DSP - TODO
        # MMM - no need
        # MUM fields - TODO

        # Per-type specific fields
        # UUU_DD fields
        ConditionalField(
            BitField("dest_device", 0, 9),
            lambda pkt: pkt.header_type == 0),
        ConditionalField(
            BitField("dest_slice", 0, 3),
            lambda pkt: pkt.header_type == 0),
        ConditionalField(
            BitField("dest_oq", 0, 9),
            lambda pkt: pkt.header_type == 0),
        ConditionalField(
            BitField("voq_congestion_level", 0, 8),
            lambda pkt: pkt.header_type == 0 and (decor.is_gibraltar() and not PACIFIC_COMPATIBLE_TM_HEADERS_MODE)),
        # UUU_DSP fields - TODO
        # MMM fields
        ConditionalField(
            BitField("multicast_id", 0, 16),
            lambda pkt: pkt.header_type == 2),
        # MUM fields - TODO
    ]


class NPU_Header(Packet):
    name = "NPU_Header"
    fields_desc = [
        XLongField("unparsed_0", 0),
        XLongField("unparsed_1", 0),
        XLongField("unparsed_2", 0),
        XLongField("unparsed_3", 0),
    ]

# Parametrized header, depends on decoding of previous header


def NPU_Soft_Header_of(byte_length, FwdHeaderType=None):
    class NPU_Soft_Header_type(Packet):
        name = "NPU_Soft_Header_of(byte_length={})".format(byte_length)
        fields_desc = [
            XBitField("unparsed_0", 0, byte_length * 8),
        ]

        def guess_payload_class(self, payload):
            return FwdHeaderType
    bind_layers(NPU_Header_ext, NPU_Soft_Header_type, fwd_offset=NPU_Header_ext.BASE_LENGTH + byte_length)
    return NPU_Soft_Header_type


class NPU_Header_ext(Packet):
    name = "NPU_Header_ext"

    base_type_dict = {
        nplapi.NPL_FABRIC_HEADER_TYPE_NPU_WITH_IVE: "NPU_WITH_IVE",
        nplapi.NPL_FABRIC_HEADER_TYPE_NPU_NO_IVE: "NPU_NO_IVE"
    }

    fwd_header_type_dict = {
        nplapi.NPL_FWD_HEADER_TYPE_ETHERNET: "ETHERNET",
        nplapi.NPL_FWD_HEADER_TYPE_IPV4: "IPV4",
        nplapi.NPL_FWD_HEADER_TYPE_IPV4_COLLAPSED_MC: "IPV4_COLLAPSED_MC",
        nplapi.NPL_FWD_HEADER_TYPE_IPV6: "IPV6",
        nplapi.NPL_FWD_HEADER_TYPE_IPV6_COLLAPSED_MC: "IPV6_COLLAPSED_MC",
        nplapi.NPL_FWD_HEADER_TYPE_MPLS_NO_BOS: "MPLS_NO_BOS",
        nplapi.NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV4: "MPLS_BOS_IPV4",
        nplapi.NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV6: "MPLS_BOS_IPV6",
        nplapi.NPL_FWD_HEADER_TYPE_MPLS_BOS_ETHERNET: "MPLS_BOS_ETHERNET",
        nplapi.NPL_FWD_HEADER_TYPE_INJECT_DOWN: "INJECT_DOWN",
        nplapi.NPL_FWD_HEADER_TYPE_REDIRECT: "REDIRECT"
    }

    BASE_LENGTH = 32  # bytes

    fields_desc = [
        # npu_base_leaba_dont_overwrite_t (64b)
        BitEnumField("base_type", 0, 4, base_type_dict),
        BitField("receive_time", 0, 32),
        BitField("meter_color", 0, 2),
        BitField("l2_flood_mc_pruning", 0, 1),
        XBitField("encap_qos_tag", 0, 7),
        BitField("qos_group", 0, 7),
        XBitField("fwd_qos_tag", 0, 7),
        BitEnumField("fwd_header_type", 0, 4, fwd_header_type_dict),

        # npu_header_cont_t (192b)
        # npu_base_header_leaba_t (28b)
        XBitField("lb_key", 0, 16),
        BitField("slp_qos_id", 0, 4),
        BitField("issu_codespace", 0, 1),
        BitField("fwd_offset", BASE_LENGTH, 7),

        # NOTE:
        # Encapsulation header and NPU App header have application defined
        # content, but fixed lengths (108b and 56b).
        # If you have errors in tests using this header check the definitions
        # of npu_encap_header_app_t and nw_npu_app_header_t in NPL files and
        # update these definitions accordingly.

        # npu_encap_header_app_t (108b)
        BitField("encap_type", 0, 4),
        XBitField("encap", 0, 76),
        XBitField("punt_mc_expand_encap", 0, 28),

        # nw_npu_app_header_t (56b)
        XBitField("ingress_ptp_info", 0, 4),
        BitField("padding", 0, 1),
        BitField("force_pipe_ttl", 0, 1),
        BitField("is_inject_up", 0, 1),
        BitField("ipv4_first_fragment", 0, 1),
        BitField("ttl", 0, 8),
        XBitField("collapsed_mc_info", 0, 2),
        XBitField("fwd_slp_info", 0, 22),
        BitField("is_mpls_inner_bos", 0, 1),
        BitField("is_ssp_ext_port", 0, 1),
        BitField("fwd_relay_id", 0, 14),
    ]

    payload_dict = {
        nplapi.NPL_FWD_HEADER_TYPE_ETHERNET: Ether,
        nplapi.NPL_FWD_HEADER_TYPE_IPV4: IP,
        nplapi.NPL_FWD_HEADER_TYPE_IPV4_COLLAPSED_MC: Ether,
        nplapi.NPL_FWD_HEADER_TYPE_IPV6: IPv6,
        nplapi.NPL_FWD_HEADER_TYPE_IPV6_COLLAPSED_MC: Ether,
        nplapi.NPL_FWD_HEADER_TYPE_MPLS_NO_BOS: MPLS,
        nplapi.NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV4: MPLS,
        nplapi.NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV6: MPLS,
        nplapi.NPL_FWD_HEADER_TYPE_MPLS_BOS_ETHERNET: MPLS,
        nplapi.NPL_FWD_HEADER_TYPE_INJECT_DOWN: InjectDown,
        nplapi.NPL_FWD_HEADER_TYPE_REDIRECT: Ether
    }

    def guess_payload_class(self, payload):
        FwdHeaderType = self.payload_dict.get(self.fwd_header_type, Ether)
        if self.fwd_offset == self.BASE_LENGTH:
            return FwdHeaderType
        else:
            return NPU_Soft_Header_of(self.fwd_offset - self.BASE_LENGTH, FwdHeaderType)


NPU_Soft_Header = NPU_Soft_Header_of(byte_length=8)


class Pause(Packet):
    name = "Pause"
    fields_desc = [
        BitField("opcode", 1, 16),
        BitField("wait_time", 5000, 16)
    ]


bind_layers(Ether, Pause, type=0x8808)

# Bind fabric headers
bind_layers(TS_PLB, TM)
bind_layers(TM, NPU_Header_ext)
bind_layers(TM, NPU_Header)
bind_layers(NPU_Header, Ether)
bind_layers(NPU_Header, NPU_Soft_Header)
bind_layers(NPU_Soft_Header, Ether)

# inject packet to specific slice, ifg, pif and checks if out_packet equals the the expected packet


def run_and_compare(

        testcase,
        uut_provider,
        ingress_packet,
        in_slice,
        in_ifg,
        in_serdes,
        expected_egress_packet,
        out_slice,
        out_ifg,
        out_serdes,
        out_first_header=Ether,
        initial_metadata_values_dict={}):

    uut_provider.flush()

    ipacket = nsim.sim_packet_info_desc()
    ipacket.packet = scapy_to_hex(ingress_packet)
    ipacket.slice = in_slice
    ipacket.ifg = in_ifg
    ipacket.pif = serdes_to_pif(uut_provider, in_serdes)
    status = uut_provider.inject_packet(ipacket, initial_metadata_values_dict)
    testcase.assertEqual(status, True)

    # Pass packet from port 1 to port 2
    status = uut_provider.step_packet()
    testcase.assertEqual(status, True)

    (status, egress_packet) = uut_provider.get_packet()
    testcase.assertTrue(status, "Packet was dropped")

    expected_egress_packet_hex = scapy_to_hex(expected_egress_packet)
    assertEqualPackets(testcase, egress_packet.packet, expected_egress_packet_hex, out_first_header)
    testcase.assertEqual(egress_packet.slice, out_slice)
    testcase.assertEqual(egress_packet.ifg, out_ifg)
    testcase.assertEqual(egress_packet.pif, serdes_to_pif(uut_provider, out_serdes))


def run_and_compare_inner_fields(
        testcase,
        uut_provider,
        ingress_packet,
        in_slice,
        in_ifg,
        in_serdes,
        expected_egress_packet,
        out_slice,
        out_ifg,
        out_serdes,
        control_expected,
        out_first_header=Ether,
        initial_metadata_values_dict={}):
    # run_and_compare_inner_fields does not work on hw. Revert to run_and_compare
    if os.getenv('SDK_DEVICE_NAME') == '/dev/uio0' or os.getenv('SIMULATOR') is not None:
        return run_and_compare(testcase, uut_provider, ingress_packet, in_slice,
                               in_ifg, in_serdes, expected_egress_packet, out_slice,
                               out_ifg, out_serdes, out_first_header)


def run_and_drop(testcase, uut_provider, ingress_packet, in_slice, in_ifg, in_serdes, initial_metadata_values_dict={}):

    uut_provider.flush()

    ipacket = nsim.sim_packet_info_desc()
    ipacket.packet = scapy_to_hex(ingress_packet)
    ipacket.slice = in_slice
    ipacket.ifg = in_ifg
    ipacket.pif = serdes_to_pif(uut_provider, in_serdes)

    status = uut_provider.inject_packet(ipacket, initial_metadata_values_dict)
    testcase.assertEqual(status, True)

    # Pass packet from port 1 to port 2
    status = uut_provider.step_packet()
    testcase.assertEqual(status, True)

    (status, egress_packet) = uut_provider.get_packet()
    testcase.assertEqual(status, False)


def run_and_compare_list(
        testcase,
        uut_provider,
        ingress_packet,
        expected_egress_packets,
        out_first_header=Ether,
        is_fe_multicast=False,
        initial_metadata_values_dict={},
        expect_unchecked=False):
    inpacket = ingress_packet.copy()
    expected_packets = copy.deepcopy(expected_egress_packets)

    egress_packets = run_and_get(
        testcase,
        uut_provider,
        inpacket['data'],
        inpacket['slice'],
        inpacket['ifg'],
        inpacket['pif'],
        initial_metadata_values_dict)
    # Compare packet count
    if not expect_unchecked:
        testcase.assertEqual(len(egress_packets), len(expected_egress_packets))
    else:
        testcase.assertEqual((len(egress_packets) > len(expected_egress_packets)), True)

    if is_fe_multicast:
        compare_packets_fe_multicast(testcase, uut_provider, egress_packets, expected_packets, out_first_header)
    else:
        if (expect_unchecked and (len(expected_packets) == 0)):
            return egress_packets

        unchecked_packets = compare_packets(
            testcase,
            uut_provider,
            egress_packets,
            expected_packets,
            out_first_header,
            expect_unchecked)
        if expect_unchecked:
            return unchecked_packets


def compare_packets_with_duplicates(testcase, uut_provider, egress_packets, expected_packets, out_first_header=Ether):
    unmatched_packets = []
    for out_packet in egress_packets:
        index = 0
        found = False
        for exp_packet in expected_packets:
            if out_packet.slice == exp_packet['slice'] and \
                    out_packet.ifg == exp_packet['ifg'] and \
                    out_packet.pif == serdes_to_pif(uut_provider, exp_packet['pif']):
                exp_packet_hex = scapy_to_hex(exp_packet['data'])
                found = True
                break
            index += 1

        if found is False:
            unmatched_packets.append(out_packet)

    testcase.assertEqual(len(unmatched_packets), 0)


def step_and_compare(
        testcase,
        uut_provider,
        expected_egress_packets,
        allow_duplicates=True,
        out_first_header=Ether):

    uut_provider.flush()

    expected_packets = copy.deepcopy(expected_egress_packets)

    status = uut_provider.step_packet()
    testcase.assertEqual(status, True)
    status = uut_provider.step_learn_notify_packet()
    testcase.assertEqual(status, True)

    egress_packets = uut_provider.get_packets()
    testcase.assertGreaterEqual(len(egress_packets), len(expected_packets))

    if allow_duplicates is True:
        compare_packets_with_duplicates(testcase, uut_provider, egress_packets, expected_packets, out_first_header)
    else:
        compare_packets(testcase, uut_provider, egress_packets, expected_packets, out_first_header)


def compare_packets(testcase, uut_provider, egress_packets, expected_packets, out_first_header=Ether, expect_unchecked=False):
    # keep a copy of egress packets' list and remove after checking it from expected packets' list
    unchecked_packets = []
    if expect_unchecked:
        unchecked_packets = egress_packets.copy()

    # Compare packets
    for out_packet in egress_packets:
        index = 0
        found = False
        for exp_packet in expected_packets:
            if out_packet.slice == exp_packet['slice'] and \
                    out_packet.ifg == exp_packet['ifg'] and \
                    out_packet.pif == serdes_to_pif(uut_provider, exp_packet['pif']):
                exp_packet_hex = scapy_to_hex(exp_packet['data'])
                assertEqualPackets(
                    testcase,
                    out_packet.packet,
                    exp_packet_hex,
                    out_first_header,
                    exp_packet.get('egress_mirror_pi_port_pkt'))
                found = True
                # we matched the egress packet and expected packet, remove from list considering verified.
                # remaining unchecked will be returned if asked by user (expect_unchecked flag)
                if len(unchecked_packets):
                    unchecked_packets.remove(out_packet)
                # regular case, verified packets are removed from expected packet list
                expected_packets.remove(exp_packet)
                break
            index += 1
        # assert if remaining only in regular case
        if (not expect_unchecked):
            testcase.assertTrue(found)

    # checked all the egress packets against the expected list, if we still find remaining expected packet, return as error
    testcase.assertEqual(len(expected_packets), 0)
    if expect_unchecked:
        return unchecked_packets


def compare_packets_fe_multicast(testcase, uut_provider, egress_packets, expected_packets, out_first_header=Ether):
    '''
        Every element in `expected_packets` list should contain the Scapy packet and a list of ports
        the packet is expected to appear on. Ports are described with slice, ifg and pif numbers.

        The comparison passes if each egress packet is matched with one expected packets, on only
        one of the expected ports.

        The `expected_packets` parameter should look like the following:
            [
                {
                    'data': # scapy packet,
                    'ports': [
                        {
                            'slice': # slice number,
                            'ifg': # ifg number,
                            'pif': # pif/serdes number
                        },
                        ...
                    ],
                },
                ...
            ]
    '''

    # Compare packets
    for out_packet in egress_packets:
        index = 0
        found = False
        for exp_packet in expected_packets:
            exp_packet_hex = scapy_to_hex(exp_packet['data'])
            for port in exp_packet['ports']:
                if out_packet.slice == port['slice'] and \
                        out_packet.ifg == port['ifg'] and \
                        out_packet.pif == serdes_to_pif(uut_provider, port['pif']):
                    assertEqualPackets(
                        testcase,
                        out_packet.packet,
                        exp_packet_hex,
                        out_first_header,
                        exp_packet.get('egress_mirror_pi_port_pkt'))
                    found = True
                    break
            if found:
                break
            index += 1

        testcase.assertTrue(found)
        del(expected_packets[index])


def run_with_system_learn_and_compare_list(
        testcase,
        uut_provider,
        ingress_packet,
        expected_egress_packets,
        out_first_header=Ether,
        initial_metadata_values_dict={}):

    uut_provider.flush()

    inpacket = ingress_packet.copy()
    expected_packets = copy.deepcopy(expected_egress_packets)

    ipacket = nsim.sim_packet_info_desc()
    ipacket.packet = scapy_to_hex(inpacket['data'])
    ipacket.slice = inpacket['slice']
    ipacket.ifg = inpacket['ifg']
    ipacket.pif = serdes_to_pif(uut_provider, inpacket['pif'])

    status = uut_provider.inject_packet(ipacket, initial_metadata_values_dict)
    testcase.assertEqual(status, True)

    # Pass packet from port 1 to port 2
    status = uut_provider.step_packet()
    testcase.assertEqual(status, True)

    # Enable Learn FIFO dequeing to NPU host
    # Expect NPU host to generate a packet
    status = uut_provider.step_learn_notify_packet()
    testcase.assertEqual(status, True)

    # Compare packet count
    egress_packets = uut_provider.get_packets()
    testcase.assertEqual(len(egress_packets), len(expected_egress_packets))

    # normalize the ssp field in the punt header
    for exp_packet in expected_packets:
        try:
            exp_packet['data'][Punt].source_sp = 0
        except BaseException:
            pass
    for out_packet in egress_packets:
        out_packet_scapy = hex_to_scapy(out_packet.packet)
        try:
            out_packet_scapy[Punt].source_sp = 0
            out_packet.packet = scapy_to_hex(out_packet_scapy)
        except BaseException:
            pass

    # Compare packets
    for out_packet in egress_packets:
        index = 0
        found = False
        for exp_packet in expected_packets:
            if out_packet.slice == exp_packet['slice'] and \
                    out_packet.ifg == exp_packet['ifg'] and \
                    out_packet.pif == serdes_to_pif(uut_provider, exp_packet['pif']):
                exp_packet_hex = scapy_to_hex(exp_packet['data'])
                assertEqualPackets(testcase, out_packet.packet, exp_packet_hex, out_first_header)
                found = True
                break
            index += 1

        testcase.assertTrue(found)
        del(expected_packets[index])


def run_with_system_learn(
        testcase,
        uut_provider,
        ingress_packets,
        expected_egress_packets,
        out_first_header=Ether,
        initial_metadata_values_dict={}):

    uut_provider.flush()

    expected_packets = copy.deepcopy(expected_egress_packets)

    for in_packet in ingress_packets:
        inpacket = in_packet.copy()

        ipacket = nsim.sim_packet_info_desc()
        ipacket.packet = scapy_to_hex(inpacket['data'])
        ipacket.slice = inpacket['slice']
        ipacket.ifg = inpacket['ifg']
        ipacket.pif = serdes_to_pif(uut_provider, inpacket['pif'])

        status = uut_provider.inject_packet(ipacket, initial_metadata_values_dict)
        testcase.assertEqual(status, True)

        # Pass packet from port 1 to port 2
        status = uut_provider.step_packet()
        testcase.assertEqual(status, True)

    for fifo_trigger in ingress_packets:
        # Enable Learn FIFO dequeing to NPU host
        # Expect NPU host to generate a packet
        status = uut_provider.step_learn_notify_packet()
        testcase.assertEqual(status, True)

    # return egress packets directly for further processing
    egress_packets = uut_provider.get_packets()
    return egress_packets

# Inject packet to specific slice, ifg, pif and return all the egress packets


def run_and_get(
        testcase,
        uut_provider,
        ingress_packet,
        in_slice,
        in_ifg,
        in_serdes,
        initial_metadata_values_dict={}):

    uut_provider.flush()

    ipacket = nsim.sim_packet_info_desc()
    ipacket.packet = scapy_to_hex(ingress_packet)
    ipacket.slice = in_slice
    ipacket.ifg = in_ifg
    ipacket.pif = serdes_to_pif(uut_provider, in_serdes)
    status = uut_provider.inject_packet(ipacket, initial_metadata_values_dict)
    testcase.assertEqual(status, True)

    # Pass packet from port 1 to egress ports
    status = uut_provider.step_packet()
    testcase.assertEqual(status, True)

    egress_packets = uut_provider.get_packets()
    return egress_packets


def trigger_npu_host_and_compare(
        testcase,
        uut_provider,
        line,
        expected_egress_packet,
        out_slice,
        out_ifg,
        out_serdes,
        out_first_header=Ether):

    uut_provider.inject_db_trigger(line)

    status = uut_provider.step_packet()
    testcase.assertEqual(status, True)

    (status, egress_packet) = uut_provider.get_packet()
    testcase.assertEqual(status, True)

    expected_egress_packet_hex = scapy_to_hex(expected_egress_packet)
    assertEqualPackets(testcase, egress_packet.packet, expected_egress_packet_hex, out_first_header)
    testcase.assertEqual(egress_packet.slice, out_slice)
    testcase.assertEqual(egress_packet.ifg, out_ifg)
    testcase.assertEqual(egress_packet.pif, serdes_to_pif(uut_provider, out_serdes))


def verify_padding(testcase, actual_pkt_hex, egress_mirror_pi_port_pkt=False):
    pkt_len = len(actual_pkt_hex) // 2
    if egress_mirror_pi_port_pkt:
        if pkt_len > len(Ether() / Dot1Q() / Punt()):
            pkt_len = pkt_len - len(Ether() / Dot1Q() / Punt())
        else:
            pkt_len = 0
    testcase.assertGreaterEqual(
        pkt_len, MIN_PKT_SIZE_WITHOUT_CRC, 'RUNT Packet({} bytes): Packet is not padded to {} bytes'.format(
            pkt_len, MIN_PKT_SIZE_WITHOUT_CRC))


def assertEqualPackets(testcase, actual_pkt_hex, expected_pkt_hex, pkt_first_header=Ether, egress_mirror_pi_port_pkt=False):
    verify_padding(testcase, actual_pkt_hex, egress_mirror_pi_port_pkt)
    min_pkt_size = MIN_PKT_SIZE_WITHOUT_CRC
    if egress_mirror_pi_port_pkt:
        min_pkt_size += len(Ether() / Dot1Q() / Punt())

    if ((len(expected_pkt_hex) // 2) < min_pkt_size) and ((len(actual_pkt_hex) // 2) == min_pkt_size):
        print(
            'Detected padding condition [most likely] Expected length : {0} Actual length {1}'.format(
                len(expected_pkt_hex) // 2,
                len(actual_pkt_hex) // 2))
        actual_pkt_hex = actual_pkt_hex[0:len(expected_pkt_hex)]

    # Create an instance of packet_mismatch_printer, with the actual and expected packet bytes.
    packet_mismatch_handler = packet_mismatch_printer(actual_pkt_hex, expected_pkt_hex, pkt_first_header)

    # If actual_pkt_hex and expected_pkt_hex are not equal then a custom message packet_mismatch_handler is printed.
    # packet_mismatch_handler is not a string but a class with an overloaded __str__ function,
    # so the printed custom message is actually the output of __str__
    testcase.assertEqual(actual_pkt_hex, expected_pkt_hex, packet_mismatch_handler)

# This class is used to print a side-by-side comparison of scapy-formatted packets.
# The packets fields are compared textually using their scapy-printed output.
# A field that is mismatched between the two packets is printed in yellow. The specific mismatching characters are marked in red.
# The actual comparison code is in the overloaded __str__ function, which
# is called when the class should do a "to_string" translation.


class packet_mismatch_printer:

    def __init__(self, actual_pkt_hex, expected_pkt_hex, pkt_first_header):
        self.actual_pkt_hex = actual_pkt_hex
        self.expected_pkt_hex = expected_pkt_hex
        self.pkt_first_header = pkt_first_header

    def __str__(self):
        actual_pkt = hex_to_scapy(self.actual_pkt_hex, self.pkt_first_header)
        expected_pkt = hex_to_scapy(self.expected_pkt_hex, self.pkt_first_header)

        # Scapy doesn't support printing a packet structure into a variable - only to the stdout.
        # So need to capture the scapy's show() function from the stdout.
        # Capture the readable format of the packets
        actual_pkt_io = StringIO()
        sys.stdout = actual_pkt_io
        actual_pkt.show()

        expected_pkt_io = StringIO()
        sys.stdout = expected_pkt_io
        expected_pkt.show()

        # Restore the stdout
        sys.stdout = sys.__stdout__

        # Extract list of lines from the packetIos
        actual_pkt_io.seek(0)
        expected_pkt_io.seek(0)

        actual_pkt_str = actual_pkt_io.readlines()
        expected_pkt_str = expected_pkt_io.readlines()

        # Prepare coloring constants. These are places in the string to change the color.
        COLOR_UNDERLINE = '\033[4m'
        COLOR_NORMAL = '\033[0m'
        COLOR_RED = '\033[1;31m'

        # Prepare table format, and columns headers
        COLUMN_DISTANCE = 20
        max_field_len = 30  # Arbitrary value. Change if needed

        msg = (
            '\n{column0:{padding}}{column1}\n'.format(
                column0="Actual",
                column1="Expected",
                padding=max_field_len +
                COLUMN_DISTANCE))

        # The two string lists may have a different number of lines (hence the packet had different number of headers/fields).
        # For easier comparing of the string lines, crate a list of line pairs.
        # If one string list has more lines than the other, then the member that doesn't have an input is None.
        pkt_pair_str = itertools.zip_longest(actual_pkt_str, expected_pkt_str)
        for pkt0_line, pkt1_line in pkt_pair_str:
            pkt0_clean = pkt0_line.rstrip() if pkt0_line is not None else ''
            pkt1_clean = pkt1_line.rstrip() if pkt1_line is not None else ''

            # These will collect the colored version of the line strings.
            pkt0_color = ''
            pkt1_color = ''

            if pkt0_clean == pkt1_clean:
                # If lines match, take them as-is
                pkt0_color = pkt0_clean
                pkt1_color = pkt1_clean
            else:
                # Mark both lines in yellow
                pkt0_color += COLOR_RED
                pkt1_color += COLOR_RED

                # Go over all comparable chars
                min_line_len = min(len(pkt0_clean), len(pkt1_clean))
                for idx in range(0, min_line_len):
                    # Mark mismatching chars in red
                    if pkt0_clean[idx] == pkt1_clean[idx]:
                        pkt0_color += pkt0_clean[idx]
                        pkt1_color += pkt1_clean[idx]
                    else:
                        pkt0_color += COLOR_RED + COLOR_UNDERLINE + pkt0_clean[idx] + COLOR_NORMAL + COLOR_RED
                        pkt1_color += COLOR_RED + COLOR_UNDERLINE + pkt1_clean[idx] + COLOR_NORMAL + COLOR_RED

                # Mark all excess chars (which differ in length) in red
                pkt0_color += COLOR_UNDERLINE + pkt0_clean[min_line_len:] + COLOR_NORMAL
                pkt1_color += COLOR_UNDERLINE + pkt1_clean[min_line_len:] + COLOR_NORMAL

            # The color indication is represented by a string, but the padding is not aware of it, so need to compensate
            pkt0_pad = len(pkt0_color) - len(pkt0_clean)

            msg += ('{column0:{padding}}{column1}\n'.format(column0=pkt0_color,
                                                            column1=pkt1_color, padding=max_field_len + COLUMN_DISTANCE + pkt0_pad))

        return msg


def get_injected_packet_len(device, packet, slice_id):
    return len(packet) + device.get_wrapper_headers_len(packet, slice_id) + CRC_HEADER_SIZE


def assertPacketLengthIngress(testcase, packet, slice_id, length_in_bytes, num_packets=1):
    packet_len = get_injected_packet_len(testcase.device, packet, slice_id)
    packets_total_length = num_packets * packet_len
    testcase.assertEqual(packets_total_length, length_in_bytes)


def is_padding_added_to_egress_counters(device):
    if npl_padding_done(device.device_revision):
        return True
    return False  # TODO change in akpg devices


def get_output_packet_len_for_counters(device, packet):
    pkt_len_no_crc = len(packet)
    if is_padding_added_to_egress_counters(device):
        if pkt_len_no_crc < MIN_PKT_SIZE_WITHOUT_CRC:
            pkt_len_no_crc = MIN_PKT_SIZE_WITHOUT_CRC
    return pkt_len_no_crc + CRC_HEADER_SIZE


def assertPacketLengthEgress(testcase, packet, length_in_bytes, num_packets=1):
    packet_len = get_output_packet_len_for_counters(testcase.device, packet)
    packets_total_length = num_packets * packet_len
    testcase.assertEqual(packets_total_length, length_in_bytes)


def packet_insert_layer(packet, new_layer, index):
    # inserts new layer in specific index
    # will not insert as first layer

    packet_copy = deepcopy(packet)
    pkt_tail = packet_copy[index - 1].payload
    payload_layer_type = packet_copy[index - 1].type
    packet_copy[index - 1].type = new_layer.type
    new_layer.type = payload_layer_type
    packet_copy[index - 1].remove_payload()
    pkt_head = packet_copy
    return pkt_head / new_layer / pkt_tail


def packet_remove_layer(packet, index):
    # remove layer in specific index
    # will not remove the first layer

    packet_copy = deepcopy(packet)
    pkt_tail = packet_copy[index].payload
    layer_type = packet_copy[index].type
    packet_copy[index - 1].remove_payload()
    packet_copy[index - 1].type = layer_type

    return packet_copy / pkt_tail


def npl_padding_done(revision):
    if ((revision == lldcli.la_device_revision_e_PACIFIC_A0) or
            (revision == lldcli.la_device_revision_e_PACIFIC_B0)):
        return True
    return False


def add_payload(scapy_packet, payload_len):
    if payload_len == 0:
        return scapy_packet
    raw = Raw()
    raw.load = '\x00' * payload_len
    return scapy_packet / raw


def enlarge_packet_to_min_length(scapy_packet, min_plen=MIN_PKT_SIZE_WITHOUT_CRC):
    # Add pad bytes of payload to the scapy packet
    if min_plen > len(scapy_packet):
        payload_len = min_plen - len(scapy_packet)
        return add_payload(scapy_packet, payload_len), payload_len
    else:
        return scapy_packet, 0


def pad_input_and_output_packets(input_packet, output_packet, min_pkt_len=MIN_PKT_SIZE_WITHOUT_CRC):
    # padding input packet to min minimum required size
    input_packet_result, pad_size = enlarge_packet_to_min_length(input_packet, min_plen=min_pkt_len)

    # adding same bytes to output packet
    output_packet_result = add_payload(output_packet, pad_size)

    return input_packet_result, output_packet_result


def packet_edit_layer(packet, index, field_name, new_value):
    # Edit layer's field

    packet_copy = deepcopy(packet)
    if index == 0:
        packet_copy.setfieldval(field_name, new_dip)
        return packet_copy

    pkt_tail = deepcopy(packet_copy[index])
    pkt_tail.setfieldval(field_name, new_value)
    packet_copy[index - 1].remove_payload()
    return packet_copy / pkt_tail


def scapy_to_hex(scapy_packet):
    # Convert Scapy packet to hex

    return hexlify(bytes(scapy_packet)).decode('ascii')


def hex_to_scapy(hex_packet, first_header=Ether):
    # Convert hex to Scapy packet

    return first_header(unhexlify(hex_packet.encode("ascii")))


def int_to_mac(mac_i):
    # Convert integer to MAC string

    return ("%c%c:" * 6)[:-1] % tuple(hex(mac_i)[2:])


def load_json_db(filename):
    json_db = None

    if (os.path.splitext(filename)[1] == '.gz'):
        with gzip.open(filename, 'rb') as fh:
            json_db = json.load(fh)
    else:
        with open(filename, 'r') as fh:
            json_db = json.load(fh)

    return json_db


def compare_lld_registers(testcase, ll_device, pacific_tree, expected_values, result, exclude_pattern):
    for path, exp_val in expected_values['register'].items():
        command = 'll_device.read_register({0})'.format(path)
        read_val = eval(command)
        exp_val_i = int(exp_val, 16)
        if (read_val == exp_val_i):
            result['register']['pass'] += 1
        else:
            result['register']['fail'] += 1
            line = '{} => 0x{:X}, expected 0x{:X}'.format(command, read_val, exp_val_i)
            result['failures'].append(line)
            path_unique = re.sub(r'\d+', r'X', path)
            result['register']['unique'][path_unique] = result['register']['unique'].get(path_unique, 0) + 1
            if exclude_pattern is None or re.search(exclude_pattern, path_unique) is None:
                result['register']['unique_excluded'][path_unique] = result['register']['unique_excluded'].get(path_unique, 0) + 1


def compare_lld_memories(testcase, ll_device, pacific_tree, expected_values, result, exclude_pattern):
    for path_line, compare_info in expected_values['memory'].items():
        (path, line_str) = path_line.strip(' ').split(':')
        path_unique = re.sub(r'\d+', r'X', path)
        line_num = int(line_str)
        check_command = '{0}.get_desc().is_volatile()'.format(path)
        is_volatile = eval(check_command)
        exp_val_i = int(compare_info, 16)

        command = 'll_device.read_memory({0}, {1})'.format(path, line_num)

        if (is_volatile):
            result['memory_volatile']['total'] += 1
            line = '{} => volatile, expected 0x{:X}'.format(command, exp_val_i)
            result['failures'].append(line)
            result['memory_volatile']['unique'][path_unique] = result['memory_volatile']['unique'].get(path_unique, 0) + 1
            if exclude_pattern is None or re.search(exclude_pattern, path_unique) is None:
                result['memory_volatile']['unique_excluded'][path_unique] = result['memory_volatile']['unique_excluded'].get(
                    path_unique, 0) + 1
        else:
            (status, read_val) = eval(command)
            testcase.assertEqual(status, sdk.la_status_e_SUCCESS)
            if (read_val == exp_val_i):
                result['memory']['pass'] += 1
            else:
                result['memory']['fail'] += 1
                line = '{} => 0x{:X}, expected 0x{:X}'.format(command, read_val, exp_val_i)
                result['failures'].append(line)
                result['memory']['unique'][path_unique] = result['memory']['unique'].get(path_unique, 0) + 1
                if exclude_pattern is None or re.search(exclude_pattern, path_unique) is None:
                    result['memory']['unique_excluded'][path_unique] = result['memory']['unique_excluded'].get(path_unique, 0) + 1


def compare_lld_tcams(testcase, ll_device, pacific_tree, expected_values, result, exclude_pattern):
    for path_line, compare_info in expected_values['tcam'].items():
        (path, line_str) = path_line.strip(' ').split(':')
        path_unique = re.sub(r'\d+', r'X', path)
        line_num = int(line_str)
        exp_val_i = int(compare_info['val'], 16)
        exp_mask_i = int(compare_info['mask'], 16)
        command = 'll_device.read_tcam({0}, {1})'.format(path, line_num)
        (status, read_val, read_mask, valid) = eval(command)
        testcase.assertEqual(status, sdk.la_status_e_SUCCESS)
        if ((read_val == exp_val_i) and (read_mask == exp_mask_i)):
            result['tcam']['pass'] += 1
        else:
            result['tcam']['fail'] += 1
            line = '{} => K:0x{:X}, M:0x{:X}, expected K:0x{:X}, M:0x{:X}'.format(
                command, read_val, read_mask, exp_val_i, exp_mask_i)
            result['failures'].append(line)
            result['tcam']['unique'][path_unique] = result['tcam']['unique'].get(path_unique, 0) + 1
            if exclude_pattern is None or re.search(exclude_pattern, path_unique) is None:
                result['tcam']['unique_excluded'][path_unique] = result['tcam']['unique_excluded'].get(path_unique, 0) + 1


def init_comparison_result():
    result = {}
    result['failures'] = []
    result['register'] = {"pass": 0, "fail": 0, "unique": {}, "unique_excluded": {}}
    result['memory'] = {"pass": 0, "fail": 0, "unique": {}, "unique_excluded": {}}
    result['memory_volatile'] = {"total": 0, "unique": {}, "unique_excluded": {}}
    result['tcam'] = {"pass": 0, "fail": 0, "unique": {}, "unique_excluded": {}}

    return result


def sum_comparison_result(result, allowed_failures):
    total_failures = result['register']['fail'] + result['memory']['fail'] + result['tcam']['fail']
    summary = ['Totals:']
    summary.append('     Failures: Actual {0}, Allowed {1}'.format(total_failures, allowed_failures))
    summary.append(
        '     Registers: Pass {0}, Fail {1}, Unique {2}, Unique and excluded {3}'.format(
            result['register']['pass'],
            result['register']['fail'],
            len(result['register']['unique']),
            len(result['register']['unique_excluded'])))
    summary.append(
        '     Config Memory: Pass {0}, Fail {1}, Unique {2}, Unique and excluded {3}'.format(
            result['memory']['pass'],
            result['memory']['fail'],
            len(result['memory']['unique']),
            len(result['memory']['unique_excluded'])))
    summary.append(
        '     Volatile Memory: Total {0}, Unique {1}, Unique and excluded {2}'.format(
            result['memory_volatile']['total'],
            len(result['memory_volatile']['unique']),
            len(result['memory_volatile']['unique_excluded'])))
    summary.append('     TCAM: Pass {0}, Fail {1}, Unique {2}, Unique and excluded {3}'.format(
        result['tcam']['pass'],
        result['tcam']['fail'],
        len(result['tcam']['unique']),
        len(result['tcam']['unique_excluded'])))

    return {'total_failures': total_failures, 'summary': summary}


def write_comparison_result_data(result):
    with gzip.open('failures_all.txt.gz', 'wt') as fail_fh:
        fail_fh.write("\n".join(result['failures']))

    with gzip.open('failures_unique.txt.gz', 'wt') as fail_fh:
        fail_fh.write('Registers\n')
        fail_fh.write('---------\n')
        for (path, count) in result['register']['unique_excluded'].items():
            fail_fh.write('{1:>10} {0}\n'.format(path, count))

        fail_fh.write('Configuration Memory\n')
        fail_fh.write('--------------------\n')
        for (path, count) in result['memory']['unique_excluded'].items():
            fail_fh.write('{1:>10} {0}\n'.format(path, count))

        fail_fh.write('Volatile Memory\n')
        fail_fh.write('---------------\n')
        for (path, count) in result['memory_volatile']['unique_excluded'].items():
            fail_fh.write('{1:>10} {0}\n'.format(path, count))

        fail_fh.write('TCAM\n')
        fail_fh.write('----\n')
        for (path, count) in result['tcam']['unique_excluded'].items():
            fail_fh.write('{1:>10} {0}\n'.format(path, count))


def compare_regs_mems(testcase, device, filename, test_name, allowed_failures=0, exclude_pattern=None):
    expected_db = load_json_db(filename)
    testcase.assertIsNotNone(expected_db)

    ll_device = device.get_ll_device()
    testcase.assertIsNotNone(ll_device)

    pacific_tree = ll_device.get_pacific_tree()
    testcase.assertIsNotNone(pacific_tree)

    expected_values = expected_db[test_name]

    result = init_comparison_result()

    # Compare
    compare_lld_registers(testcase, ll_device, pacific_tree, expected_values, result, exclude_pattern)
    compare_lld_memories(testcase, ll_device, pacific_tree, expected_values, result, exclude_pattern)
    compare_lld_tcams(testcase, ll_device, pacific_tree, expected_values, result, exclude_pattern)

    # Sum
    sum_result = sum_comparison_result(result, allowed_failures)

    # Check and print
    write_comparison_result_data(result)

    testcase.assertTrue(sum_result['total_failures'] <= allowed_failures, "\n".join(sum_result['summary']))

    if (sum_result['total_failures'] > 0):
        print("\n".join(sum_result['summary']))


def enum_value_to_field_name(obj, enum_prefix, value):
    for p in dir(obj):
        if p.startswith(enum_prefix) and getattr(obj, p, None) == value:
            return p.replace(enum_prefix, '')
    return str(value)


def display_forwarding_load_balance_chain(in_obj, chain):
    print('Forwarding Load Balance Chain: \n\t' +
          enum_value_to_field_name(in_obj, 'object_type_e_', in_obj.type()) + "\t[OID = %d]" % (in_obj.oid()), end='')
    for elem in chain:
        print('\n\t' + enum_value_to_field_name(elem, 'object_type_e_', elem.type()) + "\t[OID = %d]" % (elem.oid()), end='')
        if elem.type() == sdk.la_object.object_type_e_SYSTEM_PORT:
            elem = elem.downcast()
            print(': SLICE %d IFG %d BASE SERDES %d' % (elem.get_slice(), elem.get_ifg(), elem.get_base_serdes()))


def check_forwarding_load_balance_chain(testcase, chain, exp_slice, exp_ifg, exp_serdes):
    for elem in chain:
        if elem.type() == sdk.la_object.object_type_e_SYSTEM_PORT:
            elem = elem.downcast()
            testcase.assertEqual(elem.get_slice(), exp_slice)
            testcase.assertEqual(elem.get_ifg(), exp_ifg)
            testcase.assertEqual(elem.get_base_pif(), serdes_to_pif(testcase.device, exp_serdes))
            return
    assert(0), "System port is not found in chain!"


def split_bits(value, n):
    ''' Split `value` into a list of `n`-bit integers '''
    mask, parts = (1 << n) - 1, []
    parts = []
    while value:
        parts.append(value & mask)
        value >>= n
    return parts


def serdes_to_pif(uut_provider, serdes_id):
    if decor.is_asic3():
        # In GR Serdes to PIF mapping is 1->2
        return serdes_id * 2
    if decor.is_asic5():
        # In Asic5, the PIF is dynamic for the 48 serdes and has to be retrieved
        if (serdes_id < 48):
            return uut_provider.get_mac_port(0, 0, serdes_id).get_first_pif_id()

    return serdes_id
