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

from scapy.all import *
import unittest
from leaba import sdk
from ip_test_base import *
import sim_utils
import topology as T
import packet_test_utils as U


def get_expected_egress_packets(ingress_packet, expected_packets, eth_ports):
    expected_packets_p = copy.deepcopy(expected_packets)
    expected_egress_packets = []
    non_mirror_packet_trapped = 0
    num_trapped_packets = 0
    for exp_packet in expected_packets_p:
        eth_port = eth_ports[expected_packets_p.index(exp_packet)]
        if eth_port and not ('skip_mtu_test' in exp_packet.keys()):
            if len(exp_packet['data']) <= eth_port.get_mtu():
                expected_egress_packets.append(exp_packet)
            else:
                num_trapped_packets = num_trapped_packets + 1
        else:
            # includes the case of switched packets. Switched packets are not subjected to mtu checks
            expected_egress_packets.append(exp_packet)

    ingress_mirror_count = 0
    egress_mirror_count = 0
    for exp_packet in expected_egress_packets:
        if 'ingress_mirror' in exp_packet.keys() or 'ingress_mirror_pi_port_pkt' in exp_packet.keys():
            ingress_mirror_count = ingress_mirror_count + 1
        if 'egress_mirror' in exp_packet.keys() or 'egress_mirror_pi_port_pkt' in exp_packet.keys():
            egress_mirror_count = egress_mirror_count + 1
    if (ingress_mirror_count + egress_mirror_count) == len(expected_egress_packets):
        # egress mirroring will not happen if original packet is trapped to drop
        for exp_packet in expected_egress_packets:
            if 'egress_mirror' in exp_packet.keys() or 'egress_mirror_pi_port_pkt' in exp_packet.keys():
                expected_egress_packets.remove(exp_packet)
    return expected_egress_packets, num_trapped_packets


def run_mtu_test(
        testcase,
        uut_provider,
        ingress_packet,
        in_slice,
        in_ifg,
        in_pif,
        expected_egress_packet,
        out_slice,
        out_ifg,
        out_pif,
        out_first_header=Ether):
    if not U.npl_padding_done(uut_provider.device_revision):
        # only applicable to pacific
        return
    uut_provider.flush()
    # fetch egress ethernet port
    eth_port = uut_provider.get_ethernet_port(out_slice, out_ifg, out_pif)
    # get mtu of egress ethernet port
    o_mtu = eth_port.get_mtu()
    mtus = [500, 800, 1300, 1100]
    for mtu in mtus:
        # set mtu on ethernet port
        eth_port.set_mtu(mtu)
        # pad egress packet to mtu-1
        pad_len = (mtu - 1) - len(expected_egress_packet)
        expected_egress_packet_p, __ = U.enlarge_packet_to_min_length(expected_egress_packet, mtu - 1)
        # pad the ingress packet
        ingress_packet_p, __ = U.enlarge_packet_to_min_length(ingress_packet, pad_len + len(ingress_packet))
        U.run_and_compare(testcase, uut_provider, ingress_packet_p, in_slice,
                          in_ifg, in_pif, expected_egress_packet_p, out_slice, out_ifg, out_pif, out_first_header)
        # pad egress packet to mtu
        pad_len = mtu - len(expected_egress_packet)
        expected_egress_packet_p, __ = U.enlarge_packet_to_min_length(expected_egress_packet, mtu)
        # pad the ingress packet
        ingress_packet_p, __ = U.enlarge_packet_to_min_length(ingress_packet, pad_len + len(ingress_packet))
        U.run_and_compare(testcase, uut_provider, ingress_packet_p, in_slice,
                          in_ifg, in_pif, expected_egress_packet_p, out_slice, out_ifg, out_pif, out_first_header)
        # pad egress packet to mtu+1
        pad_len = (mtu + 1) - len(expected_egress_packet)
        expected_egress_packet_p, __ = U.enlarge_packet_to_min_length(expected_egress_packet, mtu + 1)
        # pad the ingress packet
        ingress_packet_p, __ = U.enlarge_packet_to_min_length(ingress_packet, pad_len + len(ingress_packet))
        tc = testcase.device.create_counter(1)
        testcase.device.set_trap_configuration(sdk.LA_EVENT_L3_TX_MTU_FAILURE, 0, tc, None, False, False, True, 0)
        U.run_and_drop(testcase, uut_provider, ingress_packet_p, in_slice,
                       in_ifg, in_pif)
        trap_packet_count = 1
        # check if sdk.LA_EVENT_L3_TX_MTU_FAILURE trap got set
        packets, bytes = tc.read(0,  # sub-counter index
                                     True,  # force_update
                                     True)  # clear_on_read
        testcase.assertEqual(packets, trap_packet_count)
        testcase.device.clear_trap_configuration(sdk.LA_EVENT_L3_TX_MTU_FAILURE)

    # clear all counters
    uut_provider.clear_counters()
    # restore mtu of egress ethernet port
    eth_port.set_mtu(o_mtu)


def run_mtu_tests(
        testcase,
        uut_provider,
        ingress_packet,
        expected_egress_packets,
        out_first_header=Ether):
    if not U.npl_padding_done(uut_provider.device_revision):
        # only applicable to pacific
        return
    uut_provider.flush()

    inpacket = ingress_packet.copy()
    expected_packets = copy.deepcopy(expected_egress_packets)

    # fetch egress ethernet ports
    eth_ports = []
    o_mtus = []
    for exp_packet in expected_packets:
        out_slice = exp_packet['slice']
        out_ifg = exp_packet['ifg']
        out_pif = exp_packet['pif']
        eth_port = uut_provider.get_ethernet_port(out_slice, out_ifg, out_pif)
        if (eth_port):
            eth_ports.append(eth_port)
            o_mtus.append(eth_port.get_mtu())
        else:
            eth_ports.append(0)
            o_mtus.append(0)
    mtus = [500, 800, 1300, 1100]
    for mtu in mtus:
        for eth_port in eth_ports:
            if eth_port == 0:
                continue
            eth_port.set_mtu(mtu)
            for pkt_pad_len in [mtu - 1, mtu, mtu + 1]:
                expected_packets_p = copy.deepcopy(expected_packets)
                pad_len = pkt_pad_len - len(expected_packets_p[eth_ports.index(eth_port)]['data'])
                # pad the ingress packet
                inpacket_p = inpacket.copy()
                inpacket_p['data'], __ = U.enlarge_packet_to_min_length(inpacket['data'], pad_len + len(inpacket['data']))
                for exp_packet in expected_packets_p:
                    exp_packet['data'], __ = U.enlarge_packet_to_min_length(exp_packet['data'], pad_len + len(exp_packet['data']))
                    eth_port_1 = eth_ports[expected_packets_p.index(exp_packet)]
                tc = testcase.device.create_counter(1)
                testcase.device.set_trap_configuration(sdk.LA_EVENT_L3_TX_MTU_FAILURE, 0, tc, None, False, False, True, 0)
                expected_egress_packets, expected_trap_counter_value = get_expected_egress_packets(inpacket_p,
                                                                                                   expected_packets_p,
                                                                                                   eth_ports)
                U.run_and_compare_list(testcase, uut_provider, inpacket_p, expected_egress_packets)
                # check if sdk.LA_EVENT_L3_TX_MTU_FAILURE trap got set
                packets, bytes = tc.read(0,  # sub-counter index
                                         True,  # force_update
                                         True)  # clear_on_read
                testcase.assertEqual(packets, expected_trap_counter_value)
                testcase.device.clear_trap_configuration(sdk.LA_EVENT_L3_TX_MTU_FAILURE)
            eth_port.set_mtu(o_mtus[eth_ports.index(eth_port)])
    # clear all counters
    uut_provider.clear_counters()
