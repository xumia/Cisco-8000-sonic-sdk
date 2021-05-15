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

import pytest
import saicli as S
from scapy.all import *
from binascii import hexlify, unhexlify
import ipaddress
from io import StringIO
from enum import Enum
import test_nsim_providercli as nsim
import time
import sai_test_utils as st_utils


MIN_PACKET_LEN = 72


class Ethertype(Enum):
    IPv4 = 0x0800                                 # IPv4
    IPv6 = 0x86dd                                 # IPv6
    Dot1Q = 0x8100                                # VLAN-tagged frame (802.1q) and Shortest Path Bridging (802.1aq)
    SVLAN = 0x88a8                                # Provider Bridging (802.1ad) and Shortest Path Bridging (802.1aq)
    QinQ = 0x9100                                 # Legacy QinQ/802.ad
    Unknown = 0xbead                              # Dummy unknown Ethertype value
    MPLS = 0x8847                                 # MPLS
    Inject = 0x7103                               # Inject
    Punt = 0x7102                                 # Punt
    PortExtender = 0x7101                         # PortExtender TPID
    LLDP = 0x88cc                                 # LLDP
    LACP = 0x8809                                 # LACP


class Punt(Packet):
    name = "Punt"
    fields_desc = [
        BitField("next_header", 0, 5),         # Next header protocol.
        BitField("fwd_header_type", 0, 4),     # Forward header type.
        BitField("reserved1", 0, 3),           #
        BitField("next_header_offset", 0, 8),  # Offset to L3 header.
        BitField("source", 0, 4),              # Punt source.
        BitField("code", 0, 8),                # Punt code.
        BitField("lpts_flow_type", 0, 8),      # LPTS flow type.
        BitField("source_sp", 0, 16),          # Source system port GID.
        BitField("destination_sp", 0, 16),     # Destination system port GID.
        BitField("source_lp", 0, 20),          # Source logical port GID.
        BitField("destination_lp", 0, 20),     # Destination logical port GID.
        BitField("reserved2", 0, 2),           #
        BitField("relay_id", 0, 14),           # Punt relay ID.
        XBitField("time_stamp", 0, 64),        # Time stamp value.
        XBitField("receive_time", 0, 32),      # Receive time stamp ns value.
    ]

    def guess_payload_class(self, payload):
        if self.source != 0:
            if self.next_header == 4:
                return IP
            elif self.next_header == 6:
                return IPv6
            elif self.next_header == 7:
                return MPLS
        return Ether


# Bind the following to support sflow Tunnel
bind_layers(UDP, Punt, dport=6343)


class sflow_tunnel_metadata(Packet):
    name = "sflow_tunnel_metadata"
    fields_desc = [
        BitField("source_sp", 0, 16),          # Source system port GID.
        BitField("reserved", 0, 16),           # Destination system port GID.
        BitField("source_lp", 0, 20),          # Source logical port GID.
        BitField("destination_sp", 0, 20),     # Destination logical port GID.
    ]


# Bind the following to support sflow Tunnel
bind_layers(UDP, sflow_tunnel_metadata, dport=6344)


def assertEqualPackets(testcase, actual_pkt_hex, expected_pkt_hex, pkt_first_header=Ether):
    # Create an instance of packet_mismatch_printer, with the actual and expected packet bytes.
    packet_mismatch_handler = packet_mismatch_printer(actual_pkt_hex, expected_pkt_hex, pkt_first_header)

    # If actual_pkt_hex and expected_pkt_hex are not equal then a custom message packet_mismatch_handler is printed.
    # packet_mismatch_handler is not a string but a class with an overloaded __str__ function,
    # so the printed custom message is actually the output of __str__
    assert actual_pkt_hex == expected_pkt_hex, packet_mismatch_handler

# Given a set of packet header fields, values of those fields are
# compared for equality in actual-packet and expected packet


def assertPartialEqualityPackets(test_case, actual_packet, expected_packet, fields):
    actual_packet_scapy = hex_to_scapy(actual_packet, first_header=Ether)
    for (header, fieldname) in fields:
        if getattr(actual_packet_scapy[Ether][header], fieldname) != getattr(expected_packet[Ether][header], fieldname):
            packet_mismatch_handler = packet_mismatch_printer(actual_packet, scapy_to_hex(expected_packet), Ether)
            assert actual_packet == scapy_to_hex(expected_packet), packet_mismatch_handler


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

# We use this for swig to identify that a String is actually MAC address


def sai_mac(mac):
    return "mac:" + mac.replace(":", "")


def sai_attr_to_mac(attr):
    mac = S.sai_py_mac_t(attr)
    return mac.addr

# convert string representing IPv4 or IPv6 address to object that can be passed to SAI SWIG
# IPv4 converted to int
# IPv6 converted to sai_u8_list_t


def sai_ip(orig_addr):
    addr = ipaddress.ip_address(orig_addr)
    if isinstance(addr, ipaddress.IPv6Address):
        int_addr = int(addr)
        ret = []

        for i in range(0, 16):
            ret.insert(0, int_addr % 256)
            int_addr = int_addr >> 8
        return S.sai_ip_address_t(S.sai_u8_list_t(ret))
    else:
        if isinstance(addr, ipaddress.IPv4Address):
            return S.sai_ip_address_t(socket.ntohl(int(addr)))
        else:
            print("Bad IP address format {0}".format(orig_addr))
            assert(False)


def sai_ip_to_string(sai_ip):
    ip = S.sai_py_ip_t(sai_ip)
    return ip.addr


# Convert Scapy packet to hex


def scapy_to_hex(scapy_packet):
    return hexlify(bytes(scapy_packet)).decode('ascii')


# Convert hex to Scapy packet
def hex_to_scapy(hex_packet, first_header=Ether):
    return first_header(unhexlify(hex_packet.encode("ascii")))


def run_and_compare(
        test_case,
        in_packet,
        in_port,
        expected_out_packet,
        out_port):

    run_and_compare_set(test_case, in_packet, in_port, {out_port: expected_out_packet})


# port_packets should be dictionary with entries: {expected_out_port: expected_out_pkt}
# Function verifies that one of the out packets arrived
# useful when we have multiple output ports from which a packet can go out (lag for example)


def run_and_compare_set(
        test_case,
        in_packet,
        in_port,
        port_packets, match_all=False, pkt_cntrs=None, with_learn=False):

    if pytest.tb.is_hw():
        return

    # match_all == false means that the output packets contains the input port_packets (this is used by test case in test_next_hop_group_v4.py.
    # match_all == true means that the output packets exactly match with the
    # input port_packets including the number of port_packets pairs.

    s_i_p_in = st_utils.lane_to_slice_ifg_pif(in_port)

    in_pad_len = 0
    if len(in_packet) < MIN_PACKET_LEN:
        in_pad_len = MIN_PACKET_LEN - len(in_packet)
        padded_in_packet = in_packet / ("\0" * in_pad_len)
    else:
        padded_in_packet = in_packet

    ipacket = nsim.sim_packet_info_desc()
    ipacket.packet = scapy_to_hex(padded_in_packet)
    ipacket.slice = s_i_p_in['slice']
    ipacket.ifg = s_i_p_in['ifg']
    ipacket.pif = s_i_p_in['pif']
    pytest.tb.nsim_inject_packet(ipacket)

    pytest.tb.nsim_step_packet()
    if with_learn:
        pytest.tb.nsim_provider.step_learn_notify_packet()

    out_pkts = pytest.tb.nsim_provider.get_packets()

    if match_all:
        assert len(out_pkts) == len(port_packets)
        if len(out_pkts) == 0:
            return

    found = False
    for out_pkt in out_pkts:
        found = False

        # counter for every packet found
        if pkt_cntrs is not None:
            port_pif = st_utils.lane_from_slice_ifg_pif(out_pkt.slice, out_pkt.ifg, out_pkt.pif)
            pkt_cntrs[port_pif] = (pkt_cntrs[port_pif] + 1) if port_pif in pkt_cntrs else 1

        for port, pkt in port_packets.items():
            s_i_p_out = st_utils.lane_to_slice_ifg_pif(port)
            if s_i_p_out['slice'] is not out_pkt.slice:
                continue
            if s_i_p_out['ifg'] is not out_pkt.ifg:
                continue
            if s_i_p_out['pif'] is not out_pkt.pif:
                continue

            expected_padded_out_packet = pkt / ("\0" * in_pad_len)
            assertEqualPackets(test_case, out_pkt.packet, scapy_to_hex(expected_padded_out_packet))
            found = True

            break

        if not found and pkt_cntrs is not None:
            pkt_cntrs['not_found'] = (pkt_cntrs['not_found'] + 1) if 'not_found' in pkt_cntrs else 1

        if match_all and not found:
            raise
        elif not match_all and found:
            break

    if not found:
        raise

# Injects packet (in_packet) on in_port and compares two sets of packets.
# full_compare_packets is a set of tuples (port, packet)  that are compared for equality
# of packets egressed on respective output port.
# partial_compare_packets is a set of tuples (port, packet)  that are compared for partial equality
# of packets egressed on respective output port. A list of packet header fields are provided
# that are compared using expected packet and actual egressed packet.


def run_and_compare_partial_packet(
        test_case,
        in_packet,
        in_port,
        full_compare_packets, partial_compare_packets, match_all=False):

    if pytest.tb.is_hw():
        return

    s_i_p_in = st_utils.lane_to_slice_ifg_pif(in_port)

    in_pad_len = 0
    if len(in_packet) < MIN_PACKET_LEN:
        in_pad_len = MIN_PACKET_LEN - len(in_packet)
        padded_in_packet = in_packet / ("\0" * in_pad_len)
    else:
        padded_in_packet = in_packet

    ipacket = nsim.sim_packet_info_desc()
    ipacket.packet = scapy_to_hex(padded_in_packet)
    ipacket.slice = s_i_p_in['slice']
    ipacket.ifg = s_i_p_in['ifg']
    ipacket.pif = s_i_p_in['pif']
    pytest.tb.nsim_inject_packet(ipacket)

    pytest.tb.nsim_step_packet()
    out_pkts = pytest.tb.nsim_provider.get_packets()

    if match_all:
        # Account all out packet count is same as expected packet count.
        assert len(out_pkts) == len(full_compare_packets) + len(partial_compare_packets)

    matched_pkts = []
    for out_pkt in out_pkts:
        found = False
        for port, pkt in full_compare_packets.items():
            s_i_p_out = st_utils.lane_to_slice_ifg_pif(port)
            if s_i_p_out['slice'] is not out_pkt.slice:
                continue
            if s_i_p_out['ifg'] is not out_pkt.ifg:
                continue
            if s_i_p_out['pif'] is not out_pkt.pif:
                continue
            expected_padded_out_packet = pkt / ("\0" * in_pad_len)
            if out_pkt.packet == scapy_to_hex(expected_padded_out_packet):
                matched_pkts.append(out_pkt)

    mismatched_pkts = []
    for out_pkt in out_pkts:
        if out_pkt not in matched_pkts:
            mismatched_pkts.append(out_pkt)

    partial_matched_count = 0
    for out_mismatched_pkt in mismatched_pkts:
        # compare if packet matches partially
        for port, pkt_and_fields in partial_compare_packets.items():
            s_i_p_out = st_utils.lane_to_slice_ifg_pif(port)
            if s_i_p_out['slice'] is not out_mismatched_pkt.slice:
                continue
            if s_i_p_out['ifg'] is not out_mismatched_pkt.ifg:
                continue
            if s_i_p_out['pif'] is not out_mismatched_pkt.pif:
                continue
            pkt, fields = pkt_and_fields
            expected_padded_out_packet = pkt / ("\0" * in_pad_len)
            assertPartialEqualityPackets(test_case, out_mismatched_pkt.packet, expected_padded_out_packet, fields)
            partial_matched_count += 1
            break

    if partial_matched_count != len(mismatched_pkts):
        raise


def run(
        test_case,
        in_packet,
        in_port):

    s_i_p_in = st_utils.lane_to_slice_ifg_pif(in_port)

    if len(in_packet) < MIN_PACKET_LEN:
        padded_in_packet = in_packet / ("\0" * (MIN_PACKET_LEN - len(in_packet)))
    else:
        padded_in_packet = in_packet

    ipacket = nsim.sim_packet_info_desc()
    ipacket.packet = scapy_to_hex(padded_in_packet)
    ipacket.slice = s_i_p_in['slice']
    ipacket.ifg = s_i_p_in['ifg']
    ipacket.pif = s_i_p_in['pif']
    pytest.tb.nsim_inject_packet(ipacket)

    pytest.tb.nsim_step_packet()

    status, out_pkt = pytest.tb.get_packet()

    return (status, out_pkt)


def run_and_compare_snoop(
        test_case,
        in_pkt,
        in_port,
        exp_out_port_packets,
        exp_out_cpu_pkt,
        cpu_pkt_count=1,
        trap_type=None,
        match_all=False):

    punt_snoop_test_helper(test_case, in_pkt, in_port, exp_out_port_packets, exp_out_cpu_pkt, cpu_pkt_count, trap_type, match_all)


def punt_test(test_case, in_pkt, port, exp_out_pkt=None, count=1, trap_type=None, inject_mode=None):
    punt_snoop_test_helper(test_case, in_pkt, port, None, exp_out_pkt, count, trap_type, inject_mode)


# send in_pkt on in_port
# Verify receipt of cpu_pkt_count packets to CPU
# if exp_out_port_packets != None, verify also receipt of packets out port
def punt_snoop_test_helper(
        test_case,
        in_pkt,
        in_port,
        exp_out_port_packets,
        exp_out_cpu_pkt,
        cpu_pkt_count=1,
        trap_type=None,
        match_all=False,
        inject_mode=None,
        out_port=None,
        ingress=True):

    in_pad_len = 0
    if len(in_pkt) < MIN_PACKET_LEN:
        in_pad_len = MIN_PACKET_LEN - len(in_pkt)
        padded_in_packet = in_pkt / ("\0" * in_pad_len)
    else:
        padded_in_packet = in_pkt

    num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
    s_i_p = st_utils.lane_to_slice_ifg_pif(in_port)

    if pytest.tb.is_hw():
        if inject_mode == "up":
            pytest.tb.inject_packet_up(in_pkt, in_port)
        else:
            pytest.tb.inject_packet_down(in_pkt, in_port)

    else:
        pytest.tb.inject_network_packet(padded_in_packet, s_i_p["slice"], s_i_p["ifg"], s_i_p["pif"])

    for i in range(0, 3):
        time.sleep(0.4)
        num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()

        if num_pkts != num_pkts_before:
            break

    assert num_pkts == num_pkts_before + cpu_pkt_count

    # if exp_out_cpu_pkt not specified, assume we expect to get the in_pkt
    if cpu_pkt_count != 0:
        if exp_out_cpu_pkt is None:
            assertEqualPackets(test_case, out_pkt, scapy_to_hex(padded_in_packet))
        else:
            exp_pad_pkt = scapy_to_hex(exp_out_cpu_pkt / ("\0" * in_pad_len))
            assertEqualPackets(test_case, out_pkt, exp_pad_pkt)
            if ingress:
                assert pkt_sip == pytest.tb.ports[in_port]
            else:
                assert pkt_dst_port == pytest.tb.ports[out_port]
            if trap_type is not None:
                assert pkt_trap_id == trap_type

    if exp_out_port_packets is None:
        return

    # continue to verify receipt of port packets
    out_pkts = pytest.tb.nsim_provider.get_packets()
    if match_all:
        assert len(out_pkts) == len(exp_out_port_packets)

    found = False
    for out_pkt in out_pkts:
        found = False
        for port, pkt in exp_out_port_packets.items():
            s_i_p_out = st_utils.lane_to_slice_ifg_pif(port)
            if s_i_p_out['slice'] is not out_pkt.slice:
                continue
            if s_i_p_out['ifg'] is not out_pkt.ifg:
                continue
            if s_i_p_out['pif'] is not out_pkt.pif:
                continue

            expected_padded_out_packet = pkt / ("\0" * in_pad_len)
            assertEqualPackets(test_case, out_pkt.packet, scapy_to_hex(expected_padded_out_packet))
            found = True
            break

        if match_all and not found:
            raise
        elif not match_all and found:
            break

    if not found:
        raise


def inject_up_test(test_case, in_pkt, expected_out_pkt):
    pytest.tb.inject_packet_up(in_pkt)

    if pytest.tb.is_gb:
        if len(expected_out_pkt) < 60:
            pad = Padding()
            pad.load = '\x00' * (60 - len(expected_out_pkt))
            expected_out_pkt = expected_out_pkt / pad

    for i in range(0, 3):
        time.sleep(0.4)
        status, out_pkt = pytest.tb.get_packet()
        if status:
            break

    pytest.tb.log("out_pkt.port = {}/{}/{}, out_pkt len = {}".format(out_pkt.slice, out_pkt.ifg, out_pkt.pif, len(out_pkt.packet)))

    if not status:
        raise
    else:
        assertEqualPackets(test_case, out_pkt.packet, scapy_to_hex(expected_out_pkt))


def inject_up_then_punt_test(test_case, in_pkt):

    num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()

    padded_in  = in_pkt
    if len(padded_in) < MIN_PACKET_LEN:
        pad = Padding()
        pad.load = '\x00' * (MIN_PACKET_LEN - len(padded_in))
        padded_in  = padded_in  / pad

    pytest.tb.inject_packet_up(padded_in)

    for i in range(0, 3):
        time.sleep(0.4)
        num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        if num_pkts != num_pkts_before:
            break

    assert num_pkts == num_pkts_before + 1
    assertEqualPackets(test_case, out_pkt, scapy_to_hex(padded_in))

    assert pkt_sip == pytest.tb.cpu_port


def inject_down_test(test_case, in_pkt, queue_index=0):
    expected_out_pkt = in_pkt

    queues = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port]).to_pylist()
    queue_oid = queues[queue_index]
    start_pkt_count = pytest.tb.get_queue_stats(queue_oid)[0]

    if pytest.tb.is_gb:
        if len(expected_out_pkt) < 60:
            pad = Padding()
            pad.load = '\x00' * (60 - len(expected_out_pkt))
            expected_out_pkt = expected_out_pkt / pad

    pytest.tb.inject_packet_down(in_pkt, pytest.top.out_port, queue_index)

    for i in range(0, 3):
        time.sleep(0.4)
        status, out_pkt = pytest.tb.get_packet()
        if status:
            break

    end_pkt_count = pytest.tb.get_queue_stats(queue_oid)[0]

    assert end_pkt_count == start_pkt_count + 1

    if not status:
        raise
    else:
        assertEqualPackets(test_case, out_pkt.packet, scapy_to_hex(expected_out_pkt))
