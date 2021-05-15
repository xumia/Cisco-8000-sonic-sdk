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


###
# Test packet send/receive thru the Leaba NIC driver.
###

import os
import sys
import socket

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *
from binascii import hexlify

from leaba import sdk
import test_nsim_providercli as nsim
from packet_test_defs import *

import voq_allocator
import network_objects
import packet_dma
import tm_utils
from sanity_constants import *

NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS = 7

NUM_IFGS_PER_SLICE = 2
VOQ_SET_SIZE = 8
SYS_PORT_GID = 0x111
AC_PORT_GID = 0x311

ENTRY_VLAN = 0x123
EXIT_VLAN = 0x321
DEVICE = 1
SLICE = 0
IFG = 0
DST_MAC = network_objects.mac_addr('ca:fe:ca:fe:ca:fe')
SRC_MAC = network_objects.mac_addr('de:ad:de:ad:de:ad')
PUNT_INJECT_PORT_MAC_ADDR = network_objects.mac_addr('11:11:11:11:11:11')
PCI_PIF = 18


PacketDmaWaHeader8_bytes = b'\x08\x00\x00\x00\x00\x00\x00\x00'
PacketDmaWaHeader16_bytes = b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


inject_packets = {
    0: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x71c50),
    1: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x471b20),
    2: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x2c70f40),
    3: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x1bc69880),
    4: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x115c1f500),
    5: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0xad9939200),
    6: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x6c7fc3b400),
    7: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x43cfda50800),
    8: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x2a61e8725000),
    9: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x1a7d314772000),
    10: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x108e3ecca74000),
    11: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0xa58e73fe888000),
    12: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x6779087f1550000),
    13: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x40aba54f6d520000),
    14: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x1234),
    15: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN, type=TPID_Inject) /
    InjectUp(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ssp_gid=0) /
    Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0xb608)}


expected_packets = {
    0: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x71c50),
    1: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x471b20),
    2: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x2c70f40),
    3: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x1bc69880),
    4: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x115c1f500),
    5: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0xad9939200),
    6: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x6c7fc3b400),
    7: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x43cfda50800),
    8: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x2a61e8725000),
    9: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x1a7d314772000),
    10: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x108e3ecca74000),
    11: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0xa58e73fe888000),
    12: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x6779087f1550000),
    13: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x40aba54f6d520000),
    14: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0x1234),
    15: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) /
    Dot1Q(prio=2, id=1, vlan=ENTRY_VLAN) /
    IP() / TCP() / Raw(load=0xb608)}

# Linux kernel removes the 802.1Q header
linux_expected_packets = {
    0: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x71c50),
    1: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x471b20),
    2: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x2c70f40),
    3: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x1bc69880),
    4: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x115c1f500),
    5: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0xad9939200),
    6: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x6c7fc3b400),
    7: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x43cfda50800),
    8: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x2a61e8725000),
    9: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x1a7d314772000),
    10: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x108e3ecca74000),
    11: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0xa58e73fe888000),
    12: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x6779087f1550000),
    13: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x40aba54f6d520000),
    14: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0x1234),
    15: Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_IPv4) /
    IP() / TCP() / Raw(load=0xb608)}


class hw_device:
    ETH_P_ALL = 3
    STANDALONE_DEV = [sdk.la_slice_mode_e_NETWORK] * 6

    def __init__(self, device_id):

        sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)
        device_path = '/dev/uio0'
        self.la_dev = sdk.la_create_device(device_path, device_id)
        print('Device created')

        self.ll_dev = self.la_dev.get_ll_device()
        self.pacific = self.ll_dev.get_pacific_tree()

        self.la_dev.initialize(sdk.la_device.init_phase_e_DEVICE)

        for sid in range(len(hw_device.STANDALONE_DEV)):
            self.la_dev.set_slice_mode(sid, hw_device.STANDALONE_DEV[sid])

        self.la_dev.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

        print('Device initialized')
        self.sockets = NUM_SLICES_PER_DEVICE * [None]

    def write_register(self, reg, val):
        print('write_register %s 0x%x' % (reg.get_name(), val))
        self.ll_dev.write_register(reg, val)

    def read_register(self, reg):
        status, val = self.ll_dev.read_register(reg)
        assert(status == 0)
        print('read_register %s 0x%x' % (reg.get_name(), val))
        return val

    def inject(self, packet, entry_slice):
        s = self.sockets[entry_slice]
        bytes_num = s.send(packet)
        if bytes_num != len(packet):
            print('Error: send failed len(packet)=%d bytes_num=%d' % (len(packet), bytes_num))

    def get_packets_with_inject_header(self, ssp, test):
        inject_packet = inject_packets[test]
        inject_packet[2].ssp_gid = ssp
        expected_packet = linux_expected_packets[test]
        return (inject_packet, expected_packet)

    def get_output_packet(self, exit_slice, expected_packet_len):
        s = self.sockets[exit_slice]
        packet = s.recv(expected_packet_len)
        if expected_packet_len != len(packet):
            print('Error: send failed len(packet)=%d expected_packet_len=%d' % (len(packet), expected_packet_len))
        return packet

    def open_sockets(self):
        for i in range(NUM_SLICES_PER_DEVICE):
            with open('/sys/class/uio/uio0/device/leaba_nic%d' % i) as fd:
                first_line = fd.readline()
                if first_line.find('not active') < 0:
                    self.open_socket(i)

    def open_socket(self, slice_id):
        if_name = self.la_dev.get_ll_device().get_network_interface_name(slice_id)

        os.system('echo 0 > /proc/sys/net/ipv6/conf/%s/router_solicitations' % if_name)
        os.system('/sbin/ifconfig %s up' % if_name)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(hw_device.ETH_P_ALL))
        s.bind((if_name, hw_device.ETH_P_ALL))
        self.sockets[slice_id] = s

    def close_sockets(self):
        for i in range(NUM_SLICES_PER_DEVICE):
            self.close_socket(i)

    def close_socket(self, slice_id):
        s = self.sockets[slice_id]
        if s is None:
            return
        if_name = self.la_dev.get_ll_device().get_network_interface_name(slice_id)
        os.system('/sbin/ifconfig %s down' % (if_name))
        s.close()
        self.sockets[slice_id] = None

    def teardown(self):
        sdk.la_destroy_device(self.la_dev)


class hw_device_1(hw_device):
    def __init__(self, device_id):

        hw_device.__init__(self, device_id)
        self.interface = SLICE * NUM_IFGS_PER_SLICE

        self.dev_dma = packet_dma.packet_dma(self.la_dev.get_ll_device(), self.interface)
        self.dev_dma.configure()
        print('Interface %d configured' % self.interface)

    def inject(self, packet, entry_slice):
        interface = entry_slice * NUM_IFGS_PER_SLICE
        assert(interface == self.interface)

        is_success = self.dev_dma.inject(packet)
        if not is_success:
            raise Exception('Error: inject failed')

    def get_output_packet(self, exit_slice, expected_packet_len):
        interface = exit_slice * NUM_IFGS_PER_SLICE
        assert(interface == self.interface)

        (is_success, packet) = self.dev_dma.extract()
        if not is_success:
            raise Exception('Error: extract failed')

        return packet

    def get_packets_with_inject_header(self, ssp, test):
        inject_packet = inject_packets[test]
        inject_packet[2].ssp_gid = ssp

        expected_packet = expected_packets[test]
        expected_packet[2].ssp_gid = ssp

        if test in [0, 9, 10, 11, 12, 13, 14, 15]:
            expected_packet = PacketDmaWaHeader16_bytes + bytes(expected_packet)
        else:
            expected_packet = PacketDmaWaHeader8_bytes + bytes(expected_packet)

        return (inject_packet, expected_packet)
