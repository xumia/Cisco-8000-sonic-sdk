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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import time
from functools import cmp_to_key

IN_SLICE_IDS = range(4)
IN_IFG_IDS = range(2)
THE_OUT_SLICE = 4
THE_OUT_IFG = 1
THE_OUT_FIRST_SERDES = 14
THE_OUT_LAST_SERDES = 15
SERDES_PER_IFG = 16
DEBUG = True

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9


class countered_port:
    def __init__(self, slice, ifg, first_serdes, last_serdes, eth_port, ac_port):
        self.slice = slice
        self.ifg = ifg
        self.first_serdes = first_serdes
        self.last_serdes = last_serdes
        self.eth_port = eth_port
        self.ac_port = ac_port

    def to_string(self):
        return "slice:{}, ifg:{}, first_serdes:{}, last_serdes:{}, counter_val:{}".format(self.slice, self.ifg,
                                                                                          self.first_serdes,
                                                                                          self.last_serdes, self.read())

    def read(self, force=True, clear=False):
        return self.ac_port.hld_obj.get_ingress_counter(sdk.la_counter_set.type_e_PORT).read(0, force, clear)


class counters_state:
    def __init__(self, countered_ports):
        self.state = {}
        for countered_port in countered_ports:
            self.state[self.get_entry(countered_port)] = countered_port.read()

    def get_entry(self, countered_port):
        return (countered_port.slice, countered_port.ifg, countered_port.first_serdes)

    def __eq__(self, other):
        for entry in self.state:
            if self.state[entry] != other.state[entry]:
                return False
        for entry in other.state:
            if self.state[entry] != other.state[entry]:
                return False
        return True


class counters_base(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device, create_default_topology=False)
        self.topology.create_default_profiles()
        self.topology.create_inject_ports()

        self.create_ports()
        self.create_packets()
        if DEBUG:
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_RA, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_TABLES, sdk.la_logger_level_e_DEBUG)

    def tearDown(self):
        self.destroy_ports()
        self.device.tearDown()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()
        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    def create_ports(self, in_slices=IN_SLICE_IDS, in_ifgs=IN_IFG_IDS, serdes_per_ifg=SERDES_PER_IFG):
        runinng_SYS_PORT_GID_BASE = SYS_PORT_GID_BASE
        running_AC_PORT_GID_BASE = AC_PORT_GID_BASE
        self.ac_profile = T.ac_profile(self, self.device)
        self.out_eth_port = T.ethernet_port(
            self,
            self.device,
            THE_OUT_SLICE,
            THE_OUT_IFG,
            runinng_SYS_PORT_GID_BASE,
            THE_OUT_FIRST_SERDES,
            THE_OUT_LAST_SERDES
        )
        runinng_SYS_PORT_GID_BASE += 1
        self.out_ac_port = T.l2_ac_port(
            self,
            self.device,
            running_AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            self.out_eth_port,
            None,
            VLAN,
            0x0)
        running_AC_PORT_GID_BASE += 1
        self.countered_ports = []
        for in_slice in in_slices:
            for in_ifg in in_ifgs:
                for even_serdes in range(0, serdes_per_ifg, 2):
                    if self.is_the_out_countered_port(even_serdes, in_ifg, in_slice):
                        continue
                    eth_port = T.ethernet_port(
                        self,
                        self.device,
                        in_slice,
                        in_ifg,
                        runinng_SYS_PORT_GID_BASE,
                        even_serdes,
                        even_serdes + 1
                    )
                    runinng_SYS_PORT_GID_BASE += 1
                    eth_port.set_ac_profile(self.ac_profile)
                    ac_port = T.l2_ac_port(
                        self,
                        self.device,
                        running_AC_PORT_GID_BASE,
                        self.topology.filter_group_def,
                        None,
                        eth_port,
                        None,
                        VLAN,
                        0x0
                    )
                    running_AC_PORT_GID_BASE += 1
                    ac_port.hld_obj.set_destination(self.out_ac_port.hld_obj)
                    curr_countered_port = countered_port(
                        slice=in_slice,
                        ifg=in_ifg,
                        first_serdes=even_serdes,
                        last_serdes=even_serdes + 1,
                        eth_port=eth_port,
                        ac_port=ac_port
                    )
                    self.countered_ports.append(curr_countered_port)

    def is_the_out_countered_port(self, even_serdes, in_ifg, in_slice):
        return in_slice == THE_OUT_SLICE and THE_OUT_IFG == in_ifg and THE_OUT_FIRST_SERDES == even_serdes

    def destroy_ports(self):
        for countered_port in self.countered_ports:
            countered_port.ac_port.hld_obj.set_destination(None)
        self.out_ac_port.destroy()
        self.out_eth_port.destroy()
        for countered_port in self.countered_ports:
            countered_port.ac_port.destroy()
            countered_port.eth_port.destroy()
        self.ac_profile.destroy()

    def counter_ports_to_string(self):
        ans = ""
        for countered_port in self.countered_ports:
            ans += countered_port.to_string() + '\n'
        return ans

    def assign_counter(self, countered_port):
        counter = self.device.create_counter(1)
        countered_port.ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, counter)

    def inject_packet(self, countered_port):
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            countered_port.slice,
            countered_port.ifg,
            countered_port.first_serdes,
            self.out_packet,
            THE_OUT_SLICE,
            THE_OUT_IFG,
            THE_OUT_FIRST_SERDES
        )

    def assign_counters(self):
        for countered_port in self.countered_ports:
            self.assign_counter(countered_port)

    def clear_counters(self):
        for countered_port in self.countered_ports:
            countered_port.read(force=True, clear=True)

    def inject_packets_thorugh_countered_ports(self, in_slices=IN_SLICE_IDS, in_ifgs=IN_IFG_IDS,
                                               serdes_per_ifg=SERDES_PER_IFG):
        for countered_port in self.countered_ports:
            self.inject_packet(countered_port)
        return counters_state(self.countered_ports)
