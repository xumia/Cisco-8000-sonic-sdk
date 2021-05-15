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


import decor
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
import os
import ip_test_base
import warm_boot_test_utils as wb


PRIVATE_DATA = 0x1234567890abcdef
TTL = 128
SA = T.mac_addr('be:ef:5d:35:7a:35')
DA = T.mac_addr('02:02:02:02:02:02')

SIP_V4 = T.ipv4_addr('12.10.12.10')
DIP_V4 = T.ipv4_addr('82.81.95.250')

SIP_V6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP_V6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')


class warm_boot_voq_counters_base(sdk_test_case_base):
    IN_PACKET_ENQUEUE_BASE = S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP() / S.TCP()

    OUT_PACKET_ENQUEUE_BASE = S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP() / S.TCP()

    IN_PACKET_ENQUEUE, OUT_PACKET_ENQUEUE = U.pad_input_and_output_packets(IN_PACKET_ENQUEUE_BASE, OUT_PACKET_ENQUEUE_BASE)

    NO_SERVICE_MAPPING_VID = T.RX_L2_AC_PORT_VID1 + 1
    IN_PACKET_DROP_BASE = \
        S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=NO_SERVICE_MAPPING_VID) / \
        S.IP() / S.TCP()

    IN_PACKET_DROP, __ = U.enlarge_packet_to_min_length(IN_PACKET_DROP_BASE)

    def setUp(self):
        super().setUp()
        self.init_ports()
        self.warm_boot_file_name = wb.get_warm_boot_file_name()

    def tearDown(self):
        super().tearDown()
        if os.path.exists(self.warm_boot_file_name):
            os.remove(self.warm_boot_file_name)

    def init_ports(self):
        self.rx_eth_port = self.topology.rx_eth_port
        self.rx_ac_port = self.topology.rx_l2_ac_port
        self.tx_eth_port = self.topology.tx_svi_eth_port_reg
        self.tx_ac_port = self.topology.tx_l2_ac_port_reg

        self.rx_ac_port.hld_obj.detach()
        self.rx_ac_port.hld_obj.set_destination(self.tx_ac_port.hld_obj)

    def create_and_attach_counter(self):
        tx_eth_port_voq_set = self.tx_eth_port.sys_port.voq_set
        wb.warm_boot(self.device.device)
        tx_eth_port_voq_set_size = tx_eth_port_voq_set.get_set_size()
        wb.warm_boot(self.device.device)
        tx_eth_port_voq_counter = self.device.device.create_counter(2)
        wb.warm_boot(self.device.device)
        tx_eth_port_voq_set.set_counter(sdk.la_voq_set.voq_counter_type_e_BOTH,
                                        tx_eth_port_voq_set_size,
                                        tx_eth_port_voq_counter)
        return tx_eth_port_voq_counter

    def check_counter_values(self, counter, exp_enq_pkts, exp_enq_bytes, exp_drop_pkts, exp_drop_bytes):
        enqueue_packet_count, enqueue_byte_count = counter.read(0, True, True)
        drop_packet_count, drop_byte_count = counter.read(1, True, True)
        self.assertEqual(enqueue_packet_count, exp_enq_pkts)
        self.assertEqual(enqueue_byte_count, exp_enq_bytes)
        self.assertEqual(drop_packet_count, exp_drop_pkts)
        self.assertEqual(drop_byte_count, exp_drop_bytes)


class warm_boot_l2_counters_base(sdk_test_case_base):
    IN_PACKET_BASE = S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP() / S.TCP()

    OUT_PACKET_BASE = S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP() / S.TCP()

    IN_PACKET, OUT_PACKET = U.pad_input_and_output_packets(IN_PACKET_BASE, OUT_PACKET_BASE)

    def setUp(self):
        super().setUp()
        self.init_ports()
        self.warm_boot_file_name = wb.get_warm_boot_file_name()

    def tearDown(self):
        super().tearDown()
        if os.path.exists(self.warm_boot_file_name):
            os.remove(self.warm_boot_file_name)

    def init_ports(self):
        self.rx_ac_port = self.topology.rx_l2_ac_port
        self.tx_ac_port = self.topology.tx_l2_ac_port_reg

        self.rx_ac_port.hld_obj.detach()
        self.rx_ac_port.hld_obj.set_destination(self.tx_ac_port.hld_obj)

    def create_and_attach_counters(self):
        # ingress counter
        ingress_counter = self.device.create_counter(1)
        wb.warm_boot(self.device.device)
        self.rx_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_counter)

        # egress counter
        egress_counter = self.device.create_counter(1)
        wb.warm_boot(self.device.device)
        self.tx_ac_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        return ingress_counter, egress_counter

    def check_counter_values(self, counter, expected_packets, expected_bytes):
        packet_count, byte_count = counter.read(0, True, True)
        self.assertEqual(packet_count, expected_packets)
        self.assertEqual(byte_count, expected_bytes)


class warm_boot_l3_counters_base(sdk_test_case_base):

    def setUp(self):
        super().setUp()

        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, PRIVATE_DATA)

        self.warm_boot_file_name = wb.get_warm_boot_file_name()

    def tearDown(self):
        super().tearDown()
        if os.path.exists(self.warm_boot_file_name):
            os.remove(self.warm_boot_file_name)

    def create_and_attach_counters(self):
        # Create and set ingress counter
        counter_set_size = 1
        ingress_counter = self.device.create_counter(counter_set_size)
        wb.warm_boot(self.device.device)
        self.l3_port_impl.rx_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_counter)

        # Create and set egress counter
        if self.l3_port_impl.is_svi:
            egress_counter = self.device.create_counter(counter_set_size)
            wb.warm_boot(self.device.device)
            self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)
        else:
            egress_counter = self.device.create_counter(counter_set_size)
            wb.warm_boot(self.device.device)
            self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        return ingress_counter, egress_counter

    def check_counter_values(self, counter, expected_packets, expected_bytes):
        packet_count, byte_count = counter.read(0, True, True)
        self.assertEqual(packet_count, expected_packets)
        self.assertEqual(byte_count, expected_bytes)

    def do_warm_boot_l3_counters_test(self):
        # create and attach counters
        ingress_counter, egress_counter = self.create_and_attach_counters()

        # verify the counters are empty
        wb.warm_boot(self.device.device)
        self.check_counter_values(ingress_counter, expected_packets=0, expected_bytes=0)
        wb.warm_boot(self.device.device)
        self.check_counter_values(egress_counter, expected_packets=0, expected_bytes=0)
        wb.warm_boot(self.device.device)

        U.run_and_compare(
            self,
            self.device,
            self.IN_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.OUT_PACKET,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        # verify counters' values are as expected
        ingress_packet_size = U.get_injected_packet_len(self.device, self.IN_PACKET, T.RX_SLICE)
        egress_packet_size = U.get_output_packet_len_for_counters(self.device, self.OUT_PACKET)
        wb.warm_boot(self.device.device)
        self.check_counter_values(ingress_counter, expected_packets=1, expected_bytes=ingress_packet_size)
        wb.warm_boot(self.device.device)
        self.check_counter_values(egress_counter, expected_packets=1, expected_bytes=egress_packet_size)

    def do_warm_boot_l3_counters_test_sdk_down_kernel_module_up(self):
        # create and attach counters
        ingress_counter, egress_counter = self.create_and_attach_counters()

        # verify the counters are empty
        self.check_counter_values(ingress_counter, expected_packets=0, expected_bytes=0)
        self.check_counter_values(egress_counter, expected_packets=0, expected_bytes=0)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_compare(
            self,
            self.device,
            self.IN_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.OUT_PACKET,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)

        # verify counters' values are as expected
        ingress_packet_size = U.get_injected_packet_len(self.device, self.IN_PACKET, T.RX_SLICE)
        egress_packet_size = U.get_output_packet_len_for_counters(self.device, self.OUT_PACKET)
        self.check_counter_values(ingress_counter, expected_packets=1, expected_bytes=ingress_packet_size)
        self.check_counter_values(egress_counter, expected_packets=1, expected_bytes=egress_packet_size)


class warm_boot_ipv4_svi_counters_base(warm_boot_l3_counters_base):
    SIP = SIP_V4
    DIP = DIP_V4

    l3_port_impl_class = T.ip_svi_base
    ip_impl_class = ip_test_base.ipv4_test_base

    IN_PACKET_BASE = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    OUT_PACKET_BASE = \
        S.Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

    IN_PACKET, OUT_PACKET = U.pad_input_and_output_packets(IN_PACKET_BASE, OUT_PACKET_BASE)


class warm_boot_ipv4_ac_counters_base(warm_boot_l3_counters_base):
    SIP = SIP_V4
    DIP = DIP_V4

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv4_test_base

    IN_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    OUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

    IN_PACKET, OUT_PACKET = U.pad_input_and_output_packets(IN_PACKET_BASE, OUT_PACKET_BASE)


class warm_boot_ipv6_svi_counters_base(warm_boot_l3_counters_base):
    SIP = SIP_V6
    DIP = DIP_V6

    l3_port_impl_class = T.ip_svi_base
    ip_impl_class = ip_test_base.ipv6_test_base

    IN_PACKET_BASE = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL, plen=40)

    OUT_PACKET_BASE = \
        S.Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1, plen=40)

    IN_PACKET, OUT_PACKET = U.pad_input_and_output_packets(IN_PACKET_BASE, OUT_PACKET_BASE)


class warm_boot_ipv6_ac_counters_base(warm_boot_l3_counters_base):
    SIP = SIP_V6
    DIP = DIP_V6

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv6_test_base

    IN_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL, plen=40)

    OUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1, plen=40)

    IN_PACKET, OUT_PACKET = U.pad_input_and_output_packets(IN_PACKET_BASE, OUT_PACKET_BASE)
