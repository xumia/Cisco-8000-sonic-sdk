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

from packet_test_utils import *
from leaba import sdk
import topology as T
from sdk_test_case_base import *

# Helper class


class phy_port:
    pass


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class security_group_acl_spa_base(sdk_test_case_base):

    # Static members

    IN_SLICE = T.get_device_slice(2)
    IN_IFG = 0
    IN_SERDES_FIRST = 4
    IN_SERDES_LAST = IN_SERDES_FIRST + 1
    SYS_PORT_GID_BASE = 23
    AC_PORT_GID_BASE = 10

    DST_MAC = "ca:fe:ca:fe:ca:fe"
    DST_MAC_A = "ca:fe:ca:fe:ca:ff"
    SRC_MAC_A = "de:ad:be:ef:de:ad"
    SRC_MAC_B = "de:ad:de:ad:de:ad"
    SRC_MAC_C = "de:ad:ce:cd:de:ad"
    VLAN = 0xAB9

    TX_PORT_NUM_A = 0
    TX_PORT_NUM_B = 1

    s_tx = [phy_port() for i in range(4)]
    s_tx[0].slice = 0
    s_tx[0].ifg = 0
    s_tx[0].first_serdes = T.get_device_first_serdes(4)
    s_tx[0].last_serdes = T.get_device_last_serdes(5)
    s_tx[1].slice = T.get_device_slice(3)
    s_tx[1].ifg = T.get_device_ifg(1)
    s_tx[1].first_serdes = 8
    s_tx[1].last_serdes = 9
    s_tx[2].slice = T.get_device_slice(1)
    s_tx[2].ifg = 0
    s_tx[2].first_serdes = 0
    s_tx[2].last_serdes = 1
    s_tx[3].slice = 0
    s_tx[3].ifg = T.get_device_ifg(1)
    s_tx[3].first_serdes = 4
    s_tx[3].last_serdes = 5

    def choose_slices(self):
        self.s_tx[0].slice = T.choose_active_slices(self.device, self.s_tx[0].slice, [0, 4])
        self.s_tx[1].slice = T.choose_active_slices(self.device, self.s_tx[1].slice, [3, 1, 5])
        self.s_tx[2].slice = T.choose_active_slices(self.device, self.s_tx[2].slice, [1, 5, 3])
        self.s_tx[3].slice = T.choose_active_slices(self.device, self.s_tx[3].slice, [0, 4])

    def setUp(self, create_spa_topology=True):
        super().setUp(create_default_topology=False)
        self.choose_slices()
        self.topology.create_inject_ports()
        self._add_objects_to_keep()

        self.create_packets()

    def create_packets(self):
        in_packet_base_a = Ether(dst=self.DST_MAC, src=self.SRC_MAC_A, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP(src='10.10.10.10', dst='20.20.20.20') / TCP()

        in_packet_base_b = Ether(dst=self.DST_MAC, src=self.SRC_MAC_B, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP(src='10.10.10.10', dst='20.20.20.20') / TCP()

        in_packet_base_c = Ether(dst=self.DST_MAC_A, src=self.SRC_MAC_B, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP(src='10.10.10.10', dst='20.20.20.20') / TCP()

        in_packet_base_d = Ether(dst=self.DST_MAC, src=self.SRC_MAC_A, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IPv6(src='2000::1', dst='2000::2') / TCP()

        out_packet_base_a = Ether(dst=self.DST_MAC, src=self.SRC_MAC_A, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP(src='10.10.10.10', dst='20.20.20.20') / TCP()

        out_packet_base_b = Ether(dst=self.DST_MAC, src=self.SRC_MAC_B, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP(src='10.10.10.10', dst='20.20.20.20') / TCP()

        out_packet_base_c = Ether(dst=self.DST_MAC_A, src=self.SRC_MAC_B, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP(src='10.10.10.10', dst='20.20.20.20') / TCP()

        out_packet_base_d = Ether(dst=self.DST_MAC, src=self.SRC_MAC_A, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IPv6(src='2000::1', dst='2000::2') / TCP()

        self.in_packet_a, self.out_packet_a = pad_input_and_output_packets(in_packet_base_a, out_packet_base_a)
        self.in_packet_b, self.out_packet_b = pad_input_and_output_packets(in_packet_base_b, out_packet_base_b)
        self.in_packet_c, self.out_packet_c = pad_input_and_output_packets(in_packet_base_c, out_packet_base_c)
        self.in_packet_d, self.out_packet_d = pad_input_and_output_packets(in_packet_base_d, out_packet_base_d)

    def create_topology(self, spa_port=None):
        vid1 = self.VLAN
        vid2 = 0x0

        self.m_mac_port = T.mac_port(self, self.device, self.IN_SLICE, self.IN_IFG, self.IN_SERDES_FIRST, self.IN_SERDES_LAST)
        self.m_mac_port.activate()
        self.m_sys_port = T.system_port(self, self.device, self.SYS_PORT_GID_BASE, self.m_mac_port)
        self.m_eth_port = T.sa_ethernet_port(self, self.device, self.m_sys_port)
        self.m_ac_port_sp = self.create_ac_port_on_ethernet_port(self.m_eth_port, self.AC_PORT_GID_BASE, vid1, vid2)

        self.m_spa_port = self.create_spa_port_with_two_system_ports() if spa_port is None else spa_port
        self.eth_port = T.sa_ethernet_port(self, self.device, self.m_spa_port)

        self.m_ac_port_spa = self.create_ac_port_on_ethernet_port(self.eth_port, 143, vid1, vid2)

        self.sw1 = T.switch(self, self.device, 100)

        self.m_ac_port_sp.hld_obj.attach_to_switch(self.sw1.hld_obj)
        self.m_ac_port_spa.hld_obj.attach_to_switch(self.sw1.hld_obj)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        dest_mac = sdk.la_mac_addr_t()
        dest_mac.flat = 0xcafecafecafe
        self.sw1.hld_obj.set_mac_entry(dest_mac, self.m_ac_port_spa.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

    def create_system_port(self, slice, ifg, first_serdes, last_serdes, system_port_gid):
        _mac_port = T.mac_port(self, self.device, slice, ifg, first_serdes, last_serdes)
        _mac_port.activate()
        sys_port = T.system_port(self, self.device, system_port_gid, _mac_port)

        return sys_port

    def create_sys_port_from_phy_port(self, phy_port, system_port_gid):
        return self.create_system_port(
            self.s_tx[phy_port].slice,
            self.s_tx[phy_port].ifg,
            self.s_tx[phy_port].first_serdes,
            self.s_tx[phy_port].last_serdes,
            system_port_gid)

    def create_spa_port_with_two_system_ports(self):
        self.m_mac_port_member_0 = T.mac_port(
            self,
            self.device,
            self.s_tx[0].slice,
            self.s_tx[0].ifg,
            self.s_tx[0].first_serdes,
            self.s_tx[0].last_serdes)
        self.m_mac_port_member_0.activate()
        self.m_sys_port_member_0 = T.system_port(self, self.device, 100, self.m_mac_port_member_0)

        self.m_mac_port_member_1 = T.mac_port(
            self,
            self.device,
            self.s_tx[1].slice,
            self.s_tx[1].ifg,
            self.s_tx[1].first_serdes,
            self.s_tx[1].last_serdes)
        self.m_mac_port_member_1.activate()
        self.m_sys_port_member_1 = T.system_port(self, self.device, 101, self.m_mac_port_member_1)

        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(self.m_sys_port_member_0)
        spa_port.add(self.m_sys_port_member_1)

        return spa_port

    def create_ethernet_port_on_spa_port(self):
        self.m_spa_port = self.create_spa_port_with_two_system_ports()
        eth_port = T.sa_ethernet_port(self, self.device, self.m_spa_port)

        return eth_port

    def create_ac_port_on_system_port(
            self,
            slice,
            ifg,
            first_serdes,
            last_serdes,
            system_port_gid,
            ac_port_gid,
            vid1,
            vid2):

        sys_port = self.create_system_port(slice, ifg, first_serdes, last_serdes, system_port_gid)
        eth_port = T.sa_ethernet_port(self, self.device, sys_port)
        ac_port = self.create_ac_port_on_ethernet_port(eth_port, ac_port_gid, vid1, vid2)

        return ac_port

    def create_ac_port_on_ethernet_port(self, eth_port, ac_port_gid, vid1, vid2):
        ac_port = T.l2_ac_port(self, self.device, ac_port_gid, self.topology.filter_group_def, None, eth_port, None, vid1, vid2)

        return ac_port

    def inject_and_verify_packet_ingress(self, in_packet, out_packet, sender, receiver):
        run_and_compare(
            self,
            self.device,
            in_packet,
            self.s_tx[sender].slice,
            self.s_tx[sender].ifg,
            self.s_tx[sender].first_serdes,
            out_packet,
            self.s_tx[receiver].slice,
            self.s_tx[receiver].ifg,
            self.s_tx[receiver].first_serdes)

    def send_packet(
            self,
            drop,
            spa_port,
            lb_vec_type,
            input_packet,
            input_slice,
            input_ifg,
            input_serdes,
            out_packet):
        dst_mac = T.mac_addr(input_packet[Ether].dst)
        src_mac = T.mac_addr(input_packet[Ether].src)

        hw_lb_vec = sdk.la_lb_vector_t()
        soft_lb_vec = sdk.la_lb_vector_t()
        lb_vec_entry_list = []

        if lb_vec_type == sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP:
            dst_mac = T.mac_addr(input_packet[Ether].dst)
            src_mac = T.mac_addr(input_packet[Ether].src)
            hw_lb_vec.type = sdk.LA_LB_VECTOR_ETHERNET_VLAN_TAG
            hw_lb_vec.ethernet.vlan_id = self.VLAN
            hw_lb_vec.ethernet.da = dst_mac.hld_obj
            hw_lb_vec.ethernet.sa = src_mac.hld_obj
            lb_vec_entry_list.append(hw_lb_vec)

            dip = T.ipv4_addr(input_packet[IP].dst)
            sip = T.ipv4_addr(input_packet[IP].src)
            if decor.is_akpg():
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            else:
                soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
            soft_lb_vec.ipv4.sip = sip.hld_obj.s_addr
            soft_lb_vec.ipv4.dip = dip.hld_obj.s_addr
            soft_lb_vec.ipv4.protocol = input_packet[IP].proto
            lb_vec_entry_list.append(soft_lb_vec)
        elif lb_vec_type == sdk.LA_LB_VECTOR_IPV6_TCP_UDP:
            dst_mac = T.mac_addr(input_packet[Ether].dst)
            src_mac = T.mac_addr(input_packet[Ether].src)
            hw_lb_vec.type = sdk.LA_LB_VECTOR_ETHERNET_VLAN_TAG
            hw_lb_vec.ethernet.vlan_id = self.VLAN
            hw_lb_vec.ethernet.da = dst_mac.hld_obj
            hw_lb_vec.ethernet.sa = src_mac.hld_obj
            lb_vec_entry_list.append(hw_lb_vec)

            dip = split_bits(T.ipv6_addr(input_packet[IPv6].dst).to_num(), 32)
            sip = split_bits(T.ipv6_addr(input_packet[IPv6].src).to_num(), 32)
            if decor.is_akpg():
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV6_L4
            else:
                soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            soft_lb_vec.ipv6.sip = sip
            soft_lb_vec.ipv6.dip = dip
            soft_lb_vec.ipv6.next_header = input_packet[IPv6].nh
            soft_lb_vec.ipv6.flow_label = input_packet[IPv6].fl
            soft_lb_vec.ipv6.src_port = input_packet[TCP].sport
            soft_lb_vec.ipv6.dest_port = input_packet[TCP].dport
            lb_vec_entry_list.append(soft_lb_vec)

        # Actual member (from nsim):
        # pacific: member = 'dspa_member_id_result.id' value.
        #
        # gibraltar: member = entry * 4 + addr, where:
        # entry - resolution_unified_stage_em_table_result.entry_select
        # addr - resolution_unified_stage_em_table_result.addr[11:0]
        # (corresponds to sdk's struct 'resolution_assoc_data_table_addr_t')
        # table inserts correspond to - 'stage3_assoc_data_table[0]'
        #
        # Expected member (from lb emulator):
        # out_member = self.device.get_forwarding_load_balance_stage(self.spa_port.hld_obj, lb_vec)
        # print('out_member = ' + str(out_member))

        out_dest_chain = self.device.get_forwarding_load_balance_chain(spa_port.hld_obj, lb_vec_entry_list)

        # For Debug:
        # display_forwarding_load_balance_chain(self.spa_port.hld_obj, out_dest_chain)

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)

        out_dsp = out_dest_chain[-1].downcast()

        if drop:
            run_and_drop(self, self.device,
                         input_packet, input_slice, input_ifg, input_serdes)
        else:
            run_and_compare(self, self.device,
                            input_packet, input_slice, input_ifg, input_serdes,
                            out_packet, out_dsp.get_slice(), out_dsp.get_ifg(), out_dsp.get_base_serdes())
