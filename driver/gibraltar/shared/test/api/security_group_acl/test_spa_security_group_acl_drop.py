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

import topology as T
from security_group_acl_spa_base import *
import decor


@unittest.skipIf(not decor.is_gibraltar(), "Test is only enabled on Gibraltar")
class test_spa_security_group_acl_drop(security_group_acl_spa_base):

    def setUp(self, create_spa_topology=True):
        super().setUp(create_spa_topology=False)

    def test_security_group_policy_acl_on_spa_port(self):
        vid1 = self.VLAN
        vid2 = 0x0

        # Create RX ac port
        _mac_port = T.mac_port(self, self.device, self.IN_SLICE, self.IN_IFG, self.IN_SERDES_FIRST, self.IN_SERDES_LAST)
        _mac_port.activate()
        sys_port = T.system_port(self, self.device, self.SYS_PORT_GID_BASE, _mac_port)
        rx_eth_port = T.sa_ethernet_port(self, self.device, sys_port)
        ac_port_sp = self.create_ac_port_on_ethernet_port(rx_eth_port, self.AC_PORT_GID_BASE, vid1, vid2)

        # Create TX SPA
        spa_port = T.spa_port(self, self.device, 123)
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            self.s_tx[0].slice,
            self.s_tx[0].ifg,
            self.s_tx[0].first_serdes,
            self.s_tx[0].last_serdes)
        mac_port_member_1.activate()
        sys_port_member_1 = T.system_port(self, self.device, 10, mac_port_member_1)

        mac_port_member_2 = T.mac_port(
            self,
            self.device,
            self.s_tx[1].slice,
            self.s_tx[1].ifg,
            self.s_tx[1].first_serdes,
            self.s_tx[1].last_serdes)
        mac_port_member_2.activate()
        sys_port_member_2 = T.system_port(self, self.device, 11, mac_port_member_2)

        mac_port_member_3 = T.mac_port(
            self,
            self.device,
            self.s_tx[2].slice,
            self.s_tx[2].ifg,
            self.s_tx[2].first_serdes,
            self.s_tx[2].last_serdes)
        mac_port_member_3.activate()
        sys_port_member_3 = T.system_port(self, self.device, 12, mac_port_member_3)
        mac_port_member_4 = T.mac_port(
            self,
            self.device,
            self.s_tx[3].slice,
            self.s_tx[3].ifg,
            self.s_tx[3].first_serdes,
            self.s_tx[3].last_serdes)
        mac_port_member_4.activate()
        sys_port_member_4 = T.system_port(self, self.device, 14, mac_port_member_4)

        # add system ports to SPA
        spa_port.add(sys_port_member_1)
        spa_port.add(sys_port_member_2)

        # Create TX Ethernet port over the SPA
        tx_eth_port = T.sa_ethernet_port(self, self.device, spa_port)

        # Create TX ac port over the SPA eth_port
        ac_port_spa = self.create_ac_port_on_ethernet_port(tx_eth_port, 143, vid1, vid2)

        # Create Switch
        sw1 = T.switch(self, self.device, 100)

        # Attach RX and TX ac ports to switch
        ac_port_sp.hld_obj.attach_to_switch(sw1.hld_obj)
        ac_port_spa.hld_obj.attach_to_switch(sw1.hld_obj)

        # Add 'cafecafecafe' to the MAC table, going to SPA ac port
        dest_mac = sdk.la_mac_addr_t()
        dest_mac.flat = 0xcafecafecafe
        sw1.hld_obj.set_mac_entry(dest_mac, ac_port_spa.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        # Enable dsp enforcement on switch and spa port
        self.device.set_sda_mode(True)
        rx_eth_port.hld_obj.set_security_group_tag(100)
        tx_eth_port.hld_obj.set_security_group_tag(0x222)
        tx_eth_port.hld_obj.set_security_group_policy_enforcement(True)
        sw1.hld_obj.set_security_group_policy_enforcement(True)

        # Create SGACL and apply it on the cell
        self.sgacl_key_profile = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_SGACL, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_SECURITY_GROUP, 0)
        self.sgacl_command_profile = self.device.create_acl_command_profile(sdk.LA_SGACL_COMMAND)

        sgt = 100
        dgt = 101
        cell = self.device.create_security_group_cell(sgt, dgt, sdk.la_ip_version_e_IPV4)
        cell.set_monitor_mode(True)

        # Install IPv4 prefix
        self.DIP_V4 = T.ipv4_addr('20.20.20.20')
        self.prefix = sdk.la_ipv4_prefix_t()
        self.prefix.addr.s_addr = self.DIP_V4.to_num()
        self.prefix.length = 32
        self.default_prefix = sdk.la_ipv4_prefix_t()
        self.default_prefix.length = 0

        self.g_vrf = self.device.create_vrf(0)
        self.g_vrf.add_security_group_tag(self.default_prefix, 0)
        self.g_vrf.add_security_group_tag(self.prefix, dgt)

        # Create sgacl
        sgacl = self.device.create_acl(self.sgacl_key_profile, self.sgacl_command_profile)

        self.assertNotEqual(sgacl, None)
        count = sgacl.get_count()
        self.assertEqual(count, 0)

        cmds = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_cmd_type_e_SGACL
        action.data.drop = True
        cmds.append(action)

        k = []
        k_all = []
        f = sdk.la_acl_field()

        f.type = sdk.la_acl_field_type_e_PROTOCOL
        f.val.protocol = sdk.la_l4_protocol_e_TCP
        f.mask.protocol = 0xff
        k.append(f)
        k_all.append(f)

        f.type = sdk.la_acl_field_type_e_SGACL_BINCODE
        f.val.sgacl_bincode = 0x1
        f.mask.sgacl_bincode = 0x1
        k.append(f)
        k_all.append(f)

        count_pre = sgacl.get_count()
        sgacl.insert(0, k, cmds)
        count_post = sgacl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        cell.set_acl(sgacl)
        cell.set_bincode(1)

        # Inject ipv4 packets SP-AC -> SPA-AC, packets should be dropped
        self.send_packet(
            True,
            spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)
        self.send_packet(
            True,
            spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_b,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_b)

        # Inject ipv6 packets SP-AC -> SPA-AC, this should not be dropped
        self.send_packet(
            False,
            spa_port,
            sdk.LA_LB_VECTOR_IPV6_TCP_UDP,
            self.in_packet_d,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_d)

        # Add system ports to SPA, enforcement should set automatically
        spa_port.add(sys_port_member_3)
        spa_port.add(sys_port_member_4)

        # Disable enforecemnt on the spa ethernet port
        tx_eth_port.hld_obj.set_security_group_policy_enforcement(False)

        # Inject ipv4 packets SP-AC -> SPA-AC, packets should not be dropped
        self.send_packet(
            False,
            spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)
        self.send_packet(
            False,
            spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_b,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_b)
        self.send_packet(
            False,
            spa_port,
            sdk.LA_LB_VECTOR_IPV6_TCP_UDP,
            self.in_packet_d,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_d)

        # Enable enforecemnt on the spa ethernet port
        tx_eth_port.hld_obj.set_security_group_policy_enforcement(True)

        # Inject ipv4 packets SP-AC -> SPA-AC, packets should be dropped
        self.send_packet(
            True,
            spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)
        self.send_packet(
            True,
            spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_b,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_b)

        spa_port.remove(sys_port_member_1)
        spa_port.remove(sys_port_member_2)

        # send bidirectional traffic on removed member port AC, check traffic should not be dropped
        mac_port_member_1.activate()
        rx_eth_port_1 = T.sa_ethernet_port(self, self.device, sys_port_member_1)
        ac_port_sp_1 = self.create_ac_port_on_ethernet_port(rx_eth_port_1, self.AC_PORT_GID_BASE + 1, vid1, vid2)
        # Attach ac_port_sp_1 ports to switch
        ac_port_sp_1.hld_obj.attach_to_switch(sw1.hld_obj)

        dest_mac.flat = 0xcafecafecaff
        sw1.hld_obj.set_mac_entry(dest_mac, ac_port_sp_1.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        rx_eth_port_1.hld_obj.set_security_group_policy_enforcement(True)

        # Inject packets SPA-AC -> SP-AC (port created on the removed system port from spa_port)
        self.inject_and_verify_packet_ingress(self.in_packet_c, self.out_packet_c, 3, 0)

        # Inject packets SP-AC (port created on the removed system port from spa_port) -> SPA-AC
        sw1.hld_obj.set_mac_entry(dest_mac, ac_port_spa.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.inject_and_verify_packet_ingress(self.in_packet_c, self.out_packet_c, 0, 3)

        cell.clear_acl()
        self.device.destroy(sgacl)
        self.device.destroy(cell)


if __name__ == '__main__':
    unittest.main()
