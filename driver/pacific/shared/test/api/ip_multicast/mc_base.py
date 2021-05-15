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

import sim_utils
import topology as T
from leaba import sdk

import smart_slices_choise as ssch


class mc_base:

    SA = T.mac_addr('be:ef:5d:35:7a:35')
    MC_GROUP_GID = 0x13
    MC_EMPTY_GROUP_GID = 0x14
    HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
    TTL = 127
    PUNT_VLAN = 0xB13
    PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
    INJECT_SLICE = T.get_device_slice(3)
    INJECT_IFG = 0
    INJECT_PIF_FIRST = T.get_device_first_serdes(8)
    INJECT_SP_GID = 20
    MIRROR_CMD_GID = 9
    MIRROR_GID_INGRESS_OFFSET = 32
    MIRROR_GID_EGRESS_OFFSET = 0
    MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
    MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

    MIRROR_VLAN = 0xA12
    BRIDGE_SLICE = T.get_device_slice(4)  # slice in which bridge copies will be recevied
    BRIDGE_IFG = 0
    BRIDGE_SERDES1 = 10
    BRIDGE_SERDES2 = 12
    BRIDGE_SYS_PORT1_GID = 0x28
    BRIDGE_SYS_PORT2_GID = 0x29
    BRIDGE_AC_PORT1_GID = 0x213
    BRIDGE_AC_PORT2_GID = 0x214
    NH_MAC = T.RX_MAC
    NH_GID = 0x691
    PRIVATE_DATA = 0x1234567890abcdef
    SERDES4 = T.get_device_first_serdes(4)
    SERDES5 = T.get_device_last_serdes(5)
    SERDES6 = T.get_device_next_first_serdes(6)
    SERDES7 = T.get_device_next_last_serdes(7)
    VLAN0 = 0
    RX_SYS_PORT_GID = 0x10
    RX_AC_PORT_GID = 0x100
    MC_GROUP_ID = 0x20

    class extra_packet_struct:
        def __init__(self, packet, slice_id, ifg, serdes):
            self.packet = packet
            self.slice_id = slice_id
            self.ifg = ifg
            self.serdes = serdes

    def initSnoopsAndTraps(device, punt_dest, mirror_cmd):
        device.set_trap_configuration(sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS, 1, None, punt_dest, False, False, True, 0)
        device.set_trap_configuration(sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL, 2, None, punt_dest, False, False, True, 0)
        device.set_trap_configuration(sdk.LA_EVENT_L3_IP_MC_DROP, 3, None, None, True, False, True, 0)

        device.set_snoop_configuration(sdk.LA_EVENT_L3_IP_MC_SNOOP_DC_PASS, 0, False, False, mirror_cmd)
        device.set_snoop_configuration(sdk.LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS, 1, False, False, mirror_cmd)
        device.set_snoop_configuration(sdk.LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL, 1, False, False, mirror_cmd)

    @classmethod
    def rechoose_odd_inject_slice(cls, device):
        ssch.rechoose_odd_inject_slice(cls, device)

    def create_l2_ports(self):
        # create l2ac ports on rx_switch (on ingress switch)
        self.rx_mac_port1 = T.mac_port(self, self.device, T.RX_SLICE, T.RX_IFG, mc_base.SERDES4, mc_base.SERDES5)
        self.rx_sys_port1 = T.system_port(self, self.device, mc_base.RX_SYS_PORT_GID, self.rx_mac_port1)
        self.rx_eth_port1 = T.sa_ethernet_port(self, self.device, self.rx_sys_port1)
        self.rx_ac_port1 = T.l2_ac_port(self, self.device, mc_base.RX_AC_PORT_GID, None,
                                        self.topology.rx_switch, self.rx_eth_port1, T.RX_MAC, T.RX_L2_AC_PORT_VID1, mc_base.VLAN0)
        self.rx_mac_port1.activate()

        self.rx_mac_port2 = T.mac_port(self, self.device, T.RX_SLICE, T.RX_IFG, mc_base.SERDES6, mc_base.SERDES7)
        self.rx_sys_port2 = T.system_port(self, self.device, mc_base.RX_SYS_PORT_GID + 1, self.rx_mac_port2)
        self.rx_eth_port2 = T.sa_ethernet_port(self, self.device, self.rx_sys_port2)
        self.rx_ac_port2 = T.l2_ac_port(self, self.device, mc_base.RX_AC_PORT_GID + 1, None,
                                        self.topology.rx_switch, self.rx_eth_port2, T.RX_MAC, T.RX_L2_AC_PORT_VID1, mc_base.VLAN0)
        self.rx_mac_port2.activate()

        # create flood destination for rx_switch
        self.rx_sw_mc_group = self.device.create_l2_multicast_group(mc_base.MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.rx_sw_mc_group)
        self.rx_sw_mc_group.add(self.rx_ac_port1.hld_obj, self.rx_sys_port1.hld_obj)
        self.rx_sw_mc_group.add(self.rx_ac_port2.hld_obj, self.rx_sys_port2.hld_obj)
        self.topology.rx_switch.hld_obj.set_flood_destination(self.rx_sw_mc_group)
