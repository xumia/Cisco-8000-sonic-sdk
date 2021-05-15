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
    MIRROR_VLAN = 0xA12
    BRIDGE_SLICE = T.get_device_slice(4)  # slice in which bridge copies will be recevied
    BRIDGE_IFG = 0
    BRIDGE_SERDES1 = T.get_device_next_first_serdes(10)
    BRIDGE_SERDES2 = T.get_device_next2_first_serdes(12)
    BRIDGE_SYS_PORT1_GID = 0x28
    BRIDGE_SYS_PORT2_GID = 0x29
    BRIDGE_AC_PORT1_GID = 0x213
    BRIDGE_AC_PORT2_GID = 0x214
    NH_MAC = T.RX_MAC
    NH_GID = 0x691
    PRIVATE_DATA = 0x1234567890abcdef
    SERDES4 = T.get_device_next3_first_serdes(4)
    SERDES5 = T.get_device_next3_last_serdes(5)
    SERDES6 = T.get_device_next4_first_serdes(6)
    SERDES7 = T.get_device_next4_last_serdes(7)
    VLAN0 = 0
    RX_SYS_PORT_GID = 0x10
    RX_AC_PORT_GID = 0x100
    MC_GROUP_ID = 0x20
    INPUT_LABEL_TAIL = sdk.la_mpls_label()
    INPUT_LABEL_TAIL.label = 0x65
    LPTS_FLOW_TYPE_V4 = 10
    LPTS_PUNT_CODE_V4 = 120
    LPTS_FLOW_TYPE_V6 = 12
    LPTS_PUNT_CODE_V6 = 122
    PIM_TYPE = 0x67

    def initSnoopsAndTraps(device, punt_dest, mirror_cmd):
        device.set_trap_configuration(sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS, 1, None, punt_dest, False, False, True, 0)
        device.set_trap_configuration(sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL, 2, None, punt_dest, False, False, True, 0)
        device.set_trap_configuration(sdk.LA_EVENT_L3_IP_MC_DROP, 3, None, None, True, False, True, 0)

        device.set_snoop_configuration(sdk.LA_EVENT_L3_IP_MC_SNOOP_DC_PASS, 0, False, False, mirror_cmd)
        device.set_snoop_configuration(sdk.LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS, 1, False, False, mirror_cmd)
        device.set_snoop_configuration(sdk.LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL, 1, False, False, mirror_cmd)


class ipv4_mc:

    @staticmethod
    def get_mc_sa_addr_str(ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        sa_addr_str = '01:00:5e'
        sa_addr_str += ':%02x' % (0x7f & int(octets[1]))
        for o in octets[2:]:
            sa_addr_str += ':%02x' % (int(o))
        return sa_addr_str


class ipv6_mc:
    @staticmethod
    def get_mc_sa_addr_str(ip_addr):
        shorts = ip_addr.addr_str.split(':')
        assert(len(shorts) == T.ipv6_addr.NUM_OF_SHORTS)
        sa_addr_str = '33:33'
        for s in shorts[-2:]:
            sl = int(s, 16) & 0xff
            sh = (int(s, 16) >> 8) & 0xff
            sa_addr_str += ':%02x:%02x' % (sh, sl)
        return sa_addr_str
