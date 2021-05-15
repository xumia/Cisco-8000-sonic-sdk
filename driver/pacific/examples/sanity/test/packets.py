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


from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

import network_objects
from sanity_constants import *

###
# Packet definition for sanity test
###


SRC_MAC = network_objects.mac_addr('44:44:44:44:44:44')
DST_MAC = network_objects.mac_addr('22:22:22:22:22:22')
TTL = 128
PCP = 0
DEI = 0
SIP = network_objects.ipv4_addr('12.10.12.10')
DIP = network_objects.ipv4_addr('82.81.95.250')


def get_input_packet(expected_vid1):
    packet = \
        Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) / \
        Dot1Q(prio=PCP, id=DEI, vlan=expected_vid1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / TCP() / \
        Raw(load=0x123456)

    return packet


def get_expected_packet(expected_vid1, expected_ttl=TTL):

    packet = \
        Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=TPID_Dot1Q) / \
        Dot1Q(prio=0, id=0, vlan=expected_vid1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=expected_ttl) / TCP() / \
        Raw(load=0x123456)

    return packet
