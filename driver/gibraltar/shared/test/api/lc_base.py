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
from scapy.all import *
import unittest
from leaba import sdk
import topology as T

INGRESS_DEVICE_ID = 1
INGRESS_RX_SLICE = 2
INGRESS_RX_IFG = 0
INGRESS_RX_SERDES_FIRST = 4
INGRESS_RX_SERDES_LAST = INGRESS_RX_SERDES_FIRST + 1

INGRESS_TX_SLICE = 4
INGRESS_TX_IFG = 1
INGRESS_TX_SERDES_FIRST = 2
INGRESS_TX_SERDES_LAST = INGRESS_TX_SERDES_FIRST + 1

EGRESS_DEVICE_ID = 10

EGRESS_RX_SLICE = 4
EGRESS_RX_IFG = 1
EGRESS_RX_SERDES_FIRST = 2
EGRESS_RX_SERDES_LAST = EGRESS_RX_SERDES_FIRST + 1

EGRESS_TX_SLICE = 2
EGRESS_TX_IFG = 0
EGRESS_TX_SERDES_FIRST = 12
EGRESS_TX_SERDES_LAST = EGRESS_TX_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 23
EGRESS_SYS_PORT_GID = SYS_PORT_GID_BASE + 1

GID_BASE = 10
AC_PORT_GID_BASE = GID_BASE

SWITCH_GID = 100

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9

VRF_GID = 0x3ee
IN_L3_AC_PORT_MAC = "40:40:40:40:40:40"
OUT_L3_AC_PORT_MAC = "40:41:42:43:44:45"

PRIVATE_DATA = 0xfedcba9876543210
SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')
TTL = 255
