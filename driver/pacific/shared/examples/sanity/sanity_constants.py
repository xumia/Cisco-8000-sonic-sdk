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

###
# Constants for sanity tests
###

TPID_Dot1Q = 0x8100                                # VLAN-tagged frame (802.1q) and Shortest Path Bridging (802.1aq)
TPID_IPv4 = 0x0800                                 # IPv4
TPID_Inject = 0x7103                               # Inject
TPID_Punt = 0x7102                                 # Punt

NUM_SLICES_PER_DEVICE = 6
NUM_TC_CLASSES = 8
NUM_IFGS_PER_SLICE = 2
NUM_PIF_PER_IFG = 18
NUM_PIF_PER_DEVICE = NUM_PIF_PER_IFG * NUM_IFGS_PER_SLICE * NUM_SLICES_PER_DEVICE
NUM_PIF_PER_SLICE = NUM_IFGS_PER_SLICE * NUM_PIF_PER_IFG

CHAR_BIT = 8
BYTES_NUM_IN_IPv4_ADDR = 4

KILO = 1000
MEGA = 1000 * KILO
GIGA = 1000 * MEGA

VOQ_SET_SIZE = 8
