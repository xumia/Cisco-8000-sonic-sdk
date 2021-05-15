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

import sys
import json
import re
import gzip
import time

from scapy.all import *
from packet_test_defs import *
import npu_host_packet_gen
from binascii import hexlify, unhexlify
import test_nsim_providercli as nsim
import test_racli as ra
import nplapicli as nplapi
import sim_utils

from leaba import sdk
from leaba import debug
import lldcli
import topology

# List of all NPU block IDs
pacific_npu_blocks = [
    lldcli.pacific_tree.LLD_BLOCK_ID_IDB2_TOP,
    lldcli.pacific_tree.LLD_BLOCK_ID_IDB1_TOP,
    lldcli.pacific_tree.LLD_BLOCK_ID_IDB0_TOP,
    lldcli.pacific_tree.LLD_BLOCK_ID_IDB2_RES,
    lldcli.pacific_tree.LLD_BLOCK_ID_IDB1_RES,
    lldcli.pacific_tree.LLD_BLOCK_ID_IDB0_RES,
    lldcli.pacific_tree.LLD_BLOCK_ID_CDB_TOP,
    lldcli.pacific_tree.LLD_BLOCK_ID_CDB_CORE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_CDB_CORE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_CDB_CORE2,
    lldcli.pacific_tree.LLD_BLOCK_ID_CDB_CORE3,
    lldcli.pacific_tree.LLD_BLOCK_ID_CDB_CORE4,
    lldcli.pacific_tree.LLD_BLOCK_ID_CDB_CORE5,
    lldcli.pacific_tree.LLD_BLOCK_ID_CDB_CORE6,
    lldcli.pacific_tree.LLD_BLOCK_ID_CDB_CORE7,
    lldcli.pacific_tree.LLD_BLOCK_ID_SDB_ENC,
    lldcli.pacific_tree.LLD_BLOCK_ID_SDB_MAC,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_CDB_CACHE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_CDB_CACHE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_CDB_CACHE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_CDB_CACHE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_CDB_CACHE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_CDB_CACHE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FWD,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FWD,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FWD,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FWD,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FWD,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FWD,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_SNA,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_SNA,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_SNA,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_SNA,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_SNA,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_SNA,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_TERM,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_TERM,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_TERM,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_TERM,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_TERM,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_TERM,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FI_ENG0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FI_ENG1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FI_ENG2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FI_ENG3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FI_ENG4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FI_ENG5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FI_ENG6,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FI_ENG7,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FI_ENG0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FI_ENG1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FI_ENG2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FI_ENG3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FI_ENG4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FI_ENG5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FI_ENG6,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FI_ENG7,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FI_ENG0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FI_ENG1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FI_ENG2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FI_ENG3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FI_ENG4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FI_ENG5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FI_ENG6,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FI_ENG7,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FI_ENG0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FI_ENG1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FI_ENG2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FI_ENG3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FI_ENG4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FI_ENG5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FI_ENG6,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FI_ENG7,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FI_ENG0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FI_ENG1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FI_ENG2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FI_ENG3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FI_ENG4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FI_ENG5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FI_ENG6,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FI_ENG7,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FI_ENG0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FI_ENG1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FI_ENG2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FI_ENG3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FI_ENG4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FI_ENG5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FI_ENG6,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FI_ENG7,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_FI_STAGE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_FI_STAGE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_FI_STAGE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_FI_STAGE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_FI_STAGE,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_FI_STAGE,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP2,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP3,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP4,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP5,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP0_CLUSTER0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP0_CLUSTER1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP1_CLUSTER0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP1_CLUSTER1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP2_CLUSTER0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP2_CLUSTER1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP3_CLUSTER0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP3_CLUSTER1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP4_CLUSTER0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP4_CLUSTER1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP5_CLUSTER0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP5_CLUSTER1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_NPE2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_NPE3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_NPE4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP0_NPE5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_NPE2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_NPE3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_NPE4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP1_NPE5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_NPE2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_NPE3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_NPE4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP2_NPE5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_NPE2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_NPE3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_NPE4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP3_NPE5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_NPE2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_NPE3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_NPE4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP4_NPE5,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_NPE2,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_NPE3,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_NPE4,
    lldcli.pacific_tree.LLD_BLOCK_ID_RXPP5_NPE5,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP0_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP0_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP1_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP1_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP2_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP2_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP3_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP3_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP4_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP4_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP5_NPE0,
    lldcli.pacific_tree.LLD_BLOCK_ID_TXPP5_NPE1,
    lldcli.pacific_tree.LLD_BLOCK_ID_NPUH_NPE,
    lldcli.pacific_tree.LLD_BLOCK_ID_NPUH_FI,
    lldcli.pacific_tree.LLD_BLOCK_ID_NPUH,
]

gb_npu_blocks = [
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_TERM,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FWD,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_CDB_CACHE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_SNA,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FI_STAGE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FLC_DB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FLC_QUEUES,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_NPE2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_NPE3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_NPE4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_NPE5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FI_ENG0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FI_ENG1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FI_ENG2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FI_ENG3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FI_ENG4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FI_ENG5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FI_ENG6,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP0_FI_ENG7,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_TERM,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FWD,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_CDB_CACHE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_SNA,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FI_STAGE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FLC_DB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FLC_QUEUES,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_NPE2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_NPE3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_NPE4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_NPE5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FI_ENG0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FI_ENG1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FI_ENG2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FI_ENG3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FI_ENG4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FI_ENG5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FI_ENG6,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP1_FI_ENG7,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_TERM,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FWD,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_CDB_CACHE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_SNA,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FI_STAGE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FLC_DB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FLC_QUEUES,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_NPE2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_NPE3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_NPE4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_NPE5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FI_ENG0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FI_ENG1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FI_ENG2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FI_ENG3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FI_ENG4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FI_ENG5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FI_ENG6,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP2_FI_ENG7,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_TERM,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FWD,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_CDB_CACHE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_SNA,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FI_STAGE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FLC_DB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FLC_QUEUES,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_NPE2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_NPE3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_NPE4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_NPE5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FI_ENG0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FI_ENG1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FI_ENG2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FI_ENG3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FI_ENG4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FI_ENG5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FI_ENG6,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP3_FI_ENG7,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_TERM,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FWD,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_CDB_CACHE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_SNA,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FI_STAGE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FLC_DB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FLC_QUEUES,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_NPE2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_NPE3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_NPE4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_NPE5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FI_ENG0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FI_ENG1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FI_ENG2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FI_ENG3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FI_ENG4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FI_ENG5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FI_ENG6,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP4_FI_ENG7,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_TERM,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FWD,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_CDB_CACHE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_SNA,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FI_STAGE,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FLC_DB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FLC_QUEUES,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_NPE2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_NPE3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_NPE4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_NPE5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FI_ENG0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FI_ENG1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FI_ENG2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FI_ENG3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FI_ENG4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FI_ENG5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FI_ENG6,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_RXPP5_FI_ENG7,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_CDB_TOP,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_CDB_CORE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_CDB_CORE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_CDB_CORE2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_CDB_CORE3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_CDB_CORE4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_CDB_CORE5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_CDB_CORE6,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_CDB_CORE7,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP0_CLUSTER0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP0_CLUSTER1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP0_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP0_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP1_CLUSTER0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP1_CLUSTER1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP1_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP1_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP2,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP2_CLUSTER0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP2_CLUSTER1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP2_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP2_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP3,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP3_CLUSTER0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP3_CLUSTER1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP3_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP3_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP4,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP4_CLUSTER0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP4_CLUSTER1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP4_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP4_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP5,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP5_CLUSTER0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP5_CLUSTER1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP5_NPE0,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_TXPP5_NPE1,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_IDB0_ENCDB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_IDB0_MACDB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_IDB0_RES,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_IDB1_ENCDB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_IDB1_MACDB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_IDB1_RES,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_IDB2_ENCDB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_IDB2_MACDB,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_IDB2_RES,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_NPUH,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_NPUH_FI,
    lldcli.gibraltar_tree.LLD_BLOCK_ID_NPUH_NPE
]


#
# Compare RTL simulator memory image vs expected command file.
#


def compare_vs_expected(ldevice, expected_cmd_file):

    archive = gzip.open(expected_cmd_file, 'rt')
    lines = archive.readlines()
    archive.close()

    print("\n-I- Compare simulator memory vs %s" % expected_cmd_file)

    remark_regex = r'^#'
    command_regex = r'^write_\S*(mem|reg) (\S+) (\d+) (\S+)'

    # Build commands map. Last one is the one, which determines value.
    # Therefore, in case of multiple writes to the same address, we take the last one.
    commands = {}
    last_remark_line = ""
    line_count = 0
    for line in lines:
        if re.search(remark_regex, line):
            last_remark_line = line.rstrip()
            continue

        match = re.search(command_regex, line)
        if not match:
            continue

        # add write command
        type = match.group(1)
        addr = int(match.group(2), 16)
        val = match.group(4)
        commands[addr] = {"type": type, "val": val, "line": line_count, "high_level_cmd": last_remark_line}

        line_count += 1

    # Now check the values.
    res = True
    for addr in commands.keys():
        command = commands[addr]

        hl_cmd = command['high_level_cmd']
        exp_val = command['val']
        line = command['line']
        type = command['type']
        is_mem = True if type == 'mem' else False

        val = ra.ra_simulator_check_address(ldevice, addr, exp_val, is_mem)
        val_int = int(val, 16)
        exp_val_int = int(exp_val, 16)
        if (val_int == exp_val_int):
            continue

        # Diff - report it
        print("-E- diff type=%s, line=%8d, addr=%011x, test=%s, expected=%s, from: %s" % (type, line, addr, val, exp_val, hl_cmd))
        res = False

    return res


#
# Generates forward destinations file, expected by npu host injection flow.
#
class forward_destinations_file_template:
    TX_CUD = hex(0xffffff)
    NEW_FWD_DESTINATION_LINE = '##### FORWARDING-DESTINATION-CONFIGURATION #####'

    @classmethod
    def generate_file(cls, la_device, filename):
        objs = la_device.get_objects()
        lines_to_write = []
        for o in objs:
            o_type = o.type()
            if o_type == sdk.la_object.object_type_e_SYSTEM_PORT:
                lines_to_write += cls.append_dsp_to_file(o)
            elif o_type == sdk.la_object.object_type_e_VOQ_SET:
                lines_to_write += cls.append_voq_to_file(o)
            elif o_type == sdk.la_object.object_type_e_L2_MULTICAST_GROUP or o_type == sdk.la_object.object_type_e_IP_MULTICAST_GROUP:
                lines_to_write += cls.append_mc_to_file(o)

        with open(filename, 'w+') as out_file:
            out_file.writelines('\n'.join(lines_to_write))

    @classmethod
    def append_dsp_to_file(cls, dsp):
        gid = dsp.get_gid()
        tm_dest_prefix = 0xd
        tm_fwd_dest = (tm_dest_prefix << 16) | gid

        lines_to_write = []
        lines_to_write.append(cls.NEW_FWD_DESTINATION_LINE)
        lines_to_write.append('tm_fwd_dest: {fd}'.format(fd=hex(tm_fwd_dest)))
        lines_to_write.append('dest_type: DSP')
        lines_to_write.append('gid: {g}'.format(g=gid))
        lines_to_write.append('num_of_members: 1')
        lines_to_write.append('member_id: 0 (out of total 1 members)')

        indentation = ' ' * 4

        lines_to_write.append('{ind}gid: {g}'.format(g=gid, ind=indentation))
        lines_to_write.append('{ind}dest-device: {devid}'.format(devid=dsp.get_device().get_id(), ind=indentation))
        lines_to_write.append('{ind}dest-slice: {sid}'.format(sid=dsp.get_slice(), ind=indentation))
        lines_to_write.append('{ind}dest-ifg: {ifg}'.format(ifg=dsp.get_ifg(), ind=indentation))
        lines_to_write.append('{ind}dest-pif: {pif}'.format(pif=dsp.get_base_pif(), ind=indentation))
        lines_to_write.append('{ind}tx-cud: {tx_cud}'.format(tx_cud=cls.TX_CUD, ind=indentation))

        return lines_to_write

    @classmethod
    def append_mc_to_file(cls, mcg):
        lines_to_write = []
        tm_dest_prefix = 0xf
        return lines_to_write

    @classmethod
    def append_voq_to_file(cls, voq_set):
        lines_to_write = []
        tm_dest_prefix = 0xe
        return lines_to_write

#
# Generates packet file, expected by npu host injection flow.
#


class npu_inject_packet_file_template:

    prefix = '''def inject_packet(pkt_injection_module):'''

    file_line = '''
                ##################################
                ########## INPUT PACKET ##########
                ##################################
                #--> packet_name = sdk_packet_flow_%(flow_id)d_pkt_%(packet_id)d
                flow_id = %(flow_id)d
                pkt_id = %(packet_id)d
                pkt = '%(packet)s'
                slice_id = %(slice_id)d # NOTE: in case using inject up, this is the slice of inject_up packet
                ifg = %(ifg)d   # NOTE: in case using inject up, this is the ifg of inject_up packet
                pif = %(pif)d   # NOTE: in case using inject up, this is the pif of inject_up packet
                pkt_injection_module.inject_packet(flow_id, pkt_id, pkt, slice_id, ifg, pif)
    '''

    suffix = ''''''

    @classmethod
    def generate_file(cls, file_name, packets):

        fd = open(file_name, 'w')

        print(cls.prefix, file=fd)
        for packet in packets:
            print(cls.file_line % packet, file=fd)
        print(cls.suffix, file=fd)

        fd.close()


class npu_extract_packet_file_template:

    prefix = '''def expected_packet(pkt_extraction_module):'''

    file_line = '''
                ##################################
                ######### EXPECTED PACKET ########
                ##################################
                #--> packet_name = sdk_packet_flow_%(flow_id)d_pkt_%(packet_id)d
                flow_id = %(flow_id)d
                pkt_id = %(packet_id)d
                pkt = '%(packet)s'
                slice_id = %(slice_id)d
                ifg = %(ifg)d
                pif = %(pif)d
                pkt_extraction_module.add_expected_packet(flow_id, pkt_id, pkt, slice_id, ifg, pif)
    '''

    suffix = ''''''

    @classmethod
    def generate_file(cls, file_name, packets):

        fd = open(file_name, 'w')

        print(cls.prefix, file=fd)
        for packet in packets:
            print(cls.file_line % packet, file=fd)
        print(cls.suffix, file=fd)

        fd.close()


# Get system port GID from physical location (slice, ifg, pif)
# We assume no port extender and only one system_port exists on this (slice, ifg, pif)
def get_port_gid(device, slice, ifg, pif):
    la_objects = device.get_objects()
    for la_obj in la_objects:
        if (la_obj.type() != sdk.la_object.object_type_e_SYSTEM_PORT):
            continue

        sys_port = la_obj.downcast()
        sys_port_slice = sys_port.get_slice()
        sys_port_ifg = sys_port.get_ifg()
        sys_port_pif = sys_port.get_base_pif()

        if ((sys_port_slice == slice) and (sys_port_ifg == ifg) and (sys_port_pif == pif)):
            return sys_port.get_gid()

    # Should not get here
    return 0


class device_handlers_class:
    def __init__(self, la_dev):
        self.la_dev = la_dev
        self.ll_device = la_dev.get_ll_device()
        self.tree = sim_utils.get_device_tree(self.ll_device)
        self.debug_device = debug.debug_device(la_dev)

#
# Sim provider interface, implementing simulator control interface for NPU host injection flow.
#


class ra_npu_rtl_sim_provider:

    def __init__(self, device, use_socket, inject_from_npu_host, add_inject_up_header_if_inject_from_npuh=True):
        # Device handlers
        self.dev_h = device_handlers_class(device)
        # Sim options and provider
        self.use_socket = use_socket
        self.provider = ra.ra_sim_provider()
        # Packets and TM Database
        self.packet_inject_file_name = './packet_inject.py'
        self.packet_extract_file_name = './packet_extract.py'
        self.fwd_destinations_file_name = './tm_database.txt'
        self.expected_packet = None
        self.stream_id = 0
        # Traffic-gen
        self.inject_from_npu_host = inject_from_npu_host
        self.add_inject_up_header_if_inject_from_npuh = add_inject_up_header_if_inject_from_npuh
        self.npu_host_traffic_gen_args = None
        self.npu_host_traffic_gen_config = None
        self.npu_host_traffic_gen_send = None

    def _set_traffic_gen(self):
        if (self.inject_from_npu_host):
            print("ra_npu_rtl_sim_provider::_set_traffic_gen() -> inject_from_npu_host is set -> using NPU-HOST as packet-gen")
            self.npu_host_traffic_gen_config = npu_host_packet_gen.npuh_traffic_gen_config_module(self.dev_h)
            self.npu_host_traffic_gen_send = npu_host_packet_gen.npuh_traffic_gen_send_module(self.dev_h)
            # Set npu-host packet-gen macro
            data = self.dev_h.debug_device.read_register(self.dev_h.tree.npuh.host.macro_ids)
            data.mps_macro = nplapi.NPL_NPU_HOST_TRAFFIC_GEN_MACRO
            self.dev_h.debug_device.write_register(self.dev_h.tree.npuh.host.macro_ids, data)
            # init_npu_host_traffic_gen_args
            self.npu_host_traffic_gen_args = npu_host_packet_gen.NpuHostPacketGenAttribute()
            self.npu_host_traffic_gen_args.configure_packets = 1
            self.npu_host_traffic_gen_args.configure_scanners = 1
            self.npu_host_traffic_gen_args.packet_inject_module = self.packet_inject_file_name
            self.npu_host_traffic_gen_args.randomize_inject_order = 0
            self.npu_host_traffic_gen_args.num_of_replications = 1
            self.npu_host_traffic_gen_args.packet_rate_type = npu_host_packet_gen.PacketRateType.CALCULATED
            self.npu_host_traffic_gen_args.npuh_port_rate = 50  # Gb / sec
            self.npu_host_traffic_gen_args.inject_percentage = 99
            self.npu_host_traffic_gen_args.clk_rate = 1.2
        else:
            print("ra_npu_rtl_sim_provider::_set_traffic_gen() -> inject_from_npu_host is not set -> will use RTL IFG/Stubs")

    def inject_actual_ifg(self, slice_id, ifg):
        if self.dev_h.ll_device.is_pacific():
            slices_to_flip = [0, 3, 4]
        elif self.dev_h.ll_device.is_gibraltar():
            slices_to_flip = [1, 2, 5]
        else:
            slices_to_flip = []

        if slice_id in slices_to_flip:
            return (1 ^ ifg)
        return ifg

    def get_inject_pci_pif(self, slice_id, ifg):
        if self.dev_h.ll_device.is_pacific():
            inject_pci_pif = 18
        elif self.dev_h.ll_device.is_gibraltar():
            inject_pci_pif = 24
        elif self.dev_h.ll_device.is_asic3():
            inject_pci_pif = 32
        else:
            inject_pci_pif = None
        return inject_pci_pif

    def inject_packet(self, packet_desc, initial_values={}, num_of_replications=1):
        # Set traffic Gen
        self._set_traffic_gen()

        # Inject packet
        print("ra_npu_rtl_sim_provider::inject_packet()")
        print("slice            = %d" % packet_desc.slice)
        print("ifg              = %d" % packet_desc.ifg)
        print("pif              = %d" % packet_desc.pif)
        print("packet           = %s" % packet_desc.packet)

        ssp_gid = get_port_gid(self.dev_h.la_dev, packet_desc.slice, packet_desc.ifg, packet_desc.pif)
        assert ssp_gid, print("Could not find gid by slice=%d, ifg=%d, pif=%d" %
                              (packet_desc.slice, packet_desc.ifg, packet_desc.pif))

        forward_destinations_file_template.generate_file(self.dev_h.la_dev, self.fwd_destinations_file_name)

        if (self.inject_from_npu_host):
            inject_up_header = Ether(
                dst=topology.INJECT_PORT_MAC_ADDR,
                src=topology.HOST_MAC_ADDR,
                type=Ethertype.Dot1Q.value) / Dot1Q(
                type=Ethertype.Inject.value) / InjectUpStd(
                type=nplapi.NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS,
                ifg_id=self.inject_actual_ifg(
                    packet_desc.slice,
                    packet_desc.ifg),
                pif_id=packet_desc.pif)
            # InjectUp(ssp_gid=ssp_gid)

            # Select inject port
            inject_pci_pif = self.get_inject_pci_pif(packet_desc.slice, packet_desc.ifg)

            if (self.add_inject_up_header_if_inject_from_npuh):
                print("Add inject-up is requeset -> Adding inject-up headers it on top of the native packet")
                packet_desc.packet = hexlify(bytes(inject_up_header)).decode('ascii') + packet_desc.packet
                print("inject_up_packet = %s" % packet_desc.packet)
                print()

            packet = {'flow_id': self.stream_id,
                      'packet_id': 0,
                      'packet': packet_desc.packet,
                      'slice_id': packet_desc.slice,
                      'ifg': 0,  # where inject_port was defined
                      'pif': inject_pci_pif}  # pci_port pif

            npu_inject_packet_file_template.generate_file(self.packet_inject_file_name, [packet])

            # Configure npu-host as packet generator
            self.npu_host_traffic_gen_args.num_of_replications = num_of_replications
            self.npu_host_traffic_gen_config.config_packets_and_scanners(self.npu_host_traffic_gen_args)
            # Inject packets
            self.provider.inject_packet(packet_desc, {})  # Inform RTL about new inject packet
        else:
            packet = {'flow_id': self.stream_id,
                      'packet_id': 0,
                      'packet': packet_desc.packet,
                      'slice_id': packet_desc.slice,
                      'ifg': packet_desc.ifg,
                      'pif': packet_desc.pif}
            npu_inject_packet_file_template.generate_file(self.packet_inject_file_name, [packet])
            self.provider.inject_packet(packet_desc, {})

        # let simulation run
        self.step(20)
        time.sleep(0.5)

        return True

    def step_packet(self):
        print("ra_npu_rtl_sim_provider::step_packet()")

        if (self.inject_from_npu_host):
            if not self.npu_host_traffic_gen_send:
                print("ra_npu_rtl_sim_provider::step_packet() ERROR -> npu_host_traffic_gen_send is None")
                return False
            self.npu_host_traffic_gen_send.start_npu_host_inject()
            # let simulation run
            self.step(1000)
            time.sleep(0.5)
            self.npu_host_traffic_gen_send.stop_npu_host_inject()
            self.provider.step_packet()
        else:
            self.provider.step_packet()  # This informs RTL that config is done and traffic injection will start
            self.step(1000)
            time.sleep(0.5)

        return True

    def get_packet(self):

        packet_desc = None
        if not self.use_socket:
            print("ra_npu_rtl_sim_provider::get_packet() FAKE")
            packet_desc = self.expected_packet
        else:
            print("ra_npu_rtl_sim_provider::get_packet() From RTL")
            packet_desc = self.provider.get_packet()

        print("slice            = %d" % packet_desc.slice)
        print("ifg              = %d" % packet_desc.ifg)
        print("pif              = %d" % packet_desc.pif)
        print("packet           = %s" % packet_desc.packet)

        return packet_desc

    def get_packets(self):
        if not self.use_socket:
            return list(self.expected_packet)

        return self.provider.get_packets()

    # Stab to let the flow pass in case socket is not connected.
    def set_expected_packet(self, slice, ifg, pif, scapy_packet):
        self.expected_packet = nsim.sim_packet_info_desc()
        self.expected_packet.packet = hexlify(bytes(scapy_packet)).decode('ascii')
        self.expected_packet.slice = slice
        self.expected_packet.ifg = ifg
        self.expected_packet.pif = pif
        # Dump expected packet to file
        packet = {'flow_id': self.stream_id,
                  'packet_id': 0,
                  'packet': self.expected_packet.packet,
                  'slice_id': self.expected_packet.slice,
                  'ifg': self.expected_packet.ifg,
                  'pif': self.expected_packet.pif}
        npu_extract_packet_file_template.generate_file(self.packet_extract_file_name, [packet])

    def step(self, delay, blocking=False):
        self.provider.step(delay, blocking)

    def poll(self, addr, val, mask, iterations, blocking=False):
        self.provider.poll(addr, val, mask, iterations, blocking)

    def reinject_last_packet(self):
        print("ra_npu_rtl_sim_provider::reinject_last_packet()")
        self.provider.reinject_last_packet()
        self.step(50)
        if (self.inject_from_npu_host):
            if not self.npu_host_traffic_gen_send:
                print("ra_npu_rtl_sim_provider::step_packet() ERROR -> npu_host_traffic_gen_send is None")
                return False
            self.npu_host_traffic_gen_send.start_npu_host_inject()
            # let simulation run
            self.step(200)
            time.sleep(0.1)
            self.npu_host_traffic_gen_send.stop_npu_host_inject()
            # let simulation run
            self.step(50)
            time.sleep(0.1)

    def pop_packet(self):
        print("ra_npu_rtl_sim_provider::pop_packet()")
        self.provider.pop_packet()

    def stop_simulation(self):
        print("ra_npu_rtl_sim_provider::stop_simulation()")
        self.provider.stop_simulation()

    def force_reg_access_method(self, method=0):
        # 0: default (no force)
        # 1: backdoor
        # 2: frontdoor
        print("ra_npu_rtl_sim_provider::force_reg_access_method()")
        self.provider.force_reg_access_method(method)


#
# Sim provider interface, implementing simulator control interface for NPU host injection flow via NSIM.
#
class ra_npuh_nsim_provider:

    def __init__(self, device, nsim_provider):
        self.device = device
        self.provider = nsim_provider

    def inject_packet(self, packet_desc):
        print("ra_npuh_nsim_provider::inject_packet()")

        print("slice            = %d" % packet_desc.slice)
        print("ifg              = %d" % packet_desc.ifg)
        print("pif              = %d" % packet_desc.pif)
        print("packet           = %s" % packet_desc.packet)

        ssp_gid = get_port_gid(self.device, packet_desc.slice, packet_desc.ifg, packet_desc.pif)
        assert ssp_gid, print("Could not find gid by slice=%d, ifg=%d, pif=%d" %
                              (packet_desc.slice, packet_desc.ifg, packet_desc.pif))

        inject_up_header = Ether(
            dst=topology.INJECT_PORT_MAC_ADDR,
            src=topology.HOST_MAC_ADDR,
            type=Ethertype.Dot1Q.value) / Dot1Q(
            type=Ethertype.Inject.value) / InjectUpStd(
            type=nplapi.NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS,
            ifg_id=self.inject_actual_ifg(
                packet_desc.slice,
                packet_desc.ifg),
            pif_id=packet_desc.pif)
        # InjectUp(ssp_gid=ssp_gid)

        packet_desc.ifg = 0
        packet_desc.pif = 18
        packet_desc.packet = hexlify(bytes(inject_up_header)).decode('ascii') + packet_desc.packet
        print("inject_up_packet = %s" % packet_desc.packet)
        print()

        return self.provider.inject_packet(packet_desc)

    def step_packet(self):
        return self.provider.step_packet()

    def get_packet(self):
        return self.provider.get_packet()

    def get_packets(self):
        return self.provider.get_packets()

    # Stab to let the flow pass in case socket is not connected.
    def set_expected_packet(self, slice, ifg, pif, scapy_packet):
        pass

    def step(self, delay, blocking=False):
        pass

    def poll(self, addr, val, mask, iterations, blocking=False):
        pass

    def stop_simulation(self):
        pass


if __name__ == '__main__':

    compare_vs_expected(None, './sdk_cmd_file.txt')
