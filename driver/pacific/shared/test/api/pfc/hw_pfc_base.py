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
import unittest
from leaba import sdk
import packet_test_utils as U
from scapy.all import *
import topology as T
import ip_test_base
from sim_utils import *
from leaba.debug import debug_device
from packet_test_defs import *
import pdb

KILO = 1000
MEGA = 1000 * KILO
GIGA = 1000 * MEGA
TERA = 1000 * GIGA

SMS_BLOCK_SIZE_IN_BYTES = 384
NUM_TC_CLASSES = 8
PFC_QUANTA_BIT_VALUE = 512

TIMER_1 = 0xdead
TIMER_2 = 0xbeef
QUANTA_1 = 0x800
QUANTA_2 = 0x2000
HR_TIMER_RESOLUTION = 4
HR_THRESHOLD = 0xabc * SMS_BLOCK_SIZE_IN_BYTES
HR_TIMER = 0xcccc * HR_TIMER_RESOLUTION
PORT_SPEED = 50
TC_BITMAP = 0x18
TC_BITMAP_DISABLED = 0x00
TC_BITMAP_FAIL = TC_BITMAP_DISABLED
TC_1 = 4
TC_2 = 5
SQG_1 = 0
SQG_2 = 1
DROP_COUNTER_1 = 3
DROP_COUNTER_2 = 4
L3_AC_GID = 0x23
L3_AC_GID1 = 0x24
L3_AC_MAC = T.mac_addr("12:34:12:34:12:34")
L3_AC_MAC1 = T.mac_addr("12:34:12:34:12:35")

DEFAULT_SQG = 1
DEFAULT_DROP_COUNTER = 0

RXPDR_CTR_A_THRESHOLDS = sdk.la_rx_pdr_sms_bytes_drop_thresholds()
RXPDR_CTR_A_THRESHOLDS.thresholds = [0x1F * SMS_BLOCK_SIZE_IN_BYTES, 0x2F * SMS_BLOCK_SIZE_IN_BYTES]

THRESHOLDS_1 = [0x1F * SMS_BLOCK_SIZE_IN_BYTES, 0x2F * SMS_BLOCK_SIZE_IN_BYTES, 0x3F * SMS_BLOCK_SIZE_IN_BYTES]
THRESHOLDS_2 = [0x4C * SMS_BLOCK_SIZE_IN_BYTES, 0x4C * SMS_BLOCK_SIZE_IN_BYTES, 0xFF * SMS_BLOCK_SIZE_IN_BYTES]
THRESHOLDS_FAIL_1 = [0x1F * SMS_BLOCK_SIZE_IN_BYTES, 0x2F * SMS_BLOCK_SIZE_IN_BYTES, 0x3FFFFFF * SMS_BLOCK_SIZE_IN_BYTES]
THRESHOLDS_FAIL_2 = [0x1F * SMS_BLOCK_SIZE_IN_BYTES, 0x3F * SMS_BLOCK_SIZE_IN_BYTES, 0x2F * SMS_BLOCK_SIZE_IN_BYTES]

SQG_THRESHOLDS_1 = sdk.la_rx_cgm_sqg_thresholds()
SQG_THRESHOLDS_1.thresholds = THRESHOLDS_1
CTR_A_THRESHOLDS_1 = sdk.la_rx_cgm_sms_bytes_quantization_thresholds()
CTR_A_THRESHOLDS_1.thresholds = THRESHOLDS_1
SQ_THRESHOLDS_1 = sdk.la_rx_cgm_sq_profile_thresholds()
SQ_THRESHOLDS_1.thresholds = THRESHOLDS_1
SQG_THRESHOLDS_2 = sdk.la_rx_cgm_sqg_thresholds()
SQG_THRESHOLDS_2.thresholds = THRESHOLDS_2
CTR_A_THRESHOLDS_2 = sdk.la_rx_cgm_sms_bytes_quantization_thresholds()
CTR_A_THRESHOLDS_2.thresholds = THRESHOLDS_2
SQ_THRESHOLDS_2 = sdk.la_rx_cgm_sq_profile_thresholds()
SQ_THRESHOLDS_2.thresholds = THRESHOLDS_2
SQG_THRESHOLDS_FAIL_1 = sdk.la_rx_cgm_sqg_thresholds()
SQG_THRESHOLDS_FAIL_1.thresholds = THRESHOLDS_FAIL_1
CTR_A_THRESHOLDS_FAIL_1 = sdk.la_rx_cgm_sms_bytes_quantization_thresholds()
CTR_A_THRESHOLDS_FAIL_1.thresholds = THRESHOLDS_FAIL_1
SQ_THRESHOLDS_FAIL_1 = sdk.la_rx_cgm_sq_profile_thresholds()
SQ_THRESHOLDS_FAIL_1.thresholds = THRESHOLDS_FAIL_1
SQG_THRESHOLDS_FAIL_2 = sdk.la_rx_cgm_sqg_thresholds()
SQG_THRESHOLDS_FAIL_2.thresholds = THRESHOLDS_FAIL_2
CTR_A_THRESHOLDS_FAIL_2 = sdk.la_rx_cgm_sms_bytes_quantization_thresholds()
CTR_A_THRESHOLDS_FAIL_2.thresholds = THRESHOLDS_FAIL_2
SQ_THRESHOLDS_FAIL_2 = sdk.la_rx_cgm_sq_profile_thresholds()
SQ_THRESHOLDS_FAIL_2.thresholds = THRESHOLDS_FAIL_2

OQ_THRESHOLDS = sdk.la_tx_cgm_oq_profile_thresholds()
OQ_THRESHOLDS.fc_bytes_threshold = 0x1234
OQ_THRESHOLDS.fc_buffers_threshold = 0x567
OQ_THRESHOLDS.fc_pds_threshold = 0xdea
OQ_THRESHOLDS.drop_bytes_threshold = 0xabcd
OQ_THRESHOLDS.drop_buffers_threshold = 0x333
OQ_THRESHOLDS.drop_pds_threshold = 0x123

# Fabric rates given in KB
FABRIC_RATE_1 = int(2 * TERA / KILO)
FABRIC_RATE_2 = int(3.2 * TERA / KILO)

VALID_LINKS_THRESHOLDS_1 = sdk.la_fabric_valid_links_thresholds()
VALID_LINKS_THRESHOLDS_1.thresholds = [10, 20, 30]
VALID_LINKS_THRESHOLDS_2 = sdk.la_fabric_valid_links_thresholds()
VALID_LINKS_THRESHOLDS_2.thresholds = [30, 30, 40]
CONGESTED_LINKS_THRESHOLDS_1 = sdk.la_fabric_congested_links_thresholds()
CONGESTED_LINKS_THRESHOLDS_1.thresholds = [10, 20, 30]
CONGESTED_LINKS_THRESHOLDS_2 = sdk.la_fabric_congested_links_thresholds()
CONGESTED_LINKS_THRESHOLDS_2.thresholds = [30, 30, 40]


class hw_pfc_base(unittest.TestCase):
    RX_SLICE_OTHER = 2

    def setUp(self):
        self.device = U.sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)
        self.rx_counter = self.device.create_counter(8)

        self.mac_port = self.topology.rx_eth_port.mac_port.hld_obj
        self.mac_port1 = self.topology.rx_eth_port1.mac_port.hld_obj

        # MATILDA_SAVE -- need review
        if self.RX_SLICE_OTHER not in self.device.get_used_slices():
            self.RX_SLICE_OTHER = 4
        elif T.TX_SLICE_EXT == self.RX_SLICE_OTHER:
            self.RX_SLICE_OTHER = 1

        self.mac_port_other_slice = T.mac_port(self, self.device, self.RX_SLICE_OTHER, 0, 0, 1).hld_obj

        # Default topology does not have port with no VLAN - needed to test PFC src mac
        self.l3_port = T.l3_ac_port(self, self.device, L3_AC_GID, self.topology.rx_eth_port, self.topology.vrf,
                                    L3_AC_MAC)
        self.l3_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.l3_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        self.l3_port1 = T.l3_ac_port(self, self.device, L3_AC_GID1, self.topology.rx_eth_port1, self.topology.vrf,
                                     L3_AC_MAC1)
        self.l3_port1.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.l3_port1.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_PFC_DEVICE_TUNING, True)

    def init_rx_counting(self, eth_port, tc):
        mac_port = eth_port.mac_port.hld_obj
        mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR,
                             sdk.la_mac_port.fc_mode_e_PFC)
        mac_port.set_pfc_enable(1 << tc)
        counter = self.device.create_counter(8)
        mac_port.set_pfc_counter(counter)
        self.enable_rx_counting(eth_port)

    def tearDown(self):
        self.device.tearDown()
