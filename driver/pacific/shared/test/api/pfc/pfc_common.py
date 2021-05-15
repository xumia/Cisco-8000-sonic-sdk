#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import topology as T

TC_VALUE = 5
PFC_MAC_ADDR = "01:80:c2:00:00:01"
L2CP_PROF_INDEX = 1


class pfc_common():

    def init_common(self):
        self.tc_value = TC_VALUE
        self.s_rx_mac = T.mac_addr('84:20:75:3e:8c:05')
        self.port_speed = 50

        self.pfc_packet = Ether(dst=PFC_MAC_ADDR,
                                src=self.s_rx_mac.addr_str,
                                type=Ethertype.FlowControl.value) / PFC(class_enable_vector=1 << TC_VALUE,
                                                                        time_class4=int(100 * self.port_speed / 512),
                                                                        time_class5=int(100 * self.port_speed / 512))

    def create_npu_host_destination(self):
        SYS_PORT_GID_BASE = 23
        NPUH_SP_GID = SYS_PORT_GID_BASE + 3
        if not hasattr(self, "npu_host_destination"):
            self.npu_host_port = T.npu_host_port(self, self.device, self.device.get_id(), False, NPUH_SP_GID)
            self.npu_host_destination = self.device.create_npu_host_destination(self.npu_host_port.hld_obj)

    def enable_rx_counting(self, eth_port):
        eth_port.hld_obj.set_copc_profile(L2CP_PROF_INDEX)

    def enable_rx_counting_common(self, eth_port):
        DA_L2CP = T.mac_addr('01:80:c2:00:00:01')
        MASK = T.mac_addr('ff:ff:ff:ff:ff:ff')  # Mask

        npp_attribute = 0x1
        self.copc_mac = self.device.create_copc(sdk.la_control_plane_classifier.type_e_MAC)

        key1 = []
        f1 = sdk.field()
        f1.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERNET_PROFILE_ID
        f1.val.mac.ethernet_profile_id = npp_attribute
        f1.mask.mac.ethernet_profile_id = npp_attribute
        key1.append(f1)

        f2 = sdk.field()
        f2.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_DA
        f2.val.mac.da = DA_L2CP.hld_obj
        f2.mask.mac.da.flat = 0xffffffffffff
        key1.append(f2)

        f3 = sdk.field()
        f3.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERTYPE
        f3.val.mac.ethertype = Ethertype.FlowControl.value
        f3.mask.mac.ethertype = 0xffff
        key1.append(f3)

        result1 = sdk.result()
        result1.event = sdk.LA_EVENT_ETHERNET_L2CP0

        self.copc_mac.append(key1, result1)

        eth_port.hld_obj.set_copc_profile(npp_attribute)
        prof_val = eth_port.hld_obj.get_copc_profile()
        self.assertEqual(prof_val, npp_attribute)

        self.create_npu_host_destination()
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_L2CP0, 0, None, self.npu_host_destination, False, False, True, 0)
