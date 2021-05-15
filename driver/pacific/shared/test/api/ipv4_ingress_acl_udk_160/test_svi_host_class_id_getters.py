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

import unittest
import decor
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from ipv4_ingress_acl_class_id_160_base import *
import sim_utils
import topology as T


@unittest.skipUnless(decor.is_gibraltar(), "Class ID tests supported only on GB")
class unified_acl(ipv4_ingress_acl_class_id_160_base):

    @unittest.skipUnless(decor.is_gibraltar(), "Class ID tests supported only on GB")
    def test_svi_host_class_id_getters(self):
        acl1 = self.create_host_class_id_unified_acl()

        # Attach the Unified ACL
        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Update the L2 table MAC entry - this should not affect L3 class ID getter api's
        self.topology.tx_switch1.hld_obj.set_mac_entry(
            self.svi_port_impl.ext_nh.mac_addr.hld_obj,
            self.topology.tx_l2_ac_port_ext.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        res_mac = self.svi_port_impl.tx_port_ext.hld_obj.get_ipv4_host(DIP_HOST1.hld_obj)
        self.assertEqual(res_mac.flat, self.svi_port_impl.ext_nh.mac_addr.hld_obj.flat)

        res_mac, c = self.svi_port_impl.tx_port_ext.hld_obj.get_ipv4_host_and_class_id(DIP_HOST1.hld_obj)
        self.assertEqual(res_mac.flat, self.svi_port_impl.ext_nh.mac_addr.hld_obj.flat)
        self.assertEqual(c, self.CLASS_ID_HOST)

        # Update to Default Class ID
        self.ip_impl.modify_host_with_class_id(
            self.svi_port_impl.tx_port_ext,
            DIP_HOST1,
            self.svi_port_impl.ext_nh.mac_addr,
            sdk.LA_CLASS_ID_DEFAULT)

        # Update the L2 table MAC entry - this should not affect L3 class ID getter api's
        self.topology.tx_switch1.hld_obj.set_mac_entry(
            self.svi_port_impl.ext_nh.mac_addr.hld_obj,
            self.topology.tx_l2_ac_port_ext.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        res_mac = self.svi_port_impl.tx_port_ext.hld_obj.get_ipv4_host(DIP_HOST1.hld_obj)
        self.assertEqual(res_mac.flat, self.svi_port_impl.ext_nh.mac_addr.hld_obj.flat)

        res_mac, c = self.svi_port_impl.tx_port_ext.hld_obj.get_ipv4_host_and_class_id(DIP_HOST1.hld_obj)
        self.assertEqual(res_mac.flat, self.svi_port_impl.ext_nh.mac_addr.hld_obj.flat)
        self.assertEqual(c, sdk.LA_CLASS_ID_DEFAULT)

        # Update to Original Class ID
        self.ip_impl.modify_host_with_class_id(
            self.svi_port_impl.tx_port_ext,
            DIP_HOST1,
            self.svi_port_impl.ext_nh.mac_addr,
            self.CLASS_ID_HOST)

        # Remove the L2 table MAC entry - this should not affect L3 class ID getter api's
        self.topology.tx_switch1.hld_obj.remove_mac_entry(
            self.svi_port_impl.ext_nh.mac_addr.hld_obj)

        res_mac = self.svi_port_impl.tx_port_ext.hld_obj.get_ipv4_host(DIP_HOST1.hld_obj)
        self.assertEqual(res_mac.flat, self.svi_port_impl.ext_nh.mac_addr.hld_obj.flat)

        res_mac, c = self.svi_port_impl.tx_port_ext.hld_obj.get_ipv4_host_and_class_id(DIP_HOST1.hld_obj)
        self.assertEqual(res_mac.flat, self.svi_port_impl.ext_nh.mac_addr.hld_obj.flat)
        self.assertEqual(c, self.CLASS_ID_HOST)

        res_macs = self.svi_port_impl.tx_port_ext.hld_obj.get_ipv4_hosts()
        self.assertEqual(len(res_macs), 1)
        self.assertEqual(res_macs[0].flat, self.svi_port_impl.ext_nh.mac_addr.hld_obj.flat)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)


if __name__ == '__main__':
    unittest.main()
