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
import sim_utils
from scapy.all import *
from lc_multicast_v6_base import *
import unittest
from leaba import sdk
import ip_test_base
import topology as T
import decor


class ingress_lc_multicast(lc_multicast_v6_base):

    @unittest.skipIf(decor.is_gibraltar() or decor.is_hw_device(), "Skip on HW device or gibraltar.")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_lc_multicast_spa(self):
        vrf = T.vrf(self, self.device, 0)
        ac_profile = T.ac_profile(self, self.device)
        in_rx_eth_port = T.ethernet_port(
            self,
            self.device,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            SYS_PORT_GID_BASE,
            INGRESS_RX_SERDES_FIRST,
            INGRESS_RX_SERDES_LAST)
        in_rx_eth_port.set_ac_profile(ac_profile)

        in_l3_port_mac = T.mac_addr(IN_L3_AC_PORT_MAC)
        self.in_l3_ac = T.l3_ac_port(self, self.device,
                                     GID_BASE,
                                     in_rx_eth_port,
                                     vrf,
                                     in_l3_port_mac,
                                     VLAN)

        self.in_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.in_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # Create fabric port
        in_tx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            INGRESS_TX_SERDES_LAST)
        in_tx_fabric_port = T.fabric_port(self, self.device, in_tx_fabric_mac_port)

        # Manually set reachability to egress device
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)
        reachable_devices = []
        reachable_devices.append(EGRESS_DEVICE_ID)
        in_tx_fabric_port.hld_obj.set_reachable_lc_devices(reachable_devices)

        self.system_ports = []
        self.spa_port = T.spa_port(self, self.device, 0)

        # Create remote port 1
        remote_port1 = T.remote_port(
            self,
            self.device,
            EGRESS_DEVICE_ID,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)

        # Create remote system port above the remote port
        remote_sys_port1 = T.system_port(self, self.device, EGRESS_SYS_PORT_GID, remote_port1)

        self.spa_port.add(remote_sys_port1)

        # Create remote port 1
        remote_port2 = T.remote_port(
            self,
            self.device,
            EGRESS_DEVICE_ID,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST + 2,
            EGRESS_TX_SERDES_LAST + 2)

        # Create remote system port above the remote port
        remote_sys_port2 = T.system_port(self, self.device, EGRESS_SYS_PORT_GID + 1, remote_port2)

        self.spa_port.add(remote_sys_port2)

        # Create remote ethernet port above the remote system port
        remote_eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)

        # Create remote AC port above the remote ethernet
        remote_l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        remote_l3_ac = T.l3_ac_port(self, self.device,
                                    GID_BASE + 1,
                                    remote_eth_port,
                                    vrf,
                                    remote_l3_port_mac)

        remote_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        remote_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.device.set_int_property(sdk.la_device_property_e_MULTICAST_MCID_SCALE_THRESHOLD, MC_TEST_THRESHOLD)

        # create the multicast group
        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)

# *,g is currently broken because the threshold/destination logic is missing
# in the NPL.
        # *,g lookup
#        vrf.hld_obj.add_ipv6_multicast_route(
#            sdk.LA_IPV6_ANY_IP, self.mc_group_addr.hld_obj, self.mc_group, None, False, False, None)

        # s,g lookup
        vrf.hld_obj.add_ipv6_multicast_route(
            self.mc_sip.hld_obj, self.mc_group_addr.hld_obj, self.mc_group, None, False, False, None)

        run_and_compare(
            self,
            self.device,
            self.ingress_rx_pkt,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            INGRESS_RX_SERDES_FIRST,
            self.ingress_tx_pkt,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            TS_PLB)


if __name__ == '__main__':
    unittest.main()
