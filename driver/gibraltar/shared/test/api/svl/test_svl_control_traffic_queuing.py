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

import unittest
import svl_base
import svl_test_loader as stl
import decor

from leaba import sdk
import packet_test_utils as U
import topology as T
from packet_test_defs import *
from scapy.all import *

from svl_base import *

STACK_CONTROL_TRAFFIC_QUEUING_VOQ_OFFSET = 0
STACK_IPC_TRAFFIC_QUEUING_VOQ_OFFSET = 1
REMOTE_NETWORK_CONTROL_TRAFFIC_QUEUING_VOQ_OFFSET = 2

load_contrib("cdp")


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
@unittest.skipIf(not (decor.is_gibraltar() or decor.is_pacific()), "Test is applicable only on Pacific and Gibraltar")
@unittest.skipIf(decor.is_matilda('8T_'), "not yet enabled on GB 8T")
class SvlControlQueuing(unittest.TestCase, svl_base.SvlBaseActiveContext):
    topology_init_done = False
    base = None
    dev = None
    topology = None

    def setUp(self):
        if not SvlControlQueuing.topology_init_done:
            if SvlControlQueuing.dev is None:
                self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
                self.device = SvlBase.dev
                SvlControlQueuing.dev = self.device
                SvlControlQueuing.base = self.base
            else:
                self.base = SvlControlQueuing.base
                self.device = SvlControlQueuing.dev
            if not T.can_be_used_as_fabric(self.device):
                self.skipTest("This device does not have so many slices as needed by this test, so skip.")
                return
            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlControlQueuing.topology = self.topology
            SvlControlQueuing.topology_init_done = True
            # configure control traffic queueing on stack port
            sys_port = SvlBase.ssps[0].hld_obj
            voq_set  = self.create_control_traffic_queuing_voq_set(stack_ports[0].slice, stack_ports[0].ifg)
            SvlBase.stackport.set_control_traffic_queueing(sys_port, voq_set)
        self.device = SvlBase.dev
        self.base = SvlControlQueuing.base
        self.topology = SvlControlQueuing.topology

    @classmethod
    def tearDownClass(cls):
        if SvlControlQueuing.dev is not None:
            SvlControlQueuing.dev.tearDown()
        del cls

    def create_control_traffic_queuing_voq_set(self, slice_id, ifg):
        is_success, base_voq, base_vsc_vec = T.topology.allocate_voq_set(self.device, self.device.get_id(), slice_id, ifg, 4)
        self.assertTrue(is_success)
        self.voq_set = self.device.create_voq_set(base_voq, 4, base_vsc_vec, self.device.get_id(), slice_id, ifg)
        for voq in range(4):
            self.voq_set.set_cgm_profile(voq, self.topology.uc_voq_cgm_profile_def)
        return self.voq_set

    def test_stack_control_traffic_queuing(self):
        sys_port = SvlBase.ssps[0].hld_obj

        bvn_destination_id = SvlBase.stackport.get_control_traffic_destination_id(
            sys_port, STACK_CONTROL_TRAFFIC_QUEUING_VOQ_OFFSET)

        ISIS_ISO = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            LLC(dsap=0xFE, ssap=0xFE, ctrl=0x3) / ISO() / \
            Raw(load=0x03111111111111001e003700d303000000f001028101cc01040349000184040a000001)
        ISIS_ISO[ISO].disc = 0x83  # ISIS
        ISIS_ISO[ISO].lenIndic = 20
        ISIS_ISO[ISO].idExt = 1
        ISIS_ISO[ISO].pduType = 17  # P2P HELLO
        ISIS_ISO[ISO].pduVer = 1

        ISIS_INJECT_PACKET = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=bvn_destination_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / ISIS_ISO

        PUNT_PIF = self.device.get_pci_serdes()

        U.run_and_compare(self, self.device,
                          ISIS_INJECT_PACKET, 2, 0, PUNT_PIF,
                          ISIS_ISO, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes)

    def test_stack_ipc_traffic_queuing(self):
        sys_port = SvlBase.ssps[0].hld_obj

        bvn_destination_id = SvlBase.stackport.get_control_traffic_destination_id(sys_port, STACK_IPC_TRAFFIC_QUEUING_VOQ_OFFSET)

        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        IPC_INPUT_PACKET = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            IP(src='10.1.0.1', dst='10.2.0.1', ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        dest_remote = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.ssps[0].hld_obj.get_gid())

        IPC_INJECT_PACKET = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=bvn_destination_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            Ether(dst=IPC_PUNT_DEST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            IPC_INPUT_PACKET

        IPC_OUTPUT_PACKET = Ether(dst=IPC_PUNT_DEST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            IPC_INPUT_PACKET
        PUNT_PIF = self.device.get_pci_serdes()

        U.run_and_compare(self, self.device,
                          IPC_INJECT_PACKET, 2, 0, PUNT_PIF,
                          IPC_OUTPUT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes)

    def test_remote_network_control_traffic_queuing(self):
        sys_port = SvlBase.ssps[0].hld_obj

        bvn_destination_id = SvlBase.stackport.get_control_traffic_destination_id(
            sys_port, REMOTE_NETWORK_CONTROL_TRAFFIC_QUEUING_VOQ_OFFSET)
        cdp_da = '01:00:0C:CC:CC:CC'
        SA = '00:BE:EF:CA:FE:00'

        PUNT_PIF = self.device.get_pci_serdes()

        CDP_PACKET_BASE = \
            Ether(dst=cdp_da, src=SA, type=0x011e) / \
            LLC(dsap=170, ssap=170, ctrl=3) / SNAP() / CDPv2_HDR() / CDPMsgDeviceID() / CDPAddrRecordIPv4() / CDPMsgAddr() / \
            CDPMsgPortID() / CDPMsgCapabilities() / CDPMsgSoftwareVersion() / CDPMsgPlatform()

        dest_remote = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.rsps[0].hld_obj.get_gid())

        INJECT_PACKET = \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=0, type=U.Ethertype.Inject.value) / \
            InjectDown(dest=bvn_destination_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=0, type=U.Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            CDP_PACKET_BASE

        STACK_PORT_OUTPUT_PACKET = \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=0, type=U.Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            CDP_PACKET_BASE

        U.run_and_compare(self, self.device,
                          INJECT_PACKET, 0, 0, PUNT_PIF,
                          STACK_PORT_OUTPUT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes)


if __name__ == '__main__':
    unittest.main()
