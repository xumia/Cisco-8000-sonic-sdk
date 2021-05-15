#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import pytest
from saicli import *
import sai_packet_utils as U
import sai_test_utils as st_utils
from scapy.all import *
from sai_packet_test_defs import *
from mirror_utils import *

# Packet sampling using mirror session objects and applying sampling rate from packet-sampling object
# Test cases covered
# ------------------
#   Ingress-Mirroring
#       1. Create/delete PacketSample object of type mirror session
#       2. Modify packet sample object attributes
#       3. Create/delete PacketSample object of type mirror session. Create Sflow mirror object.
#          Attach sflow mirror object as SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION value on a port
#       4. Create Packet sample, Sample mirror, attach, detach on a port.
#       5. Create Packet sample, Sample mirror, attach and then detach , packet sample
#          on a port, modify packet sample object attribute, attach and detach modified
#          packet sample object on a port.
#    L2 Testing
#    ----------
#    Below test cases 6 to 14, packets are sampled on bridge port. Ingress port is a bridge port.
#       6. Create new mirror packet sample object. Attach it to port. Using an
#          Sflow mirror object, attach to the same port as a mirror sample object.
#          Check correctness of packet sampling using attributes,destination from sflow mirror
#          instance but sampling rate from packet sample object.
#       7. Complete [6] and then attach packet sample object on second ingress port.
#          Attach same sflow mirror object on both ports. Check ingress traffic on
#          both ingress ports get sampled at the sampling rate specified by single packet sample object.
#       8  Variation of test case [7]. Attach and detach both packet sample object, and sample mirror.
#       9  Variation of test case [7]. Attach and detach only packet sample object.
#       10  Variation of test case [7]. Attach and detach only sample mirror object.
#       11. Perform [7]. Modify sample rate on packet sample object to zero. Check no sampling is done
#          both ingress ports.
#       12. Create 2 new packet sample objects with rate R1=100% and R2=0%. Attach sample1 on port 1 and sample2
#          on port2. Attach same sflow mirror object on both ports. Check ingress traffic on both
#          ingress ports get sampled at the sampling rate specified by respective packet sample object.
#       13. Perform [12]. Change sampling rate on packet object 1 = 0% and on packet object 2 to 100%
#           Check packets are mirrored only on those ports where sample object1 is attached but not
#           on ingress port where packet sample object2 is attached.
#       14. Perform [7]. Check packet sampling correctness on a logical port. Delete and add back
#           logical port on both ports. Check packet sampling correctness.
#       15. Perform [14]. Check packet sampling correctness on a logical port. Delete and add back
#           logical port with various combinations of
#               -  packet sample object attach, detach
#               -  sample mirror object attach, detach
#               -  both packet sample object and sample mirror object attach, detach
#
#       16. Perform [3] 50 times (more than 32 times)  to ensure no mirror ids are leaked.
#       17. Modify mirror object's sampling rate value. This value should NOT be applied
#           on packet sampling mirror instances.
#       18. Modify mirror object's attribute other than sampling rate value. This value should
#           be applied on packet sampling mirror instances.
#
#    L3 Testing
#    ----------
#       6..16. Repeat test cases L2 test cases 6 to 14 with packets sampled on RIF. Ingress port is a RIF
#
#   Egress Mirroring
#       TBD


class HelperUtils():
    def create_sflow_session(self):
        sflowUtils = SflowUtils()
        attrs = sflowUtils.build_sflow_session_attr()
        sflow_session = sflowUtils.create_sflow_session(attrs)
        assert sflow_session != 0
        return sflow_session

    def create_mirror_type_samplepacket_session(self, sampleRate=1):
        args = {}
        args[SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE] = sampleRate
        args[SAI_SAMPLEPACKET_ATTR_TYPE] = SAI_SAMPLEPACKET_TYPE_MIRROR_SESSION
        samplepacket = pytest.tb.create_object(SAI_OBJECT_TYPE_SAMPLEPACKET, args, verify=[True, False])
        return samplepacket

    def modify_packet_sampling_object_attribute(self, packetSampleOid, attrTypeValueList):
        for a, v in attrTypeValueList.items():
            pytest.tb.set_object_attr(packetSampleOid, a, v, verify=True)

    def attach_sample_mirror_session(self, port, mirrorSessionOids, isIngress=True):
        attributeId = SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION if isIngress else SAI_PORT_ATTR_EGRESS_SAMPLE_MIRROR_SESSION
        pytest.tb.set_object_attr(
            pytest.tb.ports[port],
            attributeId,
            mirrorSessionOids,
            verify=True)

    def detach_sample_mirror_session(self, port, isIngress=True):
        attributeId = SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION if isIngress else SAI_PORT_ATTR_EGRESS_SAMPLE_MIRROR_SESSION
        pytest.tb.set_object_attr(
            pytest.tb.ports[port],
            attributeId,
            [],
            verify=True)

    def attach_samplepacket_object(self, port, samplePacketOid, isIngress=True):
        attributeId = SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE if isIngress else SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE
        pytest.tb.set_object_attr(pytest.tb.ports[port], attributeId, samplePacketOid, verify=True)

    def detach_samplepacket_object(self, port, isIngress=True):
        attributeId = SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE if isIngress else SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE
        pytest.tb.set_object_attr(pytest.tb.ports[port], attributeId, SAI_NULL_OBJECT_ID, verify=True)


@pytest.mark.usefixtures("mirror_bridge_rif_topology")
@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
@pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar and later asics")
class TestSflowPacketSamplingOnBridgeport():
    '''
        Test packet sampling that uses mirror object/s and applies on bridge port.
        Sampling mirror object used in this case is an sflow mirror object.
    '''

    def __init(self):
        self.utils = HelperUtils()
        self.sflowUtils = SflowUtils()

    def __bridge_pkt_from_port1_to_port2_compare_sflow_fields(self, in_pkt, out_pkt, sflow_pkt):
        U.run_and_compare_partial_packet(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: out_pkt}, {
                pytest.top.mirror_dest: [
                    sflow_pkt, [
                        (U.sflow_tunnel_metadata, "source_sp")]]}, True)

    def __bridge_pkt_from_port2_to_port1_compare_sflow_fields(self, in_pkt, out_pkt, sflow_pkt):
        U.run_and_compare_partial_packet(
            self, in_pkt, pytest.top.out_port, {
                pytest.top.in_port: out_pkt}, {
                pytest.top.mirror_dest: [
                    sflow_pkt, [
                        (U.sflow_tunnel_metadata, "source_sp")]]}, True)

    # Test case 1
    def test_create_delete_packet_sampling(self):
        self.__init()
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 2
    def test_create_delete_modify_mirror_type_packet_sampling(self):
        self.__init()
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 100})
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 3
    def test_attach_packet_sampling_attach_sample_mirror_session(self):
        self.__init()
        sflowOid = self.utils.create_sflow_session()
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 4
    def test_attach_sample_mirror_session_attach_packet_sampling(self):
        '''
        Change order of binding sample mirror session and packet sampling to port.
        '''
        self.__init()
        sflowOid = self.utils.create_sflow_session()
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 5
    def test_attach_sample_mirror_session_attach_packet_sampling_detach_attach_sample_mirror(self):
        '''
        Change order of binding sample mirror session and packet sampling to port.
        '''
        self.__init()
        sflowOid = self.utils.create_sflow_session()
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 100})
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 6
    def test_packet_sampling_rate_on_one_port(self):
        '''
        Create new mirror packet sample object. Attach it to port. Using an
        Sflow mirror object, attach as sample mirror session object to the
        same port as a packet sample object is attached to. Check correctness
        of packet sampling using attributes,destination from sflow mirror
        instance but sampling rate from packet sample object.
        '''
        self.__init()
        sflowOid, in_pkt, sflow_pkt = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt, in_pkt, sflow_pkt)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 7
    def test_packet_sampling_rate_on_two_port(self):
        '''
        Create new mirror packet sample object. Attach it to port. Using an
        Sflow mirror object, attach as sample mirror session object to the
        same port as a packet sample object is attached to. Check correctness
        of packet sampling using attributes,destination from sflow mirror
        instance but sampling rate from packet sample object. Attach packet
        sample object on second ingress port.  Attach same sflow mirror object
        on both ports. Check ingress traffic on both ingress ports get sampled at
        the sampling rate specified by single packet sample object.
        '''

        self.__init()
        # create Sflow mirror session and pkt to be injected on port1 switched to port2
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2 = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac1)

        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 8
    def test_packet_sampling_rate_on_two_port_attach_detach(self):
        '''
        Variations of test case [7]. Attach and Detach both packet sample object,
        and sample mirror.
        '''

        self.__init()
        # create sflow mirror session and pkt to be injected on port1 switched to port2
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2 = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Detach from port1
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)

        # Check sampling on port2 is unaffected
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Reattach on port1
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Check sampling on port1 and port2 is back up and fine.
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Detach from port2
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)

        # Check sampling on port1 is unaffected
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Reattach on port2
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # Check sampling on port1 and port2 is back up and fine.
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 9
    def test_packet_sampling_rate_on_two_port_attach_detach_sample_object(self):
        '''
        Variations of test case [7]. Attach and Detach only packet sample object
        '''

        self.__init()
        # create sflowmirror session and pkt to be injected on port1 switched to port2
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2 = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac1)

        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Detach from port1
        self.utils.detach_samplepacket_object(pytest.top.in_port)

        # Check sampling on port2 is unaffected
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Reattach on port1
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)

        # Check sampling on port1 and port2 is back up and fine.
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Detach from port2
        self.utils.detach_samplepacket_object(pytest.top.out_port)

        # Check sampling on port1 is unaffected
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Reattach on port2
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)

        # Check sampling on port1 and port2 is back up and fine.
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 10
    def test_packet_sampling_rate_on_two_port_attach_detach_sample_mirror_object(self):
        '''
        Variations of test case [7]. Attach and Detach only sample mirror object
        '''

        self.__init()
        # create sflow mirror session and pkt to be injected on port1 switched to port2
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2 = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac1)

        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Detach from port1
        self.utils.detach_samplepacket_object(pytest.top.in_port)

        # Check sampling on port2 is unaffected
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Reattach on port1
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)

        # Check sampling on port1 and port2 is back up and fine.
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Detach from port2
        self.utils.detach_samplepacket_object(pytest.top.out_port)

        # Check sampling on port1 is unaffected
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Reattach on port2
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)

        # Check sampling on port1 and port2 is back up and fine.
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 11
    def test_packet_sampling_rate_on_two_port_sampling_rate_modified(self):
        '''
        Perform [7]. Modify sample rate on packet sample object to zero. Check no sampling is done
        both ingress ports.
        '''
        self.__init()

        # create sflow mirror session and pkt to be injected on port1 switched to port2
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2 = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 0})
        U.run_and_compare_set(
            self, in_pkt1, pytest.top.in_port, {pytest.top.out_port: in_pkt1}, True)
        U.run_and_compare_set(
            self, in_pkt2, pytest.top.out_port, {pytest.top.in_port: in_pkt2}, True)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 12
    def test_packet_sampling_rate_on_two_port_two_sampling_rates(self):
        '''
        Create two new packet sample objects with rate R1=100% and R2=0%. Attach sample1 on port 1 and sample2
        on port2. Attach same sflow mirror object on both ports. Check ingress traffic on both
        ingress ports get sampled at the sampling rate specified by respective packet sample object.
        '''
        self.__init()

        # create sflow mirror session and pkt to be injected on port1 switched to port2
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)

        # Create packet sampling object1 with 100% sampling rate
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)

        # Create packet sampling object1 with 0% sampling rate
        mirrorPacketSampleOidZeroPcent = self.utils.create_mirror_type_samplepacket_session(0)

        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOidZeroPcent)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2 = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac1)

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # No packet should arrive on mirror destination port since sampling rate is zero.
        U.run_and_compare_set(
            self, in_pkt2, pytest.top.out_port, {
                pytest.top.in_port: in_pkt2}, True)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)
        pytest.tb.remove_object(mirrorPacketSampleOidZeroPcent)

    # Test case 13
    def test_packet_sampling_rate_on_two_port_two_sampling_rates_swap(self):
        '''
        Perform [12]. Change sampling rate on packet object 1 = 0% and on packet object 2 to 100%
        Check packets are mirrored only on those ports where sample object1 is attached but not
        on ingress port where packet sample object2 is attached.
        '''
        self.__init()

        # create sflow mirror session and pkt to be injected on port1 switched to port2
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)

        # Create packet sampling object1 with 100% sampling rate
        mirrorPacketSampleOid1 = self.utils.create_mirror_type_samplepacket_session(1)
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid1)

        # Create packet sampling object1 with 0% sampling rate
        mirrorPacketSampleOid2 = self.utils.create_mirror_type_samplepacket_session(0)

        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid2)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2 = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac1)

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # No packet should arrive on mirror destination port since sampling rate of zero is attached on top.out_port.
        U.run_and_compare_set(
            self, in_pkt2, pytest.top.out_port, {
                pytest.top.in_port: in_pkt2}, True)

        # Flip Sampling rate on packet sampling instances.
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid1, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 0})
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid2, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 1})
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)
        U.run_and_compare_set(self, in_pkt1, pytest.top.in_port, {pytest.top.out_port: in_pkt1}, True)

        # Flip back
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid1, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 1})
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid2, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 0})
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)
        U.run_and_compare_set(
            self, in_pkt2, pytest.top.out_port, {
                pytest.top.in_port: in_pkt2}, True)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid1)
        pytest.tb.remove_object(mirrorPacketSampleOid2)

    # Test case 14
    def test_packet_sampling_rate_on_two_port_add_delete_logical_ports(self):
        '''
        Create new mirror packet sample object. Attach it to port. Using an
        Sflow mirror object, attach as sample mirror session object to the
        same port as a packet sample object is attached to. Check correctness
        of packet sampling using attributes,destination from sflow mirror
        instance but sampling rate from packet sample object. Attach packet
        sample object on second ingress port.  Attach same sflow mirror object
        on both ports. Check ingress traffic on both ingress ports get sampled at
        the sampling rate specified by single packet sample object.

        Delete existing logical ports on both physical ports ana add them
        back. After adding them back, check packet sampling correctness.
        '''
        self.__init()

        # create Sflow mirror session and pkt to be injected on port1 switched to port2
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2 = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac1)

        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Delete bridge port and add back to check if newly created l2-port continues to mirror.
        pytest.tb.remove_fdb_entry(pytest.tb.vlans[pytest.top.vlan], pytest.top.neighbor_mac2)
        pytest.tb.deconfigure_vlan_members()
        pytest.tb.obj_wrapper.remove_object(pytest.tb.bridge_ports[pytest.top.in_port])
        # create bridge port on top of port with attached mirror session
        pytest.tb.create_bridge_port(pytest.top.in_port)
        pytest.tb.configure_vlan_members([{"vlan": pytest.top.vlan, "port": pytest.top.in_port, "is_tag": False},
                                          {"vlan": pytest.top.vlan, "port": pytest.top.out_port, "is_tag": False}])
        pytest.tb.create_fdb_entry(pytest.tb.vlans[pytest.top.vlan],
                                   pytest.top.neighbor_mac2,
                                   pytest.tb.bridge_ports[pytest.top.out_port])

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 15
    def test_packet_sampling_rate_on_two_port_add_delete_logical_ports_sampling_obect_attach_detach(self):
        '''
        Create new mirror packet sample object. Attach it to port. Using an
        Sflow mirror object, attach as sample mirror session object to the
        same port as a packet sample object is attached to. Check correctness
        of packet sampling using attributes,destination from sflow mirror
        instance but sampling rate from packet sample object. Attach packet
        sample object on second ingress port.  Attach same sflow mirror object
        on both ports. Check ingress traffic on both ingress ports get sampled at
        the sampling rate specified by single packet sample object.

        Delete existing logical ports on both physical ports ana add them
        back. After adding them back, check packet sampling correctness.
        Perform various variations of delete/add logical port along with
             - detach/attach sample mirror objects
             - detach/attach sample packet objects

        '''

        def delete_add_bport():
            pytest.tb.remove_fdb_entry(pytest.tb.vlans[pytest.top.vlan], pytest.top.neighbor_mac2)
            pytest.tb.deconfigure_vlan_members()

            pytest.tb.obj_wrapper.remove_object(pytest.tb.bridge_ports[pytest.top.in_port])
            # create bridge port on top of port with attached mirror session
            pytest.tb.create_bridge_port(pytest.top.in_port)

            pytest.tb.configure_vlan_members([{"vlan": pytest.top.vlan, "port": pytest.top.in_port, "is_tag": False},
                                              {"vlan": pytest.top.vlan, "port": pytest.top.out_port, "is_tag": False}])
            pytest.tb.create_fdb_entry(pytest.tb.vlans[pytest.top.vlan],
                                       pytest.top.neighbor_mac2,
                                       pytest.tb.bridge_ports[pytest.top.out_port])

        def packet_sampling_check():
            self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)
            self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        self.__init()

        # create Sflow mirror session and pkt to be injected on port1 switched to port2
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt1, in_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2 = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac1)
        self.__bridge_pkt_from_port2_to_port1_compare_sflow_fields(in_pkt2, in_pkt2, sflow_pkt2)

        # Delete bridge port and add back to check if newly created l2-port continues to mirror.
        delete_add_bport()
        packet_sampling_check()

        # Variation 1: Detach sample mirror object, add, delete logical port and attach back sample mirror object
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        delete_add_bport()
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])
        packet_sampling_check()

        # Variation 2: Detach sample packet object, add, delete logical port and attach back sample packet object
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        delete_add_bport()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        packet_sampling_check()

        # Variation 3: Detach sample mirror object and packet sample object, add,
        # delete logical port and attach back sample mirror object and packet
        # sample object
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        delete_add_bport()
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        packet_sampling_check()

        # cleanup
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 16
    def test_resource_leak_check(self):
        self.__init()
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()

        # There are resources for 32 mirror sessions. Repeat more than 32 times.
        for i in range(50):
            sflowOid = self.utils.create_sflow_session()
            self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
            self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])
            self.utils.detach_sample_mirror_session(pytest.top.in_port)
            self.utils.detach_samplepacket_object(pytest.top.in_port)
            pytest.tb.remove_object(sflowOid)

        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 17
    def test_modify_mirror_object_sampling_rate(self):
        '''
        Modify mirror object's sampling rate. This new rate should not be applied
        on packet sampling mirror instances.
        '''
        self.__init()
        sflowOid, in_pkt, sflow_pkt = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt, in_pkt, sflow_pkt)

        # Modify mirror objects sample rate.
        attrs = {}
        attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 0
        for k, v in attrs.items():
            pytest.tb.set_object_attr(sflowOid, k, v, verify=True)

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt, in_pkt, sflow_pkt)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 18
    def test_modify_mirror_object_encap(self):
        '''
        Modify mirror object's attribute other than sampling rate. This new attribute be applied
        on packet sampling mirror instances.
        '''
        self.__init()
        sflowOid, in_pkt, sflow_pkt = self.sflowUtils.create_sflow_session_and_bridge_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt, in_pkt, sflow_pkt)

        # Modify mirror objects encap.
        attrs = {}
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS] = "11.11.11.11"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS] = "22.22.22.22"
        for k, v in attrs.items():
            pytest.tb.set_object_attr(sflowOid, k, v, verify=True)

        # Build sflow pkt to reflect change in encap.
        attrs = self.sflowUtils.build_sflow_session_attr()
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS] = "11.11.11.11"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS] = "22.22.22.22"
        _, new_sflow_pkt = self.sflowUtils.create_bridge_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.in_port_sp_gid, pytest.top.neighbor_mac2)

        self.__bridge_pkt_from_port1_to_port2_compare_sflow_fields(in_pkt, in_pkt, new_sflow_pkt)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)


@pytest.mark.usefixtures("mirror_rif_topology")
@pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar and later asics")
@pytest.mark.skipif(is_sai_15x(), reason="Disabled on SAI 1.5.x")
class TestSflowPacketSamplingOnRif():
    '''
        Test packet sampling that uses mirror object/s and applies on rif.
        Sampling mirror object used in this case is an Sflow mirror object.
    '''

    def __init(self):
        self.utils = HelperUtils()
        self.sflowUtils = SflowUtils()

    def __route_pkt_from_port1_to_port2(self, in_pkt, expected_out_pkt, sflow_pkt):
        U.run_and_compare_partial_packet(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt}, {
                pytest.top.mirror_dest: [
                    sflow_pkt, [
                        (U.sflow_tunnel_metadata, "source_sp")]]}, True)

    def __route_pkt_from_port2_to_port1(self, in_pkt, expected_out_pkt, sflow_pkt):
        U.run_and_compare_partial_packet(
            self, in_pkt, pytest.top.out_port, {
                pytest.top.in_port: expected_out_pkt}, {
                pytest.top.mirror_dest: [
                    sflow_pkt, [
                        (U.sflow_tunnel_metadata, "source_sp")]]}, True)

    # Test case 6 -- packet sampled on rif
    def test_packet_sampling_rate_on_one_port(self):
        '''
        Create new mirror packet sample object. Attach it to port. Using an
        Sflow mirror object, attach as sample mirror session object to the
        same port as a packet sample object is attached to. Check correctness
        of packet sampling using attributes,destination from sflow mirror
        instance but sampling rate from packet sample object.
        '''
        self.__init()
        sflowOid, in_pkt, sflow_pkt = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__route_pkt_from_port1_to_port2(in_pkt, expected_out_pkt, sflow_pkt)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 7
    def test_packet_sampling_rate_on_two_port(self):
        '''
        Create new mirror packet sample object. Attach it to port. Using an
        Sflow mirror object, attach as sample mirror session object to the
        same port as a packet sample object is attached to. Check correctness
        of packet sampling using attributes,destination from sflow mirror
        instance but sampling rate from packet sample object. Attach packet
        sample object on second ingress port.  Attach same sflow mirror object
        on both ports. Check ingress traffic on both ingress ports get sampled at
        the sampling rate specified by single packet sample object.
        '''

        self.__init()
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2, expected_out_pkt2  = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac2, pytest.top.neighbor_mac1, pytest.top.neighbor_ip2, pytest.top.neighbor_ip1)

        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 8
    def test_packet_sampling_rate_on_two_port_attach_detach(self):
        '''
        Variations of test case [7]. Attach and Detach both packet sample object,
        and sample mirror.
        '''

        self.__init()
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 routed to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2, expected_out_pkt2  = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac2, pytest.top.neighbor_mac1, pytest.top.neighbor_ip2, pytest.top.neighbor_ip1)
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Detach from port1
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)

        # Check sampling on port2 is unaffected
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Reattach on port1
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Check sampling on port1 and port2 is back up and fine.
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Detach from port2
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)

        # Check sampling on port1 is unaffected
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Reattach on port2
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 9
    def test_packet_sampling_rate_on_two_port_attach_detach_sample_object(self):
        '''
        Variations of test case [7]. Attach and Detach only packet sample object
        '''

        self.__init()
        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2, expected_out_pkt2  = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac2, pytest.top.neighbor_mac1, pytest.top.neighbor_ip2, pytest.top.neighbor_ip1)

        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Detach from port1
        self.utils.detach_samplepacket_object(pytest.top.in_port)

        # Check sampling on port2 is unaffected
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Reattach on port1
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)

        # Check sampling on port1 and port2 is back up and fine.
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Detach from port2
        self.utils.detach_samplepacket_object(pytest.top.out_port)

        # Check sampling on port1 is unaffected
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Reattach on port2
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)

        # Check sampling on port1 and port2 is back up and fine.
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 10
    def test_packet_sampling_rate_on_two_port_attach_detach_sample_mirror_object(self):
        '''
        Variations of test case [7]. Attach and Detach only sample mirror object
        '''

        self.__init()

        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2, expected_out_pkt2  = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac2, pytest.top.neighbor_mac1, pytest.top.neighbor_ip2, pytest.top.neighbor_ip1)

        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Detach from port1
        self.utils.detach_samplepacket_object(pytest.top.in_port)

        # Check sampling on port2 is unaffected
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Reattach on port1
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)

        # Check sampling on port1 and port2 is back up and fine.
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Detach from port2
        self.utils.detach_samplepacket_object(pytest.top.out_port)

        # Check sampling on port1 is unaffected
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Reattach on port2
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)

        # Check sampling on port1 and port2 is back up and fine.
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 11
    def test_packet_sampling_rate_on_two_port_sampling_rate_modified(self):
        '''
        Perform [7]. Modify sample rate on packet sample object to zero. Check no sampling is done
        both ingress ports.
        '''
        self.__init()

        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2, expected_out_pkt2  = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac2, pytest.top.neighbor_mac1, pytest.top.neighbor_ip2, pytest.top.neighbor_ip1)

        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 0})
        U.run_and_compare_set(
            self, in_pkt1, pytest.top.in_port, {pytest.top.out_port: expected_out_pkt1}, True)
        U.run_and_compare_set(
            self, in_pkt2, pytest.top.out_port, {pytest.top.in_port: expected_out_pkt2}, True)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 12
    def test_packet_sampling_rate_on_two_port_two_sampling_rates(self):
        '''
        Create two new packet sample objects with rate R1=100% and R2=0%. Attach sample1 on port 1 and sample2
        on port2. Attach same sflow mirror object on both ports. Check ingress traffic on both
        ingress ports get sampled at the sampling rate specified by respective packet sample object.
        '''
        self.__init()

        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Create packet sampling object1 with 100% sampling rate
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)

        # Create packet sampling object1 with 0% sampling rate
        mirrorPacketSampleOidZeroPcent = self.utils.create_mirror_type_samplepacket_session(0)

        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOidZeroPcent)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2, expected_out_pkt2  = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac2, pytest.top.neighbor_mac1, pytest.top.neighbor_ip2, pytest.top.neighbor_ip1)

        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # No packet should arrive on mirror destination port since sampling rate is zero.
        U.run_and_compare_set(
            self, in_pkt2, pytest.top.out_port, {
                pytest.top.in_port: expected_out_pkt2}, True)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)
        pytest.tb.remove_object(mirrorPacketSampleOidZeroPcent)

    # Test case 13
    def test_packet_sampling_rate_on_two_port_two_sampling_rates_swap(self):
        '''
        Perform [12]. Change sampling rate on packet object 1 = 0% and on packet object 2 to 100%
        Check packets are mirrored only on those ports where sample object1 is attached but not
        on ingress port where packet sample object2 is attached.
        '''
        self.__init()

        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Create packet sampling object1 with 100% sampling rate
        mirrorPacketSampleOid1 = self.utils.create_mirror_type_samplepacket_session(1)
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid1)

        # Create packet sampling object1 with 0% sampling rate
        mirrorPacketSampleOid2 = self.utils.create_mirror_type_samplepacket_session(0)

        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid2)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2, expected_out_pkt2  = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac2, pytest.top.neighbor_mac1, pytest.top.neighbor_ip2, pytest.top.neighbor_ip1)

        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # No packet should arrive on mirror destination port since sampling rate of zero is attached on top.out_port.
        U.run_and_compare_set(
            self, in_pkt2, pytest.top.out_port, {
                pytest.top.in_port: expected_out_pkt2}, True)

        # Flip Sampling rate on packet sampling instances.
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid1, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 0})
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid2, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 1})

        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)
        U.run_and_compare_set(self, in_pkt1, pytest.top.in_port, {pytest.top.out_port: expected_out_pkt1}, True)

        # Flip back
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid1, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 1})
        self.utils.modify_packet_sampling_object_attribute(mirrorPacketSampleOid2, {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: 0})

        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)
        U.run_and_compare_set(
            self, in_pkt2, pytest.top.out_port, {
                pytest.top.in_port: expected_out_pkt2}, True)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid1)
        pytest.tb.remove_object(mirrorPacketSampleOid2)

    # Test case 14
    def test_packet_sampling_rate_on_two_port_add_delete_logical_ports(self):
        '''
        Create new mirror packet sample object. Attach it to port. Using an
        Sflow mirror object, attach as sample mirror session object to the
        same port as a packet sample object is attached to. Check correctness
        of packet sampling using attributes,destination from sflow mirror
        instance but sampling rate from packet sample object. Attach packet
        sample object on second ingress port.  Attach same sflow mirror object
        on both ports. Check ingress traffic on both ingress ports get sampled at
        the sampling rate specified by single packet sample object.

        Delete existing logical ports on both physical ports ana add them
        back. After adding them back, check packet sampling correctness.
        '''
        self.__init()

        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2, expected_out_pkt2  = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac2, pytest.top.neighbor_mac1, pytest.top.neighbor_ip2, pytest.top.neighbor_ip1)

        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Delete rif and add back to check if newly created l3-port continues to mirror.
        pytest.top.deconfigure_rif_id_1_v4_v6()
        pytest.top.configure_rif_id_1_v4_v6(pytest.top.in_port)

        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)
        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 15
    def test_packet_sampling_rate_on_two_port_add_delete_logical_ports_sampling_obect_attach_detach(self):
        '''
        Create new mirror packet sample object. Attach it to port. Using an
        Sflow mirror object, attach as sample mirror session object to the
        same port as a packet sample object is attached to. Check correctness
        of packet sampling using attributes,destination from sflow mirror
        instance but sampling rate from packet sample object. Attach packet
        sample object on second ingress port.  Attach same sflow mirror object
        on both ports. Check ingress traffic on both ingress ports get sampled at
        the sampling rate specified by single packet sample object.

        Delete existing logical ports on both physical ports ana add them
        back. After adding them back, check packet sampling correctness.
        Perform various variations of delete/add logical port along with
             - detach/attach sample mirror objects
             - detach/attach sample packet objects

        '''

        def delete_add_rif():
            pytest.top.deconfigure_rif_id_1_v4_v6()
            pytest.top.configure_rif_id_1_v4_v6(pytest.top.in_port)

        def packet_sampling_check():
            self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)
            self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        self.__init()

        sflowOid, in_pkt1, sflow_pkt1 = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Create packet sampling object
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        # Attach sflow mirror object as sampling mirror object to use.
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        # Inject traffic and check packet is sampled to sflow mirror object's
        # destination with sampling rate in mirrorPacketSampleOid
        self.__route_pkt_from_port1_to_port2(in_pkt1, expected_out_pkt1, sflow_pkt1)

        # Attach packet sampling on second port
        self.utils.attach_samplepacket_object(pytest.top.out_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.out_port, [sflowOid])

        # create pkt to be injected on port2 switched to port1
        attrs = self.sflowUtils.build_sflow_session_attr()
        in_pkt2, sflow_pkt2, expected_out_pkt2  = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.out_port_sp_gid, pytest.top.neighbor_mac2, pytest.top.neighbor_mac1, pytest.top.neighbor_ip2, pytest.top.neighbor_ip1)

        self.__route_pkt_from_port2_to_port1(in_pkt2, expected_out_pkt2, sflow_pkt2)

        # Delete bridge port and add back to check if newly created l2-port continues to mirror.
        delete_add_rif()
        packet_sampling_check()

        # Variation 1: Detach sample mirror object, add, delete logical port and attach back sample mirror object
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        delete_add_rif()
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])
        packet_sampling_check()

        # Variation 2: Detach sample packet object, add, delete logical port and attach back sample packet object
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        delete_add_rif()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        packet_sampling_check()

        # Variation 3: Detach sample mirror object and packet sample object, add,
        # delete logical port and attach back sample mirror object and packet
        # sample object
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        delete_add_rif()
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        packet_sampling_check()

        # cleanup
        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        self.utils.detach_sample_mirror_session(pytest.top.out_port)
        self.utils.detach_samplepacket_object(pytest.top.out_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 16
    def test_resource_leak_check(self):
        '''
        Check mirror resource leak by creating sample mirror sessions, attaching to port
        and detating from port.
        '''
        self.__init()
        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()

        # There are resources for 32 mirror sessions. Repeat more than 32 times.
        for i in range(50):
            sflowOid = self.utils.create_sflow_session()
            self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
            self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])
            self.utils.detach_sample_mirror_session(pytest.top.in_port)
            self.utils.detach_samplepacket_object(pytest.top.in_port)
            pytest.tb.remove_object(sflowOid)

        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 17
    def test_modify_mirror_object_sampling_rate(self):
        '''
        Modify mirror object's sampling rate. This new rate should not be applied
        on packet sampling mirror instances.
        '''
        self.__init()
        sflowOid, in_pkt, sflow_pkt = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__route_pkt_from_port1_to_port2(in_pkt, expected_out_pkt, sflow_pkt)

        # Modify mirror objects sample rate.
        attrs = {}
        attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 0
        for k, v in attrs.items():
            pytest.tb.set_object_attr(sflowOid, k, v, verify=True)

        self.__route_pkt_from_port1_to_port2(in_pkt, expected_out_pkt, sflow_pkt)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)

    # Test case 18
    def test_modify_mirror_object_encap(self):
        '''
        Modify mirror object's attribute other than sampling rate. This new attribute be applied
        on packet sampling mirror instances.
        '''
        self.__init()
        sflowOid, in_pkt, sflow_pkt = self.sflowUtils.create_sflow_session_and_route_inpkt_sflow_pkt(
            pytest.top.port_cfg.in_port_sp_gid)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        mirrorPacketSampleOid = self.utils.create_mirror_type_samplepacket_session()
        self.utils.attach_samplepacket_object(pytest.top.in_port, mirrorPacketSampleOid)
        self.utils.attach_sample_mirror_session(pytest.top.in_port, [sflowOid])

        self.__route_pkt_from_port1_to_port2(in_pkt, expected_out_pkt, sflow_pkt)

        # Modify mirror objects encap.
        attrs = {}
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS] = "11.11.11.11"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS] = "22.22.22.22"
        for k, v in attrs.items():
            pytest.tb.set_object_attr(sflowOid, k, v, verify=True)

        # Build sflow pkt to reflect change in encap.
        attrs = self.sflowUtils.build_sflow_session_attr()
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS] = "11.11.11.11"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS] = "22.22.22.22"
        _, new_sflow_pkt, _ = self.sflowUtils.create_routable_inpkt_and_out_sflow_pkt(
            attrs, pytest.top.port_cfg.in_port_sp_gid, pytest.top.neighbor_mac1, pytest.top.neighbor_mac2, pytest.top.neighbor_ip1, pytest.top.neighbor_ip2)

        self.__route_pkt_from_port1_to_port2(in_pkt, expected_out_pkt, new_sflow_pkt)

        self.utils.detach_sample_mirror_session(pytest.top.in_port)
        self.utils.detach_samplepacket_object(pytest.top.in_port)
        pytest.tb.remove_object(sflowOid)
        pytest.tb.remove_object(mirrorPacketSampleOid)
