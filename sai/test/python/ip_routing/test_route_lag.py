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

import pytest
import sai_packet_utils as U
import sai_test_utils as st_utils
from scapy.all import *
from saicli import *


@pytest.mark.usefixtures("router_lag_v4_topology")
@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_route_lag():
    def test_topology_config(self):
        pytest.top.deconfigure_router_lag_topology()
        pytest.top.configure_router_lag_topology()
        pytest.top.deconfigure_router_lag_topology()
        pytest.top.configure_router_lag_topology()

    def test_rp_to_rp_lag(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.sw_port: expected_out_pkt})

        # Disable ttl
        pytest.tb.set_object_attr(pytest.top.lag_id, SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL, True)

        expected_out_pkt_dis_ttl = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt_dis_ttl, pytest.top.sw_port: expected_out_pkt_dis_ttl})

        pytest.tb.set_object_attr(pytest.top.lag_id, SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL, False)

        # Disable traffic distribution on one the lag members
        pytest.tb.set_lag_mem_egress_set_state(pytest.top.lag_member_id, disable=True)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.sw_port)
        # Unable traffic distribution and check the traffic back through out_port
        pytest.tb.set_lag_mem_egress_set_state(pytest.top.lag_member_id, disable=False)
        pytest.tb.set_lag_mem_egress_set_state(pytest.top.lag_member_id2, disable=True)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    def test_rp_lag_to_rp(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac2) / \
            IP(src=pytest.top.neighbor_ip2, dst=pytest.top.neighbor_ip1, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip2, dst=pytest.top.neighbor_ip1, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

    def test_lag_port_attributes(self):
        # get the following attributes before the out_port joining lag
        port_attr_list = [SAI_PORT_ATTR_ADMIN_STATE,
                          SAI_PORT_ATTR_FEC_MODE,
                          SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE,
                          SAI_PORT_ATTR_MEDIA_TYPE,
                          SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE,
                          SAI_PORT_ATTR_PORT_VLAN_ID,
                          SAI_PORT_ATTR_MTU,
                          SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP,
                          SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP,
                          SAI_PORT_ATTR_DISABLE_DECREMENT_TTL,
                          SAI_PORT_ATTR_INTERFACE_TYPE,
                          SAI_PORT_ATTR_PKT_TX_ENABLE,
                          SAI_PORT_ATTR_INGRESS_MIRROR_SESSION,
                          SAI_PORT_ATTR_EGRESS_MIRROR_SESSION,
                          SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE,
                          SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE,
                          SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION,
                          SAI_PORT_ATTR_EGRESS_SAMPLE_MIRROR_SESSION]

        pytest.tb.remove_lag_member(pytest.top.lag_member_id)

        out_port_oid = pytest.tb.ports[pytest.top.port_cfg.out_port]

        # get port attributes before lag
        lag_attr_dict = {}
        for attr in port_attr_list:
            attr_val = pytest.tb.get_object_attr(out_port_oid, attr)
            lag_attr_dict[attr] = attr_val

        # join lag
        pytest.top.lag_member_id = pytest.tb.create_lag_member(pytest.top.lag_id, pytest.top.out_port)

        # check port attribute before and after join lag
        for attr in port_attr_list:
            attr_val = pytest.tb.get_object_attr(out_port_oid, attr)
            print("attr = {0} val = {1}".format(attr, attr_val))
            assert lag_attr_dict[attr] == attr_val

        pytest.tb.do_warm_boot()

        # check port attribute before and warmboot
        for attr in port_attr_list:
            attr_val = pytest.tb.get_object_attr(out_port_oid, attr)
            print("attr = {0} val = {1}".format(attr, attr_val))
            assert lag_attr_dict[attr] == attr_val
