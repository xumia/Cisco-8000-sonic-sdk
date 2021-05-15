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

#!/usr/bin/env python3

import saicli as S
import sai_test_utils as st_utils
import sai_packet_utils as U
from prettytable import PrettyTable


class sai_topology():
    tg_port = 0
    snake_port_list = []

    neighbor_mac1 = "00:06:06:06:06:06"
    neighbor_mac1_user_meta = 0x1
    neighbor_mac2 = "00:07:07:07:07:07"
    neighbor_mac2_user_meta = 0x1f
    neighbor_mac4 = "00:08:08:08:08:08"
    neighbor_mac4_user_meta = 0xff

    svi_dst_host1 = "00:00:00:00:25:26"
    svi_acc_host = "00:00:00:33:55:55"

    svi_mac1 = "00:55:55:56:66:13"
    svi_mac2 = "00:77:77:78:88:14"

    svi_mac = "10:12:13:14:15:16";
    svi_dst_neighbor_mac = "00:72:73:74:75:76";
    svi_router_neighbor_mac = "00:a2:a3:a4:a5:a6";
    svi_router_router_mac = "00:22:23:24:25:26";

    v4_svi_ip1 = "12.10.3.3"
    v4_svi_ip2 = "12.10.3.9"
    v4_svi_ip_prefix = "12.10.3.0"
    v4_svi_ip_prefix_mask = "255.255.255.0"

    v4_svi_dst_prefix = "12.10.0.0"
    v4_svi_dst_prefix_mask = "255.255.0.0"
    v4_svi_dst_neighbor_ip = "12.10.12.10"
    v4_svi_router_prefix = "82.81.0.0"
    v4_svi_router_prefix_mask = "255.255.0.0"
    v4_svi_router_ip = "82.81.1.2"
    v4_svi_router_neighbor_ip = "82.81.95.250"
    v4_svi_route2_prefix = "13.11.0.0"
    v4_svi_route2_mask = "255.255.0.0"
    v4_svi_route2_ip = "13.11.0.33"
    v4_route3_prefix = "13.11.11.0"
    v4_route3_mask = "255.255.255.0"
    v4_route3_ip = "13.11.11.50"
    v4_route4_prefix = "13.0.0.0"
    v4_route4_mask = "255.0.0.0"
    v4_route4_ip = "13.1.1.1"
    v4_svi_route3_prefix = "13.12.0.0"
    v4_svi_route3_mask = "255.255.0.0"
    v4_svi_route3_ip = "13.12.11.10"

    v4_default_ip = "0.0.0.0"
    v4_default_ip_mask = "0.0.0.0"
    v4_local_ip1 = "192.168.0.1"
    v4_local_ip2 = "192.169.0.1"

    v4_neighbor_ip1 = "192.168.1.6"
    v4_neighbor_ip1_user_meta = 5
    v4_neighbor_ip2 = "192.169.1.7"
    v4_neighbor_ip2_user_meta = 6
    v4_neighbor_ip4 = "192.170.1.8"
    v4_route_prefix1 = "192.168.0.0"
    v4_route_prefix1_mask = "255.255.0.0"
    v4_route_prefix1_user_meta = 1
    v4_route_prefix2 = "192.169.0.0"
    v4_route_prefix2_mask = "255.255.0.0"
    v4_route_prefix2_user_meta = 2
    v4_route_prefix3 = "190.122.0.0"
    v4_route_prefix3_mask = "255.255.0.0"
    v4_route_prefix3_user_meta = 33
    v4_route_ip3 = "190.122.1.12"
    v4_route_prefix4 = "192.170.0.0"
    v4_route_prefix4_mask = "255.255.0.0"
    v4_route_prefix4_user_meta = 44
    v4_full_mask = "255.255.255.255"

    v6_neighbor_ip1 = "1111:db9:a0b:12f0::2222"
    v6_neighbor_ip1_user_meta = 7
    v6_neighbor_ip2 = "1111:db8:a0b:12f0::1111"
    v6_neighbor_ip2_user_meta = 8
    v6_neighbor_ip4 = "1111:db7:a0b:12f0::1120"
    v6_route_prefix1 = "1111:db9:a00::"
    v6_route_prefix1_mask = "ffff:ffff:ff00::"
    v6_route_prefix1_user_meta = 3
    v6_route_prefix2 = "1111:db8:a00::"
    v6_route_prefix2_mask = "ffff:ffff:ff00::"
    v6_route_prefix2_user_meta = 4
    v6_route_prefix3 = "1133:db8:a00::"
    v6_route_prefix3_mask = "ffff:ffff:ff00::"
    v6_route_ip3 = "1133:db8:a00::3333"
    v6_route_prefix4 = "1111:db7:a00::"
    v6_route_prefix4_mask = "ffff:ffff:ff00::"

    v6_default_ip = "0000::"
    v6_default_ip_mask = "0000::"
    v6_local_ip1 = "fe80:0db9:0a0b:12f0:4041:43ff:fe45:4749"
    v6_local_ip2 = "fe80:0db9:0a0b:12f0:4041:43ff:fe45:474a"

    v6_svi_ip1 = "2222:db8:a00::3333:8888";
    v6_svi_ip2 = "2222:db8:a00::3333:9999";
    v6_svi_ip_prefix = "2222:db8:a0b:12f0:3333::"
    v6_svi_ip_prefix_mask = "ffff:ffff:ffff:ffff:ffff::"
    v6_svi_dst_prefix = "2222:db8:a00::"
    v6_svi_dst_prefix_mask = "ffff:ffff:ff00::"
    v6_svi_dst_neighbor_ip = "2222:db8:a0b:12f0::2222";
    v6_svi_router_neighbor_mac = "a1:a2:a3:a4:a5:a6";
    v6_svi_router_router_mac = "21:22:23:24:25:26";
    v6_svi_router_prefix = "3333:db8:0a00::"
    v6_svi_router_prefix_mask = "ffff:ffff:ff00::"
    v6_svi_router_neighbor_ip = "3333:db8:a0b:12f0::3333";
    v6_svi_route2_prefix = "4444:0db8:0a00::"
    v6_svi_route2_mask = "ffff:ffff:ff00::"
    v6_svi_route2_ip = "4444:db8:a00::4444";
    v6_route3_prefix = "4444:db8:a00:a00::"
    v6_route3_mask = "ffff:ffff:ffff:ff00::"
    v6_route3_ip = "4444:db8:a00:a00::4444"
    v6_route4_prefix = "4444:db8::"
    v6_route4_mask = "ffff:ffff::"
    v6_route4_ip = "4444:db8:100::"
    v6_svi_route3_prefix = "4444:b00:a00::"
    v6_svi_route3_mask = "ffff:ffff:ff00::"
    v6_svi_route3_ip = "4444:b00:a00::4444"

    v6_inj_ll_ip = "5555:db8:a00::"
    v6_inj_ll_mask = "ffff:ffff:ff00::"
    v6_link_local_mac = "40:41:43:45:aa:aa"
    v6_link_local_ip = "ff80:db9:a0b:12f0:4041:43ff:fe45:aaaa"
    v6_full_mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

    vlan = 203
    snake_base_vlan = 203

    # vxlan topology variables# single port setup

    # local loopback address
    v4_vxlan_local_lpbk = "5.0.0.0"

    # remote loopback address
    v4_vxlan_remote_lpbk = "5.0.0.1"

    def __init__(self, st_base, ip_type):
        self.tb = st_base
        self.ip_type = ip_type

        self.port_cfg = st_utils.PortConfig()
        self.in_port = self.port_cfg.in_port
        self.out_port = self.port_cfg.out_port
        self.rt_port = self.port_cfg.rt_port
        self.rt_port1 = self.port_cfg.rt_port1
        self.mirror_dest = self.port_cfg.mirror_dest
        self.sw_port = self.port_cfg.sw_port
        self.in_port_cfg = self.port_cfg.in_port_cfg
        self.out_port_cfg = self.port_cfg.out_port_cfg
        self.sw_port_cfg = self.port_cfg.sw_port_cfg
        self.rt_port_cfg = self.port_cfg.rt_port_cfg
        self.rt_port1_cfg = self.port_cfg.rt_port1_cfg
        self.mirror_dest_cfg = self.port_cfg.mirror_dest_cfg

        if ip_type == "v4":
            self.neighbor_ip1 = self.v4_neighbor_ip1
            self.neighbor_ip2 = self.v4_neighbor_ip2
            self.neighbor_ip4 = self.v4_neighbor_ip4
            self.route_prefix1 = self.v4_route_prefix1
            self.route_prefix1_mask = self.v4_route_prefix1_mask
            self.route_prefix2 = self.v4_route_prefix2
            self.route_prefix2_mask = self.v4_route_prefix2_mask
            self.route_prefix3 = self.v4_route_prefix3
            self.route_prefix3_mask = self.v4_route_prefix3_mask
            self.route_prefix3_user_meta = self.v4_route_prefix3_user_meta
            self.route_ip3 = self.v4_route_ip3
            self.route_prefix4 = self.v4_route_prefix4
            self.route_prefix4_mask = self.v4_route_prefix4_mask
            self.route_prefix4_user_meta = self.v4_route_prefix4_user_meta

            self.default_ip = self.v4_default_ip
            self.default_ip_mask = self.v4_default_ip_mask
            self.local_ip1 = self.v4_local_ip1
            self.local_ip2 = self.v4_local_ip2
            self.full_mask = self.v4_full_mask

            self.svi_ip1 = self.v4_svi_ip1
            self.svi_ip2 = self.v4_svi_ip2
            self.svi_ip_prefix = self.v4_svi_ip_prefix
            self.svi_ip_prefix_mask = self.v4_svi_ip_prefix_mask
            self.svi_dst_prefix = self.v4_svi_dst_prefix
            self.svi_dst_prefix_mask = self.v4_svi_dst_prefix_mask
            self.svi_dst_neighbor_ip = self.v4_svi_dst_neighbor_ip
            self.svi_router_prefix = self.v4_svi_router_prefix
            self.svi_router_prefix_mask = self.v4_svi_router_prefix_mask
            self.svi_router_ip = self.v4_svi_router_ip
            self.svi_router_neighbor_ip = self.v4_svi_router_neighbor_ip
            self.svi_route2_prefix = self.v4_svi_route2_prefix
            self.svi_route2_mask = self.v4_svi_route2_mask
            self.svi_route2_ip = self.v4_svi_route2_ip

            self.route3_prefix = self.v4_route3_prefix
            self.route3_mask = self.v4_route3_mask
            self.route3_ip = self.v4_route3_ip
            self.route4_prefix = self.v4_route4_prefix
            self.route4_mask = self.v4_route4_mask
            self.route4_ip = self.v4_route4_ip
            self.svi_route3_prefix = self.v4_svi_route3_prefix
            self.svi_route3_mask = self.v4_svi_route3_mask
            self.svi_route3_ip = self.v4_svi_route3_ip

        elif ip_type == "v6":
            self.neighbor_ip1 = self.v6_neighbor_ip1
            self.neighbor_ip2 = self.v6_neighbor_ip2
            self.neighbor_ip4 = self.v6_neighbor_ip4
            self.route_prefix1 = self.v6_route_prefix1
            self.route_prefix1_mask = self.v6_route_prefix1_mask
            self.route_prefix2 = self.v6_route_prefix2
            self.route_prefix2_mask = self.v6_route_prefix2_mask
            self.route_prefix3 = self.v6_route_prefix3
            self.route_prefix3_mask = self.v6_route_prefix3_mask
            self.route_prefix4 = self.v6_route_prefix4
            self.route_prefix4_mask = self.v6_route_prefix4_mask
            self.route_ip3 = self.v6_route_ip3
            self.default_ip = self.v6_default_ip
            self.default_ip_mask = self.v6_default_ip_mask
            self.local_ip1 = self.v6_local_ip1
            self.local_ip2 = self.v6_local_ip2
            self.full_mask = self.v6_full_mask

            self.svi_ip1 = self.v6_svi_ip1
            self.svi_ip2 = self.v6_svi_ip2
            self.svi_ip_prefix = self.v6_svi_ip_prefix
            self.svi_ip_prefix_mask = self.v6_svi_ip_prefix_mask
            self.svi_dst_prefix = self.v6_svi_dst_prefix
            self.svi_dst_prefix_mask = self.v6_svi_dst_prefix_mask
            self.svi_dst_neighbor_ip = self.v6_svi_dst_neighbor_ip
            self.svi_router_prefix = self.v6_svi_router_prefix
            self.svi_router_prefix_mask = self.v6_svi_router_prefix_mask
            self.svi_router_neighbor_ip = self.v6_svi_router_neighbor_ip
            self.svi_route2_prefix = self.v6_svi_route2_prefix
            self.svi_route2_mask = self.v6_svi_route2_mask
            self.svi_route2_ip = self.v6_svi_route2_ip

            self.route3_prefix = self.v6_route3_prefix
            self.route3_mask = self.v6_route3_mask
            self.route3_ip = self.v6_route3_ip
            self.route4_prefix = self.v6_route4_prefix
            self.route4_mask = self.v6_route4_mask
            self.route4_ip = self.v6_route4_ip
            self.svi_route3_prefix = self.v6_svi_route3_prefix
            self.svi_route3_mask = self.v6_svi_route3_mask
            self.svi_route3_ip = self.v6_svi_route3_ip

        else:
            print("Wrong IP type")
            assert(False)

    # basic router topology for IPv4 and IPv6 tests
    #                    ---------------------------------
    #                    |in_port:             out_port: |
    # neighbor_ip1       |route_prefix1    route_prefix2 |      neighbor_ip2
    # neighbor_mac1 <--> |router_mac           router_mac| <--> neighbor_mac2
    #                    |                               |
    #                    |                 route_prefix4 |      neighbor_ip4
    #                    |                     router_mac| <--> neighbor_mac4
    #                    ---------------------------------
    def configure_rif_id_1(self, port_index):
        self.tb.rif_id_1 = self.tb.create_router_interface(
            self.tb.virtual_router_id, port_index, S.SAI_ROUTER_INTERFACE_TYPE_PORT)
        self.tb.create_route(self.tb.virtual_router_id, self.route_prefix1, self.route_prefix1_mask, self.tb.rif_id_1)
        self.tb.create_neighbor(self.tb.rif_id_1, self.neighbor_ip1, self.neighbor_mac1)
        self.tb.nh_id1 = self.tb.create_next_hop(self.neighbor_ip1, self.tb.rif_id_1)

    def deconfigure_rif_id_1(self):
        self.tb.remove_next_hop(self.tb.nh_id1)
        self.tb.remove_neighbor(self.tb.rif_id_1, self.neighbor_ip1)
        self.tb.remove_route(self.tb.virtual_router_id, self.route_prefix1, self.route_prefix1_mask)
        self.tb.remove_router_interface(self.tb.rif_id_1)

    def configure_rif_id_1_v4_v6(self, port_index):
        self.tb.rif_id_1 = self.tb.create_router_interface(self.tb.virtual_router_id, port_index, S.SAI_ROUTER_INTERFACE_TYPE_PORT)
        self.tb.create_route(self.tb.virtual_router_id, self.v4_route_prefix1, self.v4_route_prefix1_mask, self.tb.rif_id_1)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_route_prefix1, self.v6_route_prefix1_mask, self.tb.rif_id_1)
        self.tb.create_neighbor(self.tb.rif_id_1, self.v4_neighbor_ip1, self.neighbor_mac1)
        self.tb.create_neighbor(self.tb.rif_id_1, self.v6_neighbor_ip1, self.neighbor_mac1)
        self.tb.nh_id1_v4 = self.tb.create_next_hop(self.v4_neighbor_ip1, self.tb.rif_id_1)
        self.tb.nh_id1_v6 = self.tb.create_next_hop(self.v6_neighbor_ip1, self.tb.rif_id_1)

    def deconfigure_rif_id_1_v4_v6(self):
        self.tb.remove_next_hop(self.tb.nh_id1_v4)
        self.tb.remove_next_hop(self.tb.nh_id1_v6)
        self.tb.remove_neighbor(self.tb.rif_id_1, self.v4_neighbor_ip1)
        self.tb.remove_neighbor(self.tb.rif_id_1, self.v6_neighbor_ip1)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_route_prefix1, self.v4_route_prefix1_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_route_prefix1, self.v6_route_prefix1_mask)
        self.tb.remove_router_interface(self.tb.rif_id_1)

    def configure_rif_id_2_v4_v6(self, port_index):
        self.tb.rif_id_2 = self.tb.create_router_interface(self.tb.virtual_router_id, port_index, S.SAI_ROUTER_INTERFACE_TYPE_PORT)
        self.tb.create_route(self.tb.virtual_router_id, self.v4_route_prefix2, self.v4_route_prefix2_mask, self.tb.rif_id_2)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_route_prefix2, self.v6_route_prefix2_mask, self.tb.rif_id_2)
        self.tb.create_neighbor(self.tb.rif_id_2, self.v4_neighbor_ip2, self.neighbor_mac2)
        self.tb.create_neighbor(self.tb.rif_id_2, self.v6_neighbor_ip2, self.neighbor_mac2)
        self.tb.nh_id2_v4 = self.tb.create_next_hop(self.v4_neighbor_ip2, self.tb.rif_id_2)
        self.tb.nh_id2_v6 = self.tb.create_next_hop(self.v6_neighbor_ip2, self.tb.rif_id_2)

    def deconfigure_rif_id_2_v4_v6(self):
        self.tb.remove_next_hop(self.tb.nh_id2_v4)
        self.tb.remove_next_hop(self.tb.nh_id2_v6)
        self.tb.remove_neighbor(self.tb.rif_id_2, self.v4_neighbor_ip2)
        self.tb.remove_neighbor(self.tb.rif_id_2, self.v6_neighbor_ip2)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_route_prefix2, self.v4_route_prefix2_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_route_prefix2, self.v6_route_prefix2_mask)
        self.tb.remove_router_interface(self.tb.rif_id_2)

    def configure_rif_id_2(self, port_index, rif=None):
        if rif is None:
            self.tb.rif_id_2 = self.tb.create_router_interface(
                self.tb.virtual_router_id, port_index, S.SAI_ROUTER_INTERFACE_TYPE_PORT)
        else:
            self.tb.rif_id_2 = self.tb.rif_id_1
        self.tb.create_route(self.tb.virtual_router_id, self.route_prefix2, self.route_prefix2_mask, self.tb.rif_id_2)
        self.tb.create_neighbor(self.tb.rif_id_2, self.neighbor_ip2, self.neighbor_mac2)
        self.tb.nh_id2 = self.tb.create_next_hop(self.neighbor_ip2, self.tb.rif_id_2)

    def deconfigure_rif_id_2(self, rif=None):
        self.tb.remove_next_hop(self.tb.nh_id2)
        self.tb.remove_neighbor(self.tb.rif_id_2, self.neighbor_ip2)
        self.tb.remove_route(self.tb.virtual_router_id, self.route_prefix2, self.route_prefix2_mask)
        if rif is None:
            self.tb.remove_router_interface(self.tb.rif_id_2)

    def configure_rif_id_4(self, port_index):
        self.tb.rif_id_4 = self.tb.create_router_interface(
            self.tb.virtual_router_id, port_index, S.SAI_ROUTER_INTERFACE_TYPE_PORT)
        self.tb.create_route(self.tb.virtual_router_id, self.route_prefix4, self.route_prefix4_mask, self.tb.rif_id_4)
        self.tb.create_neighbor(self.tb.rif_id_4, self.neighbor_ip4, self.neighbor_mac4)
        self.tb.nh_id3 = self.tb.create_next_hop(self.neighbor_ip4, self.tb.rif_id_4)

    def deconfigure_rif_id_4(self):
        self.tb.remove_next_hop(self.tb.nh_id3)
        self.tb.remove_neighbor(self.tb.rif_id_4, self.neighbor_ip4)
        self.tb.remove_route(self.tb.virtual_router_id, self.route_prefix4, self.route_prefix4_mask)
        self.tb.remove_router_interface(self.tb.rif_id_4)

    def configure_link_local(self, rif_id):
        if self.ip_type == "v4":
            return
        self.tb.create_neighbor(rif_id, self.v6_link_local_ip, self.v6_link_local_mac, True)
        self.tb.nh_ll = self.tb.create_next_hop(self.v6_link_local_ip, rif_id)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_inj_ll_ip, self.v6_inj_ll_mask, self.tb.nh_ll)

    def deconfigure_link_local(self, rif_id):
        if self.ip_type == "v4":
            return
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_inj_ll_ip, self.v6_inj_ll_mask)
        self.tb.remove_next_hop(self.tb.nh_ll)
        self.tb.remove_neighbor(rif_id, self.v6_link_local_ip)

    def configure_rif_loopback(self):
        self.tb.rif_loopback = self.tb.create_router_interface(
            self.tb.virtual_router_id, 0, S.SAI_ROUTER_INTERFACE_TYPE_LOOPBACK)

    def deconfigure_rif_loopback(self):
        self.tb.remove_router_interface(self.tb.rif_loopback)

    # same as basic route topology, but with in_port == out_port
    # this is for runnining with traffic generator connected to SAI device by one port
    def configure_basic_route_one_port_topology(self):
        # to satisfy tests using out_port
        self.out_port = self.in_port
        self.configure_basic_route_topology(in_equals_out=True)

    def deconfigure_basic_route_one_port_topology(self):
        self.out_port = self.in_port
        self.deconfigure_basic_route_topology(in_equals_out=True)

    def configure_basic_route_topology_v4_v6(self):
        # init in_port and out_port
        ports_to_config = [self.in_port_cfg, self.out_port_cfg]
        self.tb.configure_ports(ports_to_config)

        self.configure_rif_id_1_v4_v6(self.in_port)
        self.configure_rif_id_2_v4_v6(self.out_port)

        self.configure_link_local(self.tb.rif_id_2)

        self.tb.create_route(self.tb.virtual_router_id, self.v4_default_ip, self.v4_default_ip_mask, S.SAI_NULL_OBJECT_ID)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_default_ip, self.v6_default_ip_mask, S.SAI_NULL_OBJECT_ID)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v4_local_ip1, self.v4_full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v4_local_ip2, self.v4_full_mask)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v6_local_ip1, self.v6_full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v6_local_ip2, self.v6_full_mask)

        self.configure_rif_loopback()

    def deconfigure_basic_route_topology_v4_v6(self):
        self.deconfigure_rif_loopback()

        self.tb.remove_route(self.tb.virtual_router_id, self.v4_local_ip1, self.v4_full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_local_ip2, self.v4_full_mask)

        self.tb.remove_route(self.tb.virtual_router_id, self.v6_local_ip1, self.v6_full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_local_ip2, self.v6_full_mask)

        self.tb.remove_route(self.tb.virtual_router_id, self.v4_default_ip, self.v4_default_ip_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_default_ip, self.v6_default_ip_mask)

        self.deconfigure_link_local(self.tb.rif_id_2)

        self.deconfigure_rif_id_2_v4_v6()
        self.deconfigure_rif_id_1_v4_v6()
        self.tb.remove_ports()

    def configure_basic_route_topology(self, in_equals_out=False):
        # init in_port and out_port
        ports_to_config = [self.in_port_cfg]

        if not in_equals_out:
            ports_to_config.append(self.out_port_cfg)

        self.tb.configure_ports(ports_to_config)

        self.configure_rif_id_1(self.in_port)

        if in_equals_out:
            rif_id_2 = self.tb.rif_id_1  # use rif_id_1 as rif_id_2
        else:
            rif_id_2 = None  # need to create it
        self.configure_rif_id_2(self.out_port, rif_id_2)
        self.configure_link_local(self.tb.rif_id_2)

        self.tb.create_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask, S.SAI_NULL_OBJECT_ID)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.configure_rif_loopback()

    def deconfigure_basic_route_topology(self, in_equals_out=False):
        self.deconfigure_rif_loopback()
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.tb.remove_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask)

        self.deconfigure_link_local(self.tb.rif_id_2)

        if in_equals_out:
            rif_id_2 = self.tb.rif_id_1
        else:
            rif_id_2 = None
        self.deconfigure_rif_id_2(rif_id_2)
        self.deconfigure_rif_id_1()
        self.tb.remove_ports()

    # svi router topology for IPv4 and IPv6 tests
    #                    -----------------------------------------
    #                    |in_port:                      out_port:| <--> svi_dst_neighbor_mac
    # neighbor_ip1       |route_prefix1                          |      svi_dst_host1
    # neighbor_mac1 <--> |router_mac    svi_rif:                 |
    #                    |              vlan                     |
    #                    |              svi_dst_prefix   sw_port:| <--> acc_host
    #                    |              svi_mac                  |
    #                    |                                       |
    #                    -----------------------------------------
    def configure_bridge_ports(self, vlan, port1, port2, tag=False):
        self.bridge_id = self.tb.create_bridge()
        self.tb.configure_bridge_ports([port1, port2])
        self.tb.configure_vlans([vlan])

        self.tb.configure_vlan_members([{"vlan": vlan, "port": port2, "is_tag": tag},
                                        {"vlan": vlan, "port": port1, "is_tag": tag}]
                                       )
        self.tb.create_fdb_entry(self.tb.vlans[vlan], self.neighbor_mac2, self.tb.bridge_ports[port2])

    def deconfigure_bridge_ports(self, expect_to_fail=False):
        if expect_to_fail is True:
            try:
                self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2)
            except BaseException:
                pass
        else:
            self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2)
        self.tb.deconfigure_vlan_members()

        self.tb.deconfigure_vlans()
        self.tb.deconfigure_bridge_ports()
        self.tb.remove_bridge(self.bridge_id)

    def configure_bridge_ports_learning_mode(self, learning_mode):
        for bridge_port_obj_id in self.tb.bridge_ports.values():
            bport_learn_mode = self.tb.get_bridge_port_attr(bridge_port_obj_id, S.SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE)
            if bport_learn_mode is not learning_mode:
                self.tb.set_bridge_port_attr(bridge_port_obj_id, S.SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE,
                                             learning_mode)

    def configure_bridge_ports_flood_learn(self, vlan, port1, port2, port3):
        self.bridge_id = self.tb.create_bridge()
        self.tb.configure_bridge_ports([port1, port2, port3])
        self.tb.configure_vlans([vlan])

        self.tb.configure_vlan_members([{"vlan": vlan, "port": port3, "is_tag": False},
                                        {"vlan": vlan, "port": port2, "is_tag": False},
                                        {"vlan": vlan, "port": port1, "is_tag": False}])

    def configure_vlan_members_flood_learn(self, vlan, port1, port2, port3):
        self.bridge_id = self.tb.create_bridge()
        self.tb.configure_bridge_ports([port1, port2, port3])
        self.tb.configure_vlans([vlan])

        self.tb.configure_vlan_members([{"vlan": vlan, "port": port3, "is_tag": False},
                                        {"vlan": vlan, "port": port2, "is_tag": True, "out_tag_vlan": 101},
                                        {"vlan": vlan, "port": port1, "is_tag": True, "out_tag_vlan": 101}])

    def configure_svi_ports_v4_v6(self, vlan, port1, port2, tag=False):
        self.configure_bridge_ports(vlan, port1, port2, tag)
        self.tb.svi_rif_id = self.tb.create_router_interface(
            self.tb.virtual_router_id, 0, S.SAI_ROUTER_INTERFACE_TYPE_VLAN, self.svi_mac, vlan)
        self.tb.create_fdb_entry(self.tb.vlans[vlan], self.svi_dst_neighbor_mac, self.tb.bridge_ports[port1])
        self.tb.create_fdb_entry(self.tb.vlans[vlan], self.svi_dst_host1, self.tb.bridge_ports[port1])
        self.tb.create_fdb_entry(self.tb.vlans[vlan], self.svi_acc_host, self.tb.bridge_ports[port2])
        self.tb.create_route(self.tb.virtual_router_id, self.v4_svi_dst_prefix, self.v4_svi_dst_prefix_mask, self.tb.svi_rif_id)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_svi_dst_prefix, self.v6_svi_dst_prefix_mask, self.tb.svi_rif_id)
        self.tb.create_neighbor(self.tb.svi_rif_id, self.v4_svi_dst_neighbor_ip, self.svi_dst_neighbor_mac)
        self.tb.create_neighbor(self.tb.svi_rif_id, self.v6_svi_dst_neighbor_ip, self.svi_dst_neighbor_mac)
        self.tb.svi_nh_v4 = self.tb.create_next_hop(self.v4_svi_dst_neighbor_ip, self.tb.svi_rif_id)
        self.tb.svi_nh_v6 = self.tb.create_next_hop(self.v6_svi_dst_neighbor_ip, self.tb.svi_rif_id)

    def deconfigure_svi_ports_v4_v6(self):
        self.tb.remove_next_hop(self.tb.svi_nh_v4)
        self.tb.remove_next_hop(self.tb.svi_nh_v6)
        self.tb.remove_neighbor(self.tb.svi_rif_id, self.v4_svi_dst_neighbor_ip)
        self.tb.remove_neighbor(self.tb.svi_rif_id, self.v6_svi_dst_neighbor_ip)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_svi_dst_prefix, self.v4_svi_dst_prefix_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_svi_dst_prefix, self.v6_svi_dst_prefix_mask)
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.svi_dst_neighbor_mac)
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.svi_dst_host1)
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.svi_acc_host)
        self.tb.remove_router_interface(self.tb.svi_rif_id)
        self.deconfigure_bridge_ports()

    def configure_svi_ports(self, vlan, port1, port2, tag=False):
        self.configure_bridge_ports(vlan, port1, port2, tag)
        self.tb.svi_rif_id = self.tb.create_router_interface(
            self.tb.virtual_router_id, 0, S.SAI_ROUTER_INTERFACE_TYPE_VLAN, self.svi_mac, vlan)
        self.tb.create_fdb_entry(self.tb.vlans[vlan], self.svi_dst_neighbor_mac, self.tb.bridge_ports[port1])
        self.tb.create_fdb_entry(self.tb.vlans[vlan], self.svi_dst_host1, self.tb.bridge_ports[port1])
        self.tb.create_fdb_entry(self.tb.vlans[vlan], self.svi_acc_host, self.tb.bridge_ports[port2])
        self.tb.create_route(self.tb.virtual_router_id, self.svi_dst_prefix, self.svi_dst_prefix_mask, self.tb.svi_rif_id)
        self.tb.create_neighbor(self.tb.svi_rif_id, self.svi_dst_neighbor_ip, self.svi_dst_neighbor_mac)
        self.tb.svi_nh = self.tb.create_next_hop(self.svi_dst_neighbor_ip, self.tb.svi_rif_id)

    def deconfigure_svi_ports(self):
        self.tb.remove_next_hop(self.tb.svi_nh)
        self.tb.remove_neighbor(self.tb.svi_rif_id, self.svi_dst_neighbor_ip)
        self.tb.remove_route(self.tb.virtual_router_id, self.svi_dst_prefix, self.svi_dst_prefix_mask)
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.svi_dst_neighbor_mac)
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.svi_dst_host1)
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.svi_acc_host)

        self.tb.remove_router_interface(self.tb.svi_rif_id)

        self.deconfigure_bridge_ports()

    def configure_svi_route_topology_v4_v6(self, tag=False):
        # configure in_port, out_port and sw_port
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.sw_port_cfg, self.rt_port_cfg])

        self.configure_rif_id_1_v4_v6(self.in_port)
        self.configure_rif_id_2_v4_v6(self.rt_port)

        # configure out_port and sw_port as switch ports with svi on vlan
        self.configure_svi_ports_v4_v6(self.vlan, self.out_port, self.sw_port, tag)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v4_local_ip1, self.v4_full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v4_local_ip2, self.v4_full_mask)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v6_local_ip1, self.v6_full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v6_local_ip2, self.v6_full_mask)

        self.tb.set_object_attr(self.tb.switch_id, S.SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, self.tb.router_mac)

        # routes through next hops
        self.tb.create_route(self.tb.virtual_router_id, self.v4_route_prefix3, self.v4_route_prefix3_mask, self.tb.nh_id1_v4)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_route_prefix3, self.v6_route_prefix3_mask, self.tb.nh_id1_v6)
        self.tb.create_route(self.tb.virtual_router_id, self.v4_svi_route2_prefix, self.v4_svi_route2_mask, self.tb.svi_nh_v4)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_svi_route2_prefix, self.v6_svi_route2_mask, self.tb.svi_nh_v6)

        # adding more routes
        self.tb.create_route(self.tb.virtual_router_id, self.v4_route4_prefix, self.v4_route4_mask, self.tb.nh_id2_v4)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_route4_prefix, self.v6_route4_mask, self.tb.nh_id2_v6)
        self.tb.create_route(self.tb.virtual_router_id, self.v4_route3_prefix, self.v4_route3_mask, self.tb.nh_id1_v4)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_route3_prefix, self.v6_route3_mask, self.tb.nh_id1_v6)
        self.tb.create_route(self.tb.virtual_router_id, self.v4_svi_route3_prefix, self.v4_svi_route3_mask, self.tb.svi_nh_v4)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_svi_route3_prefix, self.v6_svi_route3_mask, self.tb.svi_nh_v6)

        # default route
        self.tb.create_route(self.tb.virtual_router_id, self.v4_default_ip, self.v4_default_ip_mask, S.SAI_NULL_OBJECT_ID)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_default_ip, self.v6_default_ip_mask, S.SAI_NULL_OBJECT_ID)

    def deconfigure_svi_route_topology_v4_v6(self):
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_default_ip, self.v4_default_ip_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_default_ip, self.v6_default_ip_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_svi_route3_prefix, self.v4_svi_route3_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_svi_route3_prefix, self.v6_svi_route3_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_route3_prefix, self.v4_route3_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_route3_prefix, self.v6_route3_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_route4_prefix, self.v4_route4_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_route4_prefix, self.v6_route4_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_svi_route2_prefix, self.v4_svi_route2_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_svi_route2_prefix, self.v6_svi_route2_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_route_prefix3, self.v4_route_prefix3_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_route_prefix3, self.v6_route_prefix3_mask)

        self.tb.remove_route(self.tb.virtual_router_id, self.v4_local_ip1, self.v4_full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v4_local_ip2, self.v4_full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_local_ip1, self.v6_full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.v6_local_ip2, self.v6_full_mask)

        self.deconfigure_svi_ports_v4_v6()
        self.deconfigure_rif_id_1_v4_v6()
        self.deconfigure_rif_id_2_v4_v6()

        self.tb.remove_ports()

    def configure_svi_route_topology(self, tag=False):
        # configure in_port, out_port and sw_port
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.sw_port_cfg, self.rt_port_cfg])

        self.configure_rif_id_1(self.in_port)
        self.configure_rif_id_2(self.rt_port)

        # configure out_port and sw_port as switch ports with svi on vlan
        self.configure_svi_ports(self.vlan, self.out_port, self.sw_port, tag)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.tb.set_object_attr(self.tb.switch_id, S.SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, self.tb.router_mac)

        # routes through next hops
        self.tb.create_route(self.tb.virtual_router_id, self.route_prefix3, self.route_prefix3_mask, self.tb.nh_id1)
        self.tb.create_route(self.tb.virtual_router_id, self.svi_route2_prefix, self.svi_route2_mask, self.tb.svi_nh)

        # adding more routes
        self.tb.create_route(self.tb.virtual_router_id, self.route4_prefix, self.route4_mask, self.tb.nh_id2)
        self.tb.create_route(self.tb.virtual_router_id, self.route3_prefix, self.route3_mask, self.tb.nh_id1)
        self.tb.create_route(self.tb.virtual_router_id, self.svi_route3_prefix, self.svi_route3_mask, self.tb.svi_nh)

        # default route
        self.tb.create_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask, S.SAI_NULL_OBJECT_ID)

    # svi router topology for IPv4 and IPv6 tests
    #                    -----------------------------------------
    #                    |in_port:                      out_port:| <--> svi_dst_neighbor_mac
    # neighbor_ip1       |route_prefix1                          |      svi_dst_host1
    # neighbor_mac1 <--> |router_mac    svi_rif:                 |
    #                    |              vlan                     |
    #                    |              svi_dst_prefix   sw_port:| <--> acc_host
    # neighbor_ip2       |rt_port:      svi_mac                  |
    # neighbor_mac2 <--> |router_pefix2                          |
    #                    -----------------------------------------
    def deconfigure_svi_route_topology(self):
        self.tb.remove_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.svi_route3_prefix, self.svi_route3_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.route3_prefix, self.route3_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.route4_prefix, self.route4_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.svi_route2_prefix, self.svi_route2_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.route_prefix3, self.route_prefix3_mask)

        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.deconfigure_svi_ports()
        self.deconfigure_rif_id_1()
        self.deconfigure_rif_id_2()

        self.tb.remove_ports()

    def configure_next_hop_group_base_topology(self):
        # configure in_port, out_port, sw_port and rt_port
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.sw_port_cfg, self.rt_port_cfg, self.rt_port1_cfg])

        self.configure_rif_id_1(self.in_port)
        self.configure_rif_id_2(self.rt_port)
        self.configure_rif_id_4(self.rt_port1)
        # configure out_port and sw_port as switch ports with svi on vlan
        self.configure_svi_ports(self.vlan, self.out_port, self.sw_port)

        # default route
        self.tb.create_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask, S.SAI_NULL_OBJECT_ID)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

    def deconfigure_next_hop_group_base_topology(self):
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip2, self.full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask)

        self.deconfigure_svi_ports()

        self.deconfigure_rif_id_4()
        self.deconfigure_rif_id_2()
        self.deconfigure_rif_id_1()
        self.tb.remove_ports()

    def configure_dot1q_bridge_lag_topology(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.sw_port_cfg, self.rt_port_cfg])

        self.lag_id1 = self.tb.create_lag("Label1")
        self.lag_member_id1 = self.tb.create_lag_member(self.lag_id1, self.in_port)
        self.lag_member_id2 = self.tb.create_lag_member(self.lag_id1, self.sw_port)

        self.lag_id2 = self.tb.create_lag("Label2")
        self.lag_member_id3 = self.tb.create_lag_member(self.lag_id2, self.out_port)
        self.lag_member_id4 = self.tb.create_lag_member(self.lag_id2, self.rt_port)

        self.configure_bridge_ports(self.vlan, self.lag_id1, self.lag_id2, True)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

    def deconfigure_dot1q_bridge_lag_topology(self):
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.deconfigure_bridge_ports()

        self.tb.remove_lag_member(self.lag_member_id1)
        self.tb.remove_lag_member(self.lag_member_id2)
        self.tb.remove_lag(self.lag_id1)

        self.tb.remove_lag_member(self.lag_member_id3)
        self.tb.remove_lag_member(self.lag_member_id4)
        self.tb.remove_lag(self.lag_id2)

        self.tb.remove_ports()

    def configure_dot1q_bridge_topology(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg])
        self.configure_bridge_ports(self.vlan, self.in_port, self.out_port)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

    def deconfigure_dot1q_bridge_topology(self):
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.deconfigure_bridge_ports()
        self.tb.remove_ports()

    def configure_flood_local_learn_bridge_topology(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.sw_port_cfg])
        self.configure_bridge_ports_flood_learn(self.vlan, self.in_port, self.out_port, self.sw_port)
        self.configure_bridge_ports_learning_mode(S.SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW)

    def deconfigure_flood_local_learn_bridge_topology(self):
        self.deconfigure_bridge_ports(expect_to_fail=True)
        self.tb.remove_ports()

    def configure_vlan_member_flood_local_learn_bridge_topology(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.sw_port_cfg])
        self.configure_vlan_members_flood_learn(self.vlan, self.in_port, self.out_port, self.sw_port)
        self.configure_bridge_ports_learning_mode(S.SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW)

    def deconfigure_vlan_member_flood_local_learn_bridge_topology(self):
        self.deconfigure_bridge_ports()
        self.tb.remove_ports()

    def configure_flood_system_learn_bridge_topology(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.sw_port_cfg])
        self.configure_bridge_ports_flood_learn(self.vlan, self.in_port, self.out_port, self.sw_port)
        self.configure_bridge_ports_learning_mode(S.SAI_BRIDGE_PORT_FDB_LEARNING_MODE_FDB_NOTIFICATION)

    # MPLS topology
    #                       ---------------------------------
    #                       |in_port:             out_port: |
    # neighbor_ip1          |route_prefix1    route_prefix2 |      neighbor_ip2
    # neighbor_mac1 <-->    |router_mac           router_mac| <--> neighbor_mac2
    # mpls_in_label_php  -> | --------------------------->  |
    #                       |                               |
    # mpls_in_label_swap -> | ----> nh_id_mpls              |
    #      route4_prefix -> | ---->                         |
    #                       |                               |
    #        mpls_out_label | <-- nh_id_mpls                |
    #                       |                               |
    #  mpls_in_label_pop -> |rif_id_mpls_in                 |
    #                       |                               |
    # route_3_ip  ---->     |                               |
    # mpls_in_next_hop -->  | nh_group -->mpls_out_label, in_port     |
    # mpls_in_next_hop2 --> |          --> neighbor_ip2, out_port     |
    #                       ---------------------------------

    def configure_rif_id_mpls(self):
        self.mpls_out_label = 40
        self.mpls_in_label_pop = 30
        self.mpls_in_label_swap = 31
        self.mpls_in_label_php = 32
        self.mpls_in_next_hop = 33
        self.mpls_in_next_hop2 = 35

        # pop
        # rif_id_mpls_in will be routed according to routes from self.tb.virtual_router_id
        self.tb.rif_id_mpls_in = self.tb.create_router_interface(
            vrf_id=self.tb.virtual_router_id, rif_type=S.SAI_ROUTER_INTERFACE_TYPE_MPLS_ROUTER)
        attrs = {S.SAI_INSEG_ENTRY_ATTR_NUM_OF_POP: 1,
                 S.SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID: self.tb.rif_id_mpls_in
                 }
        self.tb.create_inseg_entry(self.mpls_in_label_pop, attrs)

        # swap - in_label_swap will get to nh_id_mpls, and will be swapped by mpls_out_label
        self.tb.nh_id_mpls = self.tb.create_next_hop(
            self.neighbor_ip1,
            self.tb.rif_id_1,
            S.SAI_NEXT_HOP_TYPE_MPLS,
            self.mpls_out_label)
        attrs[S.SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID] = self.tb.nh_id_mpls
        self.tb.create_inseg_entry(self.mpls_in_label_swap, attrs)

        # php
        attrs[S.SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID] = self.tb.nh_id2
        self.tb.create_inseg_entry(self.mpls_in_label_php, attrs)

        # push
        self.tb.create_route(self.tb.virtual_router_id, self.route4_prefix, self.route4_mask, self.tb.nh_id_mpls)

        self.nh_group = self.tb.create_next_hop_group()
        # adding members exiting from two different ports, so it will be easy to verify in the test
        self.nh_grp_mem = self.tb.create_next_hop_group_member(self.nh_group, self.tb.nh_id_mpls)
        self.nh_grp_mem2 = self.tb.create_next_hop_group_member(self.nh_group, self.tb.nh_id2)

        # ECMP doing IP route or push
        self.tb.create_route(self.tb.virtual_router_id, self.route3_prefix, self.route3_mask, self.nh_group)

        attrs[S.SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID] = self.nh_group
        # ECMP doing swap or php
        self.tb.create_inseg_entry(self.mpls_in_next_hop, attrs)
        self.tb.create_inseg_entry(self.mpls_in_next_hop2, attrs)

    def deconfigure_rif_id_mpls(self):
        self.mpls_in_next_hop = 33
        self.mpls_in_next_hop2 = 35

        self.tb.remove_inseg_entry(self.mpls_in_next_hop)
        self.tb.remove_inseg_entry(self.mpls_in_next_hop2)

        self.tb.remove_route(self.tb.virtual_router_id, self.route3_prefix, self.route3_mask)

        self.tb.remove_next_hop_group_member(self.nh_grp_mem)
        self.tb.remove_next_hop_group_member(self.nh_grp_mem2)
        self.tb.remove_next_hop_group(self.nh_group)

        self.tb.remove_route(self.tb.virtual_router_id, self.route4_prefix, self.route4_mask)
        self.tb.remove_inseg_entry(self.mpls_in_label_php)
        self.tb.remove_inseg_entry(self.mpls_in_label_swap)

        self.tb.remove_next_hop(self.tb.nh_id_mpls)
        self.tb.remove_inseg_entry(self.mpls_in_label_pop)
        self.tb.remove_router_interface(self.tb.rif_id_mpls_in)

    def configure_rif_id_mpls_unsupported_label_size(self):
        self.mpls_out_label = 40
        self.mpls_in_label_pop = 30
        self.mpls_in_label_swap = 31
        self.mpls_in_label_php = 32
        self.mpls_in_next_hop = 33
        self.mpls_in_next_hop2 = 35

        # pop
        # rif_id_mpls_in will be routed according to routes from self.tb.virtual_router_id
        self.tb.rif_id_mpls_in = self.tb.create_router_interface(
            vrf_id=self.tb.virtual_router_id, rif_type=S.SAI_ROUTER_INTERFACE_TYPE_MPLS_ROUTER)
        attrs = {S.SAI_INSEG_ENTRY_ATTR_NUM_OF_POP: 1,
                 S.SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID: self.tb.rif_id_mpls_in
                 }
        self.tb.create_inseg_entry(self.mpls_in_label_pop, attrs)

        with expect_sai_error(SAI_STATUS_INVALID_PARAMETER):
            self.tb.nh_id_mpls = self.tb.create_next_hop(
                self.neighbor_ip1,
                self.tb.rif_id_1,
                S.SAI_NEXT_HOP_TYPE_MPLS,
                [self.mpls_in_label_pop, self.mpls_in_label_swap, self.mpls_in_label_swap, self.mpls_out_label])

    def configure_mpls_topology(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg])
        self.configure_rif_id_1(self.in_port)
        self.configure_rif_id_2(self.out_port)
        self.configure_rif_id_mpls()

    def configure_mpls_topology_unsupported_label_size(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg])
        self.configure_rif_id_1(self.in_port)
        self.configure_rif_id_2(self.out_port)
        self.configure_rif_id_mpls_unsupported_label_size()

    def deconfigure_mpls_topology_unsupported_label_size(self):
        self.deconfigure_rif_id_1()
        self.deconfigure_rif_id_2()

    def deconfigure_mpls_topology(self):
        self.deconfigure_rif_id_mpls()
        self.deconfigure_rif_id_1()
        self.deconfigure_rif_id_2()

        self.tb.remove_ports()

    def configure_svi_route_lag_topology(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.sw_port_cfg, self.rt_port_cfg])

        self.lag_id = self.tb.create_lag()
        self.lag_member_id = self.tb.create_lag_member(self.lag_id, self.out_port)
        self.lag_member_id2 = self.tb.create_lag_member(self.lag_id, self.sw_port)

        self.configure_rif_id_1(self.in_port)
        self.configure_rif_id_2(self.rt_port)
        self.configure_bridge_port(self.vlan, self.lag_id)
        self.tb.svi_rif_id = self.tb.create_router_interface(
            self.tb.virtual_router_id, 0, S.SAI_ROUTER_INTERFACE_TYPE_VLAN, self.svi_mac, self.vlan)
        self.tb.create_fdb_entry(self.tb.vlans[self.vlan], self.svi_dst_neighbor_mac, self.tb.bridge_ports[self.lag_id])
        self.tb.create_fdb_entry(self.tb.vlans[self.vlan], self.svi_dst_host1, self.tb.bridge_ports[self.lag_id])
        self.tb.create_fdb_entry(self.tb.vlans[self.vlan], self.svi_acc_host, self.tb.bridge_ports[self.lag_id])
        self.tb.create_route(self.tb.virtual_router_id, self.svi_dst_prefix, self.svi_dst_prefix_mask, self.tb.svi_rif_id)
        self.tb.create_neighbor(self.tb.svi_rif_id, self.svi_dst_neighbor_ip, self.svi_dst_neighbor_mac)
        self.tb.svi_nh = self.tb.create_next_hop(self.svi_dst_neighbor_ip, self.tb.svi_rif_id)

        self.tb.create_route(self.tb.virtual_router_id, self.route_prefix3, self.route_prefix3_mask, self.tb.nh_id1)
        self.tb.create_route(self.tb.virtual_router_id, self.svi_route2_prefix, self.svi_route2_mask, self.tb.svi_nh)

        # default route
        self.tb.create_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask, S.SAI_NULL_OBJECT_ID)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.configure_rif_loopback()

    def configure_bridge_port(self, vlan, port1, tag=False):
        self.bridge_id = self.tb.create_bridge()
        self.tb.configure_bridge_ports([port1])
        self.tb.configure_vlans([vlan])
        self.tb.configure_vlan_members([{"vlan": vlan, "port": port1, "is_tag": tag}]
                                       )
        self.tb.create_fdb_entry(self.tb.vlans[vlan], self.neighbor_mac2, self.tb.bridge_ports[port1])

    def deconfigure_svi_route_lag_topology(self):
        self.tb.remove_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask)

        self.deconfigure_rif_loopback()
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.tb.remove_route(self.tb.virtual_router_id, self.route_prefix3, self.route_prefix3_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.svi_route2_prefix, self.svi_route2_mask)

        self.tb.remove_next_hop(self.tb.svi_nh)
        self.tb.remove_neighbor(self.tb.svi_rif_id, self.svi_dst_neighbor_ip)
        self.tb.remove_route(self.tb.virtual_router_id, self.svi_dst_prefix, self.svi_dst_prefix_mask)
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.svi_dst_neighbor_mac)
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.svi_dst_host1)
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.svi_acc_host)

        self.tb.remove_router_interface(self.tb.svi_rif_id)

        self.deconfigure_bridge_ports()

        self.tb.remove_lag_member(self.lag_member_id)
        self.tb.remove_lag_member(self.lag_member_id2)
        self.tb.remove_lag(self.lag_id)

        self.deconfigure_rif_id_1()
        self.deconfigure_rif_id_2()
        # remove the lag_id from the ports list
        self.tb.remove_ports()

    def configure_router_lag_topology(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.sw_port_cfg, self.rt_port_cfg])

        self.lag_id = self.tb.create_lag()
        self.lag_member_id = self.tb.create_lag_member(self.lag_id, self.out_port)
        self.lag_member_id2 = self.tb.create_lag_member(self.lag_id, self.sw_port)
        self.tb.ports[self.lag_id] = self.lag_id

        self.configure_rif_id_2(self.lag_id)
        self.configure_rif_id_1(self.in_port)

        self.tb.create_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask, S.SAI_NULL_OBJECT_ID)

        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.configure_rif_loopback()

    def deconfigure_router_lag_topology(self):
        self.tb.remove_route(self.tb.virtual_router_id, self.default_ip, self.default_ip_mask)

        self.deconfigure_rif_loopback()
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip1, self.full_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.local_ip2, self.full_mask)

        self.deconfigure_rif_id_1()
        self.deconfigure_rif_id_2()

        self.tb.remove_lag_member(self.lag_member_id)
        self.tb.remove_lag_member(self.lag_member_id2)
        self.tb.remove_lag(self.lag_id)

        del self.tb.ports[self.lag_id]
        self.tb.remove_ports()

    def configure_one_vxlan_tunnel_topology(self):
        self.underlay_lpbk = self.tb.create_router_interface(self.tb.virtual_router_id, 0, S.SAI_ROUTER_INTERFACE_TYPE_LOOPBACK)

        # create decap mapper
        args = {}
        args[S.SAI_TUNNEL_MAP_ATTR_TYPE] = S.SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID
        self.decap_map = self.tb.create_object(S.SAI_OBJECT_TYPE_TUNNEL_MAP, args)

        args = {}
        args[S.SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE] = S.SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID
        args[S.SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP] = self.decap_map
        args[S.SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY] = 9000
        args[S.SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE] = self.tb.virtual_router_id
        self.decap_map_entry = self.tb.create_object(S.SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, args)

        args = {}
        args[S.SAI_TUNNEL_MAP_ATTR_TYPE] = S.SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI
        self.encap_map = self.tb.create_object(S.SAI_OBJECT_TYPE_TUNNEL_MAP, args)

        args = {}
        args[S.SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE] = S.SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI
        args[S.SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP] = self.encap_map
        args[S.SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY] = self.tb.virtual_router_id
        args[S.SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE] = 9000
        self.encap_map_entry = self.tb.create_object(S.SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, args)

        args = {}
        args[S.SAI_TUNNEL_ATTR_TYPE] = S.SAI_TUNNEL_TYPE_VXLAN
        args[S.SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE] = self.underlay_lpbk
        args[S.SAI_TUNNEL_ATTR_DECAP_MAPPERS] = [self.decap_map]
        args[S.SAI_TUNNEL_ATTR_ENCAP_MAPPERS] = [self.encap_map]
        args[S.SAI_TUNNEL_ATTR_ENCAP_TTL_MODE] = S.SAI_TUNNEL_TTL_MODE_PIPE_MODEL
        args[S.SAI_TUNNEL_ATTR_ENCAP_TTL_VAL] = 128
        args[S.SAI_TUNNEL_ATTR_ENCAP_SRC_IP] = "5.0.0.0"
        self.tunnel = self.tb.create_object(S.SAI_OBJECT_TYPE_TUNNEL, args)

    def deconfigure_one_vxlan_tunnel_topology(self):
        self.tb.remove_object(self.tunnel)
        self.tb.remove_object(self.decap_map_entry)
        self.tb.remove_object(self.decap_map)
        self.tb.remove_object(self.encap_map_entry)
        self.tb.remove_object(self.encap_map)
        self.tb.remove_router_interface(self.underlay_lpbk)

    # Bridging snake topology - Configure rewrite of egress dot1Q tag to next port vlan.
    #                           -----------------------------------------------
    # Traffic Gen vlan[0]  <=== |tx tg_port --<--------------------------\  |
    #             vlan[0]  ===> |rx tg_port -->-------\                  |  |
    #                           |                       |        vlan[0]   |  |
    #                       /-- |tx loopback_ports[0] --/                  |  |
    #   vlan[1]   PHY LPBK  |   |                                          |  |
    #                       \-- |rx loopback_ports[0] --\                  |  |
    #                           |                       |        vlan[1]   |  |
    #                       /-- |tx loopback_ports[1] --/                  |  |
    #   vlan[2]   PHY LPBK  |   |                                          |  |
    #                       \-- |rx loopback_ports[1] ------\    vlan[2]   |  |
    #                           |                           |              |  |
    #                           |           ...           --/              |  |
    #                           |                                          |  |
    #                           |                           |              |  |
    #                   /====== |tx external_port2port[0] --/    vlan[x]   |  |
    #  vlan[x+1]  Cable |       |                                          |  |
    #                   \====== |rx external_port2port[1] --\    vlan[x+1] |  |
    #                           |                           |              |  |
    #                           |           ...           --/              |  |
    #                           |                                          |  |
    #                           |                           |              |  |
    #                   /====== |tx external_port2port[-2]--/    vlan[n-1] |  |
    #    vlan[n]  Cable |       |                                          |  |
    #                   \====== |rx external_port2port[-1] ----- vlan[n] --/  |
    #                           -----------------------------------------------
    # external_port2port must be even number. If not present, last loopback_ports will loop back to tx tg_port.
    # Only 1 tg_port can be used.
    # if create_ports = False, sai_test_base.ports needs to setup before configure topology.
    # use sai_test_utils.list_active_ports to back-annotate all created ports to sai_test_base.ports
    # This will be useful when ports are created by create_port_mix() in sai_switch.cpp
    def configure_dot1q_bridge_snake_topology(self, ports_config, create_ports=True, install_macs=True):
        # create sai ports for traffic gen port and loopback ports
        assert('traffic_gen_port' in ports_config), "Missing traffic_gen_port in port config file."
        if create_ports:
            self.tb.configure_ports(ports_config['traffic_gen_port'])
        self.tg_port = ports_config['traffic_gen_port'][0]['pif']
        self.snake_port_list = [self.tg_port]

        if 'loopback_ports' in ports_config:
            if create_ports:
                self.tb.configure_ports(ports_config['loopback_ports'])
            for port in ports_config['loopback_ports']:
                self.snake_port_list.append(port['pif'])
        if 'external_port2port' in ports_config:
            if create_ports:
                self.tb.configure_ports(ports_config['external_port2port'])
            for port in ports_config['external_port2port']:
                self.snake_port_list.append(port['pif'])

        # create a vlan list
        num_of_lpbk_port = len(ports_config['loopback_ports']) if 'loopback_ports' in ports_config else 0
        num_of_ext_p2p = len(ports_config['external_port2port']) >> 1 if 'external_port2port' in ports_config else 0
        self.vlan_list = list(range(self.snake_base_vlan, self.snake_base_vlan + num_of_lpbk_port + num_of_ext_p2p + 1))

        # create sai bridge ports
        self.tb.create_bridge()
        self.tb.configure_bridge_ports(self.snake_port_list)
        self.tb.configure_vlans(self.vlan_list)

        # Check at least 2 port...
        assert(len(self.snake_port_list) >= 2), "Need at least 2 ports"

        # configure a snake vlan topology
        self.tb.log("VLAN IDs ({}): {}".format(len(self.vlan_list), self.vlan_list))

        print("Configure snake vlan member...")
        fdb_table = PrettyTable(title="FDB Table")
        fdb_table.field_names = ["VLAN", "PORT", "SAI_VLAN_ID", "MAC", "SAI_BRIDGE_PORT_ID"]

        # Example of vlan member for bridging snake (below implementation):
        # tg_port: [0x808], loopback_port: [0x300, 0x308], external_port2port: [0x800, 0x900, 0x908, 0xa08]
        # +------+-------+------+----------+--------------------+--------------------+-------------------+
        # | VLAN |  PIF  | TAG  | OUT_VLAN |    SAI_VLAN_ID     | SAI_BRIDGE_PORT_ID |    SAI_PORT_ID    |
        # +------+-------+------+----------+--------------------+--------------------+-------------------+
        # | 203  | 0x808 | True |    0     | 0x26000000000000cb | 0x3a00000000000001 | 0x100000000000007 |
        # | 203  | 0x300 | True |   204    | 0x26000000000000cb | 0x3a00000000000002 | 0x100000000000008 |
        # | 204  | 0x300 | True |   204    | 0x26000000000000cc | 0x3a00000000000002 | 0x100000000000008 |
        # | 204  | 0x308 | True |   205    | 0x26000000000000cc | 0x3a00000000000003 | 0x100000000000009 |
        # | 205  | 0x308 | True |   205    | 0x26000000000000cd | 0x3a00000000000003 | 0x100000000000009 |
        # | 205  | 0x800 | True |   206    | 0x26000000000000cd | 0x3a00000000000004 | 0x10000000000000a |
        # | 206  | 0x900 | True |   206    | 0x26000000000000ce | 0x3a00000000000005 | 0x10000000000000b |
        # | 206  | 0x908 | True |   207    | 0x26000000000000ce | 0x3a00000000000006 | 0x10000000000000c |
        # | 207  | 0xa08 | True |   207    | 0x26000000000000cf | 0x3a00000000000007 | 0x10000000000000d |
        # | 207  | 0x808 | True |   203    | 0x26000000000000cf | 0x3a00000000000001 | 0x100000000000007 |
        # +------+-------+------+----------+--------------------+--------------------+-------------------+

        last_port_idx = len(self.snake_port_list) - 1
        itr_plist = iter(enumerate(self.snake_port_list))
        itr_vlist = iter(enumerate(self.vlan_list))
        for ((vlan_idx, vlan), (idx, port)) in zip(itr_vlist, itr_plist):
            if idx == 0:
                # for traffic_gen_port
                self.tb.configure_vlan_members(
                    [{"vlan": vlan, "port": port, "is_tag": True, "out_tag_vlan": 0},
                     {"vlan": vlan, "port": self.snake_port_list[idx + 1], "is_tag": True, "out_tag_vlan": self.vlan_list[vlan_idx + 1]}]
                )
                if install_macs is True:
                    self.tb.create_fdb_entry(self.tb.vlans[vlan], self.neighbor_mac2,
                                             self.tb.bridge_ports[self.snake_port_list[idx + 1]])
                    fdb_table.add_row([vlan, hex(self.snake_port_list[idx + 1]), hex(self.tb.vlans[vlan]),
                                       self.neighbor_mac2, hex(self.tb.bridge_ports[self.snake_port_list[idx + 1]])])
            elif idx < (num_of_lpbk_port + 1):
                # for loopback_ports

                if idx < last_port_idx:
                    self.tb.configure_vlan_members(
                        [{"vlan": vlan, "port": port, "is_tag": True, "out_tag_vlan": vlan},
                         {"vlan": vlan, "port": self.snake_port_list[idx + 1], "is_tag": True, "out_tag_vlan": self.vlan_list[vlan_idx + 1]}]
                    )
                    self.tb.create_fdb_entry(self.tb.vlans[vlan], self.neighbor_mac2,
                                             self.tb.bridge_ports[self.snake_port_list[idx + 1]])
                    fdb_table.add_row([vlan, hex(self.snake_port_list[idx + 1]), hex(self.tb.vlans[vlan]),
                                       self.neighbor_mac2, hex(self.tb.bridge_ports[self.snake_port_list[idx + 1]])])
                else:
                    self.tb.configure_vlan_members(
                        [{"vlan": vlan, "port": port, "is_tag": True, "out_tag_vlan": vlan},
                         {"vlan": vlan, "port": self.snake_port_list[0], "is_tag": True, "out_tag_vlan": self.vlan_list[0]}]
                    )
                    if install_macs is True:
                        self.tb.create_fdb_entry(self.tb.vlans[vlan], self.neighbor_mac2,
                                                 self.tb.bridge_ports[self.snake_port_list[0]])
                        fdb_table.add_row([vlan, hex(self.snake_port_list[0]), hex(self.tb.vlans[vlan]),
                                           self.neighbor_mac2, hex(self.tb.bridge_ports[self.snake_port_list[0]])])
            else:
                # For external_port2port ..
                # get the next port in list and skip for next iteration.
                (nxt_idx, nxt_port) = next(itr_plist, None)

                if nxt_idx < (last_port_idx - 1):
                    self.tb.configure_vlan_members(
                        [{"vlan": vlan, "port": nxt_port, "is_tag": True, "out_tag_vlan": vlan},
                         {"vlan": vlan, "port": self.snake_port_list[nxt_idx + 1], "is_tag": True, "out_tag_vlan": self.vlan_list[vlan_idx + 1]}]
                    )
                    self.tb.create_fdb_entry(self.tb.vlans[vlan], self.neighbor_mac2,
                                             self.tb.bridge_ports[self.snake_port_list[nxt_idx + 1]])
                    fdb_table.add_row([vlan, hex(self.snake_port_list[nxt_idx + 1]), hex(self.tb.vlans[vlan]),
                                       self.neighbor_mac2, hex(self.tb.bridge_ports[self.snake_port_list[nxt_idx + 1]])])
                else:
                    self.tb.configure_vlan_members(
                        [{"vlan": vlan, "port": nxt_port, "is_tag": True, "out_tag_vlan": vlan},
                         {"vlan": vlan, "port": self.snake_port_list[0], "is_tag": True, "out_tag_vlan": self.vlan_list[0]}]
                    )
                    self.tb.create_fdb_entry(self.tb.vlans[vlan], self.neighbor_mac2, self.tb.bridge_ports[self.snake_port_list[0]])
                    fdb_table.add_row([vlan, hex(self.snake_port_list[0]), hex(self.tb.vlans[vlan]),
                                       self.neighbor_mac2, hex(self.tb.bridge_ports[self.snake_port_list[0]])])

        self.tb.log(self.tb.vlan_mem_table)
        self.tb.log(fdb_table)

    def snake_configure_svi_vlan_members(self, member_list, table):
        list_size = len(member_list)
        # ---- constructing ingress ------
        member = member_list[0]
        # create vlan
        self.tb.configure_vlans([member['vlan_idx'] + self.snake_base_vlan])
        vlan = self.tb.vlans[member['vlan_idx'] + self.snake_base_vlan]
        # create vlan member
        vlan_mem = self.tb.create_vlan_member(vlan, self.tb.bridge_ports[member["port"]],
                                              True, member['out_tag_vlan'] + self.snake_base_vlan)
        # create svi
        svi = self.tb.create_router_interface(
            member['vrf'],
            0,
            S.SAI_ROUTER_INTERFACE_TYPE_VLAN,
            member['svi_mac'],
            member['vlan_idx'] +
            self.snake_base_vlan,
            member['out_tag_vlan'] +
            self.snake_base_vlan)
        table.add_row([hex(member['port']),
                       hex(vlan_mem),
                       hex(vlan),
                       hex(member["out_tag_vlan"] + self.snake_base_vlan),
                       hex(self.tb.bridge_ports[member["port"]]),
                       hex(svi),
                       hex(member['vrf']),
                       member['svi_mac'],
                       member['neighbor_mac'], 0, 0])

        if len(member_list) < 2:
            return

        # ---- constructing egress -----
        #table.field_names = ["PIF", "VLAN MEMBER", "IN_VLAN", "OUT_VLAN", "BRIDGE_PORT_ID", "SVI_ID", "VRF_ID", "SVI MAC", "NEIGHBOR MAC", "NEIGHBOR_IP", "NEXT_HOP"]
        member = member_list[1]
        # create vlan
        self.tb.configure_vlans([member['vlan_idx'] + self.snake_base_vlan])
        vlan = self.tb.vlans[member['vlan_idx'] + self.snake_base_vlan]
        # create vlan member
        vlan_mem = self.tb.create_vlan_member(vlan, self.tb.bridge_ports[member["port"]],
                                              True, member['out_tag_vlan'] + self.snake_base_vlan)
        # create fdb entry for neighbor
        self.tb.create_fdb_entry(vlan, member['neighbor_mac'], self.tb.bridge_ports[member["port"]])
        # create svi
        svi = self.tb.create_router_interface(
            member['vrf'],
            0,
            S.SAI_ROUTER_INTERFACE_TYPE_VLAN,
            member['svi_mac'],
            member['vlan_idx'] +
            self.snake_base_vlan,
            member['out_tag_vlan'] +
            self.snake_base_vlan)
        # create route on router_interface
        self.tb.create_route(member['vrf'], self.svi_ip_prefix, self.svi_ip_prefix_mask, svi)
        # create neighbor
        self.tb.create_neighbor(svi, self.svi_ip2, member['neighbor_mac'])
        # create nexthop
        next_hop = self.tb.create_next_hop(self.svi_ip2, svi)
        # create route
        self.tb.create_route(member['vrf'], self.svi_router_prefix, self.svi_router_prefix_mask, next_hop)
        table.add_row([hex(member['port']),
                       hex(vlan_mem),
                       hex(vlan),
                       hex(member["out_tag_vlan"] + self.snake_base_vlan),
                       hex(self.tb.bridge_ports[member["port"]]),
                       hex(svi),
                       hex(member['vrf']),
                       member['svi_mac'],
                       member['neighbor_mac'],
                       self.svi_ip2,
                       hex(next_hop)])

    # svi_route_snake_topology
    # svi route snake same dest mac, same dest ip in different vrfs and vlans
    #
    #  v0 <------ PORT(0) <------ VLAN(2N-1) <--- SVI(2N-1) -------------------------+
    #  v0 ------> PORT(0) ------> VLAN(0) ------> SVI(0) ----------+                 |
    #                                                              |---- VRF(0)      |
    #  v2 <------ PORT(1) <------ VLAN(1) <------ SVI(1) ----------+                 |
    #     |-----> PORT(1) ------> VLAN(2) ------> SVI(2) ----------+                 |
    #                                                              |---- VRF(1)      |
    #  v4 <------ PORT(2) <------ VLAN(3) <------ SVI(3) ----------+                 |
    #     |-----> PORT(2) ------> VLAN(4) ------> SVI(4) ----------+                 |
    #                                                              |---- VRF(2)      |
    #  v6 <------ PORT(3) <------ VLAN(5) <------ SVI(5) ----------+                 |
    #     |-----> PORT(3) ------> VLAN(6) ------> SVI(6) ----------+                 |
    #                                                              |---- VRF(3)      |
    #  v8 <------ PORT(4) <------ VLAN(7) <------ SVI(7) ----------+                 |
    #     |-----> PORT(4) ------> VLAN(8) ------> SVI(8) ----------+                 |
    #                                                              |---- VRF(4)      |
    #     .................................................                          |
    #     .................................................                          |
    #     |-----> PORT(N-2) ----> VLAN(2N-4) ----> SVI(2N-4) ------+                 |
    #                                                              |---- VRF(N-2)    |
    # v2N-2<----- PORT(N-1) <---- VLAN(2N-3) <---- SVI(2N-3) ------+                 |
    #     |-----> PORT(N-1) ----> VLAN(2N-2) ----> SVI(2N-2) ------+                 |
    #                                                              |---- VRF(N-1)    |
    #                                                              +-----------------+
    #
    def get_svi_neighbor_mac(self, idx):
        if idx % 2:
            return (self.svi_mac2, self.svi_mac1)
        else:
            return (self.svi_mac1, self.svi_mac2)

    def configure_svi_route_snake_topology(self, ports_config):
        # create sai ports for traffic gen port and loopback ports
        assert('traffic_gen_port' in ports_config), "Missing traffic_gen_port in port config file."
        self.tb.configure_ports(ports_config['traffic_gen_port'])
        self.tg_port = ports_config['traffic_gen_port'][0]['pif']
        self.snake_port_list = [self.tg_port]

        if 'loopback_ports' in ports_config:
            self.tb.configure_ports(ports_config['loopback_ports'])
            for port in ports_config['loopback_ports']:
                self.snake_port_list.append(port['pif'])

        external_2ports = False
        if 'external_port2port' in ports_config:
            external_2ports = True
            self.tb.configure_ports(ports_config['external_port2port'])
            for port in ports_config['external_port2port']:
                self.snake_port_list.append(port['pif'])

        # create a vlan list
        num_of_lpbk_port = len(ports_config['loopback_ports']) if 'loopback_ports' in ports_config else 0
        num_of_ext_p2p = len(ports_config['external_port2port']) >> 1 if 'external_port2port' in ports_config else 0
        total_ports = len(self.snake_port_list)

        # Check at least 2 port...
        assert(total_ports >= 2), "Need at least 2 ports"

        self.tb.configure_bridge_ports(self.snake_port_list)
        self.vrf_list = self.tb.configure_vrfs(total_ports)
        self.tb.log("VRF IDs ({}): {}".format(len(self.vrf_list), self.vrf_list))

        print("Configure snake svi vlan members...")
        svi_vlan_mem_table = PrettyTable(title="SVI VLAN MEMBER Table")
        svi_vlan_mem_table.field_names = [
            "PIF",
            "VLAN MEMBER",
            "IN_VLAN",
            "OUT_VLAN",
            "BRIDGE_PORT_ID",
            "SVI_ID",
            "VRF_ID",
            "SVI MAC",
            "NEIGHBOR MAC",
            "NEIGHBOR_IP",
            "NEXT_HOP"]

        itr_plist = iter(enumerate(self.snake_port_list))
        for (vrf, (idx, port)) in zip(self.vrf_list, itr_plist):
            # for traffic_gen_port first:out vlan member second:in vlan_member
            (svi_mac, neighbor_mac) = self.get_svi_neighbor_mac(idx)

            self.tb.setup_vrf_punt_path(vrf, self.local_ip1, self.full_mask)

            if idx < (total_ports - 1):
                self.snake_configure_svi_vlan_members([{"vrf": vrf,
                                                        "port": port,
                                                        "vlan_idx": 2 * idx,
                                                        "out_tag_vlan": 2 * idx,
                                                        "svi_mac": svi_mac,
                                                        "neighbor_mac": neighbor_mac},
                                                       {"vrf": vrf,
                                                        "port": self.snake_port_list[idx + 1],
                                                        "vlan_idx": (2 * idx + 1),
                                                        "out_tag_vlan": (2 * idx + 2),
                                                        "svi_mac": svi_mac,
                                                        "neighbor_mac": neighbor_mac}],
                                                      svi_vlan_mem_table)
            elif not external_2ports:
                self.snake_configure_svi_vlan_members([{"vrf": vrf,
                                                        "port": port,
                                                        "vlan_idx": (2 * idx),
                                                        "out_tag_vlan": (2 * idx),
                                                        "svi_mac": svi_mac,
                                                        "neighbor_mac": neighbor_mac},
                                                       {"vrf": vrf,
                                                        "port": self.snake_port_list[0],
                                                        "vlan_idx": (2 * idx + 1),
                                                        "out_tag_vlan": (0),
                                                        "svi_mac":svi_mac,
                                                        "neighbor_mac":neighbor_mac}],
                                                      svi_vlan_mem_table)
            else:
                self.snake_configure_svi_vlan_members([{"vrf": vrf,
                                                        "port": port,
                                                        "vlan_idx": (2 * idx),
                                                        "out_tag_vlan": (2 * idx),
                                                        "svi_mac": svi_mac,
                                                        "neighbor_mac": neighbor_mac}],
                                                      svi_vlan_mem_table)

        self.tb.log(svi_vlan_mem_table)

    def configure_mirror_bridge_topology(self):
        '''
                       +-----------------------------+
                       |                             | Port2 (Bridge dest Port)
                       |           +---------------->|------------>
        Port1          |           ^                 | oid = bridge_ports[port2]
        (Bridge source |           |                 | (Switched Packet, dmac = neighbor_mac2)
         port)         |           |                 |
        -------------->|-----------+                 |
        oid =          |           |                 |
        bridge_ports[  |           |                 | mirror_dest (Bridge Mirror Port)
        port1]         |           V                 | oid = bridge_ports[mirror_dest]
                       |           +---------------->|------------>
                       |                             | (Mirrored packet)
                       +-----------------------------+
        '''
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.mirror_dest_cfg])
        self.bridge_id = self.tb.create_bridge()
        port1 = self.in_port
        port2 = self.out_port
        mirror_dest = self.mirror_dest
        self.tb.configure_bridge_ports([port1, port2, mirror_dest])
        self.tb.configure_vlans([self.vlan])
        self.tb.configure_vlan_members([{"vlan": self.vlan, "port": port1, "is_tag": False},
                                        {"vlan": self.vlan, "port": port2, "is_tag": False},
                                        {"vlan": self.vlan, "port": mirror_dest, "is_tag": False}])
        self.tb.create_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2, self.tb.bridge_ports[port2])

    def deconfigure_mirror_bridge_topology(self):
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2)
        self.tb.deconfigure_vlan_members()
        self.tb.deconfigure_vlans()
        self.tb.deconfigure_bridge_ports()
        self.tb.remove_bridge(self.bridge_id)
        self.tb.remove_ports()

    def configure_mirror_rif_topology(self):
        '''
                       +-----------------------------+
                       |                             | oid = rif_id_2
                       |           +---------------->|------------>
                       |           ^                  | ip = topo.v4/v6_neighbor_ip2, topo.neighbor_mac2
        ip=topo.v4/v6  |           |                 |
        _neighbor_ip1  |           |                 |
        -------------->|-----------+                 |
   topo.neighbor_mac1  |           |                 | oid = rif_id_4
                       |           |                 | mirror_dest (rif Mirror Port)
        oid = rif_id_1 |           V                 | ip = topo.v4/v6_neighbor_ip4, topo.neighbor_mac4
                       |           +---------------->|------------>
                       |                             | (Mirrored packet)
                       +-----------------------------+
        '''
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.mirror_dest_cfg])
        self.configure_rif_id_1_v4_v6(self.in_port)
        self.configure_rif_id_2_v4_v6(self.out_port)
        self.configure_rif_id_4(self.mirror_dest)

    def deconfigure_mirror_rif_topology(self):
        self.deconfigure_rif_id_1_v4_v6()
        self.deconfigure_rif_id_2_v4_v6()
        self.deconfigure_rif_id_4()
        self.tb.remove_ports()

    def configure_mirror_bridge_rif_topology(self):
        '''
                       +-----------------------------+
                       |                             | Port2 (Bridge dest Port)
                       |           +---------------->|------------>
        Port1          |           ^                 | oid = bridge_ports[port2]
        (Bridge source |           |                 | (Switched Packet, dmac = neighbor_mac2)
         port)         |           |                 |
        -------------->|-----------+                 |
        oid =          |           |                 |
        bridge_ports[  |           |                 | mirror_dest (RIF Mirror Port)
        port1]         |           V                 | oid = rif_id_4
                       |           +---------------->|------------>
                       |                             | (Mirrored packet)
                       +-----------------------------+
        '''
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.mirror_dest_cfg])
        self.bridge_id = self.tb.create_bridge()
        port1 = self.in_port
        port2 = self.out_port
        self.tb.configure_bridge_ports([port1, port2])
        self.tb.configure_vlans([self.vlan])
        self.tb.configure_vlan_members([{"vlan": self.vlan, "port": port1, "is_tag": False},
                                        {"vlan": self.vlan, "port": port2, "is_tag": False}])
        self.tb.create_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2, self.tb.bridge_ports[port2])
        self.configure_rif_id_4(self.mirror_dest)

    def deconfigure_mirror_bridge_rif_topology(self):
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2)
        self.tb.deconfigure_vlan_members()
        self.tb.deconfigure_vlans()
        self.tb.deconfigure_bridge_ports()
        self.tb.remove_bridge(self.bridge_id)
        self.deconfigure_rif_id_4()
        self.tb.remove_ports()

    def configure_bridge_topology_with_fdb_user_meta(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.mirror_dest_cfg])
        self.bridge_id = self.tb.create_bridge()
        port1 = self.in_port
        port2 = self.out_port
        mirror_dest = self.mirror_dest
        self.tb.configure_bridge_ports([port1, port2, mirror_dest])
        self.tb.configure_vlans([self.vlan])
        self.tb.configure_vlan_members([{"vlan": self.vlan, "port": port1, "is_tag": False},
                                        {"vlan": self.vlan, "port": port2, "is_tag": False},
                                        {"vlan": self.vlan, "port": mirror_dest, "is_tag": False}])
        self.tb.create_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2, self.tb.bridge_ports[port2])
        fdb_entry = S.sai_fdb_entry_t(self.tb.switch_id, U.sai_mac(self.neighbor_mac2), self.tb.vlans[self.vlan])
        # set L2 classID/User-meta for the created FDB entry.
        self.tb.set_object_attr([S.SAI_OBJECT_TYPE_FDB_ENTRY, fdb_entry], S.SAI_FDB_ENTRY_ATTR_META_DATA,
                                self.neighbor_mac2_user_meta, verify=True)
        self.tb.create_fdb_entry(self.tb.vlans[self.vlan],
                                 self.neighbor_mac1,
                                 self.tb.bridge_ports[port1],
                                 user_meta=self.neighbor_mac1_user_meta)

    def deconfigure_bridge_topology_with_fdb_user_meta(self):
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2)
        self.tb.deconfigure_vlan_members()
        self.tb.deconfigure_vlans()
        self.tb.deconfigure_bridge_ports()
        self.tb.remove_bridge(self.bridge_id)
        self.tb.remove_ports()

    def configure_rif_id_v4_v6_with_user_meta(self, port_index, rif_data):
        rif_id = self.tb.create_router_interface(self.tb.virtual_router_id, port_index, S.SAI_ROUTER_INTERFACE_TYPE_PORT)
        self.tb.create_route(
            self.tb.virtual_router_id,
            rif_data['v4_route_prefix'],
            rif_data['v4_route_prefix_mask'],
            rif_id,
            user_meta=rif_data['v4_route_user_meta'])
        self.tb.create_route(
            self.tb.virtual_router_id,
            rif_data['v6_route_prefix'],
            rif_data['v6_route_prefix_mask'],
            rif_id,
            user_meta=rif_data['v6_route_user_meta'])
        self.tb.create_neighbor(
            rif_id,
            rif_data['v4_neighbor_ip'],
            rif_data['neighbor_mac'],
            user_meta=rif_data['v4_neighbor_user_meta'])
        self.tb.create_neighbor(
            rif_id,
            rif_data['v6_neighbor_ip'],
            rif_data['neighbor_mac'],
            user_meta=rif_data['v6_neighbor_user_meta'])
        nh_id_v4 = self.tb.create_next_hop(rif_data['v4_neighbor_ip'], rif_id)
        nh_id_v6 = self.tb.create_next_hop(rif_data['v6_neighbor_ip'], rif_id)
        return rif_id, nh_id_v4, nh_id_v6

    def configure_basic_route_topology_with_l3_user_meta(self):
        if not self.tb.is_gb:
            return
        # init in_port and out_port
        ports_to_config = [self.in_port_cfg, self.out_port_cfg]
        self.tb.configure_ports(ports_to_config)
        rif_data = {}
        rif_data['v4_route_prefix'] = self.v4_route_prefix1
        rif_data['v4_route_prefix_mask'] = self.v4_route_prefix1_mask
        rif_data['v6_route_prefix'] = self.v6_route_prefix1
        rif_data['v6_route_prefix_mask'] = self.v6_route_prefix1_mask
        rif_data['v4_neighbor_ip'] = self.v4_neighbor_ip1
        rif_data['v6_neighbor_ip'] = self.v6_neighbor_ip1
        rif_data['neighbor_mac'] = self.neighbor_mac1
        rif_data['v4_route_user_meta'] = self.v4_route_prefix1_user_meta
        rif_data['v6_route_user_meta'] = self.v6_route_prefix1_user_meta
        rif_data['v4_neighbor_user_meta'] = self.v4_neighbor_ip1_user_meta
        rif_data['v6_neighbor_user_meta'] = self.v6_neighbor_ip1_user_meta
        self.tb.rif_id_1, self.tb.nh_id1_v4, self.tb.nh_id1_v6  = self.configure_rif_id_v4_v6_with_user_meta(self.in_port, rif_data)

        rif_data['v4_route_prefix'] = self.v4_route_prefix2
        rif_data['v4_route_prefix_mask'] = self.v4_route_prefix2_mask
        rif_data['v6_route_prefix'] = self.v6_route_prefix2
        rif_data['v6_route_prefix_mask'] = self.v6_route_prefix2_mask
        rif_data['v4_neighbor_ip'] = self.v4_neighbor_ip2
        rif_data['v6_neighbor_ip'] = self.v6_neighbor_ip2
        rif_data['neighbor_mac'] = self.neighbor_mac2
        rif_data['v4_route_user_meta'] = self.v4_route_prefix2_user_meta
        rif_data['v6_route_user_meta'] = self.v6_route_prefix2_user_meta
        rif_data['v4_neighbor_user_meta'] = self.v4_neighbor_ip2_user_meta
        rif_data['v6_neighbor_user_meta'] = self.v6_neighbor_ip2_user_meta
        self.tb.rif_id_2, self.tb.nh_id2_v4, self.tb.nh_id2_v6  = self.configure_rif_id_v4_v6_with_user_meta(
            self.out_port, rif_data)

        # classID works with only nexthop group, create NHgroup and add single NH into it
        # Add LPM route with user meta
        # Add LPM route without user meta and then set user-meta attribute
        self.nh_group = self.tb.create_next_hop_group()
        self.nh_mem1 = self.tb.create_next_hop_group_member(self.nh_group, self.tb.nh_id2_v4, 10)
        self.tb.create_route(
            self.tb.virtual_router_id,
            self.route_prefix3,
            self.route_prefix3_mask,
            self.nh_group,
            user_meta=self.route_prefix3_user_meta)
        self.tb.create_route(self.tb.virtual_router_id, self.route_prefix4, self.route_prefix4_mask, self.nh_group)
        self.tb.set_route_attribute(
            self.tb.virtual_router_id,
            self.route_prefix4,
            self.route_prefix4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA,
            self.route_prefix4_user_meta)

        self.configure_link_local(self.tb.rif_id_2)
        self.tb.create_route(
            self.tb.virtual_router_id,
            self.v4_default_ip,
            self.v4_default_ip_mask,
            S.SAI_NULL_OBJECT_ID)
        self.tb.create_route(self.tb.virtual_router_id, self.v6_default_ip, self.v6_default_ip_mask, S.SAI_NULL_OBJECT_ID)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v4_local_ip1, self.v4_full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v4_local_ip2, self.v4_full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v6_local_ip1, self.v6_full_mask)
        self.tb.setup_vrf_punt_path(self.tb.virtual_router_id, self.v6_local_ip2, self.v6_full_mask)
        self.configure_rif_loopback()

    def deconfigure_basic_route_topology_with_l3_user_meta(self):
        if not self.tb.is_gb:
            return
        self.tb.remove_route(self.tb.virtual_router_id, self.route_prefix3, self.route_prefix3_mask)
        self.tb.remove_route(self.tb.virtual_router_id, self.route_prefix4, self.route_prefix4_mask)
        self.tb.remove_next_hop_group_member(self.nh_mem1)
        self.tb.remove_next_hop_group(self.nh_group)
        self.deconfigure_basic_route_topology_v4_v6()

    def configure_mirror_port_bridge_topology(self, mirror_lag=False):
        '''
                       +-----------------------------+
                       |                             | Port2 (Bridge dest Port)
                       |           +---------------->|------------>
        Port1          |           ^                 | oid = bridge_ports[port2]
        (Bridge source |           |                 | (Switched Packet, dmac = neighbor_mac2)
         port)         |           |                 |
        -------------->|-----------+                 |
        oid =          |           |                 |
        bridge_ports[  |           |                 | mirror_dest
        port1]         |           V                 |
                       |           +---------------->|------------>
                       |                             | (Mirrored packet)
                       +-----------------------------+
        '''
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.mirror_dest_cfg])
        self.bridge_id = self.tb.create_bridge()
        port1 = self.in_port
        port2 = self.out_port
        if mirror_lag:
            self.lag_id = self.tb.create_lag()
            self.lag_member_id = self.tb.create_lag_member(self.lag_id, self.mirror_dest)
        self.tb.configure_bridge_ports([port1, port2])
        self.tb.configure_vlans([self.vlan])
        self.tb.configure_vlan_members([{"vlan": self.vlan, "port": port1, "is_tag": False},
                                        {"vlan": self.vlan, "port": port2, "is_tag": False}])
        self.tb.create_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2, self.tb.bridge_ports[port2])

    def deconfigure_mirror_port_bridge_topology(self, mirror_lag=False):
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2)
        self.tb.deconfigure_vlan_members()
        self.tb.deconfigure_vlans()
        self.tb.deconfigure_bridge_ports()
        self.tb.remove_bridge(self.bridge_id)
        if mirror_lag:
            self.tb.remove_lag_member(self.lag_member_id)
            self.tb.remove_lag(self.lag_id)
        self.tb.remove_ports()

    def configure_mirror_port_rif_topology(self, mirror_lag=False):
        '''
                       +-----------------------------+
                       |                             | oid = rif_id_2
                       |           +---------------->|------------>
                       |           ^                  | ip = topo.v4/v6_neighbor_ip2, topo.neighbor_mac2
        ip=topo.v4/v6  |           |                 |
        _neighbor_ip1  |           |                 |
        -------------->|-----------+                 |
   topo.neighbor_mac1  |           |                 |
                       |           |                 | mirror_dest
        oid = rif_id_1 |           V                 |
                       |           +---------------->|------------>
                       |                             | (Mirrored packet)
                       +-----------------------------+
        '''
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.mirror_dest_cfg])
        if mirror_lag:
            self.lag_id = self.tb.create_lag()
            self.lag_member_id = self.tb.create_lag_member(self.lag_id, self.mirror_dest)
        self.configure_rif_id_1_v4_v6(self.in_port)
        self.configure_rif_id_2_v4_v6(self.out_port)

    def deconfigure_mirror_port_rif_topology(self, mirror_lag=False):
        self.deconfigure_rif_id_1_v4_v6()
        self.deconfigure_rif_id_2_v4_v6()
        if mirror_lag:
            self.tb.remove_lag_member(self.lag_member_id)
            self.tb.remove_lag(self.lag_id)
        self.tb.remove_ports()

    def configure_mirror_port_bridge_rif_topology(self, mirror_lag=False):
        '''
                       +-----------------------------+
                       |                             | Port2 (Bridge dest Port)
                       |           +---------------->|------------>
        Port1          |           ^                 | oid = bridge_ports[port2]
        (Bridge source |           |                 | (Switched Packet, dmac = neighbor_mac2)
         port)         |           |                 |
        -------------->|-----------+                 |
        oid =          |           |                 |
        bridge_ports[  |           |                 | mirror_dest
        port1]         |           V                 |
                       |           +---------------->|------------>
                       |                             |
                       +-----------------------------+
        '''
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg, self.mirror_dest_cfg])
        if mirror_lag:
            self.lag_id = self.tb.create_lag()
            self.lag_member_id = self.tb.create_lag_member(self.lag_id, self.mirror_dest)
        self.bridge_id = self.tb.create_bridge()
        port1 = self.in_port
        port2 = self.out_port
        self.tb.configure_bridge_ports([port1, port2])
        self.tb.configure_vlans([self.vlan])
        self.tb.configure_vlan_members([{"vlan": self.vlan, "port": port1, "is_tag": False},
                                        {"vlan": self.vlan, "port": port2, "is_tag": False}])
        self.tb.create_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2, self.tb.bridge_ports[port2])

    def deconfigure_mirror_port_bridge_rif_topology(self, mirror_lag=False):
        self.tb.remove_fdb_entry(self.tb.vlans[self.vlan], self.neighbor_mac2)
        self.tb.deconfigure_vlan_members()
        self.tb.deconfigure_vlans()
        self.tb.deconfigure_bridge_ports()
        self.tb.remove_bridge(self.bridge_id)
        if mirror_lag:
            self.tb.remove_lag_member(self.lag_member_id)
            self.tb.remove_lag(self.lag_id)
        self.tb.remove_ports()
