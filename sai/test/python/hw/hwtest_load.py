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

import pytest
import pdb
import time
import saicli as S
import sai_test_base as st_base
import sai_test_utils as st_utils
from leaba import sdk
from packet_test_defs import *  # import scapy with extensions*
from binascii import hexlify, unhexlify
from utils.rate_utils import *
from utils.wait_for_user import *
from utils.checker_and_end_of_test_utils import *
from utils.constants import *


def test_warm_boot_load(init_device_and_ports, request):
    list_b = True
    list_c = True
    list_d = True

    tb = init_device_and_ports.sai_test_base

    curr_path = os.getcwd().split("/")
    sai_dir = ""
    for one_dir in curr_path:
        sai_dir += "/" + one_dir
        if one_dir == "sai":
            break

    # create all ports in the system
    port_config_file = sai_dir + "/test/python/attr/"
    if tb.is_gb:
        port_config_file += "sai_test_attr_all_ports_gb.json"
    else:
        port_config_file += "sai_test_attr_all_ports.json"
    ports_config = st_utils.load_ports_from_json(port_config_file)['all_ports_100G']
    tb.configure_ports(ports_config)

    acl_entries = []
    acl_tables = []
    bridges = []
    bridge_ports = []
    debug_counters = []
    fdb_entries = []
    lags = []
    lag_members = []
    neighbors = []
    next_hop_groups = []
    next_hops = []
    next_hop_group_members = []
    qos_maps = []
    router_interfaces = []
    virtual_routers = []
    vlans = []

    time_before = time.monotonic()
    base_scale = 10
    mac_addr = "00:06:06:06:06:06"
    port_index = 0
    bridges.append(tb.create_bridge(type="1q", verify=[False, False]))
    for i in range(base_scale):
        vlans.append(tb.create_vlan(i + 1, verify=[False, False]))
        # 2 x base_scale bridge ports
        bridge_ports.append(tb.create_bridge_port(ports_config[port_index]["pif"], verify=[False, False]))
        bridge_ports.append(tb.create_bridge_port(ports_config[port_index + 1]["pif"], verify=[False, False]))
        port_index += 2
    print("added {0} vlans {1} bridge_ports".format(len(vlans), len(bridge_ports)))

    for i in range(base_scale):
        lags.append(tb.create_lag())
        lag_members.append(tb.create_lag_member(lags[-1], ports_config[port_index]["pif"], verify=[False, False]))
        lag_members.append(tb.create_lag_member(lags[-1], ports_config[port_index + 1]["pif"], verify=[False, False]))
        port_index += 2
    print("added {0} lags {1} lag_members".format(len(lags), len(lag_members)))

    # 1030 fdb entries
    for i in range(base_scale):
        for num in range(16, 16 + 103):
            fdb_mac = "00:07:07:07:{0}:{1}".format(i + 10, hex(num)[2:])
            fdb_entries.append(tb.create_fdb_entry(vlans[0], fdb_mac, bridge_ports[0], verify=[False, False]))
    print("added {0} fdb_entries".format(len(fdb_entries)))

    for i in range(base_scale):
        virtual_routers.append(tb.create_virtual_router(verify=[False, False]))
        router_interfaces.append(tb.create_router_interface(
            virtual_routers[-1], ports_config[port_index]["pif"], S.SAI_ROUTER_INTERFACE_TYPE_PORT, verify=[False, False]))
        router_interfaces.append(tb.create_router_interface(
            virtual_routers[-1], ports_config[port_index + 1]["pif"], S.SAI_ROUTER_INTERFACE_TYPE_PORT, verify=[False, False]))
        port_index += 2

        # 40K v4 routes
        net_ip = "{0}.0.0.0".format(i + 1)
        time_before = time.monotonic()
        tb.create_route(virtual_routers[-1], net_ip, "255.255.255.0", router_interfaces[-1],
                        num_of_routes=4000, inc_start_bit=8)
        print("added {0} v4 route entries in {1} seconds".format(4000, time.monotonic() - time_before))
        # 100k v6 routes
        net_ip = "1111:{0}::".format(i)
        time_before = time.monotonic()
        tb.create_route(virtual_routers[-1], net_ip, "ffff:ffff:ffff::",
                        router_interfaces[-1], num_of_routes=10000, inc_start_bit=128 - 48)
        print("added {0} v6 route entries in {1} seconds".format(10000, time.monotonic() - time_before))

        # 1k neighbor entries
        for j in range(103):
            full_ip = "1111:{0}::{1}:2222".format(i, j)
            neighbors.append(tb.create_neighbor(router_interfaces[-1], full_ip, mac_addr, verify=[False, False]))

    for i in range(base_scale * 10):
        next_hop_groups.append(tb.create_next_hop_group(verify=[False, False]))

    for i in range(base_scale * 103):  # 1k next_hops
        full_ip = "1111:{0}::2222".format(i)
        next_hops.append(tb.create_next_hop(full_ip, router_interfaces[i % len(router_interfaces)], verify=[False, False]))
        next_hop_group_members.append(tb.create_next_hop_group_member(next_hop_groups[i % len(next_hop_groups)], next_hops[-1]))
    print("added {0} next_hop_groups {1} next_hops".format(len(next_hop_groups), len(next_hops)))

    if list_d is not None:
        for i in range(base_scale * 10):
            debug_counters.append(
                tb.create_debug_counter(
                    S.SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS,
                    [],
                    verify=[
                        False,
                        False]))

    # 1600 ACLs
    if list_b is not None:
        acl_entries_per_table = 400  # max allowed
        num_acl_tables = 4
    else:
        acl_entries_per_table = 0
        num_acl_tables = 0
    acl_table1_args = tb.generate_ipv4_acl_key()
    acl_table1_args[S.SAI_ACL_TABLE_ATTR_ACL_STAGE] = S.SAI_ACL_STAGE_INGRESS
    acl_table1_args[S.SAI_ACL_TABLE_ATTR_SIZE] = 0
    acl_table2_args = tb.generate_ipv4_acl_key()
    acl_table2_args[S.SAI_ACL_TABLE_ATTR_ACL_STAGE] = S.SAI_ACL_STAGE_EGRESS
    acl_table2_args[S.SAI_ACL_TABLE_ATTR_SIZE] = 0
    acl_table3_args = tb.generate_ipv6_acl_key()
    acl_table3_args[S.SAI_ACL_TABLE_ATTR_ACL_STAGE] = S.SAI_ACL_STAGE_INGRESS
    acl_table3_args[S.SAI_ACL_TABLE_ATTR_SIZE] = 0
    acl_table4_args = tb.generate_ipv6_acl_key()
    acl_table4_args[S.SAI_ACL_TABLE_ATTR_ACL_STAGE] = S.SAI_ACL_STAGE_EGRESS
    acl_table4_args[S.SAI_ACL_TABLE_ATTR_SIZE] = 0

    entry_args = {}
    entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
    entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 0, 3]
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, S.SAI_PACKET_ACTION_DROP]
    for table_index in range(int(num_acl_tables / 4)):  # creating 4 tables per loop
        acl_tables.append(tb.create_object(S.SAI_OBJECT_TYPE_ACL_TABLE, acl_table1_args))
        acl_tables.append(tb.create_object(S.SAI_OBJECT_TYPE_ACL_TABLE, acl_table2_args))
        acl_tables.append(tb.create_object(S.SAI_OBJECT_TYPE_ACL_TABLE, acl_table3_args))
        acl_tables.append(tb.create_object(S.SAI_OBJECT_TYPE_ACL_TABLE, acl_table4_args))

        for i in range(4):
            entry_args[S.SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_tables[-i]
            for entry_index in range(acl_entries_per_table):
                entry_args[S.SAI_ACL_ENTRY_ATTR_PRIORITY] = entry_index
                acl_entries.append(tb.create_object(S.SAI_OBJECT_TYPE_ACL_ENTRY, entry_args))
    print("added {0} ACL entries".format(len(acl_entries)))

    if list_c is not None:
        # create 10 QOS maps
        map_key_value = [(5, S.SAI_PACKET_COLOR_RED)]
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_COLOR, map_key_value))
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_COLOR, [(6, S.SAI_PACKET_COLOR_GREEN)]))
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_COLOR, [(7, S.SAI_PACKET_COLOR_YELLOW)]))

        # DSCP -> TC
        map_key_value = [(10, 7), (20, 5), (5, 4)]
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_TC, map_key_value))
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_TC, [(2, 2)]))
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_TC, [(3, 3)]))

        # TC -> queue
        map_key_value = [(7, 7), (5, 5), (4, 4)]
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_TC_TO_QUEUE, map_key_value))
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_TC_TO_QUEUE, [(1, 1)]))
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_TC_TO_QUEUE, [(5, 5)]))
        qos_maps.append(tb.create_qos_map(S.SAI_QOS_MAP_TYPE_TC_TO_QUEUE, [(7, 7), (2, 3)]))
    print("added {0} QOS maps".format(len(qos_maps)))

    warm_boot_time = tb.do_warm_boot()
    if warm_boot_time is not None:
        print("warm boot down time: {0}".format(warm_boot_time))

    print("cleaning up")
    for obj in acl_entries + acl_tables + fdb_entries + bridge_ports + debug_counters + lag_members + lags + neighbors + \
            next_hop_group_members + next_hops + next_hop_groups + qos_maps + router_interfaces + virtual_routers + vlans:
        tb.remove_object(obj)

    tb.remove_ports()
