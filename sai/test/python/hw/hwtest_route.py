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
import time
import saicli as S
import sai_test_utils as st_utils
from packet_test_defs import *  # import scapy with extensions*


def test_route_bulk_create(init_device_and_ports, request):
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

    next_hops = []
    router_interfaces = []
    virtual_routers = []

    vrf_count = 2
    batch_count = 2
    routes_v4_count = 20000
    routes_v6_count = 20000

    print("[BENCHMARK] vrf_index, batch_index, is_bulk_op, addr_type, qty, time_us")

    for vrf_index in range(vrf_count):
        virtual_routers.append(tb.create_virtual_router(verify=[False, False]))
        router_interfaces.append(tb.create_router_interface(
            virtual_routers[-1], ports_config[vrf_index % len(ports_config)]["pif"], S.SAI_ROUTER_INTERFACE_TYPE_PORT, verify=[False, False]))

        next_hop_ip = "1111:{0:04x}::2222".format(vrf_index)
        next_hops.append(tb.create_next_hop(next_hop_ip, router_interfaces[-1], verify=[False, False]))

        # running 4 batch types - bulk/regular x ipv4/ipv6
        for batch_id in range(batch_count * 4):
            use_ipv4 = batch_id % 2 == 0
            use_bulk_operation = (vrf_index % 2 == 0) ^ ((batch_id // 2) % 2 == 1)

            if use_ipv4:
                net_ip = "{0}.0.0.0".format(batch_id + 1)
                mask = "255.255.255.0"
                inc_start_bit = 8
                routes_count = routes_v4_count

            else:
                net_ip = "1111:{0:04x}::".format(batch_id)
                mask = "ffff:ffff:ffff::"
                inc_start_bit = 128 - 48
                routes_count = routes_v6_count

            time_before = time.monotonic()
            tb.create_route(virtual_routers[-1], net_ip, mask, next_hops[-1],
                            num_of_routes=routes_count, inc_start_bit=inc_start_bit,
                            bulk_operation=use_bulk_operation)
            print("[BENCHMARK] {}, {}, {}, {}, {}, {}".format(
                vrf_index, batch_id, use_bulk_operation, "ipv4" if use_ipv4 else "ipv6",
                routes_count, int((time.monotonic() - time_before) * 1000000)))

    print("cleaning up")

    for vrf_id in virtual_routers:
        S.sai_remove_all_routes(vrf_id)

    for obj in next_hops + router_interfaces + virtual_routers:
        tb.remove_object(obj)

    tb.remove_ports()
