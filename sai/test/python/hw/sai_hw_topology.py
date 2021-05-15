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

import pytest
# SAI
import saicli as S
import sai_test_utils as st_utils
import sai_topology as stp

#                        ---------------------------------
#                        |in_port:             out_port: | <--+ neighbor_mac2 = router_mac
# Traffic gen (100G) --> |route_prefix1    route_prefix2 |    | neighbor_ip2
#                        |router_mac           router_mac| <--+ loopback (50G)
#                        |                               |
#                        ---------------------------------
# Sending high rate traffic from TG --> out_port
# Packets are lost because we send from 100G port to 50G port.
# Packets coming out of out_port, going back in (because of loopback config)


@pytest.fixture(scope="module")
def sai_hw_100G_to_50G_topology(init_device_and_ports):
    ports = {}
    for dv in init_device_and_ports.json_data["devices"]:
        for port in dv["ports"]:
            ports[port["port-id"]] = {"speed": port["port-speed"], "slice": port["slice"], "ifg": port["ifg"], "pif": port["pif"]}

    te_conns = []
    for conn in init_device_and_ports.json_data["connectivity"]["connection"]:
        if "TE" in conn[0]:
            te_conn = conn[1]
        elif "TE" in conn[1]:
            te_conn = conn[0]
        else:
            continue
        te_conn_num = int(te_conn.split(":")[1])
        te_conns.append(ports[te_conn_num])

    speed = te_conns[0]["speed"].split(":")[0]
    in_slice = te_conns[0]["slice"]
    ifg = te_conns[0]["ifg"]
    start_pif = te_conns[0]["pif"][0]
    end_pif = te_conns[0]["pif"][1]

    tb = init_device_and_ports.sai_test_base

    # create SAI topology
    top = stp.sai_topology(init_device_and_ports.sai_test_base, "v4")
    # update in port from fishnet json file
    top.in_port = st_utils.lane_from_slice_ifg_pif(in_slice, ifg, start_pif)
    # packets sent to neighbor_mac2 will come back to our device (because of loopback config)
    # We don't want them to get dropped because of wrong MAC address
    top.neighbor_mac2 = tb.router_mac

    # We assume 4x25G connection to TG
    assert speed == "100"
    assert end_pif - start_pif == 3
    top.in_port_cfg = st_utils.default_100G_port_cfg(top.in_port)
    # choose output port from the config file
    # in simulation mode, fishnet fails if sending to port not found in the config file
    for port_num in ports.keys():
        if port_num != te_conn_num:
            params = ports[port_num]
            top.out_port = st_utils.lane_from_slice_ifg_pif(params["slice"], params["ifg"], params["pif"][0])
            break
    # 2x25=50G loopback port
    top.out_port_cfg = st_utils.port_config(top.out_port, 2, 25, 1514, S.SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC)

    top.configure_basic_route_topology()

    yield tb, top
