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

# Python
import pytest
import pdb
# SAI
from packet_test_defs import *  # import scapy with extensions*
import saicli as S
import sai_test_utils as st_utils
import sai_topology
# SAI HW
from sai_hw_utils import leaba_tf_wait

# In order to enable access to validation scripts, include the below import
try:
    from leaba_val import *
except ModuleNotFoundError:
    print("validation scripts not loaded")

# basic snake bridge topology: sai_topology.configure_dot1q_bridge_snake_topology
# Traffic port: sai_topology.tg_port


@pytest.fixture(scope="module")
def fixture_sai_test_topology(traffic_gen, init_device_and_ports, request):

    # find the port-id which connects to te
    te_conn_ports_id = []
    for conn in init_device_and_ports.json_data["connectivity"]["connection"]:
        if "TE" in conn[0]:
            te_conn = conn[1]
        elif "TE" in conn[1]:
            te_conn = conn[0]
        else:
            continue
        te_conn_ports_id.append(int(te_conn.split(":")[1]))

    # ports list in system, used by fishent env
    loopback_list = init_device_and_ports.json_data["connectivity"]["self-loopback"]
    loopback_mode = "MAC"
    ports = {}
    # setup ports_config for snake topology in for SAI.
    # doesn't support 'external_port2port' as unit test does in SAI env
    # Only support singel TE port.
    sai_ports_config = {}
    sai_ports_config['traffic_gen_port'] = []
    sai_ports_config['loopback_ports'] = []

    for dv in init_device_and_ports.json_data["devices"]:
        # if int(dv["id"]) != device_id:
        #    continue
        for port in dv["ports"]:
            ports[port["port-id"]] = {"speed": port["port-speed"], "slice": port["slice"], "ifg": port["ifg"], "pif": port["pif"]}

            # convert to port_config format for SAI
            port_cfg, loopback = st_utils.port_config_from(port, loopback_mode, loopback_list, te_conn_ports_id)
            if loopback:
                sai_ports_config['loopback_ports'].append(port_cfg)
            else:
                sai_ports_config['traffic_gen_port'].append(port_cfg)

    te_conns = []
    for port_id in te_conn_ports_id:
        te_conns.append(ports[port_id])

    speed = te_conns[0]["speed"].split(":")[0]
    in_slice = te_conns[0]["slice"]
    ifg = te_conns[0]["ifg"]
    start_pif = te_conns[0]["pif"][0]
    end_pif = te_conns[0]["pif"][1]

    tb = init_device_and_ports.sai_test_base

    # create SAI topology
    top = sai_topology.sai_topology(init_device_and_ports.sai_test_base, "v4")
    # update in port from fishnet json file
    top.tg_port = st_utils.lane_from_slice_ifg_pif(in_slice, ifg, start_pif)

    # We assume 4x25G connection to TG
    assert speed == "100"
    assert end_pif - start_pif == 3
    top.tg_port_cfg = st_utils.default_100G_port_cfg(top.tg_port)

    tb.debug_log = True
    top.configure_dot1q_bridge_snake_topology(sai_ports_config)
    tb.debug_log = False

    # get the ports up
    tb.set_all_ports_admin_state(True)
    leaba_tf_wait(5)

    # check connection on all ports
    for port_group_name in sai_ports_config:
        for port in sai_ports_config[port_group_name]:
            # check if port is up
            tb.link_state_check(port['pif'], is_up=True)

    st_utils.list_active_ports(tb, None, True)

    yield tb, top


def test_snake(init_device_and_ports, traffic_gen, fixture_sai_test_topology, request):
    """Basic SAI L2 bridge Snake test"""
    tb, top = fixture_sai_test_topology
    te = traffic_gen

    # snake packet
    in_pkt = Ether(dst=top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
        Dot1Q(vlan=top.snake_base_vlan) / \
        IP(src=top.neighbor_ip1, dst=top.neighbor_ip2, ttl=64) / \
        UDP(sport=64, dport=2048)

    print("Starting SAI snake test")

    stream_id = 0
    for key, port in te.ports.items():
        port_name = key
        te.add_stream(key, stream_id, 240, in_pkt, 0.1, 0)
        te.enable_capture(key, True)
        te.clear_port_statistics(key)

    te.set_expected_streams_per_port(1)

    for key, port in te.ports.items():
        te.start_traffic(key)
        # start only the first port
        break

    if request.config.getoption("--debug_mode"):
        print("Starting debugger...")
        pdb.set_trace()

    # let the traffic run for a while
    leaba_tf_wait(1)

    # Stop traffic
    te.stop_all_traffic_and_disable_capture()

    leaba_tf_wait(10)

    tgen_stat = te.get_stream_statistics(port_name, stream_id)
    tgen_tx = tgen_stat["tx_packets"]
    tgen_rx = tgen_stat["rx_packets"]

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! TE stats !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print(tgen_stat)

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! SAI stats !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("event counters")
    S.dump_event_counters(tb.switch_id)
    # st_utils.print_ports_stats(tb)

    tb.debug_log = True
    prev_counters = None
    curr_counters = None
    # check if rx/tx counters on all ports match.
    for pif in tb.ports:
        prev_counters = curr_counters
        obj_id = tb.ports[pif]
        curr_counters = tb.get_port_stats(obj_id, clear=False)
        assert curr_counters[0] == curr_counters[1], "sai_port_id({}), rx_pkt({}) != tx_pkt({})".format(
            obj_id, curr_counters[0], curr_counters[1])
        assert curr_counters[18] == curr_counters[20], "sai_port_id({}), rx_bytes({}) != tx_bytes({})".format(
            obj_id, curr_counters[18], curr_counters[20])
        tb.log("sai_port_id({}), pkt({}), bytes({})".format(obj_id, curr_counters[0], curr_counters[18]))
        if prev_counters is not None:
            assert prev_counters[0] == curr_counters[0]
            assert prev_counters[18] == curr_counters[18]

    if not pytest.IS_SIMULATOR:
        assert tgen_tx == tgen_rx
