#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from leaba import sdk


def pall(obj):
    attrs = [attr for attr in dir(obj) if not attr.startswith('__') and not attr == 'this']
    for attr in attrs:
        val = getattr(obj, attr)
        print(attr, "=", val)


def mac_ports_apply_params(mac_port):
    mac_info = {
        'slice': mac_port.get_slice(),
        'ifg': mac_port.get_ifg(),
        'serdes': mac_port.get_first_serdes_id()}
    serdes_count = mac_port.get_num_of_serdes()
    ACTIVATE = sdk.la_mac_port.serdes_param_stage_e_ACTIVATE
    PRE_ICAL = sdk.la_mac_port.serdes_param_stage_e_PRE_ICAL
    PRE_PCAL = sdk.la_mac_port.serdes_param_stage_e_PRE_PCAL
    FIXED = sdk.la_mac_port.serdes_param_mode_e_FIXED
    ADAPTIVE = sdk.la_mac_port.serdes_param_mode_e_ADAPTIVE
    props = [
        [PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF, FIXED, 4],
        [PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF, FIXED, 1],
        [ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_PLL_BB, FIXED, 1],
        [ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_PLL_IFLT, FIXED, 6],
        [ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_PLL_INT, FIXED, 8],
        [ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PLL_BB, FIXED, 25],
        [ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PLL_IFLT, FIXED, 1],
        [ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PLL_INT, FIXED, 7],
        [PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF, ADAPTIVE, 0],
        [PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF, ADAPTIVE, 0],
    ]
    for serdes in range(serdes_count):
        for prop in props:
            (stage, param, mode, val) = prop
            mac_port.set_serdes_parameter(serdes, stage, param, mode, val)


# FE
dev_id = 200
dev = sdk.la_create_device('/dev/uio0', dev_id)

dev.initialize(sdk.la_device.init_phase_e_DEVICE)

dev.set_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY, 1)

for sid in range(6):
    dev.set_slice_mode(sid, sdk.la_slice_mode_e_CARRIER_FABRIC)
    dev.set_fabric_slice_clos_direction(sid, sdk.la_clos_direction_e_DOWN)  # FE only
dev.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

fabric_mac_ports = []
fabric_ports = []
sid = 0
ifg = 0
for serdes in [12, 14]:
    p = dev.create_fabric_mac_port(
        sid,
        ifg,
        serdes,
        serdes + 1,
        sdk.la_mac_port.port_speed_e_E_100G,
        sdk.la_mac_port.fc_mode_e_NONE)
    fabric_mac_ports.append(p)

for p in fabric_mac_ports:
    fp = dev.create_fabric_port(p)
    fabric_ports.append(fp)
    mac_ports_apply_params(p)
    p.activate()

for fp in fabric_ports:
    fp.activate(sdk.la_fabric_port.link_protocol_e_PEER_DISCOVERY)
for fp in fabric_ports:
    fp.activate(sdk.la_fabric_port.link_protocol_e_LINK_KEEPALIVE)
dev.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, True)

# LC
dev_id = 100
dev = sdk.la_create_device('/dev/uio0', dev_id)
dev.initialize(sdk.la_device.init_phase_e_DEVICE)
dev.set_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY, 1)
for sid in range(3):
    dev.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)
    dev.set_slice_mode(sid + 3, sdk.la_slice_mode_e_CARRIER_FABRIC)
dev.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

fabric_mac_ports = []
fabric_ports = []
sid = 5
ifg = 0
for serdes in [0, 2]:
    p = dev.create_fabric_mac_port(
        sid,
        ifg,
        serdes,
        serdes + 1,
        sdk.la_mac_port.port_speed_e_E_100G,
        sdk.la_mac_port.fc_mode_e_NONE)
    fabric_mac_ports.append(p)

for p in fabric_mac_ports:
    fp = dev.create_fabric_port(p)
    fabric_ports.append(fp)
    mac_ports_apply_params(p)
    p.activate()

for fp in fabric_ports:
    fp.activate(sdk.la_fabric_port.link_protocol_e_PEER_DISCOVERY)

dev.set_is_fabric_time_master(True)  # LC only

# After PEER_DISCOVERY is enabled on FE side if w/ traffic
for fp in fabric_ports:
    fp.activate(sdk.la_fabric_port.link_protocol_e_LINK_KEEPALIVE)

dev.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, True)
