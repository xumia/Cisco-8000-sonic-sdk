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

import os
import re
from saicli import *
import contextlib
import unittest as T
import pytest
import json
from prettytable import PrettyTable
import sai_gen_attr_info
import ipaddress
import sai_packet_utils as U
import os
import re
import time
import pdb

# This function returns whether the SAI version in use is 1.5.2


def is_sai_15x():
    # return 'SAI_VER' in os.environ and os.environ['SAI_VER'].startswith("0x010502")
    sai_ver = get_sai_version()
    return (sai_ver >= 0x010500 and sai_ver < 0x010600)

# This function returns whether the SAI version in use is 1.7.1


def is_sai_17x_or_higher():
    # return not ('SAI_VER' in os.environ and os.environ['SAI_VER'].startswith("0x010502"))
    sai_ver = get_sai_version()
    return (sai_ver >= 0x010700)

# This function is returning wether it's GB or Pacific device.


import sai_obj_wrapper


def get_device_type(switch_id):
    return get_hw_device_type(switch_id)

# This function is returning the egress dynamic buffer pool size.


def get_egress_dynamic_buffer_pool_size(switch_id):
    hw_dev_type = get_device_type(switch_id)
    if hw_dev_type in 'pacific':
        return MAX_SAI_EGRESS_BUFFER_POOL_SIZE_PA
    elif hw_dev_type in 'gibraltar':
        return MAX_SAI_EGRESS_BUFFER_POOL_SIZE_GB
    else:
        return 0

# This function is to udpate board configuration (serdes settings) file path in profile_get_value.


def update_config_file(config_file="config/sherman_p5.json"):
    cvar.config_file_name = config_file

# boot_type == 1 means warm boot


def set_boot_type(boot_type):
    cvar.g_sai_boot_type = boot_type


def lane_to_slice_ifg_pif(lane):
    ifg_idx = int(lane >> 8)
    pif = lane & 0xFF
    slice = int(ifg_idx / 2)
    ifg = int(ifg_idx % 2)
    return {"slice": slice, "ifg": ifg, "pif": pif}


def lane_from_slice_ifg_pif(slice, ifg, pif):
    ifg_idx = slice * 2 + ifg
    lane = (ifg_idx << 8) + (pif & 0xFF)
    return lane


def sai_ilb_mode_tostr(ilb_mode):
    if ilb_mode == SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC:
        return "MAC"
    elif ilb_mode == SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY:
        return "PHY"
    elif ilb_mode == SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE:
        return "NONE"
    else:
        return "ERROR"


def sai_fec_mode_tostr(fec_mode):
    if fec_mode == SAI_PORT_FEC_MODE_FC:
        return "FC"
    elif fec_mode == SAI_PORT_FEC_MODE_RS:
        return "RS"
    elif fec_mode == SAI_PORT_FEC_MODE_NONE:
        return "NONE"
    else:
        return "ERROR"


def sai_qos_map(map_type, key_value_list):
    # pdb.set_trace()
    # getting key, value pairs. Change them into 8-tuples in format suitable for the QOS swig
    type_to_index = {
        SAI_QOS_MAP_TYPE_DOT1P_TO_TC: [2, 0],
        SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR: [2, 6],
        SAI_QOS_MAP_TYPE_DSCP_TO_TC: [1, 0],
        SAI_QOS_MAP_TYPE_DSCP_TO_COLOR: [1, 6],
        SAI_QOS_MAP_TYPE_TC_TO_QUEUE: [0, 5],
        SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE: [3, 5],
    }
    if is_sai_17x_or_higher():
        type_to_index[SAI_QOS_MAP_TYPE_MPLS_EXP_TO_TC] = [7, 0]
        type_to_index[SAI_QOS_MAP_TYPE_MPLS_EXP_TO_COLOR] = [7, 6]
        type_to_index[SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_MPLS_EXP] = [[0, 6], 7]

    key_index = type_to_index[map_type][0]
    val_index = type_to_index[map_type][1]

    complete_key_value_list = []
    for old_key_val in key_value_list:
        new_key_val = [[0] * 8, [0] * 8]
        if isinstance(key_index, list):
            for i in range(len(key_index)):
                new_key_val[0][i] = old_key_val[0][i]
        else:
            new_key_val[0][key_index] = old_key_val[0]
        new_key_val[1][val_index] = old_key_val[1]
        if (not is_sai_17x_or_higher()):
            # Reduce keys and vals by 1 since there is no mpls exp in earlier sai versions
            new_key_val[0] = new_key_val[0][0:-1]
            new_key_val[1] = new_key_val[1][0:-1]
        complete_key_value_list.append(new_key_val)

    return complete_key_value_list


class disable_logging():
    def __enter__(self):
        sai_logging_param_set(False, False)

    def __exit__(self, a, b, c):
        sai_logging_param_set(False, True)

    def _formatMessage(self, msg, msg2):
        print("Test failure msg: {0}".format(msg2))
        assert(False)


def expect_sai_error(sai_error):
    stack = contextlib.ExitStack()
    stack.enter_context(disable_logging())
    stack.enter_context(T.TestCase.assertRaisesRegex(disable_logging(), RuntimeError, "SAI error: {0}".format(sai_error)))
    return stack


def expect_value(fn, value, max_attempts=10, interval_sec=1):
    '''
    Expect the provided function to return a value within the provided
    polling period.

    fn - Function taking no parameters that returns the current value to check
    value - The value that should eventually be returned from fn
    max_attempts - Number of times to call fn
    interval_sec - Length of time between each attempted call to fn
    '''
    new_value = fn()
    attempts = 0
    while attempts < max_attempts and new_value != value:
        time.sleep(interval_sec)
        new_value = fn()
        attempts += 1
    assert new_value == value, "Failed value expectation %s == %s, made %s attempts with sleep interval %s" % (
        str(new_value), str(value), str(max_attempts), str(interval_sec))


def port_config(pif, pif_num=4, serdes_speed=25, mtu=1514, loopback=SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE):
    port_conf = {}
    port_conf['pif'] = pif
    port_conf['pif_counts'] = pif_num
    port_conf['speed'] = pif_num * serdes_speed * 1000
    port_conf['fec'] = SAI_PORT_FEC_MODE_RS
    port_conf['mac_lpbk'] = loopback
    port_conf['fc'] = SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE
    port_conf['an'] = False
    port_conf['admin_state'] = True
    port_conf['mtu_size'] = mtu
    port_conf['media_type'] = SAI_PORT_MEDIA_TYPE_COPPER
    return port_conf


# create a 4x25G 100G port
def default_100G_port_cfg(pif):
    return port_config(pif, 4, 25, 1514)

# create a 8x50G 400G port


def default_400G_port_cfg(pif):
    return port_config(pif, 8, 50, 9600)


def port_config_attr_setup(port_mix_port_val):
    '''
    Convert from port_mix format to SAI attribute format (sai_test_base configuration format)
    Since some attributes can be missing in json configuration file, this function setup the default value.
    And, convert the json value into SAI attribute object.
    '''

    # default values
    port_mix_port = {
        'mac_lpbk': 'NONE',
        'fc': 'disable',
        'fec': 'NONE',
        'an': False,
        'admin_state': False,
        'mtu_size': 1514,
        'media_type': 'NOT_PRESENT'}
    port_mix_port.update(port_mix_port_val)

    # check if 'serdes_preemp' is correctly used.
    if 'serdes_preemp' in port_mix_port:
        assert (len(port_mix_port['serdes_preemp']) == port_mix_port['pif_counts']
                ), 'len of list \'serdes_preemp\' should be {} for \'pif\'={}'.format(port_mix_port['pif_counts'], pif_list)

    port_cfg_fec_to_attr = {'RS': SAI_PORT_FEC_MODE_RS, 'FC': SAI_PORT_FEC_MODE_FC, 'NONE': SAI_PORT_FEC_MODE_NONE}
    port_mix_port['fec'] = port_cfg_fec_to_attr[port_mix_port['fec']]

    port_cfg_lpbk_to_attr = {
        'MAC': SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC,
        'PHY': SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY,
        'NONE': SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE}
    port_mix_port['mac_lpbk'] = port_cfg_lpbk_to_attr[port_mix_port['mac_lpbk']]

    port_cfg_fc_to_attr = {
        'enable': SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE,
        'tx_only': SAI_PORT_FLOW_CONTROL_MODE_TX_ONLY,
        'rx_only': SAI_PORT_FLOW_CONTROL_MODE_RX_ONLY,
        'disable': SAI_PORT_FLOW_CONTROL_MODE_DISABLE}
    port_mix_port['fc'] = port_cfg_fc_to_attr[port_mix_port['fc']]

    port_cfg_fc_to_attr = {
        'COPPER': SAI_PORT_MEDIA_TYPE_COPPER,
        'FIBER': SAI_PORT_MEDIA_TYPE_FIBER,
        'OPTIC': SAI_PORT_MEDIA_TYPE_FIBER,
        'NOT_PRESENT': SAI_PORT_MEDIA_TYPE_NOT_PRESENT,
        '': SAI_PORT_MEDIA_TYPE_NOT_PRESENT,
        'UNKNOWN': SAI_PORT_MEDIA_TYPE_UNKNOWN}
    port_mix_port['media_type'] = port_cfg_fc_to_attr[port_mix_port['media_type']]

    return port_mix_port


def port_config_from(fishnet_setup_port, lpbk_mode="PHY", lpbk_ports=[], conn_ports=[]):
    '''
    Convert fishnet setup port configuration to sai_test_base configuration format
    fishnet_setup_port: a single port configuration from fishnet setup json file
    lpbk_mode: loopback mode for lpbk_ports; MAC for simulation, otherwire PHY.
    lpbk_ports: json_data["connectivity"]["self-loopback"] in fishnet setup
    conn_ports: list of port-id that connects to other ports via cable, such as Exit/Output/Input/traffic-gen ports.
    return:
        port_conf: port configuration object for sai_test_base
        loopback: True for loopback port (PHY or MAC); False for non-loopback port
    '''

    port_conf = {}

    # Convert to SAI pif
    port_conf['pif'] = lane_from_slice_ifg_pif(fishnet_setup_port["slice"], fishnet_setup_port["ifg"], fishnet_setup_port["pif"][0])
    port_conf['pif_counts'] = 1 if len(
        fishnet_setup_port["pif"]) == 1 else fishnet_setup_port["pif"][1] - fishnet_setup_port["pif"][0] + 1

    # convert speed to SAI speed
    port_conf['speed'] = int(fishnet_setup_port["port-speed"].split(":")[0])
    speed_multipler = 1000 if fishnet_setup_port["port-speed"].split(":")[1] == "GIGA" else 1
    port_conf['speed'] = port_conf['speed'] * speed_multipler

    # setup FEC by serdes speed
    serdes_speed = port_conf['speed'] / port_conf['pif_counts']
    port_conf['fec'] = "RS" if serdes_speed >= 25000 else "NONE"

    # set the loopback mode
    if fishnet_setup_port["port-id"] in conn_ports:
        port_conf['mac_lpbk'] = "NONE"
    elif 'all' in lpbk_ports:
        port_conf['mac_lpbk'] = lpbk_mode
    elif fishnet_setup_port["port-id"] in lpbk_ports:
        port_conf['mac_lpbk'] = lpbk_mode
    else:
        port_conf['mac_lpbk'] = "NONE"

    # default the followings
    port_conf['fc'] = "enable"
    port_conf['an'] = False
    port_conf['admin_state'] = False
    port_conf['mtu_size'] = 9600
    port_conf['media_type'] = "COPPER"
    is_self_loopback = port_conf['mac_lpbk'] != "NONE"
    return port_config_attr_setup(port_conf), is_self_loopback


def load_ports_from_json(port_cfg_path, devices_id=1):
    '''
    This function returns SAI port configuration "ports_config" from json file to python list objects
    Function can read 2 type of files, SAI configuration file or test case port configuration file.
    SAI configuration file is used when SAI switch is initializated. And, ports can be created with configurations in "port_mix" defines.
    Test case port configuration file is used only by python test cases.
    Once the ports_config structure is built by this function, user can use "print_ports_config" to print ports_config in table.
    The ports_config structure can be used by sai_test_base.configure_ports to create ports as well.
    If ports are created by SAI switch initialization, "list_active_ports" can be used to back-annotate configuration to sai_test_base.port.
    <port_cfg_path>: Path of the json file.
    <devices_id>: When multipule devices are used/tested, devices_id can be specified for loading ports from different devices in SAI configuration files.
    Here are the two main use case:
      SAI switch initialization with ports creation:
          tb = sai_test_basic()                       # create sai_test_base object
          tb.update_config_file(sai_cfg_json_file)    # specify json file which has all port configurations.
          tb.setUp()                                  # call setUp to initialize SAI switch and ports
          ports_config = load_ports_from_json(sai_cfg_json_file)     # load all port configuration to ports_config structure.
          list_active_ports(tb, ports_config)         # back-annotate ports_config to tb.ports and verify all ports are created correctly.
      Test case ports configurations:
          tb = sai_test_basic()                       # create sai_test_base object
          tb.update_config_file(sai_cfg_json_file)    # specify json file only has lane swap and serdes parametres.
          tb.setUp()                                  # call setUp to initialize SAI switch. No ports are created.
          ports_config = load_ports_from_json(port_cfg_file)     # load all port configuration to ports_config structure.
          tb.configure_ports(ports_config['ports'])   # create all ports
          list_active_ports(tb)                       # list all ports
    '''
    ports_list = []
    ports_config = {}

    print("Loading {} ...".format(port_cfg_path))
    with open(port_cfg_path, 'r') as fh:
        cfg_file_root = json.load(fh)
        port_cfg_json = None
        if 'devices' in cfg_file_root:
            port_cfg_json = [js["port_mix"] for js in cfg_file_root["devices"] if js["id"] == devices_id][0]
        else:
            port_cfg_json = cfg_file_root

        for port_groups in port_cfg_json:
            # skip 'init_switch' which is switch init mode
            if (port_groups == 'init_switch' or port_groups == 'Description'):
                continue
            ports_config[port_groups] = []
            ports_list.append(port_groups)

        for ports in ports_list:
            for port in port_cfg_json[ports]:
                pif_list = port['pif'] if isinstance(port['pif'], list) else [port['pif']]
                port_val = port
                port_val['pif'] = 0
                port_val['pif_counts'] = int(port['pif_counts'])
                port_val['speed'] = int(port['speed'])

                # setup default value for missing attribute.
                port_val = port_config_attr_setup(port_val)

                for pif in pif_list:
                    temp_val = port_val.copy()
                    temp_val['pif'] = int(pif, 16) if isinstance(pif, str) else pif
                    ports_config[ports].append(temp_val)

    return ports_config

# this function print sai port configuration objects


def print_ports_config(ports_config):
    '''
    Print ports_config from load_ports_from_json() in table format.
    '''
    for ports in ports_config:
        table = PrettyTable(title="[\'{}\']".format(ports))
        table.field_names = ["PIF", "Lanes", "Speed", "FC", "FEC", "AN", "lpbk", "mtu", "media", "Admin-ST"]
        for port in ports_config[ports]:
            table.add_row([hex(port['pif']),
                           port['pif_counts'],
                           port['speed'],
                           port['fc'],
                           sai_fec_mode_tostr(port['fec']),
                           port['an'],
                           sai_ilb_mode_tostr(port['mac_lpbk']),
                           port['mtu_size'],
                           port['media_type'],
                           port['admin_state']])
        print(table)

# sai_tb is sai_test_base class which contains apis (sai api functions) and switch_id


def get_port_phy_loc(sai_tb, port_obj_id):
    '''
    return PIF and pif_counts by SAI Port Object ID
    '''
    lanes = sai_u32_list_t(range(0, 16))
    attr = sai_attribute_t(SAI_PORT_ATTR_HW_LANE_LIST, lanes)

    sai_tb.apis[SAI_API_PORT].get_port_attribute(port_obj_id, 1, attr)
    return lane_to_slice_ifg_pif(attr.value.u32list.to_pylist()[0]), attr.value.u32list.count


def get_active_ports_list(sai_tb, ports_info):
    '''
    Returns the a list of active ports from SAI switch
    return: ports_info = [{'oid': id_0},{'oid': id_1},...]
    '''
    attr = sai_attribute_t(SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS, 0)
    sai_tb.apis[SAI_API_SWITCH].get_switch_attribute(sai_tb.switch_id, 1, attr)
    num_of_active_port = attr.value.u32

    # test port list buffer overflow
    port_obj_id_list = sai_object_list_t(range(0, num_of_active_port))
    attr = sai_attribute_t(SAI_SWITCH_ATTR_PORT_LIST, port_obj_id_list)
    sai_tb.apis[SAI_API_SWITCH].get_switch_attribute(sai_tb.switch_id, 1, attr)
    for port_obj_id in attr.value.objlist.to_pylist():
        ports_info.append({'oid': port_obj_id})


def list_port_supported(sai_tb):
    '''
    Display supported features of ports in python list format
    '''
    ports_supported = []
    get_active_ports_list(sai_tb, ports_supported)

    for port in ports_supported:
        u32_list = sai_u32_list_t(range(0, 32))
        attr = sai_attribute_t(SAI_PORT_ATTR_SUPPORTED_SPEED, u32_list)
        sai_tb.apis[SAI_API_PORT].get_port_attribute(port['oid'], 1, attr)
        port['supported_speed'] = attr.value.u32list.to_pylist()

        u32_list = sai_u32_list_t(range(0, 3))
        attr = sai_attribute_t(SAI_PORT_ATTR_SUPPORTED_FEC_MODE, u32_list)
        sai_tb.apis[SAI_API_PORT].get_port_attribute(port['oid'], 1, attr)
        port['supported_fec'] = attr.value.u32list.to_pylist()

        u32_list = sai_u32_list_t(range(0, 16))
        attr = sai_attribute_t(SAI_PORT_ATTR_SUPPORTED_HALF_DUPLEX_SPEED, u32_list)
        sai_tb.apis[SAI_API_PORT].get_port_attribute(port['oid'], 1, attr)
        port['supported_half_duplex_speed'] = attr.value.u32list.to_pylist()

        attr = sai_attribute_t(SAI_PORT_ATTR_SUPPORTED_AUTO_NEG_MODE, False)
        sai_tb.apis[SAI_API_PORT].get_port_attribute(port['oid'], 1, attr)
        port['supported_an'] = attr.value.booldata

        attr = sai_attribute_t(SAI_PORT_ATTR_SUPPORTED_FLOW_CONTROL_MODE, SAI_PORT_FLOW_CONTROL_MODE_DISABLE)
        sai_tb.apis[SAI_API_PORT].get_port_attribute(port['oid'], 1, attr)
        port['supported_fc'] = attr.value.s32

        attr = sai_attribute_t(SAI_PORT_ATTR_SUPPORTED_ASYMMETRIC_PAUSE_MODE, False)
        sai_tb.apis[SAI_API_PORT].get_port_attribute(port['oid'], 1, attr)
        port['supported_asym_pause'] = attr.value.booldata

        attr = sai_attribute_t(SAI_PORT_ATTR_SUPPORTED_MEDIA_TYPE, SAI_PORT_MEDIA_TYPE_NOT_PRESENT)
        sai_tb.apis[SAI_API_PORT].get_port_attribute(port['oid'], 1, attr)
        port['supported_media_type'] = attr.value.s32

    print(ports_supported)


def read_sai_port_info(sai_tb, port_info):
    '''
    port_info should contain 'oid': sai_object_id_t
    '''
    phy_loc, count = get_port_phy_loc(sai_tb, port_info['oid'])
    port_info['slice'] = phy_loc['slice']
    port_info['ifg'] = phy_loc['ifg']
    port_info['pif'] = phy_loc['pif']
    port_info['lanes'] = count
    port_info['sai_pif'] = lane_from_slice_ifg_pif(phy_loc['slice'], phy_loc['ifg'], phy_loc['pif'])
    if port_info['sai_pif'] not in sai_tb.ports:
        # back annotate object id in sai_test_base if missing sai_pif
        # this is normal because create_switch can create ports that listed in config file.
        sai_tb.ports[port_info['sai_pif']] = port_info['oid']

    # check object id, if not matching, this means create_switch() created some ports that are not match with test case.
    # most likely is port creation error in test case.
    assert (sai_tb.ports[port_info['sai_pif']] == port_info['oid'])

    port_info['port_status'] = sai_tb.get_object_attr(port_info['oid'], SAI_PORT_ATTR_OPER_STATUS)
    port_info['fec_mode'] = sai_tb.get_object_attr(port_info['oid'], SAI_PORT_ATTR_FEC_MODE)
    port_info['ilb_mode'] = sai_tb.get_object_attr(port_info['oid'], SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE)
    port_info['an_enable'] = sai_tb.get_object_attr(port_info['oid'], SAI_PORT_ATTR_AUTO_NEG_MODE)
    port_info['port_speed'] = sai_tb.get_object_attr(port_info['oid'], SAI_PORT_ATTR_SPEED)
    port_info['mtu_size'] = sai_tb.get_object_attr(port_info['oid'], SAI_PORT_ATTR_MTU)
    port_info['admin_state'] = sai_tb.get_object_attr(port_info['oid'], SAI_PORT_ATTR_ADMIN_STATE)
    port_info['fc'] = sai_tb.get_object_attr(port_info['oid'], SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE)
    port_info['media_type'] = sai_tb.get_object_attr(port_info['oid'], SAI_PORT_ATTR_MEDIA_TYPE)


def list_active_ports(sai_tb, crosschk_port_cfg_list=None, print_result=True):
    '''
    list all active ports in SAI switch.
    <sai_tb>: object of sai_test_base which has created sai_switch.
    <crosschk_port_cfg_list>: cross-check port configurations list.
    <print_result>: True to print active ports table
    '''
    ports_info = []
    crosschk = False if crosschk_port_cfg_list is None else True

    # Get number of active ports and a list of the port_obj_id.
    get_active_ports_list(sai_tb, ports_info)

    # Get slice/ifg/pif/lanes from port_obj_id for display
    for port in ports_info:
        read_sai_port_info(sai_tb, port)

    table_title = "SAI_SWITCH_ATTR_PORT_LIST"
    if crosschk:
        table_title += " (Cross Check Enabled)"

    table = PrettyTable(title=table_title)
    table_passed = True

    table.field_names = ["OBJ_ID", "Port:Location", "Status", "SPEED(Gbps)", "Media", "FEC", "ILB", "AN/LT", "MTU", "FC", "Err-Msg"]
    for port in ports_info:
        err_msg = ""
        if crosschk:
            port_pif = lane_from_slice_ifg_pif(port['slice'], port['ifg'], port['pif'])
            xGen = (ref_port for ref_port in crosschk_port_cfg_list if ref_port['pif'] == port_pif)
            assert xGen is not None
            expected = next(xGen, None)
            err_msg = err_msg if port_pif == expected['pif'] else "PIF!={}".format(hex(expected['pif']))
            err_msg = err_msg if port['lanes'] == expected['pif_counts'] else "Lanes!={}".format(expected['pif_counts'])
            err_msg = err_msg if port['port_speed'] == expected['speed'] else "Speed!={}".format(expected['speed'])
            err_msg = err_msg if port['media_type'] == expected['media_type'] else "Media!={}".format(expected['media_type'])
            err_msg = err_msg if port['fec_mode'] == expected['fec'] else "FEC!={}".format(expected['fec'])
            err_msg = err_msg if port['ilb_mode'] == expected['mac_lpbk'] else "ILB!={}".format(expected['mac_lpbk'])
            err_msg = err_msg if port['an_enable'] == expected['an'] else "AN/LT!={}".format(expected['an'])
            err_msg = err_msg if port['mtu_size'] == expected['mtu_size'] else "MTU!={}".format(expected['mtu_size'])
            err_msg = err_msg if port['fc'] == expected['fc'] else "FC!={}".format(expected['fc'])
            if err_msg is not "":
                table_passed = False

        table.add_row(
            [hex(port['oid']),
             '{}:[{}/{}/{}-{}]'.format(hex(port['sai_pif']), port['slice'], port['ifg'], port['pif'], port['lanes']),
             '{}-{}'.format("EN" if port['admin_state'] else 'DIS', "UP" if port['port_status'] == SAI_PORT_OPER_STATUS_UP else 'DN'),
             port['port_speed'],
             port['media_type'],
             sai_fec_mode_tostr(port['fec_mode']),
             sai_ilb_mode_tostr(port['ilb_mode']),
             port['an_enable'],
             port['mtu_size'],
             port['fc'],
             err_msg])

    if crosschk:
        if print_result or not table_passed:
            print(table)
        assert table_passed
    elif print_result:
        print(
            table.get_string(
                fields=[
                    'OBJ_ID',
                    'Port:Location',
                    'Status',
                    'SPEED(Gbps)',
                    'Media',
                    'FEC',
                    'ILB',
                    'AN/LT',
                    'MTU',
                    'FC']))


def check_active_ports(sai_tb, crosschk_port_cfg_list, print_result=False):
    '''
    list all active ports in SAI switch.
    <sai_tb>: object of sai_test_base which has created sai_switch.
    <crosschk_port_cfg_list>: cross-check port configurations list.
    <print_result>: True to print active ports table
    '''
    list_active_ports(sai_tb, crosschk_port_cfg_list, print_result)


def print_ports_stats(sai_tb, port_list=None, clear=False):
    # Print MIB counters in a table.
    port_pif_list = sai_tb.ports if port_list is None else port_list

    table = PrettyTable(title="SAI Port Counters")
    table.field_names = ["PORT", "Rx/Tx Good Pkts", "Rx/Tx Bytes Counts", "Rx/Tx Error Pkts", "Rx/Tx Pause Frames", "CRC Errors"]

    for port_pif in port_pif_list:
        counters = sai_tb.get_port_stats(sai_tb.ports[port_pif], clear)
        table.add_row([hex(port_pif),
                       [counters[0], counters[1]],
                       [counters[18], counters[20]],
                       [counters[19], counters[21]],
                       [counters[16], counters[17]],
                       counters[25]])

    print(table)


def print_port_queue_stats(sai_tb, port_obj_id):
    queue_list = sai_tb.get_queue_list(port_obj_id)
    table = PrettyTable(title="port queue counters")
    table.field_names = ["Queue", "packets", "bytes", "drop packets", "drop_bytes"]

    for q in queue_list.to_pylist():
        q_cnts = sai_tb.get_queue_stats(q)
        table.add_row([hex(q), q_cnts[0], q_cnts[1], q_cnts[2], q_cnts[3]])

    print(table)


def dump_port_stats(sai_tb, port_pif, clear=False):
    # dump port stats by port_pif (PIF ID)
    counters = sai_tb.get_port_stats(sai_tb.ports[port_pif], clear)
    sai_tb.dump_port_stats(counters)


# If dump is for comparing before/after warm boot, we need need_sort=True
# If need_sort==True, for objects that can't be sorted (routes/fdb entries,...) we only dump their number
def dump_obj_to_file(file_name, tb, obj_types="all", need_sort=True):
    if obj_types == "all":
        obj_types_to_check = sai_gen_attr_info.all_sai_attributes_info.keys()
    else:
        obj_types_to_check = obj_types

    out_file = open(file_name, "w")
    obj_wrapper = sai_obj_wrapper.lsai_obj_wrapper(tb)
    for obj_type in sorted(obj_types_to_check):
        try:
            num_objs, obj_list = tb.get_object_keys(obj_type)
        except BaseException:
            continue
        if num_objs == 0:
            continue

        out_file.write("{0} objects of type {1}\n".format(num_objs, obj_type))
        if need_sort:
            if not isinstance(obj_list[0], int):
                # some objects (FDB_ENTRY for example), do not return list of object IDs
                continue
            else:
                sorted_obj_list = []
                for i in range(num_objs):
                    sorted_obj_list.append(obj_list[i])
                sorted_obj_list.sort()
        else:
            sorted_obj_list = obj_list

        tb.disable_logging()
        for obj_id_num in range(0, num_objs):
            out_file.write("id: {}\n".format(sai_obj_to_str(sorted_obj_list[obj_id_num])))

            # for each obj, dump all its attributes to file
            for attr_id in sorted(sai_gen_attr_info.all_sai_attributes_info[obj_type].keys()):
                attr_name = sai_gen_attr_info.all_sai_attributes_info[obj_type][attr_id]["name"]
                # Don't compare these, because we do warm boot under traffic, so their values change
                if obj_type == SAI_OBJECT_TYPE_ACL_COUNTER and (
                        attr_id == SAI_ACL_COUNTER_ATTR_BYTES or attr_id == SAI_ACL_COUNTER_ATTR_PACKETS):
                    continue
                # port can also go up/down during warmboot, so ignore this on attribute comparison
                if obj_type == SAI_OBJECT_TYPE_PORT and (
                        attr_id == SAI_PORT_ATTR_OPER_STATUS or attr_id == SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE):
                    continue
                # skip temperature sensor readings
                if obj_type == SAI_OBJECT_TYPE_SWITCH and (
                        attr_id == SAI_SWITCH_ATTR_TEMP_LIST or attr_id == SAI_SWITCH_ATTR_MAX_TEMP or attr_id == SAI_SWITCH_ATTR_AVERAGE_TEMP):
                    continue
                #  get
                attr_cap = obj_wrapper.get_attr_capability(obj_type, attr_id)
                if attr_cap["get"]:
                    attr_val = obj_wrapper.get_attr_by_type(obj_type, sorted_obj_list[obj_id_num], attr_id)
                    if attr_val is not None:
                        if isinstance(attr_val, list):
                            # ACL types has a list of mixed bool and int, so it can't be sorted
                            try:
                                attr_val = sorted(attr_val)
                            except BaseException:
                                pass
                        out_file.write("{0}: {1}\n".format(attr_name, attr_val))
        tb.enable_logging()


def sai_obj_to_str(obj_id):
    if isinstance(obj_id, int):
        return hex(obj_id)
    elif str(type(obj_id)) == "<class 'saicli.sai_route_entry_t'>":
        route_entry = obj_id
        if route_entry.destination.addr_family is SAI_IP_ADDR_FAMILY_IPV4:
            addr = str(ipaddress.IPv4Address(route_entry.destination.addr.ip4.to_bytes(4, byteorder='little')))
            mask = str(route_entry.destination.mask.ip4.to_bytes(4, byteorder='little').hex())
        else:
            addr = U.sai_ip_to_string(sai_ip_address_t(route_entry.destination.addr.ip6))
            mask = U.sai_ip_to_string(sai_ip_address_t(route_entry.destination.mask.ip6))
        return "virtual router {} dest {}/{}".format(hex(route_entry.vr_id), addr, mask)
    elif str(type(obj_id)) == "<class 'saicli.sai_fdb_entry_t'>":
        return "bv_id {} mac {}" .format(hex(obj_id.bv_id), sai_py_mac_t(obj_id.mac_address).addr)
    elif str(type(obj_id)) == "<class 'saicli.sai_neighbor_entry_t'>":
        if obj_id.ip_address.addr_family is SAI_IP_ADDR_FAMILY_IPV4:
            addr = str(ipaddress.IPv4Address(obj_id.ip_address.addr.ip4.to_bytes(4, byteorder='little')))
        else:
            addr = U.sai_ip_to_string(sai_ip_address_t(obj_id.ip_address.addr.ip6))
        return "rif_id {} ip {}".format(obj_id.rif_id, addr)
    else:
        return "not implemented"


def check_if_skipped(request):
    try:
        with open("test/python/skipped_tests") as f:
            dirs_to_skip = []
            files_to_skip = []
            classes_to_skip = []
            tests_to_skip = []
            lines = f.readlines()
            for line in lines:
                split_line = line.rstrip().split(" ")
                command = split_line[0]
                obj = split_line[1]
                if command == "skip-dir":
                    dirs_to_skip.append(obj)
                if command == "skip-file":
                    files_to_skip.append(obj)
                if command == "skip-class":
                    classes_to_skip.append(obj)
                if command == "skip-test":
                    tests_to_skip.append(obj)

    except BaseException:
        return

    test_string = os.environ.get('PYTEST_CURRENT_TEST')
    test_array = test_string.split("::")
    dir_name = test_array[0].split("/")[-2]
    file_name = test_array[0].split("/")[-1]
    class_name = test_array[1]
    test_name = test_array[-1].split(" ")[0]

    if dir_name in dirs_to_skip:
        pytest.skip("Directory {} currently skipped".format(dir_name))
    if file_name in files_to_skip:
        pytest.skip("File {} currently skipped".format(file_name))
    if class_name in classes_to_skip:
        pytest.skip("Class {} currently skipped".format(class_name))
    if test_name in tests_to_skip:
        pytest.skip("Test {} currently skipped".format(test_name))


def skipIf(cond):
    if cond:
        pytest.skip("Test is currently skipped.")


def dump_route_entries(obj_count, obj_list):
    for idx in range(obj_count):
        route_entry = obj_list[idx]
        if route_entry.destination.addr_family is SAI_IP_ADDR_FAMILY_IPV4:
            addr = str(ipaddress.IPv4Address(route_entry.destination.addr.ip4.to_bytes(4, byteorder='little')))
            mask = str(route_entry.destination.mask.ip4.to_bytes(4, byteorder='little').hex())
        else:
            addr = U.sai_ip_to_string(sai_ip_address_t(obj_list[idx].destination.addr.ip6))
            mask = U.sai_ip_to_string(sai_ip_address_t(obj_list[idx].destination.mask.ip6))
        next_hop = sai_obj_to_str(pytest.tb.get_object_attr(
            [SAI_OBJECT_TYPE_ROUTE_ENTRY, route_entry], SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID))
        print(" addr/mask: {}/{} next_hop {}" .format(addr, mask, next_hop))


def dump_fdb_entries(obj_count, obj_list):
    for idx in range(obj_count):
        fdb_entry = obj_list[idx]
        mac_addr = sai_py_mac_t(fdb_entry.mac_address)
        print("SW_ID: {} BV_ID: {} MAC: {}".format(hex(fdb_entry.switch_id), hex(fdb_entry.bv_id), mac_addr.addr))


def int_to_uint(int_value, max_int=0xFFFFFFFF):
    '''
    Convert int value to unsigned int value.
    max_int is max value of unsigned value. Default is 0xFFFFFFFF for int32.
    max_int can be set to 0xFFFFFFFFFFFFFFFF for unsigned int64 conversion.
    '''
    if isinstance(int_value, list):
        return_list = []
        for value in int_value:
            return_list.append(int_to_uint(value, max_int))

        return return_list

    if int_value > 0:
        return int_value
    else:
        return (int_value + max_int + 1)


def is_asic_env_gibraltar():
    asic_name = os.getenv('ASIC', "pacific")
    is_gb = re.search(r'gibraltar', asic_name, re.IGNORECASE)
    if is_gb:
        return True
    return False


def is_hw_device():
    hw_dev = os.getenv('SDK_DEVICE_NAME', "nsim")
    is_hw = re.search(r'dev\/uio', hw_dev, re.IGNORECASE)
    if is_hw:
        return True
    return False


class PortConfig():
    VOQ_SWITCH_ID = 1

    def __init__(self):
        self._sp_gid = 1

        if is_asic_env_gibraltar():
            # b[31:8] = (slice * #ifgs_per_slice) + ifg
            # b[7:0] = pif

            # (2, 1, 0) 4
            self.in_port = 0x510
            # (2, 1, 8) 4
            self.out_port = 0x508
            # (1, 1, 8)
            self.rt_port = 0x308
            # (1, 0, 8)
            self.rt_port1 = 0x208
            # (2, 1, c)
            self.mirror_dest = 0x50c

            self.host_serdes_id = 24
            self.recycle_serdes_id = 25
        else:
            # b[31:8] = (slice * #ifgs_per_slice) + ifg
            # b[7:0] = pif

            # (3, 0, 0) 4
            self.in_port = 0x600
            # (3, 0, 8) 4
            self.out_port = 0x608
            # (1, 1, 8)
            self.rt_port = 0x308
            # (1, 0, 8)
            self.rt_port1 = 0x208
            # (3, 0, c)
            self.mirror_dest = 0x60c

            self.host_serdes_id = 18
            self.recycle_serdes_id = 19

        self.slices_per_dev = 6
        self.ifgs_per_slice = 2
        self.max_system_cores = self.slices_per_dev * self.ifgs_per_slice

        # (0, 0, 8) extra port for svi
        self.sw_port = 0x008

        self.in_port_cfg = default_100G_port_cfg(self.in_port)
        self.out_port_cfg = default_100G_port_cfg(self.out_port)
        self.sw_port_cfg = default_100G_port_cfg(self.sw_port)
        self.rt_port_cfg = default_100G_port_cfg(self.rt_port)
        self.rt_port1_cfg = default_100G_port_cfg(self.rt_port1)
        self.mirror_dest_cfg = default_100G_port_cfg(self.mirror_dest)

        # sai_system_port_config_t:
        #  port_id, attached_switch_id, attached_core_index, attached_core_port_index, speed, num_voq
        #
        # Internal system ports
        #
        # attached_core_index must reflect the internal ifgs_per_slice
        # * slice_id + ifg_id value for the port, and
        # attached_core_port_index should be the special PIF value for
        # that type of port, either host (PCI/NPUH) or recycle. This
        # PIF allows identification inside the SAI implementation of
        # the purpose of this sysport config.
        self.npuh_sys_port_cfg = [
            self.new_sp_gid(),
            self.VOQ_SWITCH_ID,
            (self.ifgs_per_slice * 0) + 1,
            self.host_serdes_id,
            PUNT_PORT_SPEED,
            8]
        self.pci_sys_port_cfgs = []
        for slice_id in range(0, self.slices_per_dev, 2):  # Even slices
            self.pci_sys_port_cfgs.append([self.new_sp_gid(), self.VOQ_SWITCH_ID,
                                           (self.ifgs_per_slice * slice_id) + 0, self.host_serdes_id, PUNT_PORT_SPEED, 8])
        self.recycle_sys_port_cfgs = []
        for slice_id in range(1, self.slices_per_dev, 2):  # Odd slices
            self.recycle_sys_port_cfgs.append([self.new_sp_gid(), self.VOQ_SWITCH_ID,
                                               (self.ifgs_per_slice * slice_id) + 0, self.recycle_serdes_id, RECYCLE_PORT_SPEED, 8])
        self.internal_sys_port_cfgs = self.recycle_sys_port_cfgs + self.pci_sys_port_cfgs + [self.npuh_sys_port_cfg]

        # Front panel system ports
        self.in_port_sp_gid = self.new_sp_gid()
        self.in_sys_port_cfg = [
            self.in_port_sp_gid,
            self.VOQ_SWITCH_ID,
            self.in_port >> 8,
            self.in_port & 0xFF,
            self.in_port_cfg['speed'],
            8]
        self.out_port_sp_gid = self.new_sp_gid()
        self.out_sys_port_cfg = [
            self.out_port_sp_gid,
            self.VOQ_SWITCH_ID,
            self.out_port >> 8,
            self.out_port & 0xFF,
            self.out_port_cfg['speed'],
            8]

        self.sysport_cfgs = [self.in_sys_port_cfg, self.out_sys_port_cfg] + self.internal_sys_port_cfgs

        # Reserve a pif with no associated port, for negative testing
        self.no_port_pif = 0x900
        self.no_port_cfg = default_100G_port_cfg(self.no_port_pif)

    def new_sp_gid(self):
        curr_sp_gid = self._sp_gid
        self._sp_gid += 1
        return curr_sp_gid

    def make_sp_cfg(self, port_config):
        aci = port_config['pif'] >> 8
        acpi = port_config['pif'] & 0xFF
        return [self.new_sp_gid(), self.VOQ_SWITCH_ID, aci, acpi, port_config['speed'], 8]
