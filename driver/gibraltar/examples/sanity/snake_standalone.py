#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


###
# Create Snake configuration base on command line parameters.
# Following are some simple examples:
#
# 1. Simple single port P2P configuration that all traffic ingress will egress from that port.
#    The port is on Slice 2, IFG 0, first SerDes 0, total two SerDes and ports speed is 50G (port is 2x25G)
#
#    snake_standalone --real_port 2 0 0 2 50 --p2p 1
#
# 2. One port connected to traffic generator and 10 loopback ports. All connected in P2P snake configuration.
#    Traffic generator port is on Slice 2, IFG 0, first SerDes 0, total two SerDes and ports speed is 50G (port is 2x25G)
#    Total 8 loopback ports, starting from Slice 4, IFG 1, SerDes 0. Each port uses 2 SerDes and speed is 100G (2x50G)
#    The traffic configured in snake (from the physical port, to first loopback, till the last and then back to the real port).
#    The P2P snake configuration does two loops on each loopback port (uses two AC ports).
#
#    snake_standalone --real_port 2 0 0 2 50 --loop_count 8 --loop_port 4 1 0 --loop_type 2 100 --loop_mode none --p2p 2
#
# 3. L3 snake with HBM over all ports. Last 10 ports evict traffic through the HBM.
#   snake_standalone --real_port 2 0 16 2 50 --loop_port 2 1 0 --loop_count 107 --loop_type 2 100 --loop_mode pma --p2p 2 --hbm
###

import os
import time
import argparse
import json
import traceback

import network_objects
from packet_test_defs import *
from sanity_constants import *
from binascii import hexlify, unhexlify
from leaba import sdk
from enum import Enum
from leaba import debug
from leaba.debug import get_bits
from leaba.debug import set_bits
import lldcli
import decor

import voq_allocator
from mac_port_helper import *

if decor.is_graphene():
    NUM_SLICES_PER_DEVICE = 8
else:
    NUM_SLICES_PER_DEVICE = 6

NUM_IFGS_PER_SLICE = 2

SLOW_PORT_TO_LINKUP_TIMEOUT = 120
FAST_PORT_TO_LINKUP_TIMEOUT = 30

VOQ_SET_SIZE = 8
if decor.is_gibraltar():
    PORTS_TO_EVICT = 17
else:
    PORTS_TO_EVICT = 8


TPID_Dot1Q = 0x8100                                # VLAN-tagged frame (802.1q) and Shortest Path Bridging (802.1aq)

HBM_MODE_DISABLE = 0
HBM_MODE_ENABLE = 1
HBM_MODE_FORCE = 2

FABRIC_PEER_DISCOVERY_RETRIES = 10
FABRIC_PEER_DISCOVERY_DELAY = (50 / 1000.0)
PACKET_INJECT_RETRIES = 10

NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS = 0x26

INJECT_ENCAP_LENGTH = 35
MAC_CRC_LENGTH = 4
ETH_P_ALL = 3
MAC_LEN_BYTES = 6
MAX_MAC_PER_SWITCH_NO_LIMIT_VALUE = 0x7FFFF

IFCONFIG_CMD = 'ifconfig'


class vlan_id_e(Enum):
    BASE_VID_1 = 0x100
    BASE_VID_2 = 0x200


class vrf_gid_e(Enum):
    VRF_BASE_GID_1 = 0x200
    VRF_BASE_GID_2 = 0x500


class mac_addr_e(Enum):
    MAC_ADDR_1 = 0xcafecafecafe
    MAC_ADDR_2 = 0x22222222260a


class nh_gid_e(Enum):
    NH_GID_1 = 0x0
    NH_GID_2 = 0x400


class ipv6_das_e(Enum):
    IPV6_DAS_1 = 0x11110db80a0b12f0
    IPV6_DAS_2 = 0x11220db80a0b12f0


class snake_base_topology:
    # Base topology constants
    SYS_PORT_BASE_GID = 0x110
    INJECT_PORT_MAC_ADDR = 0x123456789abc
    DST_MAC_BASE = 0xcafecafe0000
    SRC_MAC = 0xdeaddeaddead
    L3_MAC_ADDR = 0x222222222222

    # P2P constants
    BASE_VID1 = 0x100
    ENTRY_VLAN = BASE_VID1
    VRF_BASE_GID = 0x200
    AC_PORT_BASE_GID = 0x310
    PREFIX_BASE_GID_OFFSET = 64
    BASE_SWITCH_GID = 0x64
    PUNT_INJECT_PORT_MAC_ADDR = network_objects.mac_addr('12:34:56:78:9a:bd')
    DUMMY_SP_LEN = 2

    def __init__(self):
        self.dst_id_offset = 0
        sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)
        lldcli.set_error_mode(lldcli.error_mode_e_EXCEPTION)

    def init(
            self,
            device_name='/dev/uio0',
            device_id=0,
            board='none',
            hbm=HBM_MODE_DISABLE,
            is_linecard=False):
        self.reset()
        self.mph = mac_port_helper(verbose=not self.args.quiet)

        if self.mph.verbose:
            if self.args.debug_trace:
                sdk.la_set_logging_level(0, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
                sdk.la_set_logging_level(0, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)
            else:
                sdk.la_set_logging_level(0, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_INFO)
                sdk.la_set_logging_level(0, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_INFO)
        else:
            for log_comp in range(sdk.la_logger_component_e_FIRST, sdk.la_logger_component_e_LAST):
                sdk.la_set_logging_level(0, log_comp, sdk.la_logger_level_e_ERROR)

        self.device_init(device_id, device_name, board, hbm, is_linecard)

        first_voq = self.device.get_limit(sdk.limit_type_e_DEVICE__FIRST_ALLOCATABLE_VOQ)
        self.voq_allocator = voq_allocator.voq_allocator(first_base_voq=first_voq, slice_modes=self.all_slices_modes)

        self.mph.init(self.device)
        self.mph.setup_trap_counters()
        self.create_profiles()
        self.init_default_tm()

        if hbm != HBM_MODE_DISABLE:
            # Following are workaround to force traffic to go through HBM
            self.force_hbm_evict()

        # Create punt-inject ports for all the slices (for NPU-host injection)
        if is_linecard:
            recycle_ports = [1]
            inject_ports = [0]
        else:
            recycle_ports = self.device.get_used_slices()
            inject_ports = []
            for s in self.device.get_used_slice_pairs():
                if s * 2 in self.device.get_used_slices():
                    inject_ports.append(s * 2)
                else:
                    inject_ports.append(s * 2 + 1)
            if decor.is_pacific():
                recycle_ports = [2 * p + 1 for p in self.device.get_used_slice_pairs()]

        for s in recycle_ports:
            self.create_recycle_port(s, 0)

        for s in inject_ports:
            self.create_punt_inject_port(s, 0)

        # Open sockets and initialize PCI ports
        self.init_inject_for_ports()

        # reset counters
        self.mph.clear_mac_stats()

    def create_board_config(self):
        self.ifg_swap_lists = []
        self.anlt_swap_lists = []
        self.serdes_polarity_inverse_rx = []
        self.serdes_polarity_inverse_tx = []

    def load_board_config_from_json(self, board_cfg_path):
        with open(board_cfg_path, 'r') as fh:
            board_cfg = json.load(fh)
            for board_settings in board_cfg['board_settings']:
                self.ifg_swap_lists.insert((board_settings['slice'] * 2) + board_settings['ifg'], board_settings['ifg_swaps'])
                if 'anlt_swaps' in board_cfg['board_settings'][0]:
                    self.anlt_swap_lists.insert((board_settings['slice'] * 2) + board_settings['ifg'], board_settings['anlt_swaps'])
                    self.with_an_order = True
                else:
                    self.with_an_order = False

                self.serdes_polarity_inverse_rx.insert(
                    (board_settings['slice'] * 2) + board_settings['ifg'],
                    board_settings['rx_polarity'])
                self.serdes_polarity_inverse_tx.insert(
                    (board_settings['slice'] * 2) + board_settings['ifg'],
                    board_settings['tx_polarity'])
            if 'device_bool_properties' in board_cfg:
                for prop in board_cfg['device_bool_properties']:
                    prop_name = eval('sdk.la_device_property_e_' + prop['name'])
                    self.device.set_bool_property(prop_name, prop['value'])
            if 'device_int_properties' in board_cfg:
                for prop in board_cfg['device_int_properties']:
                    prop_name = eval('sdk.la_device_property_e_' + prop['name'])
                    self.device.set_int_property(prop_name, prop['value'])

    def modify_board_config(self):
        if self.args.loop_mode == 'none':
            return
        if self.args.port_mix != 'none':
            ifg = -1
            if 'real_port' in self.port_mix[self.args.port_mix]:
                port_cfg = self.port_mix[self.args.port_mix]['real_port']
                ifg = port_cfg[0] * 2 + port_cfg[1]
            for index, ifg_swap in enumerate(self.ifg_swap_lists):
                if index == ifg:
                    continue
                for j in range(len(ifg_swap)):
                    self.ifg_swap_lists[index][j] = j

    def create_port_mix_definition(self):
        self.port_mix = {}

        self.port_mix['sherman_4'] = {'real_port': [2, 0, 16, 2, 50], 'loopback_ports': []}
        self.create_port_mix_sherman(self.port_mix['sherman_4'])

        self.port_mix['sherman_5'] = {'real_port': [2, 1, 16, 2, 50], 'loopback_ports': []}
        self.create_port_mix_sherman(self.port_mix['sherman_5'])

    def load_port_mix_from_json(self, port_mix_path):
        self.port_mix['json'] = {'loopback_ports': []}

        with open(port_mix_path, 'r') as fh:
            port_mix_map = json.load(fh)

            if 'external_ports' in port_mix_map:
                real_port_in_port_mix_map = port_mix_map['external_ports'][0]
                speed_val = int(real_port_in_port_mix_map['speed'])
                auto_negotiate = real_port_in_port_mix_map['an'] if 'an' in real_port_in_port_mix_map else False

                self.port_mix['json']['real_port'] = [
                    real_port_in_port_mix_map['slice'],
                    real_port_in_port_mix_map['ifg'],
                    real_port_in_port_mix_map['serdes'],
                    real_port_in_port_mix_map['serdes_count'],
                    speed_val,
                    auto_negotiate]

            for loopback_port in port_mix_map['loopback_ports']:
                slice_list = loopback_port['slice'] if isinstance(loopback_port['slice'], list) else [loopback_port['slice']]
                ifg_list = loopback_port['ifg'] if isinstance(loopback_port['ifg'], list) else [loopback_port['ifg']]
                serdes_list = loopback_port['serdes'] if isinstance(loopback_port['serdes'], list) else [loopback_port['serdes']]
                loopback_port_val = loopback_port
                loopback_port_val['speed'] = eval('sdk.la_mac_port.port_speed_e_E_{}G'.format(int(loopback_port['speed'])))
                loopback_port_val['fc'] = eval('sdk.la_mac_port.fc_mode_e_{}'.format(loopback_port['fc'].upper()))
                loopback_port_val['fec'] = eval('sdk.la_mac_port.fec_mode_e_{}'.format(loopback_port['fec'].upper()))
                loopback_port_val['an'] = loopback_port['an'] if 'an' in loopback_port else False
                loopback_port_val['fabric'] = loopback_port['fabric'] if 'fabric' in loopback_port else False

                for slice in slice_list:
                    for ifg in ifg_list:
                        for serdes in serdes_list:
                            temp_val = loopback_port_val.copy()
                            temp_val['slice'] = slice
                            temp_val['ifg'] = ifg
                            temp_val['serdes'] = serdes
                            self.port_mix['json']['loopback_ports'].append(temp_val)

    def create_port_mix_sherman(self, port_mix_sherman):
        exclude_slice = port_mix_sherman['real_port'][0]
        exclude_ifg = port_mix_sherman['real_port'][1]

        num_serdices_in_port = 8
        port_speed_big = sdk.la_mac_port.port_speed_e_E_400G
        port_speed_2 = sdk.la_mac_port.port_speed_e_E_100G
        if self.matilda_model in ['6.4', '3.2A', '3.2B']:
            num_serdices_in_port = 4
            port_speed_big = sdk.la_mac_port.port_speed_e_E_100G
            port_speed_2 = sdk.la_mac_port.port_speed_e_E_50G

        for slice in self.device.get_used_slices():

            for ifg in range(2):
                for port in range(2):
                    port_mix_sherman['loopback_ports'].append({'slice': slice,
                                                               'ifg': ifg,
                                                               'serdes': port * num_serdices_in_port,
                                                               'serdes_count': num_serdices_in_port,
                                                               'speed': sdk.la_mac_port.port_speed_e_E_400G,
                                                               'p2p_loops': num_serdices_in_port})
                if (slice != exclude_slice) or (ifg != exclude_ifg):
                    port_mix_sherman['loopback_ports'].append(
                        {'slice': slice, 'ifg': ifg, 'serdes': 16, 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_100G, 'p2p_loops': 2})

    def reset(self):
        self.rcy_ports = []
        self.pci_ports = []
        self.voq_sets = []
        self.sys_ports = []
        self.rcy_sys_ports = []
        self.pci_sys_ports = []
        self.eth_ports = []
        self.sys_port_gid = snake_base_topology.SYS_PORT_BASE_GID
        self.ac_ports = []
        self.fabric_ports = []
        self.vrfs = []
        self.nhs = []
        self.prefixes = []
        self.voq_cgm_profiles = []
        self.voq_cgm_profile_ids = [2, 3]
        self.ingress_qos_profile = None
        self.egress_qos_profile = None
        self.voq_allocator = None
        self.device = None
        self.cache = None
        self.total_evict_ports = 0
        self.sockets = NUM_SLICES_PER_DEVICE * [None]

        # Track GID for object types to allow creating next object.
        self.ac_port_gid = snake_base_topology.AC_PORT_BASE_GID
        self.vlan_id = snake_base_topology.BASE_VID1
        self.switch_gid = snake_base_topology.BASE_SWITCH_GID
        # Track the switch objects and ports connected to those switches.
        self.switches = []
        self.switch_ac_ports = []
        self.inject_ac_ports = []
        self.inject_eth_ports = []

        # DST MAC used to create packets to send to different flows.  SRC_MAC we leave the same.
        self.dst_mac = sdk.la_mac_addr_t()
        self.dst_mac.flat = snake_base_topology.DST_MAC_BASE
        self.src_mac = sdk.la_mac_addr_t()
        self.src_mac.flat = snake_base_topology.SRC_MAC
        # Track the MAC addr per sys port
        self.macs_per_sp = {}
        # Keep track of what data flows through what MAC address
        self.traf_per_mac = {}
        self.TRAF_SLICE_IDX = 0
        self.TRAF_IFG_IDX = 1
        self.TRAF_SERDES_IDX = 2
        self.TRAF_PKTS_RECV_IDX = 3
        self.TRAF_PKTS_SENT_IDX = 4
        self.TRAF_PKTS_VALID_IDX = 5
        self.TRAF_PKTS_SIZE_IDX = 6
        self.TRAF_PKTS_DATA_PTRN_IDX = 7
        self.TRAF_FLOW_ID_IDX = 8
        self.set_leaba_module_path()

    def restart_asic_if_required(self):
        script_path = os.environ.get('ASIC_RESTART_SCRIPT', None)
        if script_path is None:
            return
        import subprocess
        rc = subprocess.run(script_path, shell=True)
        assert(rc.returncode == 0)

    def set_slice_mode(self, sid, mode):
        self.device.set_slice_mode(sid, mode)
        self.all_slices_modes[sid] = mode

    def init_matilda_model(self, is_line_card_mode):
        if not decor.is_gibraltar():
            self.matilda_model = 'GB'
            self.matilda_model_hw_t = False
            return None
        eFuse_values = self.device.get_device_int_capabilities()
        eFuse_matilda_value = eFuse_values[self.device.device_int_capability_e_MATILDA_MODEL]

        if eFuse_matilda_value > 0:
            self.matilda_model = decor.matilda_str_to_int(eFuse_matilda_value, reverse=True)
            self.matilda_model_hw_t = True
        else:
            value, hw_t = decor.get_matilda_model_from_env()
            self.matilda_model = value
            self.matilda_model_hw_t = hw_t
            self.device.set_int_property(sdk.la_device_property_e_MATILDA_MODEL_TYPE, decor.matilda_str_to_int(value))

        assert self.matilda_model == 'GB' or is_line_card_mode == False, 'Matilda Models do not support Linecard mode.'

        if self.matilda_model_hw_t:
            # runing in matilda_hw mode - set the device frequency acordingly
            self.args.device_frequency_khz = 900 * 1000
            # self.device.set_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY, 900 * 1000)

    def device_init(self, device_id, device_name, board_cfg_path, hbm, is_line_card_mode):
        self.restart_asic_if_required()
        self.device_id = device_id
        self.device_name = device_name
        self.device = sdk.la_create_device(self.device_name, self.device_id)
        self.device.set_int_property(sdk.la_device_property_e_LPM_REBALANCE_INTERVAL, 10)
        if is_line_card_mode:
            self.device.set_bool_property(sdk.la_device_property_e_ENABLE_PACIFIC_OOB_INTERLEAVING, True)
        if os.getenv('IGNORE_MBIST_ERRORS'):
            self.device.set_bool_property(sdk.la_device_property_e_IGNORE_MBIST_ERRORS, True)

        self.init_matilda_model(is_line_card_mode)

        if self.args.fabric_200g and decor.is_gibraltar():
            self.device.set_fabric_mac_ports_mode(sdk.la_device.fabric_mac_ports_mode_e_E_4x50)

        self.ll_device = self.device.get_ll_device()
        dev_rev = self.ll_device.get_device_revision()
        if dev_rev is lldcli.la_device_revision_e_GRAPHENE_A0:
            self.device.set_bool_property(sdk.la_device_property_e_ENABLE_DUMMY_SERDES_HANDLER, False)
            if self.args.loop_mode != 'info':
                self.device.set_bool_property(sdk.la_device_property_e_ENABLE_INFO_PHY, True)
            self.ll_device.set_shadow_read_enabled(False)
            self.ll_device.set_flush_after_write(True)

        # Use test rom
        if self.args.use_test_rom is not None:
            # use_test_rom is 0xFW_REV_FW_BUILD
            file_name = "res/serdes." + self.args.use_test_rom + ".rom"
            if os.path.isfile(file_name):
                separator = self.args.use_test_rom.rfind('_')
                self.device.set_string_property(sdk.la_device_property_e_SERDES_FW_FILE_NAME, file_name)
                self.device.set_int_property(sdk.la_device_property_e_SERDES_FW_REVISION,
                                             int(self.args.use_test_rom[:separator], 16))
                self.device.set_int_property(sdk.la_device_property_e_SERDES_FW_BUILD,
                                             int(self.args.use_test_rom[separator + 1:], 16))
            else:
                # GB Srm FW: use_test_rom is major.minor.sub.fw_build in decimal
                file_name = "res/srm_fw_" + self.args.use_test_rom + ".txt"
                if os.path.isfile(file_name):
                    self.device.set_string_property(sdk.la_device_property_e_SERDES_FW_FILE_NAME, file_name)
                    print("FW file_name %s" % (file_name))
                    name_list = self.args.use_test_rom.split('.')
                    self.device.set_int_property(sdk.la_device_property_e_SERDES_FW_REVISION,
                                                 int(name_list[1]))
                    self.device.set_int_property(sdk.la_device_property_e_SERDES_FW_BUILD,
                                                 int(name_list[3]))
                    print("FW_REVISION minor %d, FW_BUILD %d" % (int(name_list[1]), int(name_list[3])))

        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_SERDES_LOW_POWER, self.args.serdes_low_power)
        self.device.set_bool_property(
            sdk.la_device_property_e_DISABLE_SERDES_POST_ANLT_TUNE,
            self.args.disable_serdes_post_anlt_tune)

        if self.args.device_frequency_khz is not None:
            self.device.set_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY, self.args.device_frequency_khz)

        if hbm == HBM_MODE_FORCE:
            self.device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM, True)

        self.debug_device = debug.debug_device(self.device)

        dev_rev = self.ll_device.get_device_revision()
        if dev_rev is lldcli.la_device_revision_e_PACIFIC_B0 or dev_rev is lldcli.la_device_revision_e_PACIFIC_B1:
            if self.args.pacific_b0_ifg:
                self.device.set_bool_property(sdk.la_device_property_e_ENABLE_PACIFIC_B0_IFG_CHANGES, True)

        self.pacific_tree = self.ll_device.get_pacific_tree()
        self.gibraltar_tree = self.ll_device.get_gibraltar_tree()

        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)

        self.create_port_mix_definition()

        if hbm != HBM_MODE_DISABLE:
            self.device.set_hbm_pool_max_capacity(0, 0.99)

        self.all_slices_modes = [sdk.la_slice_mode_e_INVALID] * NUM_SLICES_PER_DEVICE
        if is_line_card_mode is False:
            for sid in self.device.get_used_slices():
                self.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)
        else:
            self.device.set_bool_property(sdk.la_device_property_e_LC_FORCE_FORWARD_THROUGH_FABRIC_MODE, True)
            self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)
            for sid in range(3):
                self.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)
                self.set_slice_mode(sid + 3, sdk.la_slice_mode_e_CARRIER_FABRIC)

        if self.args.json_mix is not None:
            self.args.port_mix = 'json'
            self.load_port_mix_from_json(self.args.json_mix)

        if board_cfg_path is not None:
            self.create_board_config()
            self.load_board_config_from_json(board_cfg_path)
            self.modify_board_config()
            self.board_config()

        if self.args.refclk is not None:
            refclk = 0
            for i in range(4):
                if self.args.refclk[i]:
                    refclk |= 0x7 << (3 * i)
            self.device.set_int_property(sdk.la_device_property_e_DEV_REFCLK_SEL, refclk)

        self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

        if is_line_card_mode:
            self.device.set_is_fabric_time_master(True)

        if self.args.cache:
            self.cache = self.device.get_flow_cache_handler()
            self.cache.set_flow_cache_enabled(True)

    def teardown(self):
        if self.device is None:
            self.reset()
            return

        self.close_sockets()

        for vrf in self.vrfs:
            vrf.clear_all_ipv4_routes()
            vrf.clear_all_ipv6_routes()
        for prefix in self.prefixes:
            self.device.destroy(prefix)
        for nh in self.nhs:
            self.device.destroy(nh)
        for ac_port in self.ac_ports:
            if ac_port.type() == ac_port.object_type_e_L2_SERVICE_PORT:
                ac_port.detach()
        for ac_port in self.inject_ac_ports:
            if ac_port.type() == ac_port.object_type_e_L2_SERVICE_PORT:
                ac_port.detach()
            self.device.destroy(ac_port)
        for ac_port in self.ac_ports:
            self.device.destroy(ac_port)
        for switch in self.switches:
            self.device.destroy(switch)
        for vrf in self.vrfs:
            self.device.destroy(vrf)
        for eth_port in self.eth_ports:
            self.device.destroy(eth_port)
        for eth_port in self.inject_eth_ports:
            self.device.destroy(eth_port)
        for sys_port in self.pci_sys_ports:
            self.device.destroy(sys_port)
        for sys_port in self.rcy_sys_ports:
            self.device.destroy(sys_port)
        for sys_port in self.sys_ports:
            self.device.destroy(sys_port)
        for voq_set in self.voq_sets:
            voq_set.set_state(sdk.la_voq_set.state_e_DROPPING)
            self.device.destroy(voq_set)
        for rcy_port in self.rcy_ports:
            self.device.destroy(rcy_port)
        for pci_port in self.pci_ports:
            self.device.destroy(pci_port)
        for fabric_port in self.fabric_ports:
            self.device.destroy(fabric_port)

        if self.ingress_qos_profile is not None:
            self.device.destroy(self.ingress_qos_profile)
        if self.egress_qos_profile is not None:
            self.device.destroy(self.egress_qos_profile)
        self.total_evict_ports = 0

        # TODO: Currently the destroy of tc_profile and ac_profile is not implemented, need to uncomment.
        # self.device.destroy(self.tc_profile)
        # self.device.destroy(self.ac_profile)

        self.mph.teardown()

        self.device.flush()
        sdk.la_destroy_device(self.device)
        self.reset()

    def setup_trap_counters(self):
        self.trap_counters = []
        for trap in range(sdk.LA_EVENT_ETHERNET_FIRST, sdk.LA_EVENT_OAMP_LAST):
            counter = self.device.create_counter(1)
            self.trap_counters.append((counter, trap))
            if trap != sdk.LA_EVENT_L3_DROP_ADJ:
                self.device.set_trap_configuration(trap,
                                                   0,    # priority
                                                   counter,
                                                   None,  # destination
                                                   True,
                                                   False,
                                                   True,
                                                   0)    # tc (don't care)
            else:
                self.device.set_trap_configuration(trap,
                                                   0,    # priority
                                                   counter,
                                                   None,  # destination
                                                   False,
                                                   False,
                                                   True,
                                                   0)    # tc (don't care)

        # Disable these traps so we can circulate packets on the same interface
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SAME_INTERFACE)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

    def print_trap_counter(self):
        trap_names = {}
        tnames = [t for t in dir(sdk) if 'LA_EVENT' in t]
        for t in tnames:
            trap_names[getattr(sdk, t)] = t
        for counter in self.trap_counters:
            print(counter[0].read(0, True, True), trap_names[counter[1]])

    #####################################################################################################
    # HBM work around
    #####################################################################################################
    def get_voq_profile_id(self, slice, voq):
        tree = self.gibraltar_tree
        debug_device = self.debug_device
        data = debug_device.read_memory(tree.slice[slice].pdvoq.voq_properties, voq // 16)
        profile = get_bits(data.profile, (voq % 16) * 8 + 4, (voq % 16) * 8)
        return profile

    # Assume voq_cgm_profile_ids is array of 2 elements, 0 - for non-HBM, 1 - for HBM
    def configure_gb_voq_cgm(self, voq_cgm_profile_ids):
        # Get device mode
        sa_mode = True
        lc_mode = False
        fe_mode = False
        hbm_enable = 1
        debug_device = self.debug_device
        tree = self.gibraltar_tree

        for slice in range(6):
            data = debug_device.read_register(tree.slice[slice].ics.packing_configuration)
            data.max_pds_in_pack = 16
            data.dram_burst_size = 12
            data.dram_buffer_size = 4
            debug_device.write_register(tree.slice[slice].ics.packing_configuration, data)

            data = debug_device.read_register(tree.slice[slice].ics.dram_list_param_reg)
            data.dram_eligible_th_norm = 6144
            data.dram_eligible_th_empty = 8191
            data.num_of_reads_per_dram_buffer = 128
            data.qsize_limit_to_read_it_all = 200000
            data.max_parallel_dram_contexts = 14
            debug_device.write_register(tree.slice[slice].ics.dram_list_param_reg, data)

            data = debug_device.read_register(tree.slice[slice].ics.internal_fifo_alm_full)
            data.dram_pack_fifo_alm_full = 3
            data.dram_delete_fifo_alm_full = 3
            debug_device.write_register(tree.slice[slice].ics.internal_fifo_alm_full, data)

            data = debug_device.read_register(tree.slice[slice].ics.almost_full_cfg)
            data.from_dram_flb_alm_full = 32
            data.from_dram_rlb_alm_full = 32
            data.from_dram_dics_flb_alm_full = 32
            data.from_dram_dics_rlb_alm_full = 32
            debug_device.write_register(tree.slice[slice].ics.almost_full_cfg, data)

        data = debug_device.read_register(tree.dics.credits_conf_reg)
        data.max_qb_threshold = 1024 * 1024
        data.crdt_in_bytes = 2048
        data.crdt_size_log2 = 11
        debug_device.write_register(tree.dics.credits_conf_reg, data)

        data = debug_device.read_register(tree.dics.eligible_th_reg)
        data.eir_slice_blocking_th = 18 * 1024
        data.cir_slice_blocking_th = 18 * 1024
        data.eir_slice_pds_blocking_th = 5
        data.cir_slice_pds_blocking_th = 5
        debug_device.write_register(tree.dics.eligible_th_reg, data)

        debug_device.write_memory(tree.reassembly.debug_pd_field_value_cfg, 0, 1 << 11)
        debug_device.write_memory(tree.reassembly.debug_pd_field_mask_cfg, 0, 1 << 11)
        data = debug_device.read_register(tree.reassembly.debug_pd_field_cfg)
        data.debug_pd_field_slice = 6
        debug_device.write_register(tree.reassembly.debug_pd_field_cfg, data)

        data = debug_device.read_register(self.gibraltar_tree.dvoq.used_bytes_config_register)
        data.size_when_half = 6144
        data.size_when_full = 8192
        debug_device.write_register(self.gibraltar_tree.dvoq.used_bytes_config_register, data)

        debug_device.write_register(self.gibraltar_tree.dics.read_reprt_reg, 12)

        # =================Global Buffers CGM=================
        data = debug_device.read_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg2)
        data.counter_sum_b_e_g_a_ingress_uc_drop_thr = 0x7FFFF
        data.counter_g_ibm_drop_thr = 0x7FFFF
        data.counter_sum_b_e_g_ibm_drop_thr = 0x7FFFF
        data.counter_sum_b_e_g_a_ibm_drop_thr = 0x7FFFF
        debug_device.write_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg2, data)

        data = debug_device.read_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg3)
        data.counter_sum_b_e_g_ingress_mc_drop_thr = 0x7FFFF
        data.counter_sum_b_e_g_a_ingress_mc_drop_thr = 0x7FFFF
        debug_device.write_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg3, data)

        data = debug_device.read_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg4)
        data.counter_e_drop_thr0 = 0x7FFFF
        data.counter_e_drop_thr1 = 0x7FFFF
        data.counter_sum_b_e_g_plb_mc_drop_thr = 0x7FFFF
        data.counter_sum_b_e_g_a_plb_mc_drop_thr = 0x7FFFF
        debug_device.write_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg4, data)

        data = debug_device.read_register(self.gibraltar_tree.tx_cgm_top.total_sch_uc_buffers_th)
        data.total_sch_uc_buffers_drop_th = 0x7FFFF
        data.remote_sch_uc_buffers_drop_th = 0x7FFFF
        data.remote_sch_uc_buffers_fcn_th = 0x7FFFF
        data.local_sch_uc_buffers_drop_th = 0x7FFFF
        debug_device.write_register(self.gibraltar_tree.tx_cgm_top.total_sch_uc_buffers_th, data)

        data = debug_device.read_register(self.gibraltar_tree.ics_top.dram_global_buffer_size_cfg)
        data.dram_global_buffer_size_th = set_bits(0, 19, 0, 20 * 1024)
        data.dram_global_buffer_size_th = set_bits(data.dram_global_buffer_size_th, 39, 20, 45 * 1024)
        data.dram_global_buffer_size_th = set_bits(data.dram_global_buffer_size_th, 59, 40, 60 * 1024)
        debug_device.write_register(self.gibraltar_tree.ics_top.dram_global_buffer_size_cfg, data)

        data = debug_device.read_register(self.gibraltar_tree.ics_top.dram_context_pool_alm_empty)
        data.dram_context_pool_alm_empty_th = 500
        debug_device.write_register(self.gibraltar_tree.ics_top.dram_context_pool_alm_empty, data)

        data = debug_device.read_register(self.gibraltar_tree.dram_cgm.time_control_cfg)
        data.count_enable = 1
        data.cycle_count = 4095
        debug_device.write_register(self.gibraltar_tree.dram_cgm.time_control_cfg, data)

        debug_device.write_register(self.gibraltar_tree.dram_cgm.initial_config_values, 1000000)
        debug_device.write_register(self.gibraltar_tree.dram_cgm.initial_config_pool_values[0], 1000000)

        if sa_mode:
            data = debug_device.read_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg1)
            data.voq_cgm_counter_a_thr0 = 144 * 1024
            data.voq_cgm_counter_a_thr1 = 188 * 1024
            data.voq_cgm_counter_a_thr2 = 206 * 1024
            debug_device.write_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg1, data)

            data = debug_device.read_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg2)
            data.counter_a_drop_thr0 = 216 * 1024
            data.counter_a_drop_thr1 = 226 * 1024
            debug_device.write_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg2, data)

            data = debug_device.read_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg3)
            data.counter_b_drop_thr0 = 20 * 1024
            data.counter_b_drop_thr1 = 25 * 1024
            debug_device.write_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg3, data)

            data = debug_device.read_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg4)
            data.counter_sum_b_e_txcgm_drop_thr0 = 10 * 1024
            data.counter_sum_b_e_txcgm_drop_thr1 = 15 * 1024
            data.counter_sum_b_e_txcgm_drop_thr2 = 18 * 1024
            debug_device.write_register(self.gibraltar_tree.rx_pdr.counters_thresholds_reg4, data)

            data = debug_device.read_register(self.gibraltar_tree.tx_cgm_top.total_sch_uc_buffers_th)
            data.total_sch_uc_buffers_fc_th = 32 * 1024
            debug_device.write_register(self.gibraltar_tree.tx_cgm_top.total_sch_uc_buffers_th, data)

        # =================Global PDs CGM=================
        if sa_mode:
            data = debug_device.read_register(self.gibraltar_tree.pdvoq_shared_mma.cgm_thresholds)
            data.uc_th = 130 * 1024
            data.mc_th = 10 * 1024
            debug_device.write_register(self.gibraltar_tree.pdvoq_shared_mma.cgm_thresholds, data)

            data = debug_device.read_register(self.gibraltar_tree.pdvoq_shared_mma.cgm_pool_available_region)
            data.uc_region0 = 10 * 1024
            debug_device.write_register(self.gibraltar_tree.pdvoq_shared_mma.cgm_pool_available_region, data)

            data = debug_device.read_register(self.gibraltar_tree.tx_cgm_top.total_sch_uc_pd_th)
            data.total_sch_uc_pds_fc_th = 24 * 1024
            data.total_sch_uc_pds_drop_th = 0xFFFF
            debug_device.write_register(self.gibraltar_tree.tx_cgm_top.total_sch_uc_pd_th, data)

            data = debug_device.read_register(self.gibraltar_tree.tx_cgm_top.total_mc_pd_th)
            data.total_mc_pds_drop_th = 24 * 1024
            data.total_mc_pds_status_th0 = 12 * 1024
            data.total_mc_pds_status_th1 = 18 * 1024
            data.total_mc_pds_status_th2 = 22 * 1024
            debug_device.write_register(self.gibraltar_tree.tx_cgm_top.total_mc_pd_th, data)

        # =================Individual VOQ CGM with HBM=================
        # Clean the memory
        for profile in range(2):
            for counter_a in range(4):
                for buffer_size in range(16):
                    for time_region in range(16):
                        self.gibraltar_set_voq_cgm_buff_decision(slice, profile, counter_a, buffer_size, time_region, 0, 0, 0, 0, 0)

        end_slice = 6
        for slice in range(end_slice):
            # SMS buffers
            for profile in range(32):
                if (profile == voq_cgm_profile_ids[1]):
                    self.gibraltar_set_voq_cgm_buff_ranges(slice, profile, 50, 256, 512, 1024, 2048, 3000, 6000,
                                                           7000, 8000, 9000, 10000, 12000, 14000, 15000, 16000)
                    self.gibraltar_set_voq_cgm_time_ranges(
                        slice, profile, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 255)
                    for counter_a in range(4):
                        for buffer_size in range(16):
                            for time_region in range(16):
                                if (counter_a < 3):  # FORCE EVICTION
                                    self.gibraltar_set_voq_cgm_buff_decision(
                                        slice, profile, counter_a, buffer_size, time_region, 0, 0, 1, 0, 0)
                                    '''
                                    self.gibraltar_set_voq_cgm_buff_decision(
                                        slice, profile, counter_a, buffer_size, time_region, 7, 7, 0, 0, 0)
                                    '''
                                if (counter_a == 3):  # above 206/214K buffers
                                    if (buffer_size >= 1 and time_region >= 1):  # 50 buffers and 16us -> drop
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 7, 7, 0, 0, 0)
                                    if (buffer_size == 15):  # 16000 buffers -> drop
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 7, 7, 0, 0, 0)
            # SMS PDs
            # Clean the decision memory
            for i in range(1024):
                debug_device.write_memory(self.gibraltar_tree.slice[slice].pdvoq.pd_consumption_lut_for_enq, i, 0)
            for profile in range(32):
                if (profile == voq_cgm_profile_ids[1]):
                    self.gibraltar_set_voq_cgm_pkt_ranges(slice, profile, 50, 1500, 12000, 13000, 14000, 15000, 16100)
                    if (profile == 0):  # drop - part of SDK init
                        pass
                    elif (profile == 1):  # MC
                        for total_uc_pd in range(4):
                            for pd_size in range(8):
                                if (pd_size >= 2):  # drop at 1500 PDs
                                    addr = set_bits(0, 9, 5, profile)
                                    addr = set_bits(addr, 4, 3, total_uc_pd)
                                    addr = set_bits(addr, 2, 0, pd_size)
                                    debug_device.write_memory(
                                        self.gibraltar_tree.slice[slice].pdvoq.pd_consumption_lut_for_enq, addr, 0xFFFFFFFF)
                    else:  # UC
                        for total_uc_pd in range(4):
                            for pd_size in range(8):
                                addr = set_bits(0, 9, 5, profile)
                                addr = set_bits(addr, 4, 3, total_uc_pd)
                                addr = set_bits(addr, 2, 0, pd_size)
                                # above 120K PDs and PD size above 50 and time > 16us -> drop
                                if (total_uc_pd == 0 and pd_size > 0):
                                    debug_device.write_memory(
                                        self.gibraltar_tree.slice[slice].pdvoq.pd_consumption_lut_for_enq, addr, 0xFFFEFFFE)
                                if (pd_size == 7):
                                    debug_device.write_memory(
                                        self.gibraltar_tree.slice[slice].pdvoq.pd_consumption_lut_for_enq, addr, 0xFFFFFFFF)

            # Evicted SMS buffers
            for total_evicted_buffers in range(4):
                for evicted_profile in range(4):
                    for counter_a in range(4):
                        for buffer_size in range(16):
                            addr = set_bits(0, 9, 8, total_evicted_buffers)
                            addr = set_bits(addr, 7, 6, evicted_profile)
                            addr = set_bits(addr, 5, 4, counter_a)
                            addr = set_bits(addr, 3, 0, buffer_size)
                            debug_device.write_memory(
                                self.gibraltar_tree.slice[slice].pdvoq.evicted_buffers_consumption_lut, addr, 0)
                            data = debug_device.read_memory(
                                self.gibraltar_tree.slice[slice].pdvoq.evicted_buffers_consumption_lut, addr)
                            if (counter_a == 0):  # below 144K buffers
                                if (total_evicted_buffers < 3):  # below 60K
                                    pass
                                else:  # above 60K
                                    if (buffer_size >= 5):  # VOQ > 2K buffers
                                        data.drop_green = 1
                                    if (buffer_size >= 4):  # VOQ > 1K buffers
                                        data.drop_yellow = 1
                            elif (counter_a < 3):  # below 206/214K buffers
                                if (total_evicted_buffers < 2):  # below 45K
                                    pass
                                elif (total_evicted_buffers == 2):  # below 60K
                                    if (buffer_size >= 5):  # VOQ > 2K buffers
                                        data.drop_green = 1
                                    if (buffer_size >= 4):  # VOQ > 1K buffers
                                        data.drop_yellow = 1
                                else:  # above 60K
                                    data.drop_green = 1
                                    data.drop_yellow = 1
                            else:  # above 206/214K buffers
                                if (total_evicted_buffers == 0):  # below 20K
                                    pass
                                elif (total_evicted_buffers == 1):  # below 45K
                                    if (buffer_size >= 4):  # VOQ > 1K buffers
                                        data.drop_green = 1
                                    if (buffer_size >= 3):  # VOQ > 512 buffers
                                        data.drop_yellow = 1
                                else:  # above 45K
                                    data.drop_green = 1
                                    data.drop_yellow = 1
                            debug_device.write_memory(
                                self.gibraltar_tree.slice[slice].pdvoq.evicted_buffers_consumption_lut, addr, data)

            # Evicted OK lut (new VOQ eviction)
            for profile in range(32):
                for free_dram_contexts in range(2):
                    for total_evicted_buffers in range(4):
                        addr = set_bits(0, 7, 6, total_evicted_buffers)
                        addr = set_bits(addr, 5, 5, free_dram_contexts)
                        addr = set_bits(addr, 4, 0, profile)
                        data = debug_device.read_memory(self.gibraltar_tree.slice[slice].pdvoq.evicted_ok_lut, addr)
                        data.drop_on_eviction = 0
                        if (free_dram_contexts == 1):  # num of DRAM Qs > 3500 -> avoid eviction
                            data.eviction_ok = 0
                        else:
                            if (total_evicted_buffers < 2):  # total evicted < 20K -> allow eviction
                                data.eviction_ok = 1
                            else:  # total evicted > 20K -> avoid eviction
                                data.eviction_ok = 0
                        debug_device.write_memory(self.gibraltar_tree.slice[slice].pdvoq.evicted_ok_lut, addr, data)

        # DRAM CGM
        queue_size_th = [100, 1 * 1024, 2 * 1024, 4 * 1024, 6 * 1024, 8 * 1024, 12 *
                         1024, 16 * 1024, 24 * 1024, 32 * 1024, 40 * 1024, 48 * 1024, 56 * 1024, 60 * 1024, 64000]
        shared_pool0_th = [990000, 980000, 960000, 930000, 875000, 750000, 500000]
        queue_delay_th_ms = [1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 24, 32, 64, 128]
        data = debug_device.read_register(self.gibraltar_tree.dram_cgm.quant_thresholds)
        time_data = debug_device.read_register(self.gibraltar_tree.dram_cgm.time_control_cfg)
        for i in range(15):
            queue_size_th_m = queue_size_th[i] // 16
            data.queue_size_th = set_bits(data.queue_size_th, i * 15 + 14, i * 15, queue_size_th_m)
        for i in range(7):
            shared_pool0_th_m = (1000000 - shared_pool0_th[i]) // 16
            data.shared_pool0_th = set_bits(data.shared_pool0_th, i * 16 + 15, i * 16, shared_pool0_th_m)
        for i in range(15):
            queue_delay_th = int(1000000 * queue_delay_th_ms[i] / (time_data.cycle_count /
                                                                   (self.device.get_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY) / 1000)))
            data.queue_age_th = set_bits(data.queue_age_th, i * 20 + 19, i * 20, queue_delay_th)
        debug_device.write_register(self.gibraltar_tree.dram_cgm.quant_thresholds, data)
        for profile in range(32):
            for queue_size in range(16):
                for dram_delay in range(16):
                    for shared_pool_size in range(8):
                        # set "VOQ-is-evicted" indication
                        # set_dram_cgm_lut(profile, queue_size, dram_delay, shared_pool_size, -1, -1, -1, 1, -1, -1)
                        if (queue_size > 0):
                            self.gibraltar_set_dram_cgm_lut(
                                profile, queue_size, dram_delay, shared_pool_size, -1, -1, -1, 1, -1, -1)
                        # 500K buffers and above 32ms or 64K buffers
                        if (((shared_pool_size == 7) and ((queue_size > 0 and dram_delay >= 13) or (queue_size == 15))) or
                            # 750K buffers and above 16ms or 32K buffers
                            ((shared_pool_size == 6) and ((queue_size > 0 and dram_delay >= 11) or (queue_size >= 10))) or
                            # 875K buffers and above 12ms or 16K buffers
                            ((shared_pool_size == 5) and ((queue_size > 0 and dram_delay >= 10) or (queue_size >= 8))) or
                            # 930K buffers and above  8ms or  8K buffers
                            ((shared_pool_size == 4) and ((queue_size > 0 and dram_delay >= 8) or (queue_size >= 6))) or
                            # 960K buffers and above  6ms or  4K buffers
                            ((shared_pool_size == 3) and ((queue_size > 0 and dram_delay >= 6) or (queue_size >= 4))) or
                            # 980K buffers and above  3ms or  2K buffers
                            ((shared_pool_size == 2) and ((queue_size > 0 and dram_delay >= 3) or (queue_size >= 3))) or
                            # 990K buffers and above  1ms or  1K buffers
                                ((shared_pool_size < 2) and ((queue_size > 0 and dram_delay >= 1) or (queue_size >= 2)))):
                            self.gibraltar_set_dram_cgm_lut(profile, queue_size, dram_delay, shared_pool_size, 1, 1)
                        if (queue_size == 15 and dram_delay >= 14):  # 64K buffers and 64ms -> force Q out
                            self.gibraltar_set_dram_cgm_lut(
                                profile, queue_size, dram_delay, shared_pool_size, -1, -1, -1, -1, 1, -1)

        # =================Individual VOQ CGM without HBM=================
        end_slice = 6
        for slice in range(end_slice):
            # SMS buffers
            for profile in range(32):
                if (profile == voq_cgm_profile_ids[0]):
                    self.gibraltar_set_voq_cgm_buff_ranges(slice, profile, 50, 256, 512, 1024, 2048, 3000, 6000,
                                                           7000, 8000, 9000, 10000, 12000, 14000, 15000, 16000)
                    self.gibraltar_set_voq_cgm_time_ranges(
                        slice, profile, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 255)
                    for counter_a in range(4):
                        for buffer_size in range(16):
                            for time_region in range(16):
                                if (counter_a == 0):  # below 144K buffers
                                    if (buffer_size == 12):  # 12000 buffers drop 1:100, mark 1:20
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 1, 1, 0, 1, 1)
                                    if (buffer_size == 13):  # 14000 buffers drop 1:20, mark 1:10
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 2, 2, 0, 2, 2)
                                    if (buffer_size == 14):  # 15000 buffers drop 1:10, mark 1:1
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 3, 3, 0, 3, 3)
                                    if (buffer_size == 15):  # 16000 buffers drop
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 7, 7, 0, 0, 0)
                                if (counter_a == 1):  # below 184K buffers
                                    # 50 buffers,255us - drop green 1:100,drop yellow 1:20,mark green 1:20,mark yellow 1:10
                                    if (buffer_size > 0 and buffer_size < 12 and time_region == 15):
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 1, 2, 0, 1, 2)
                                    if (buffer_size == 12):  # 12000 buffers drop 1:100, mark 1:20
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 1, 1, 0, 1, 1)
                                    if (buffer_size == 13):  # 14000 buffers drop 1:20, mark 1:10
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 2, 2, 0, 2, 2)
                                    if (buffer_size == 14):  # 15000 buffers drop 1:10, mark 1:1
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 3, 3, 0, 3, 3)
                                    if (buffer_size == 15):  # 16000 buffers drop
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 7, 7, 0, 0, 0)
                                if (counter_a == 2):  # below 206K buffers
                                    # 50 buffers, 128us - drop green 1:20,drop yellow 1:10,mark green 1:10,mark yellow 1:1
                                    if (buffer_size > 0 and buffer_size < 13 and time_region >= 8):
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 2, 3, 0, 2, 3)
                                    if (buffer_size == 12 and time_region < 8):  # 12000 buffers drop 1:100, mark 1:20
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 1, 1, 0, 1, 1)
                                    if (buffer_size == 13):  # 14000 buffers drop 1:20, mark 1:10
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 2, 2, 0, 2, 2)
                                    if (buffer_size == 14):  # 15000 buffers drop 1:10, mark 1:1
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 3, 3, 0, 3, 3)
                                    if (buffer_size == 15):  # 16000 buffers drop
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 7, 7, 0, 0, 0)
                                if (counter_a == 3):  # above 206/214K buffers
                                    if (buffer_size >= 1 and time_region >= 1):  # 50 buffers and 16us -> drop
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 7, 7, 0, 0, 0)
                                    if (buffer_size == 15):  # 16000 buffers -> drop
                                        self.gibraltar_set_voq_cgm_buff_decision(
                                            slice, profile, counter_a, buffer_size, time_region, 7, 7, 0, 0, 0)
            # SMS PDs
            # Clean the decision memory
            for i in range(1024):
                debug_device.write_memory(self.gibraltar_tree.slice[slice].pdvoq.pd_consumption_lut_for_enq, i, 0)
            for profile in range(32):
                self.gibraltar_set_voq_cgm_pkt_ranges(slice, profile, 50, 1500, 12000, 13000, 14000, 15000, 16100)
                if (profile == 0):  # drop - part of SDK init
                    pass
                elif (profile == 1):  # MC
                    for total_uc_pd in range(4):
                        for pd_size in range(8):
                            if (pd_size >= 2):  # drop at 1500 PDs
                                addr = set_bits(0, 9, 5, profile)
                                addr = set_bits(addr, 4, 3, total_uc_pd)
                                addr = set_bits(addr, 2, 0, pd_size)
                                debug_device.write_memory(
                                    self.gibraltar_tree.slice[slice].pdvoq.pd_consumption_lut_for_enq, addr, 0xFFFFFFFF)
                else:  # UC
                    for total_uc_pd in range(4):
                        for pd_size in range(8):
                            addr = set_bits(0, 9, 5, profile)
                            addr = set_bits(addr, 4, 3, total_uc_pd)
                            addr = set_bits(addr, 2, 0, pd_size)
                            # above 120K PDs and PD size above 50 and time > 16us -> drop
                            if (total_uc_pd == 0 and pd_size > 0):
                                debug_device.write_memory(
                                    self.gibraltar_tree.slice[slice].pdvoq.pd_consumption_lut_for_enq, addr, 0xFFFEFFFE)
                            if (pd_size == 7):
                                debug_device.write_memory(
                                    self.gibraltar_tree.slice[slice].pdvoq.pd_consumption_lut_for_enq, addr, 0xFFFFFFFF)

    def force_hbm_evict(self):
        if self.ll_device.is_pacific():
            return self.pacific_force_hbm_evict()
        else:
            return self.gibraltar_force_hbm_evict()

        # return self.configure_gb_voq_cgm(self.voq_cgm_profile_ids)

    # TODO Need to chose between force_hbm_evict_gb or gibraltar_force_hbm_evict
    def force_hbm_evict_gb(self):
        # // For HBM VOQs
        # Profile to evict only under congestion
        voq_cgm_p = self.voq_cgm_profiles[0]
        bytes_thresholds = sdk.sms_bytes_quantization_thresholds()
        bytes_thresholds.thresholds = [162000, 163000, 164000, 490000, 491000, 492000, 599040]
        voq_cgm_p.set_sms_bytes_quantization(bytes_thresholds)

        max_buffer_pool_available_level = self.device.get_limit(
            sdk.limit_type_e_VOQ_CGM_PROFILE__SMS_NUM_BYTES_POOL_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        max_buffer_voq_size_level = self.device.get_limit(
            sdk.limit_type_e_VOQ_CGM_PROFILE__SMS_NUM_BYTES_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        max_age = self.device.get_limit(sdk.limit_type_e_VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS)

        for buffer_pool_available_level in range(max_buffer_pool_available_level):
            for buffer_voq_size_level in range(max_buffer_voq_size_level):
                evict = True
                if buffer_voq_size_level < max_buffer_voq_size_level / 2:
                    evict = False
                for age in range(max_age):
                    for color in range(2):
                        key = sdk.la_voq_sms_size_in_bytes_color_key(buffer_pool_available_level, buffer_voq_size_level, age, color)
                        val = sdk.la_voq_sms_size_in_bytes_evict_val(evict)
                        voq_cgm_profile.set_sms_size_in_bytes_evict_behavior(key, val)

        # Profile to evict all traffic to HBM
        hbm_profile = self.voq_cgm_profiles[1]
        bytes_thresholds = sdk.sms_bytes_quantization_thresholds()
        bytes_thresholds.thresholds = [400, 400, 400, 400, 400, 800, 599040]
        hbm_profile.set_sms_bytes_quantization(bytes_thresholds)

        # Configure thresholds to cause eviction
        for total_byte_region in range(4):
            for age in range(16):
                for byte_region in range(7):
                    if byte_region < 6:
                        evict = False
                    else:
                        evict = True
                    for region in range(2):
                        hbm_profile.set_sms_size_in_bytes_behavior(
                            total_byte_region, byte_region, age, region, sdk.la_qos_color_e_RED, False, evict)

        for profile in [voq_cgm_p, hbm_profile]:
            voq_cgm_p.set_associated_hbm_pool(0)
            for region in range(13):
                for queue in range(8):
                    voq_cgm_p.set_hbm_size_in_blocks_behavior(region, queue, sdk.la_qos_color_e_RED, False)
            for region in range(2):
                for queue in range(8):
                    voq_cgm_p.set_hbm_size_in_blocks_behavior(region + 13, queue, sdk.la_qos_color_e_GREEN, True)

        # Device global CGM configurations
        HBM_GRANULARITY = 16
        hbm_pool_free_blocks = sdk.la_cgm_hbm_pool_free_blocks_quantization_thresholds()
        tmp_lst = []
        for i in range(7):
            tmp_lst.append((9000 + i) * HBM_GRANULARITY)  # values are taken from validation

        hbm_pool_free_blocks.thresholds = tmp_lst
        self.device.set_cgm_hbm_pool_free_blocks_quantization(0, hbm_pool_free_blocks)
        self.device.set_cgm_hbm_pool_free_blocks_quantization(1, hbm_pool_free_blocks)

        hbm_blocks = sdk.la_cgm_hbm_blocks_by_voq_quantization_thresholds()
        tmp_lst = []
        for i in range(15):
            tmp_lst.append((50 + i) * HBM_GRANULARITY)  # values are taken from validation

        hbm_blocks.thresholds = tmp_lst
        self.device.set_cgm_hbm_blocks_by_voq_quantization(hbm_blocks)

        # In pacific 134 contexts are prefetched to the slices, so they are out of the main pool and seems busy.
        # Therefore, to evict 15 VOQs to the HBM the following confiration is neede.
        hbm_num_voqs = sdk.la_cgm_hbm_number_of_voqs_quantization_thresholds()
        hbm_num_voqs.thresholds = [149]
        self.device.set_cgm_hbm_number_of_voqs_quantization(hbm_num_voqs)

    # TODO Need to chose between force_hbm_evict_gb or gibraltar_force_hbm_evict
    def gibraltar_force_hbm_evict(self):
        # Naive eviction setting on 3K buffers
        for slice in range(6):
            for profile in range(1, 32):
                for counter_a in range(3):
                    for buffer_size in range(0, 16):
                        for time_region in range(16):
                            self.gibraltar_set_voq_cgm_buff_decision(
                                slice, profile, counter_a, buffer_size, time_region, -1, -1, 1, -1, -1)

        # Allow eviction
        for slice in range(6):
            for i in range(1024):
                data = self.debug_device.read_memory(self.gibraltar_tree.slice[slice].pdvoq.evicted_ok_lut, i)
                data.eviction_ok = 1
                data.drop_on_eviction = 0
                self.debug_device.write_memory(self.gibraltar_tree.slice[slice].pdvoq.evicted_ok_lut, i, data)

        # Set basic DRAM CGM
        self.debug_device.write_register(self.gibraltar_tree.dram_cgm.initial_config_pool_values[0], 1000000)
        for profile in range(32):
            for queue_size in range(16):
                for dram_delay in range(16):
                    for shared_pool_size in range(8):
                        if (queue_size >= 8):  # Queue larger than 32K buffers
                            self.gibraltar_set_dram_cgm_lut(profile, queue_size, dram_delay, shared_pool_size, 1, 1)

    def gibraltar_set_voq_cgm_time_ranges(self, slice, profile, th0, th1, th2, th3, th4, th5,
                                          th6, th7, th8, th9, th10, th11, th12, th13, th14):
        tree = self.gibraltar_tree
        debug_device = self.debug_device
        data = debug_device.read_memory(tree.slice[slice].pdvoq.profile_pkt_enq_time_region_thresholds, profile)
        data.pkt_enq_time_region = 0
        th_list = [th0, th1, th2, th3, th4, th5, th6, th7, th8, th9, th10, th11, th12, th13, th14]
        for i in range(15):
            data.pkt_enq_time_region = set_bits(data.pkt_enq_time_region, i * 8 + 7, i * 8, th_list[i])
        debug_device.write_memory(tree.slice[slice].pdvoq.profile_pkt_enq_time_region_thresholds, profile, data)

    def gibraltar_set_voq_cgm_pkt_ranges(self, slice, profile, th0, th1, th2, th3, th4, th5, th6):
        tree = self.gibraltar_tree
        debug_device = self.debug_device
        data = debug_device.read_memory(tree.slice[slice].pdvoq.profile_pkt_region_thresholds, profile)
        data.qsize_pkt_region = 0
        th_list = [th0, th1, th2, th3, th4, th5, th6]
        for i in range(7):
            data.qsize_pkt_region = set_bits(data.qsize_pkt_region, i * 14 + 13, i * 14, th_list[i])
        debug_device.write_memory(tree.slice[slice].pdvoq.profile_pkt_region_thresholds, profile, data)

    def gibraltar_set_voq_cgm_buff_ranges(self, slice, profile, th0, th1, th2, th3, th4, th5,
                                          th6, th7, th8, th9, th10, th11, th12, th13, th14):
        tree = self.gibraltar_tree
        debug_device = self.debug_device
        data = debug_device.read_memory(tree.slice[slice].pdvoq.profile_buff_region_thresholds, profile)
        data.qsize_buff_region = 0
        th_list = [th0, th1, th2, th3, th4, th5, th6, th7, th8, th9, th10, th11, th12, th13, th14]
        for i in range(15):
            data.qsize_buff_region = set_bits(data.qsize_buff_region, i * 14 + 13, i * 14, th_list[i])
            # lb_note("set_voq_cgm_buff_ranges range = %0d, value = %0d" %(i,get_bits(data.qsize_buff_region, i*14+13, i*14)))
        debug_device.write_memory(tree.slice[slice].pdvoq.profile_buff_region_thresholds, profile, data)

    def gibraltar_set_voq_cgm_buff_decision(
            self,
            slice,
            profile,
            counter_a,
            buffer_size,
            time_region,
            drop_green_prob=-1,
            drop_yellow_prob=-1,
            evict=-1,
            mark_green=-1,
            mark_yellow=-1):
        tree = self.gibraltar_tree
        debug_device = self.debug_device
        addr = 0
        addr = set_bits(addr, 10, 6, profile)
        addr = set_bits(addr, 5, 4, counter_a)
        addr = set_bits(addr, 3, 0, buffer_size)
        data = debug_device.read_memory(tree.slice[slice].pdvoq.buffers_consumption_lut_for_enq, addr)
        if (drop_green_prob != -1):
            data.drop_green = set_bits(data.drop_green, 3 * time_region + 2, 3 * time_region, drop_green_prob)
        if (drop_yellow_prob != -1):
            data.drop_yellow = set_bits(data.drop_yellow, 3 * time_region + 2, 3 * time_region, drop_yellow_prob)
        if (evict != -1):
            data.evict_to_dram = set_bits(data.evict_to_dram, time_region, time_region, evict)
        if (mark_green != -1):
            data.mark_green = set_bits(data.mark_green, time_region, time_region, mark_green)
        if (mark_yellow != -1):
            data.mark_yellow = set_bits(data.mark_yellow, time_region, time_region, mark_yellow)
        debug_device.write_memory(tree.slice[slice].pdvoq.buffers_consumption_lut_for_enq, addr, data)

    def gibraltar_set_dram_cgm_lut(
            self,
            profile,
            queue_size,
            dram_delay,
            shared_pool_size,
            drop_green=-1,
            drop_yellow=-1,
            mark_green=-1,
            mark_yellow=-1,
            set_aging=-1,
            clr_aging=-1):
        tree = self.gibraltar_tree
        debug_device = self.debug_device
        addr = 0
        addr = set_bits(addr, 12, 8, profile)
        addr = set_bits(addr, 7, 4, queue_size)
        addr = set_bits(addr, 3, 0, dram_delay)
        data = debug_device.read_memory(tree.dram_cgm.cgm_lut, addr)
        if (drop_green != -1):
            data.cgm_lut_result = set_bits(data.cgm_lut_result, 6 * shared_pool_size + 4, 6 * shared_pool_size + 4, drop_green)
        if (drop_yellow != -1):
            data.cgm_lut_result = set_bits(data.cgm_lut_result, 6 * shared_pool_size + 5, 6 * shared_pool_size + 5, drop_yellow)
        if (mark_green != -1):
            data.cgm_lut_result = set_bits(data.cgm_lut_result, 6 * shared_pool_size + 2, 6 * shared_pool_size + 2, mark_green)
        if (mark_yellow != -1):
            data.cgm_lut_result = set_bits(data.cgm_lut_result, 6 * shared_pool_size + 3, 6 * shared_pool_size + 3, mark_yellow)
        if (set_aging != -1):
            data.cgm_lut_result = set_bits(data.cgm_lut_result, 6 * shared_pool_size + 1, 6 * shared_pool_size + 1, set_aging)
        if (clr_aging != -1):
            data.cgm_lut_result = set_bits(data.cgm_lut_result, 6 * shared_pool_size + 0, 6 * shared_pool_size + 0, clr_aging)
        debug_device.write_memory(tree.dram_cgm.cgm_lut, addr, data)

    def pacific_force_hbm_evict(self):
        # // For HBM VOQs
        # Profile to evict only under congestion
        voq_cgm_p = self.voq_cgm_profiles[0]
        bytes_thresholds = sdk.sms_bytes_quantization_thresholds()
        bytes_thresholds.thresholds = [162000, 163000, 164000, 490000, 491000, 492000, 599040]
        voq_cgm_p.set_sms_bytes_quantization(bytes_thresholds)

        # Configure thresholds to cause eviction
        for total_byte_region in range(4):
            for age in range(16):
                for byte_region in range(7):
                    evict = True
                    if byte_region < 4:
                        evict = False
                    # Evict VOQs to HBM when number of free HBM contexts is above threshold.
                    num_of_voqs_in_hbm_region = [False, evict]
                    for region in range(len(num_of_voqs_in_hbm_region)):
                        voq_cgm_p.set_sms_size_in_bytes_behavior(
                            total_byte_region,
                            byte_region,
                            age,
                            region,
                            sdk.la_qos_color_e_RED,
                            False,
                            num_of_voqs_in_hbm_region[region])

        # Profile to evict all traffic to HBM
        hbm_profile = self.voq_cgm_profiles[1]
        bytes_thresholds = sdk.sms_bytes_quantization_thresholds()
        bytes_thresholds.thresholds = [400, 400, 400, 400, 400, 800, 599040]
        hbm_profile.set_sms_bytes_quantization(bytes_thresholds)

        # Configure thresholds to cause eviction
        for total_byte_region in range(4):
            for age in range(16):
                for byte_region in range(7):
                    if byte_region < 6:
                        evict = False
                    else:
                        evict = True
                    for region in range(2):
                        hbm_profile.set_sms_size_in_bytes_behavior(
                            total_byte_region, byte_region, age, region, sdk.la_qos_color_e_RED, False, evict)

        for profile in [voq_cgm_p, hbm_profile]:
            voq_cgm_p.set_associated_hbm_pool(0)
            for region in range(13):
                for queue in range(8):
                    voq_cgm_p.set_hbm_size_in_blocks_behavior(region, queue, sdk.la_qos_color_e_RED, False)
            for region in range(2):
                for queue in range(8):
                    voq_cgm_p.set_hbm_size_in_blocks_behavior(region + 13, queue, sdk.la_qos_color_e_GREEN, True)

        # Device global CGM configurations
        HBM_GRANULARITY = 16
        hbm_pool_free_blocks = sdk.la_cgm_hbm_pool_free_blocks_quantization_thresholds()
        tmp_lst = []
        for i in range(7):
            tmp_lst.append((9000 + i) * HBM_GRANULARITY)  # values are taken from validation

        hbm_pool_free_blocks.thresholds = tmp_lst
        self.device.set_cgm_hbm_pool_free_blocks_quantization(0, hbm_pool_free_blocks)
        self.device.set_cgm_hbm_pool_free_blocks_quantization(1, hbm_pool_free_blocks)

        hbm_blocks = sdk.la_cgm_hbm_blocks_by_voq_quantization_thresholds()
        tmp_lst = []
        for i in range(15):
            tmp_lst.append((50 + i) * HBM_GRANULARITY)  # values are taken from validation

        hbm_blocks.thresholds = tmp_lst
        self.device.set_cgm_hbm_blocks_by_voq_quantization(hbm_blocks)

        # In pacific 134 contexts are prefetched to the slices, so they are out of the main pool and seems busy.
        # Therefore, to evict 15 VOQs to the HBM the following confiration is neede.
        hbm_num_voqs = sdk.la_cgm_hbm_number_of_voqs_quantization_thresholds()
        hbm_num_voqs.thresholds = [149]
        self.device.set_cgm_hbm_number_of_voqs_quantization(hbm_num_voqs)

    def set_sch_shaper(self, slice, ifg, serdes, rate_in_gbps, cir=-1):
        val = self.debug_device.read_register(self.debug_device.device_tree.slice[slice].ics.credits_conf_reg)
        credit_value = val.crdt_in_bytes
        if (rate_in_gbps == 0):
            value = 0
        else:
            frequency_ghz = self.device.get_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY) / 1000000
            value = int(frequency_ghz * 16 * 8 * credit_value / rate_in_gbps)
            if (value > (256 * 1024 - 1)):
                value = (256 * 1024 - 1)
        sch = self.debug_device.device_tree.slice[slice].ifg[ifg].sch
        if (cir == 1):  # CIR
            self.ll_device.write_register(sch.ifse_cir_shaper_rate_configuration[serdes], value)
        elif (cir == 0):  # PIR
            self.ll_device.write_register(sch.ifse_pir_shaper_configuration[serdes], value)
        else:  # Both
            self.ll_device.write_register(sch.ifse_cir_shaper_rate_configuration[serdes], value)
            self.ll_device.write_register(sch.ifse_pir_shaper_configuration[serdes], value)

    def get_sch_shaper(self, slice, ifg, serdes, cir=1):
        val = self.debug_device.read_register(self.debug_device.device_tree.slice[slice].ics.credits_conf_reg)
        credit_value = val.crdt_in_bytes
        if (cir == 1):  # CIR
            val = self.ll_device.read_register(
                self.debug_device.device_tree.slice[slice].ifg[ifg].sch.ifse_cir_shaper_rate_configuration[serdes])
        else:  # PIR
            val = self.ll_device.read_register(
                self.debug_device.device_tree.slice[slice].ifg[ifg].sch.ifse_pir_shaper_configuration[serdes])
        if (val != 0):
            frequency_ghz = self.device.get_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY) / 1000000
            val = (frequency_ghz * 16 * 8 * credit_value) / val
        return val

    ###########################
    # Read counters after test
    ###########################
    def print_hbm_error_counters(self):
        hbm_error_counters = self.debug_device.get_hbm_error_counters()
        for intf in range(len(hbm_error_counters)):
            print('HBM interface {}'.format(intf))
            hbm_intf_error_counters = hbm_error_counters[intf]
            for hbm_errors_info in hbm_intf_error_counters:
                print(
                    'HBM {channel} errors: write {write_parity}, addr {addr_parity}, read {read_parity}, 1b {1bit_ecc}, 2b {2bit_ecc}'.format(
                        **hbm_errors_info))

    #####################################################################################################
    # Default profiles
    #####################################################################################################
    def create_profiles(self):
        self.filter_group = self.device.create_filter_group()
        self.create_ingress_qos_profile()
        self.create_egress_qos_profile()
        self.create_tc_profile()
        self.create_ac_profile(with_fallback=True)

        for i in range(30):
            voq_cgm_p = self.device.create_voq_cgm_profile()
            self.voq_cgm_profiles.append(voq_cgm_p)

    def create_ingress_qos_profile(self):
        self.ingress_qos_profile = self.device.create_ingress_qos_profile()
        self.ingress_qos_profile.set_qos_tag_mapping_enabled(True)

        # (PCP,DEI) mapping
        pcpdei = sdk.la_vlan_pcpdei()
        for pcp in range(0, 8):
            for dei in range(0, 2):
                pcpdei.fields.pcp = pcp
                pcpdei.fields.dei = dei
                self.ingress_qos_profile.set_qos_tag_mapping_pcpdei(pcpdei, pcpdei)

        # (DSCP) mapping
        ip_dscp = sdk.la_ip_dscp()
        for dscp in range(0, 64):
            ip_dscp.value = dscp
            self.ingress_qos_profile.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, ip_dscp, ip_dscp)
            self.ingress_qos_profile.set_traffic_class_mapping(sdk.la_ip_version_e_IPV4, ip_dscp, dscp % 8)
            self.ingress_qos_profile.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, ip_dscp, ip_dscp)
            self.ingress_qos_profile.set_traffic_class_mapping(sdk.la_ip_version_e_IPV6, ip_dscp, dscp % 8)

        # (MPLS_TC) mapping
        mpsl_tc = sdk.la_mpls_tc()
        for tc in range(0, 8):
            mpsl_tc.value = tc
            self.ingress_qos_profile.set_qos_tag_mapping_mpls_tc(mpsl_tc, mpsl_tc)

        # Mapping TC --> VOQ offset
        for pcp in range(0, 8):
            for dei in range(0, 2):
                pcpdei.fields.pcp = pcp
                pcpdei.fields.dei = dei
                self.ingress_qos_profile.set_traffic_class_mapping(pcpdei, pcp)

    def create_egress_qos_profile(self, marking_source=sdk.la_egress_qos_marking_source_e_QOS_TAG):
        self.egress_qos_profile = self.device.create_egress_qos_profile(marking_source)

        encap_qos_values = sdk.encapsulating_headers_qos_values()
        # mapping to (PCP,DEI)
        pcpdei = sdk.la_vlan_pcpdei()
        for pcp in range(0, 8):
            for dei in range(0, 2):
                pcpdei.fields.pcp = pcp
                pcpdei.fields.dei = dei
                self.egress_qos_profile.set_qos_tag_mapping_pcpdei(pcpdei, pcpdei, encap_qos_values)

        # mapping to (DSCP)
        ip_dscp = sdk.la_ip_dscp()
        for dscp in range(0, 64):
            ip_dscp.value = dscp
            self.egress_qos_profile.set_qos_tag_mapping_dscp(ip_dscp, ip_dscp, encap_qos_values)

        # mapping to (MPLS_TC)
        mpls_tc = sdk.la_mpls_tc()
        for tc in range(0, 8):
            mpls_tc.value = tc
            self.egress_qos_profile.set_qos_tag_mapping_mpls_tc(mpls_tc, mpls_tc, encap_qos_values)

    def create_tc_profile(self):
        self.tc_profile = self.device.create_tc_profile()

        for tc in range(8):
            self.tc_profile.set_mapping(tc, tc)

    def create_ac_profile(self, with_fallback=False):
        self.ac_profile = self.device.create_ac_profile()

        # NO VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x0000
        pvf.tpid2 = 0x0000
        self.ac_profile.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT)

        # PORT VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x8100
        pvf.tpid2 = 0x0000
        self.ac_profile.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        # PORT VLAN VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x9100
        pvf.tpid2 = 0x8100

        if with_fallback:
            selector = sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN_WITH_FALLBACK
        else:
            selector = sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN

        self.ac_profile.set_key_selector_per_format(pvf, selector)

    #####################################################################################################
    # Board configurations
    #####################################################################################################
    def board_config(self):
        ifg_swap_lists = self.ifg_swap_lists
        anlt_swap_lists = self.anlt_swap_lists
        serdes_polarity_inverse_rx = self.serdes_polarity_inverse_rx
        serdes_polarity_inverse_tx = self.serdes_polarity_inverse_tx

        for sid in self.device.get_used_slices():
            for ifg_id in range(2):
                ifg_num = sid * 2 + ifg_id
                serdes_src = ifg_swap_lists[ifg_num]
                self.device.set_serdes_source(sid, ifg_id, serdes_src)
                if (self.with_an_order):
                    anlt_src = anlt_swap_lists[ifg_num]
                    self.device.set_serdes_anlt_order(sid, ifg_id, anlt_src)

                for serdes in serdes_polarity_inverse_rx[ifg_num]:
                    self.device.set_serdes_polarity_inversion(sid, ifg_id, serdes, sdk.la_serdes_direction_e_RX, True)

                for serdes in serdes_polarity_inverse_tx[ifg_num]:
                    self.device.set_serdes_polarity_inversion(sid, ifg_id, serdes, sdk.la_serdes_direction_e_TX, True)

    #####################################################################################################
    # System port
    #####################################################################################################
    def create_system_port(self, slice_id, ifg, underlying_port, underlying_port_speed):
        (is_success, base_voq, base_vsc_vec) = self.voq_allocator.allocate_voq_set(slice_id, ifg, VOQ_SET_SIZE)
        if not is_success:
            raise Exception('Error: allocate_voq_set failed.' % i)

        for sid in self.device.get_used_slices():
            slice_mode = self.device.get_slice_mode(sid)
            if slice_mode == sdk.la_slice_mode_e_CARRIER_FABRIC:
                base_vsc_vec[sid] = sdk.LA_VSC_GID_INVALID

        voq_set = self.device.create_voq_set(base_voq, VOQ_SET_SIZE, base_vsc_vec, self.device.get_id(), slice_id, ifg)
        voq_counter = self.device.create_counter(2)
        voq_set.set_counter(sdk.la_voq_set.voq_counter_type_e_BOTH, VOQ_SET_SIZE, voq_counter)
        self.voq_sets.append(voq_set)

        special_port = (underlying_port.type() == sdk.la_object.object_type_e_PCI_PORT) or (
            underlying_port.type() == sdk.la_object.object_type_e_RECYCLE_PORT)

        if self.args.alpha_hbm_ports is not None and not special_port:
            if (len(self.mph.mac_ports) - 1) in set(self.args.alpha_hbm_ports):
                profile = self.voq_cgm_profiles[1]
                self.total_evict_ports += 1
                print("apply evict profile to port {}".format(len(self.mph.mac_ports) - 1))
            else:
                profile = self.voq_cgm_profiles[0]
        else:
            if (special_port or self.total_evict_ports >= PORTS_TO_EVICT):
                profile = self.voq_cgm_profiles[0]
            else:
                profile = self.voq_cgm_profiles[1]
                self.total_evict_ports += 1

        for i in range(VOQ_SET_SIZE):
            voq_set.set_cgm_profile(i, profile)

        # System port
        sys_port = self.device.create_system_port(self.sys_port_gid, underlying_port, voq_set, self.tc_profile)
        self.sys_port_gid += 1

        self.init_system_port_default_tm(sys_port, base_voq, base_vsc_vec, underlying_port_speed)

        return sys_port

    #####################################################################################################
    # TM configuration
    #####################################################################################################
    def init_default_tm(self):
        ifg_speed = 985 * GIGA

        for slice_id in self.device.get_used_slices():
            for ifg_id in range(NUM_IFGS_PER_SLICE):
                ifg_sch = self.device.get_ifg_scheduler(slice_id, ifg_id)

                ifg_sch.set_credit_rate(ifg_speed)
                ifg_sch.set_credit_burst_size(16)
                ifg_sch.set_transmit_rate(ifg_speed)
                ifg_sch.set_transmit_burst_size(16)

    def init_port_default_tm(self, mac_port, speed):
        ifc_sch = mac_port.get_scheduler()
        if ifc_sch is None:
            raise Exception('Error: port::get_scheduler failed')

        ifc_sch.set_credit_cir(speed)
        ifc_sch.set_transmit_cir(speed)
        ifc_sch.set_credit_eir_or_pir(speed, False)
        ifc_sch.set_transmit_eir_or_pir(speed, False)
        ifc_sch.set_cir_weight(1)
        ifc_sch.set_eir_weight(1)

    def init_system_port_default_tm(self, sys_port, base_voq, base_vsc_vec, underlying_port_speed):
        ingress_device_id = self.device.get_id()

        port_max_speed = int(SYSTEM_PORT_SPEEDUP * underlying_port_speed)
        # print('Port max speed = {}bps which is {}Gbps'.format(port_max_speed, port_max_speed / (1024 * 1024)))

        sp_sch = sys_port.get_scheduler()
        if sp_sch is None:
            raise Exception('Error: sys_port.get_scheduler failed. status=%d' % (status))

        sp_sch.set_priority_propagation(False)
        dev_rev = self.ll_device.get_device_revision()
        if dev_rev is not lldcli.la_device_revision_e_GRAPHENE_A0:
            sp_sch.set_logical_port_enabled(False)
        for oqpg in range(8):
            sp_sch.set_oq_priority_group(oqpg, sdk.la_system_port_scheduler.priority_group_e_SP8)
            sp_sch.set_credit_pir(oqpg, port_max_speed)
            sp_sch.set_transmit_pir(oqpg, port_max_speed)
            sp_sch.set_transmit_uc_mc_weight(oqpg, 1, 1)

        for pg in range(sdk.la_system_port_scheduler.priority_group_e_SP8 + 1):
            sp_sch.set_priority_group_credit_cir(pg, port_max_speed)
            sp_sch.set_priority_group_transmit_cir(pg, port_max_speed)
            sp_sch.set_priority_group_eir_weight(pg, 7)

        for oq_id in range(VOQ_SET_SIZE):
            oq_sch = sp_sch.get_output_queue_scheduler(oq_id)

            oq_sch.set_scheduling_mode(sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_2SP_3WFQ)

            for group in range(4):
                oq_sch.set_group_weight(group, 1)

            for slice_idx in range(len(base_vsc_vec)):
                if base_vsc_vec[slice_idx] == sdk.LA_VSC_GID_INVALID:
                    continue
                vsc = base_vsc_vec[slice_idx] + oq_id
                oq_sch.attach_vsc(
                    vsc,
                    sdk.la_oq_vsc_mapping_e_RR1_RR3,
                    ingress_device_id,
                    slice_idx,
                    base_voq + oq_id)

                if dev_rev is not lldcli.la_device_revision_e_GRAPHENE_A0:
                    oq_sch.set_vsc_pir(vsc, sdk.LA_RATE_UNLIMITED)

    #####################################################################################################
    # Punt-inject port
    #####################################################################################################
    def create_punt_inject_port(self, slice_id, ifg):
        print('--------->self.create_punt_inject_port @', slice_id, ifg)
        speed = 100 * GIGA

        pci_port = self.device.create_pci_port(slice_id, ifg, False)
        self.pci_ports.append(pci_port)

        self.init_port_default_tm(pci_port, speed)

        pci_sys_port = self.create_system_port(slice_id, ifg, pci_port, speed)
        self.pci_sys_ports.append(pci_sys_port)
        pci_port.activate()

        punt_mac = sdk.la_mac_addr_t()
        punt_mac.flat = snake_base_topology.INJECT_PORT_MAC_ADDR

        # Create AC port instead of PI/PD port.  Then, we can route traffic to the punt path through a switch.
        eth_port = self.device.create_ethernet_port(pci_sys_port, sdk.la_ethernet_port.port_type_e_AC)
        eth_port.set_ac_profile(self.ac_profile)
        ac_port = self.device.create_ac_l2_service_port(self.ac_port_gid, eth_port, snake_base_topology.ENTRY_VLAN,
                                                        0,  # vid2
                                                        self.filter_group,
                                                        self.ingress_qos_profile,
                                                        self.egress_qos_profile)
        ingress_cnt = self.device.create_counter(1)
        egress_cnt = self.device.create_counter(1)
        ac_port.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_cnt)
        ac_port.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_cnt)

        self.ac_port_gid += 1
        ac_port.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
        # Keep track of all the inject AC ports, so we can punt to them later.
        self.inject_eth_ports.append(eth_port)
        self.inject_ac_ports.append(ac_port)

    def create_recycle_port(self, slice_id, ifg):
        print('--------->self.create_recycle_port @', slice_id, ifg)
        speed = 100 * GIGA

        ############# PACKET-DMA-WA ####################
        rcy_port = self.device.create_recycle_port(slice_id, ifg)
        self.rcy_ports.append(rcy_port)

        self.init_port_default_tm(rcy_port, speed)

        rcy_sys_port = self.create_system_port(slice_id, ifg, rcy_port, speed)
        self.rcy_sys_ports.append(rcy_sys_port)
        ############# PACKET-DMA-WA ####################

    def set_next_pif(self, num_serdes_per_port):
        num_pif_per_ifg = self.device.get_num_of_serdes(self.cur_slice, self.cur_ifg)

        self.cur_pif += num_serdes_per_port
        if (self.cur_pif + num_serdes_per_port) > num_pif_per_ifg:
            self.cur_pif = 0
            self.cur_ifg += 1
            if self.cur_ifg >= NUM_IFGS_PER_SLICE:
                self.cur_ifg = 0
                # choose the next slice
                active_slices = self.device.get_used_slices()
                cur_slices_index = active_slices.index(self.cur_slice)
                cur_slices_index += 1
                if cur_slices_index >= len(active_slices):
                    cur_slices_index = 0
                self.cur_slice = active_slices[cur_slices_index]

    def get_inject_actual_ifg(self, slice_id, ifg):
        if self.ll_device.is_pacific():
            slices_with_flipped_ifgs = [0, 3, 4]
        else:  # GB
            slices_with_flipped_ifgs = [1, 2, 5]

        if (slice_id in slices_with_flipped_ifgs):
            actual_ifg = ifg ^ 1
        else:
            actual_ifg = ifg

        return actual_ifg

    def get_inject_pif(self):
        if self.ll_device.is_pacific():
            return 18
        else:  # GB
            return 24

    def set_leaba_module_path(self, path="/sys/module/leaba_module"):
        self.leaba_module_path = path

    # Wrapper header adds a dummy header to the punted packet.
    def is_wrapper_header_en(self):
        param_path = "{}/{}/{}".format(self.leaba_module_path, "parameters", "m_add_wrapper_header")
        param_f = open(param_path)
        val = param_f.readline()
        param_f.close()
        if int(val) == 1:
            return True
        else:
            return False

    def open_sockets(self):
        for i in self.device.get_used_slices():
            with open('%s' % (self.ll_device.get_network_interface_file_name(i))) as fd:
                first_line = fd.readline()
                if first_line.find('not enabled') < 0:
                    self.open_socket(i)

    def open_socket(self, slice_id):
        if_name = self.ll_device.get_network_interface_name(slice_id)

        os.system('echo 0 > /proc/sys/net/ipv6/conf/{}/router_solicitations'.format(if_name))
        os.system('{} {} up'.format(IFCONFIG_CMD, if_name))
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((if_name, ETH_P_ALL))
        self.sockets[slice_id] = s

    def close_sockets(self):
        for i in self.device.get_used_slices():
            self.close_socket(i)

    def close_socket(self, slice_id):
        s = self.sockets[slice_id]
        if s is None:
            return
        if_name = self.ll_device.get_network_interface_name(slice_id)
        os.system('{} {} down'.format(IFCONFIG_CMD, if_name))
        s.close()
        self.sockets[slice_id] = None

    def fill_packet_payload(self, packet, packet_size, data_pattern):
        # Get the bytes of the input data pattern after 0x
        # bytes module cannot handle half bytes, so pad MSB with 0 if we have a half byte.
        if (len(hex(data_pattern)) % 2 == 1):
            data_pattern_hex = "0x0{:x}".format(data_pattern)
        else:
            data_pattern_hex = hex(data_pattern)
        data_pattern_bytes = bytes.fromhex(data_pattern_hex[2:])
        while len(packet) < packet_size:
            # Get each byte in the data pattern, and append it to the payload until we reach the correct payload size
            for byte in data_pattern_bytes:
                if len(packet) >= packet_size:
                    break
                # Track the created packet to compare with received packet
                packet += byte.to_bytes(1, sys.byteorder)

        return packet

    def get_inject_encap_len(self, slice):
        SRC_MAC = self.src_mac
        inject_down = False
        if slice in [1, 3, 5]:
            inject_down = True
            slice_gid = self.rcy_sys_ports[int(slice / 2)].get_gid()
            inject_encap = Ether(dst=snake_base_topology.PUNT_INJECT_PORT_MAC_ADDR.addr_str,
                                 src=self.mac_to_str(SRC_MAC),
                                 type=TPID_Dot1Q) / Dot1Q(prio=0,
                                                          id=0,
                                                          type=TPID_Inject) / InjectDown(dest=slice_gid,
                                                                                         encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE)
        inject_up_encap = Ether(dst=snake_base_topology.PUNT_INJECT_PORT_MAC_ADDR.addr_str, src=self.mac_to_str(
            SRC_MAC), type=TPID_Dot1Q) / Dot1Q(prio=0, id=0, type=TPID_Inject) / InjectUpStd()

        if inject_down:
            inject_encap = inject_encap / inject_up_encap
        else:
            inject_encap = inject_up_encap
        return len(inject_encap)

    def inject(
            self,
            packet_headers,
            test_packet_size,
            entry_slice,
            inject_packets_count,
            data_pattern):
        full_packet = packet_headers

        # Padding
        # The full packet contains the inject encapsulation and doesn't contain the MAC CRC.
        if self.check_sim_utils_exists():
            inject_encap_len = self.get_inject_encap_len(entry_slice)
        else:
            inject_encap_len = INJECT_ENCAP_LENGTH
        full_packet = self.fill_packet_payload(full_packet, test_packet_size + inject_encap_len - MAC_CRC_LENGTH, data_pattern)

        if entry_slice in [1, 3, 5]:
            s = self.sockets[0]
        else:
            s = self.sockets[entry_slice]

        for i in range(inject_packets_count):
            done = False
            for iteration in range(PACKET_INJECT_RETRIES):
                try:
                    bytes_num = s.send(full_packet)
                    if bytes_num != len(full_packet):
                        print('Error: send failed len(packet)=%d bytes_num=%d' % (len(full_packet), bytes_num))
                    else:
                        done = True
                except BaseException:
                    # Socket is busy, wait 50msec and try again
                    time.sleep(0.05)
                if done:
                    break

    def inject_setup(self, slice, ifg, pif_id, dst_mac):
        DST_MAC = dst_mac
        SRC_MAC = self.src_mac
        if not self.check_sim_utils_exists():
            packet_str = '12 34 56 78 9a bc de ad de ad de ad 81 00 01 00 71 03 26 00 00 00 c8 00 00 00 00 00 00 00 00 00 00 00 00 ca fe ca fe ca fe de ad de ad de ad 81 00 01 00 08 00 45 00 01 de 00 01 00 00 40 06 7b 17 7f 00 00 01 7f 00 00 01 00 14 00 50 00 00 00 00 00 00 00 00 50 02 20 00 8f c6 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            packet_array = packet_str.split()
            inject_full = []
            for packet_word in packet_array:
                inject_full.append(int(packet_word, 16))
            return bytes(inject_full)

        vlan = snake_base_topology.ENTRY_VLAN
        inject_down = False
        if slice in [1, 3, 5]:
            inject_down = True
            slice_gid = self.rcy_sys_ports[int(slice / 2)].get_gid()
            inject_encap = Ether(dst=snake_base_topology.PUNT_INJECT_PORT_MAC_ADDR.addr_str,
                                 src=self.mac_to_str(SRC_MAC),
                                 type=TPID_Dot1Q) / Dot1Q(prio=0,
                                                          id=0,
                                                          vlan=vlan,
                                                          type=TPID_Inject) / InjectDown(dest=slice_gid,
                                                                                         encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE)

        inject_up_encap = Ether(dst=snake_base_topology.PUNT_INJECT_PORT_MAC_ADDR.addr_str,
                                src=self.mac_to_str(SRC_MAC),
                                type=TPID_Dot1Q) / Dot1Q(prio=0,
                                                         id=0,
                                                         vlan=vlan,
                                                         type=TPID_Inject) / InjectUpStd(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS,
                                                                                         ifg_id=self.get_inject_actual_ifg(
                                                                                             slice, ifg),
                                                                                         pif_id=pif_id)

        if inject_down:
            inject_encap = inject_encap / inject_up_encap
        else:
            inject_encap = inject_up_encap
        inject_data = Ether(dst=self.mac_to_str(DST_MAC), src=self.mac_to_str(SRC_MAC), type=TPID_Dot1Q) / \
            Dot1Q(prio=0, id=0, vlan=vlan) / IP() / TCP()
        inject_full = inject_encap / inject_data

        return bytes(inject_full)

    def reset_traf_records(self):
        for mac in self.traf_per_mac.keys():
            mac_record = self.traf_per_mac[mac]
            flow_id = mac_record[self.TRAF_FLOW_ID_IDX]
            mac_record[3:] = [0 for i in range(len(mac_record) - 2)]
            mac_record[self.TRAF_FLOW_ID_IDX] = flow_id

    def init_inject_for_ports(self):
        for pci_port in self.pci_ports:
            pci_port.activate()
        self.open_sockets()

    # Set switches to circulate traffic between 2 AC ports.
    def set_switches_circulate_traffic(self):
        # For each AC port attached to a switch, get the switch and change the DST_MAC.
        for src_port, dst_port in self.switch_ac_ports:
            eth_port = src_port.get_ethernet_port()
            sp = eth_port.get_system_port()
            slice = sp.get_slice()
            # Unique destination MAC per system port.
            idx = self.get_sp_index(sp)
            dst_macs = self.macs_per_sp[sp.get_gid()]
            for DST_MAC in dst_macs:
                # Set MAC entry to the port, so traffic will circulate through the port.
                self.switches[idx].set_mac_entry(DST_MAC, dst_port, sdk.LA_MAC_AGING_TIME_NEVER)

    def send_traffic_to_port(
            self,
            slice,
            ifg,
            base_serdes,
            base_pif,
            packet_count=1,
            packet_size=500,
            data_pattern=0xa5,
            flow_id=0):
        # Get the system port that corresponds with the port we want to send to
        for idx, sp in enumerate(self.sys_ports):
            slice_p = sp.get_slice()
            ifg_p = sp.get_ifg()
            base_pif_p = sp.get_base_pif()
            if slice_p == slice and ifg_p == ifg and base_pif_p == base_pif:
                break

        # Check we got a valid port
        if sp.get_slice() != slice or sp.get_ifg() != ifg or sp.get_base_pif() != base_pif:
            raise Exception("Port {}/{}/{}/{} not created.".format(slice, ifg, base_serdes, base_pif))

        # flow_id is used to circulate different traffic streams
        # create a new MAC if it doesn't exist
        self.get_next_mac(sp, flow_id)

        # Set ports to circulate traffic after creating all the MAC addresses per flow as needed.
        self.set_switches_circulate_traffic()

        # Inject the traffic
        dst_mac = self.macs_per_sp[sp.get_gid()][flow_id]
        packet_headers = self.inject_setup(slice, ifg, base_pif, dst_mac)
        self.inject(packet_headers, packet_size, slice, packet_count, data_pattern)
        # Record keeping
        self.traf_per_mac[dst_mac][self.TRAF_PKTS_SENT_IDX] += packet_count
        self.traf_per_mac[dst_mac][self.TRAF_PKTS_SIZE_IDX] = packet_size
        self.traf_per_mac[dst_mac][self.TRAF_PKTS_DATA_PTRN_IDX] = data_pattern

    def send_traffic_to_all_ports(self, packet_count=1, packet_size=500, data_pattern=0xa5, flow_id=0):
        # Sys ports is a list of all the network ports (real ports + loop ports)
        #   Create a packet for each port, and inject to each port.
        for idx, sp in enumerate(self.sys_ports):
            slice = sp.get_slice()
            ifg = sp.get_ifg()
            base_pif = sp.get_base_pif()
            # flow_id is used to circulate different traffic streams
            # create a new MAC if it doesn't exist
            self.get_next_mac(sp, flow_id)

        # Set ports to circulate traffic after creating all the MAC addresses per flow as needed.
        self.set_switches_circulate_traffic()

        # Inject the traffic
        for idx, sp in enumerate(self.sys_ports):
            slice = sp.get_slice()
            ifg = sp.get_ifg()
            base_pif = sp.get_base_pif()
            dst_mac = self.macs_per_sp[sp.get_gid()][flow_id]
            packet_headers = self.inject_setup(slice, ifg, base_pif, dst_mac)
            self.inject(packet_headers, packet_size, slice, packet_count, data_pattern)
            # Record keeping
            self.traf_per_mac[dst_mac][self.TRAF_PKTS_SENT_IDX] += packet_count
            self.traf_per_mac[dst_mac][self.TRAF_PKTS_SIZE_IDX] = packet_size
            self.traf_per_mac[dst_mac][self.TRAF_PKTS_DATA_PTRN_IDX] = data_pattern

    def get_and_check_packets(self, slice, dst_mac, packet_count=1, packet_size=500, data_pattern=0xa5):
        # Don't both trying to get packets if 0 packets are expected.
        if packet_count == 0:
            print("Warning: requested 0 packets.")
            return 0, 0

        socket_buf_bytes = 13000
        # Socket index is based on the interface name.  For slice 1, we want interface 0.
        socket = self.sockets[(slice // 2) * 2]
        # 10 ms second timeout to receive a packet
        # After this timeout, we assume no more packets are coming
        socket.settimeout(.01)
        packets_received = 0
        packets_valid = 0
        pkts = []
        unexpected_timeout = 3000
        while True:
            if unexpected_timeout == 0:
                raise Exception('Unexpected timeout while waiting for packets...')
            try:
                # Blocking call, if we timeout there are no more packets to receive.
                pkt = socket.recv(socket_buf_bytes)
                packets_received += 1
                pkts.append(pkt)
                unexpected_timeout = 3000
            except BaseException:
                # We got at least some packets we expect, so break out of the loop.
                if packets_received == packet_count or packets_received > 0:
                    break
                print("Failed to receive packet.  Received total: ", packets_received)
                return packets_received, packets_valid
            # We should never hit this
            unexpected_timeout -= 1

        if packets_received != packet_count:
            print("Warning: received {} packets, expected {} packets.".format(packets_received, packet_count))

        # Ether + Dot1Q + IP + TCP len
        # Dot1Q is stripped by skb/kernel, so we ignore it
        recv_pkt_header_len = len(Ether() / IP() / TCP())

        # If m_add_wrapper_header is enabled, we need to account for an additional 16 byte header
        if self.is_wrapper_header_en():
            wrapper_header_len = len(Ether()) + snake_base_topology.DUMMY_SP_LEN
            # With m_add_wrapper_header, the inject packet Dot1Q is not stripped.
            recv_pkt_header_len = len(Ether() / Dot1Q() / IP() / TCP())
            expected_pkt_len_delta = 0
        else:
            wrapper_header_len = 0
            # If we don't wrap the header, expect the Dot1Q to be stripped.  We expect 4 bytes less on the punt packet in this case.
            expected_pkt_len_delta = len(Dot1Q())

        # Recreate the expected packet to compare against the actual received packet
        # Actual packet size assumes the MAC_CRC and Dot1Q are present
        expected_pkt = bytes(recv_pkt_header_len)
        expected_pkt_size = packet_size - MAC_CRC_LENGTH - expected_pkt_len_delta
        expected_pkt = self.fill_packet_payload(expected_pkt, expected_pkt_size, data_pattern)

        # Keep track of valid bytes
        data_invalid = 0
        # Verify that the packet we received matches the packet we injected
        for pkt in pkts:
            # If we added the wrapper header, handle it
            pkt = pkt[wrapper_header_len:]

            # Compare the DST_MAC to make sure we are getting the right packet
            for i in range(MAC_LEN_BYTES):
                # DST_MAC is opposite byte order as received packet DST MAC
                #   Get DST_MAC in reverse order, and subtract 1 to get the index of the byte
                if dst_mac.bytes[MAC_LEN_BYTES - 1 - i] != pkt[i]:
                    print("Failed to get packet at expected MAC destination.")
                    print(hex(dst_mac.flat), " != ", (pkt[:MAC_LEN_BYTES]))

            # The packet lengths should be identical, except for the Dot1Q header
            # If we have an added wrapper on the receive packet, then the received packet will be longer than expected.
            if len(pkt) != len(expected_pkt):
                print("PKT len != Injected packet len")
                print(len(pkt), " != ", len(expected_pkt))
                continue
            try:
                # From the end of the header, to the end of the packet, compare the payload data.
                for idx in range(recv_pkt_header_len, len(pkt)):
                    if pkt[idx] != expected_pkt[idx]:
                        data_invalid = 1
                        break
                if data_invalid == 0:
                    packets_valid += 1
                data_invalid = 0
            except BaseException:
                traceback.print_exc(file=sys.stdout)
                return packets_received, packets_valid

        return packets_received, packets_valid

    # Only applicable after the network ports have been attached to punt switches.
    # If traffic is not circulating, this function will fail.
    #
    # This function will reset the mac entry of each switch from the mac loop to the punt path
    #   This will punt the packets back to the CPU
    def get_traffic_from_port(self, slice, ifg, base_pif, packet_count=1, packet_size=500, data_pattern=0xa5, flow_id=0):

        # Get the system port that corresponds with the port we want to send to
        for idx, sp in enumerate(self.sys_ports):
            slice_p = sp.get_slice()
            ifg_p = sp.get_ifg()
            base_pif_p = sp.get_base_pif()
            if slice_p == slice and ifg_p == ifg and base_pif_p == base_pif:
                break

        # Check we got a valid port
        if sp.get_slice() != slice or sp.get_ifg() != ifg or sp.get_base_pif() != base_pif:
            raise Exception("Port {}/{}/{} not created.".format(slice, ifg, base_pif))

        # Unique destination MAC per system port per flow.
        sp_idx = self.get_sp_index(sp)
        DST_MAC = self.macs_per_sp[sp.get_gid()][flow_id]

        # Punt to the closest PCI port (rounded down) based on the current sys port slice.
        #  Ex: Ports on slice 0,1, will punt to slice 0.
        pci_ac_port = self.inject_ac_ports[slice // 2]

        # Punt traffic back to the CPU by changing the MAC entry
        self.switches[sp_idx].set_mac_entry(DST_MAC, pci_ac_port, sdk.LA_MAC_AGING_TIME_NEVER)

        # Receive and check the punted packet data
        pkts_recv, pkts_valid = self.get_and_check_packets(slice, DST_MAC, packet_count, packet_size, data_pattern)

        self.traf_per_mac[DST_MAC][self.TRAF_PKTS_RECV_IDX] += pkts_recv
        self.traf_per_mac[DST_MAC][self.TRAF_PKTS_VALID_IDX] += pkts_valid

    # Only applicable after the network ports have been attached to punt switches.
    # If traffic is not circulating, this function will fail.
    def get_traffic_from_all_ports(self, packet_count=1, packet_size=500, data_pattern=0xa5, flow_id=0):
        # Reset mac entry of switch from the mac loop to the punt path
        #   This will punt the packets back to the CPU
        passed_ports = []
        failed_ports = []

        # For each AC port attached to a switch, get the switch and change the DST_MAC.
        for port, dst_port in self.switch_ac_ports:
            try:
                eth_port = port.get_ethernet_port()
                sp = eth_port.get_system_port()
                slice = sp.get_slice()
                # Unique destination MAC per system port per flow.
                sp_idx = self.get_sp_index(sp)
                DST_MAC = self.macs_per_sp[sp.get_gid()][flow_id]

                # Punt to the closest PCI port (rounded down) based on the current sys port slice.
                #  Ex: Ports on slice 0,1, will punt to slice 0.
                pci_ac_port = self.inject_ac_ports[slice // 2]

                # Punt traffic back to the CPU by changing the MAC entry
                self.switches[sp_idx].set_mac_entry(DST_MAC, pci_ac_port, sdk.LA_MAC_AGING_TIME_NEVER)

                # Receive and check the punted packet data
                pkts_recv, pkts_valid = self.get_and_check_packets(slice, DST_MAC, packet_count, packet_size, data_pattern)

                self.traf_per_mac[DST_MAC][self.TRAF_PKTS_RECV_IDX] += pkts_recv
                self.traf_per_mac[DST_MAC][self.TRAF_PKTS_VALID_IDX] += pkts_valid

                if pkts_recv == packet_count and pkts_valid == packet_count:
                    passed_ports.append(sp)
                else:
                    failed_ports.append(sp)
            except Exception as e:
                print("Failed while setting traffic to punt path.")
                traceback.print_exc(file=sys.stdout)
                print("With exception: ", e)

        if len(failed_ports) != 0:
            print("FAILED on ports: ")
            for port in failed_ports:
                print("Port slice {} ifg {} base pif {}".format(port.get_slice(), port.get_ifg(), port.get_base_pif()))

    # For each MAC,dump traf information
    def dump_traf_to_csv(self, filepath, cycle):
        # For each sys port, record all the data
        f = open(filepath, "w+", 1)
        f.write("cycle,Slice,IFG,SerDes,packets received,packets sent,packets valid,packet size,data pattern,flow id\n")
        for mac in self.traf_per_mac.keys():
            f.write(
                "{},{},{},{},{},{},{},{},0x{:02x},{}\n".format(cycle,
                                                               self.traf_per_mac[mac][self.TRAF_SLICE_IDX],
                                                               self.traf_per_mac[mac][self.TRAF_IFG_IDX],
                                                               self.traf_per_mac[mac][self.TRAF_SERDES_IDX],
                                                               self.traf_per_mac[mac][self.TRAF_PKTS_RECV_IDX],
                                                               self.traf_per_mac[mac][self.TRAF_PKTS_SENT_IDX],
                                                               self.traf_per_mac[mac][self.TRAF_PKTS_VALID_IDX],
                                                               self.traf_per_mac[mac][self.TRAF_PKTS_SIZE_IDX],
                                                               self.traf_per_mac[mac][self.TRAF_PKTS_DATA_PTRN_IDX],
                                                               self.traf_per_mac[mac][self.TRAF_FLOW_ID_IDX]))
        f.close()

    def dump_device_info(self, filepath, cycle):
        if not self.ll_device.is_pacific():
            return
        f = open(filepath, "w+", 1)
        dev_info = self.device.get_device_information()
        import fuse
        fuse_s = fuse.fuse(self.ll_device)
        efuse_device_id = fuse_s.read_fuse()

        self.ecid = self.debug_device.get_pacific_manufacture_info(efuse_device_id)
        self.ecid_in_hex = hex(fuse_s.read_fuse_userbits())

        temp_sensor1 = self.device.get_temperature(sdk.la_temperature_sensor_e_PACIFIC_SENSOR_1)
        temp_sensor2 = self.device.get_temperature(sdk.la_temperature_sensor_e_PACIFIC_SENSOR_2)
        voltage_sensor1 = self.device.get_voltage(sdk.la_voltage_sensor_e_PACIFIC_SENSOR_1_VDD)
        voltage_sensor2 = self.device.get_voltage(sdk.la_voltage_sensor_e_PACIFIC_SENSOR_2_VDD)
        f.write("cycle,refclk, Full ECID, Wafer Number, Fab, Lot designation, Lot number, Die X location, Die Y location, device extension, device part num, device revision, temp_sensor1, temp_sensor2, voltage_sensor1, voltage_sensor2\n")
        f.write(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                cycle,
                ':'.join(map(str, self.args.refclk)),
                self.ecid_in_hex,
                self.ecid['wafer_num'],
                self.ecid['fab'],
                self.ecid['lot_designation'],
                self.ecid['lot_number'],
                self.ecid['x_sign_ch'] + str(self.ecid['x_coord']),
                self.ecid['y_sign_ch'] + str(self.ecid['y_coord']),
                dev_info.extension,
                dev_info.part_num,
                dev_info.revision,
                temp_sensor1,
                temp_sensor2,
                voltage_sensor1,
                voltage_sensor2))
        f.close()

    def dump_pmro(self, filepath):
        if not self.ll_device.is_pacific():
            return
        f = open(filepath, "w+", 1)
        import pmro
        pmro = pmro.Pmro(self.ll_device)
        pmro.read_all_pmros()
        pmro.match_pmro_case()
        pmro.log_pmro(f)
        f.close()

    #####################################################################################################
    # Helper configuration functions
    #####################################################################################################
    def initialize_fabric(self, slice, ifg, serdes, serdes_per_port, speed, fc, loop_mode):
        fabric_mac_port = self.mph.create_fabric_mac_port(slice, ifg, serdes, serdes_per_port, speed, fc, loop_mode)
        fabric_port = self.device.create_fabric_port(fabric_mac_port)
        self.fabric_ports.append(fabric_port)

    def activate_fabric(self):

        for i in range(FABRIC_PEER_DISCOVERY_RETRIES):
            success = True
            for fabric_port in self.fabric_ports:
                try:
                    fabric_port.activate(sdk.la_fabric_port.link_protocol_e_PEER_DISCOVERY)
                except sdk.AgainException:
                    success = False
            if success:
                break
            time.sleep(FABRIC_PEER_DISCOVERY_DELAY)

        for fabric_port in self.fabric_ports:
            fabric_port.activate(sdk.la_fabric_port.link_protocol_e_LINK_KEEPALIVE)
            fabric_port.set_reachable_lc_devices([0])

    def initialize_loopback(
            self,
            first_slice,
            first_ifg,
            first_pif,
            speed,
            serdes_per_port,
            fec_mode,
            fc_mode,
            loopback_mode,
            auto_negotiate=False,
            max_loopback=999):

        assert(first_slice in self.device.get_used_slices())
        self.cur_slice = first_slice
        self.cur_ifg = first_ifg
        self.cur_pif = first_pif

        loopback_num = 0

        # Create the base topology

        while loopback_num < max_loopback and self.cur_slice in self.device.get_used_slices():
            if loopback_mode != sdk.la_mac_port.loopback_mode_e_NONE:
                print(f"loopback_mode: {loopback_mode} setting loopback on: ", self.cur_slice, self.cur_ifg, self.cur_pif)
            mac_port = self.mph.create_mac_port(self.cur_slice, self.cur_ifg, self.cur_pif,
                                                serdes_per_port, speed, fec_mode, fc_mode, loopback_mode, auto_negotiate)

            sys_port = self.create_system_port(self.cur_slice, self.cur_ifg, mac_port, REAL_PORT_SPEED[speed])
            self.sys_ports.append(sys_port)

            # Ethernet port
            eth_port = self.device.create_ethernet_port(sys_port, sdk.la_ethernet_port.port_type_e_AC)

            eth_port.set_ac_profile(self.ac_profile)

            self.eth_ports.append(eth_port)

            # Update loop vars
            self.set_next_pif(serdes_per_port)
            loopback_num += 1

        self.device.flush()

    def destroy_port(self, slice, ifg, serdes):
        index = self.mph.get_mac_port_idx(slice, ifg, serdes)
        ac_port = self.ac_ports[index]

        for i, sw_ac in enumerate(self.switch_ac_ports):
            if ac_port is sw_ac[0] or ac_port is sw_ac[1]:
                del self.switch_ac_ports[i]
                del self.switches[i]

        ac_port.detach()
        if index:
            self.ac_ports[index - 1].detach()

        self.device.destroy(ac_port)
        del self.ac_ports[index]

        self.device.destroy(self.eth_ports[index])
        del self.eth_ports[index]
        del self.eth_port_loops[index]

        self.device.destroy(self.sys_ports[index])
        del self.sys_ports[index]

        self.mph.destroy_mac_port(index)

    def initialize_entry_port(self, slice, ifg, first_pif, speed, serdes_per_port, fec_mode, fc_mode, auto_negotiate=False):
        mac_port = self.mph.create_mac_port(slice, ifg, first_pif, serdes_per_port, speed,
                                            fec_mode, fc_mode, sdk.la_mac_port.loopback_mode_e_NONE, auto_negotiate)
        sys_port = self.create_system_port(slice, ifg, mac_port, REAL_PORT_SPEED[speed])
        self.sys_ports.append(sys_port)

        # Ethernet port
        eth_port = self.device.create_ethernet_port(sys_port, sdk.la_ethernet_port.port_type_e_AC)

        eth_port.set_ac_profile(self.ac_profile)

        self.eth_ports.append(eth_port)

    #  Each system port has a dict entry, where the value is a list of MAC addresses
    #  The key is the system port GID
    #  The index into the MAC address list is the flow ID
    #  Get the next MAC available
    def get_next_mac(self, sp, flow_id=0):
        # DST_MAC is used to direct traffic to either the mac port of the pci port
        DST_MAC = sdk.la_mac_addr_t()
        DST_MAC.flat = self.dst_mac.flat
        # Keep a unique MAC per system port, to inject traffic to each port individually.
        #   Each switch circulates traffic for a unique network port.
        sp_gid = sp.get_gid()
        if sp_gid in self.macs_per_sp.keys():
            # If we already have a MAC reserved at that flow_id, do nothing
            if len(self.macs_per_sp[sp_gid]) > flow_id:
                return self.macs_per_sp[sp_gid][flow_id]
            else:
                self.macs_per_sp[sp.get_gid()].insert(flow_id, DST_MAC)
        else:
            self.macs_per_sp[sp_gid] = []
            self.macs_per_sp[sp_gid].insert(flow_id, DST_MAC)

        # When we create a new MAC, create an accounting table also
        self.traf_per_mac[DST_MAC] = [sp.get_slice(), sp.get_ifg(), sp.get_base_pif(), 0, 0, 0, 0, 0, flow_id]

        next_mac = DST_MAC.flat + 1
        self.dst_mac.flat = next_mac

        return DST_MAC

    # In order to punt packets back to the CPU, create a switch which can return packets back to the CPU
    # The ingress of the switch is the network port, and the egress is either the network port or the PCI punt path.
    def create_switch(self, in_l2ac_port, dest_l2ac_port):
        # Get MAC for the inbound port
        eth_port = in_l2ac_port.get_ethernet_port()
        sp = eth_port.get_system_port()
        DST_MAC = self.get_next_mac(sp)

        sw = self.device.create_switch(self.switch_gid)
        sw.set_max_switch_mac_addresses(MAX_MAC_PER_SWITCH_NO_LIMIT_VALUE)

        # Keep a list of switches so we can change all mac entries to punt traffic
        self.switch_gid += 1
        self.switches.append(sw)
        # Keep a list of AC ports that we attach to the switch.  Then we can circulate traffic/stop traffic as needed.
        self.switch_ac_ports.append([in_l2ac_port, dest_l2ac_port])

        # Configure mac entry so traffic flows in a loop through the mac port
        sw.set_mac_entry(DST_MAC, dest_l2ac_port, sdk.LA_MAC_AGING_TIME_NEVER)

        # Attach the mac port to the loop switch, so traffic will circulate
        in_l2ac_port.detach()
        in_l2ac_port.attach_to_switch(sw)

        self.device.flush()

    def get_sp_index(self, sp):
        for sp_list in self.sys_ports:
            if sp_list.get_gid() == sp.get_gid():
                return self.sys_ports.index(sp_list)

    def mac_to_str(self, mac_t):
        mac_dec = mac_t.flat
        hex_str = format(mac_dec, 'x')
        hex_str = ':'.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))
        return hex_str

    # Create a "snake" P2P if use_external is True, assumes every two ports are connected with external P2P cable
    # Otherwise, with simple loopback.
    def initialize_p2p(self, loops=1, use_external=False, use_mix=False, remote=False, flows=[], punt_traffic=False):
        for flow in flows:
            prev_ac_port = None
            self.vlan_id = flow['vlan_id_base']
            eth_ports = flow['eth_ports']
            ac_port_base = len(self.ac_ports)
            for eth_port_idx in range(len(eth_ports)):
                eth_port = eth_ports[eth_port_idx]
                if loops != 0:
                    cur_port_loops = loops
                else:
                    cur_port_loops = self.eth_port_loops[eth_port_idx]

                if prev_ac_port is None:
                    cur_port_loops = 1

                for cur_loop in range(cur_port_loops):
                    # Create ports
                    ac_port = self.device.create_ac_l2_service_port(self.ac_port_gid, eth_port, self.vlan_id,
                                                                    0,  # vid2
                                                                    self.filter_group,
                                                                    self.ingress_qos_profile,
                                                                    self.egress_qos_profile)
                    self.ac_ports.append(ac_port)

                    ac_port.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)

                    # Edit VLAN tag
                    eve = sdk.la_vlan_edit_command()
                    eve.num_tags_to_push = 1
                    eve.num_tags_to_pop = 1
                    eve.tag0.tpid = TPID_Dot1Q
                    eve.tag0.tci.fields.vid = self.vlan_id
                    ac_port.set_egress_vlan_edit_command(eve)

                    # Add counters
                    ingress_cnt = self.device.create_counter(1)
                    egress_cnt = self.device.create_counter(1)
                    ac_port.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_cnt)
                    ac_port.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_cnt)

                    if remote is True:
                        ac_port.set_destination(ac_port)
                        if punt_traffic is True:
                            # Create a switch per ac port so we can punt back to the CPU
                            # For remote setup, we only want to punt to one side.  The other side will be the loopback.
                            self.create_switch(ac_port, ac_port)
                    else:
                        # Set P2P connection
                        if prev_ac_port is not None:
                            prev_ac_port.set_destination(ac_port)
                            if use_external:
                                ac_port.set_destination(prev_ac_port)

                        # Update loop vars
                        # if no traffic generator connected and External loopback used, then ac_port connection should start from second to third ports
                        # if traffic generator connected and External loopback used, then ac_port connection should start from the first and second ports
                        # if no traffic generator connected and internal loopback used, ac_port
                        # connected between each consecutive ports
                        if (use_external and ((prev_ac_port is not None) or ((not self.traffic_gen) and (eth_port_idx == 0)))):
                            prev_ac_port = None
                        else:
                            prev_ac_port = ac_port
                            self.vlan_id += 1

                    self.ac_port_gid += 1

            if not remote:
                # Close the loop
                # if internal loopback, closing must be through the first port
                # for external loopback, closing the loop must be to the same last port, so traffic flows backwards
                next_ac_port = -1 if use_external else ac_port_base
                self.ac_ports[-1].set_destination(self.ac_ports[next_ac_port])
                # for external loopback without traffic gen, first port must be connected
                # to itself, so packets inside the snake loop keep flowing
                if (use_external and (not self.traffic_gen)):
                    self.ac_ports[ac_port_base].set_destination(self.ac_ports[ac_port_base])

                # Create a switch to allow for punting packets back to the CPU for no-tgen case.
                # if not self.traffic_gen:
                if punt_traffic:
                    if not use_external:
                        self.create_switch(self.ac_ports[0], self.ac_ports[1])
                    else:
                        # In external case, we want to loop back to the same port, not to the next port
                        self.create_switch(self.ac_ports[0], self.ac_ports[0])

        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SAME_INTERFACE)
        self.device.flush()

    # Create an IPv6 "snake".
    # If use_external is True, assumes every two ports are connected with external P2P cable, otherwise, with simple loopback.
    def initialize_ipv6_snake(self, loops=1, use_external=False, use_mix=False, he=True, ipv6routes=108, rpf=False, flows=[]):
        # Adding source ip address to LPM for RPF
        ipv6_prefix_sip = sdk.la_ipv6_prefix_t()
        ipv6_prefix_sip.length = 64
        sdk.set_ipv6_addr(ipv6_prefix_sip.addr, 0, 0x0002000200020002)  # IPv6 0002:0002:0002:0002:w:x:y:z

        prefix_gid = 0
        ac_port_gid = snake_base_topology.AC_PORT_BASE_GID

        for flow in flows:
            # first creates all the AC ports
            prev_ac_port = None
            vlan_id = flow['vlan_id_base']
            mac_addr = sdk.la_mac_addr_t()
            mac_addr.flat = flow['mac_addr_base']

            eth_ports = flow['eth_ports']
            vrf_gid = flow['vrf_gid_base']
            vrf_base = len(self.vrfs)
            ac_port_base = len(self.ac_ports)
            for eth_port_idx in range(len(eth_ports)):
                eth_port = eth_ports[eth_port_idx]
                if loops != 0:
                    cur_port_loops = loops
                else:
                    cur_port_loops = self.eth_port_loops[eth_port_idx]

                if prev_ac_port is None:
                    cur_port_loops = 1

                for cur_loop in range(cur_port_loops):
                    vrf = self.device.create_vrf(vrf_gid)
                    self.vrfs.append(vrf)
                    vrf_gid += 1

                    # Create ports
                    ac_port = self.device.create_l3_ac_port(ac_port_gid, eth_port, vlan_id,
                                                            0,  # vid2,
                                                            mac_addr,
                                                            vrf,
                                                            self.ingress_qos_profile,
                                                            self.egress_qos_profile)

                    self.ac_ports.append(ac_port)
                    mac_addr.flat += 1

                    # Edit VLAN tag
                    evt = sdk.la_vlan_tag_t()
                    evt.tpid = TPID_Dot1Q
                    evt.tci.fields.pcp = 0
                    evt.tci.fields.dei = 0
                    evt.tci.fields.vid = vlan_id
                    ac_port.set_egress_vlan_tag(evt, sdk.LA_VLAN_TAG_UNTAGGED)

                    # Add counters
                    ingress_cnt = self.device.create_counter(1)
                    egress_cnt = self.device.create_counter(1)
                    ac_port.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_cnt)
                    ac_port.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_cnt)

                    # Enable IPv6
                    ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

                    if rpf:
                        # Enable RPF
                        ac_port.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

                    # Update loop vars
                    if use_external and (prev_ac_port is not None):
                        prev_ac_port = None
                    else:
                        prev_ac_port = ac_port
                vlan_id += 1
                ac_port_gid += 1

            num_hops = len(self.vrfs) - vrf_base

            # sets up the topology
            # use last gid as base for prefix
            if prefix_gid == 0:
                prefix_gid = ac_port_gid + self.PREFIX_BASE_GID_OFFSET

            for i in range(num_hops):
                ipv6_prefix = sdk.la_ipv6_prefix_t()
                ipv6_prefix.length = 64

                vrf = self.vrfs[i + vrf_base]
                nh_l3_ac = self.ac_ports[ac_port_base + (i + 1) % num_hops]
                m = nh_l3_ac.get_mac()
                nh = self.device.create_next_hop(i + flow['nh_gid_base'], m, nh_l3_ac, sdk.la_next_hop.nh_type_e_NORMAL)

                if he:
                    # head end (HE)
                    prefix = self.device.create_prefix_object(prefix_gid, nh, sdk.la_prefix_object.prefix_type_e_NORMAL)
                    prefix.set_nh_lsp_properties(nh, [], None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
                    prefix_gid += 1
                else:
                    # shamelessly reusing prefix variable for fec
                    prefix = self.device.create_l3_fec(nh)

                self.prefixes.append(prefix)
                ip_offset = 0

                for ip_offset in range(ipv6routes):
                    sdk.set_ipv6_addr(ipv6_prefix.addr, 0, flow['ip_dest_addr'] + ip_offset)
                    vrf.add_ipv6_route(ipv6_prefix, prefix, 0, False)
                # Add SIP to lookup table so that RFP doesnt drop packet
                vrf.add_ipv6_route(ipv6_prefix_sip, prefix, 0, False)

                self.nhs.append(nh)

        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE)
        self.device.clear_trap_configuration(sdk.LA_EVENT_IPV6_HEADER_ERROR)
        self.device.clear_trap_configuration(sdk.LA_EVENT_MPLS_INVALID_TTL)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)
        self.device.flush()
        self.insert_ipv6_acls(False)

    def create_default_ipv6_acl_profile(self):
        self.ingress_acl_key_profile_ipv6_def = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV6, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_IPV6, 0)
        self.egress_acl_key_profile_ipv6_def = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV6, sdk.la_acl_direction_e_EGRESS, sdk.LA_ACL_KEY_IPV6, 0)

        self.acl_command_profile_def = self.device.create_acl_command_profile(sdk.LA_ACL_COMMAND)

    def insert_ipv6_acls(self, is_drop):
        self.create_default_ipv6_acl_profile()

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV6_SIP
        sdk.set_ipv6_addr(f1.val.ipv6_sip, 0x22220db80a0b12f0, 0x0000000000002222)
        sdk.set_ipv6_addr(f1.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV6_SIP
        sdk.set_ipv6_addr(f2.val.ipv6_sip, 0x22220db80a0b12f0, 0x0000000000002223)
        sdk.set_ipv6_addr(f2.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        k2.append(f2)

        in_acl = self.device.create_acl(self.ingress_acl_key_profile_ipv6_def, self.acl_command_profile_def)

        commands1 = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = is_drop
        commands1.append(action1)

        in_acl.append(k1, commands1)
        in_acl.append(k2, commands1)

        out_acl = self.device.create_acl(self.egress_acl_key_profile_ipv6_def, self.acl_command_profile_def)

        out_acl.append(k1, commands1)
        out_acl.append(k2, commands1)

        ingress_ipv6_acls = []
        ingress_ipv6_acls.append(in_acl)
        ingress_acl_group = self.device.create_acl_group()
        ingress_acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ingress_ipv6_acls)

        egress_ipv6_acls = []
        egress_ipv6_acls.append(out_acl)
        egress_acl_group = self.device.create_acl_group()
        egress_acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, egress_ipv6_acls)

        for ac_port in self.ac_ports:
            ac_port.set_acl_group(sdk.la_acl_direction_e_INGRESS, ingress_acl_group)
            ac_port.set_acl_group(sdk.la_acl_direction_e_EGRESS, egress_acl_group)

    def initialize_ipv4_snake(self, loops=1, use_external=False, use_mix=False, rpf=False, flows=[]):
        # Adding source ip address to LPM for RPF
        ipv4_prefix_sip = sdk.la_ipv4_prefix_t()
        ipv4_prefix_sip.addr.s_addr = 0x02020202         # 2.2.2.2
        ipv4_prefix_sip.length = 32

        prefix_gid = 0
        ac_port_gid = snake_base_topology.AC_PORT_BASE_GID

        for flow in flows:
            # first creates all the AC ports
            prev_ac_port = None
            vlan_id = flow['vlan_id_base']
            mac_addr = sdk.la_mac_addr_t()
            mac_addr.flat = flow['mac_addr_base']

            eth_ports = flow['eth_ports']
            vrf_gid = flow['vrf_gid_base']
            vrf_base = len(self.vrfs)
            ac_port_base = len(self.ac_ports)
            for eth_port_idx in range(len(eth_ports)):
                eth_port = eth_ports[eth_port_idx]
                if loops != 0:
                    cur_port_loops = loops
                else:
                    cur_port_loops = self.eth_port_loops[eth_port_idx]

                if prev_ac_port is None:
                    cur_port_loops = 1

                for cur_loop in range(cur_port_loops):
                    vrf = self.device.create_vrf(vrf_gid)
                    self.vrfs.append(vrf)
                    vrf_gid += 1

                    # Create ports
                    ac_port = self.device.create_l3_ac_port(ac_port_gid, eth_port, vlan_id,
                                                            0,  # vid2,
                                                            mac_addr,
                                                            vrf,
                                                            self.ingress_qos_profile,
                                                            self.egress_qos_profile)

                    self.ac_ports.append(ac_port)
                    mac_addr.flat += 1

                    # Edit VLAN tag
                    evt = sdk.la_vlan_tag_t()
                    evt.tpid = TPID_Dot1Q
                    evt.tci.fields.pcp = 0
                    evt.tci.fields.dei = 0
                    evt.tci.fields.vid = vlan_id
                    ac_port.set_egress_vlan_tag(evt, sdk.LA_VLAN_TAG_UNTAGGED)

                    # Add counters
                    ingress_cnt = self.device.create_counter(1)
                    egress_cnt = self.device.create_counter(1)
                    ac_port.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_cnt)
                    ac_port.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_cnt)

                    # Enable IPv4
                    ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

                    if rpf:
                        # Enable RPF
                        ac_port.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

                    # Update loop vars
                    if use_external and (prev_ac_port is not None):
                        prev_ac_port = None
                    else:
                        prev_ac_port = ac_port

                vlan_id += 1
                ac_port_gid += 1

            num_hops = len(self.vrfs) - vrf_base

            # sets up the topology
            # use last gid as base for prefix
            if prefix_gid == 0:
                prefix_gid = ac_port_gid + self.PREFIX_BASE_GID_OFFSET

            for i in range(num_hops):
                ipv4_prefix = sdk.la_ipv4_prefix_t()
                ipv4_prefix.length = 24

                vrf = self.vrfs[i + vrf_base]
                nh_l3_ac = self.ac_ports[ac_port_base + (i + 1) % num_hops]
                m = nh_l3_ac.get_mac()
                nh = self.device.create_next_hop(i + flow['nh_gid_base'], m, nh_l3_ac, sdk.la_next_hop.nh_type_e_NORMAL)

                prefix = self.device.create_prefix_object(prefix_gid, nh, sdk.la_prefix_object.prefix_type_e_NORMAL)
                prefix.set_nh_lsp_properties(nh, [], None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
                prefix_gid += 1
                self.prefixes.append(prefix)

                for ip_offset in range(108):
                    # 192.168.10.0/24
                    ipv4_prefix.addr.s_addr = flow['ip_dest_addr'] + (ip_offset << 8)
                    vrf.add_ipv4_route(ipv4_prefix, prefix, 0, False)

                if rpf:
                    vrf.add_ipv4_route(ipv4_prefix_sip, prefix, 0, False)

                # Add SIP to lookup table so that RFP doesnt drop packet
                vrf.add_ipv4_route(ipv4_prefix_sip, prefix, 0, False)

                self.nhs.append(nh)

        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        self.device.clear_trap_configuration(sdk.LA_EVENT_MPLS_INVALID_TTL)
        self.device.clear_trap_configuration(sdk.LA_EVENT_IPV4_HEADER_ERROR)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)
        self.device.flush()

    #####################################################################################################
    # Helper information collection and print functions
    #####################################################################################################
    def get_mac_entry(self, sw, dst_mac):
        try:
            me = sw.get_mac_entry(dst_mac)
            print("MAC addr: ", hex(dst_mac.flat))
            print("MAC entry AC port GID: ", me[0].downcast().get_gid())
            if len(me) > 2:
                print("Warning: multiple mac entrys for ", hex(dst_mac.flat))
                print("all mac entrys:", me)
        except BaseException:
            print("no mac entry for mac: ", hex(dst_mac.flat))
            return 0

    def print_ac_port_destinations(self):
        for ac_port_src, ac_port_dst in self.switch_ac_ports:
            print("AC port GID: ", ac_port_src.get_gid())
            dest = ac_port_src.get_destination()

            eth_port = ac_port_src.get_ethernet_port()
            sp = eth_port.get_system_port()
            slice = sp.get_slice()
            # Unique destination MAC per system port.
            idx = self.get_sp_index(sp)
            mac_list = self.macs_per_sp[sp.get_gid()]

            if dest is None:
                # We must be attached to a switch
                sw = ac_port_src.get_attached_switch()
                for DST_MAC in mac_list:
                    self.get_mac_entry(sw, DST_MAC)
                print("Switch GID: ", sw.get_gid(), sw)
            else:
                print("Dest GID: ", dest.get_gid(), dest)

    def get_ac_port_stats(self, ac_index):
        ac_port = self.ac_ports[ac_index]
        in_cnt = ac_port.get_ingress_counter(sdk.la_counter_set.type_e_PORT)
        eg_cnt = ac_port.get_egress_counter(sdk.la_counter_set.type_e_PORT)

        ac_info = {'index': ac_index}

        (ac_info['in_packets'], ac_info['in_bytes']) = in_cnt.read(0, True, True)
        (ac_info['eg_packets'], ac_info['eg_bytes']) = eg_cnt.read(0, True, True)

        return ac_info

    def print_ac_ports(self):
        for index in range(len(self.ac_ports)):
            ac_info = self.get_ac_port_stats(index)

            print(
                'AC PORT [{index}] Ingress packets {in_packets} bytes {in_bytes}, Egress packets {eg_packets} bytes {eg_bytes}'.format(
                    **ac_info))

    def speed_value_to_enum(self, speed_value):
        return {
            10: sdk.la_mac_port.port_speed_e_E_10G,
            25: sdk.la_mac_port.port_speed_e_E_25G,
            40: sdk.la_mac_port.port_speed_e_E_40G,
            50: sdk.la_mac_port.port_speed_e_E_50G,
            100: sdk.la_mac_port.port_speed_e_E_100G,
            200: sdk.la_mac_port.port_speed_e_E_200G,
            400: sdk.la_mac_port.port_speed_e_E_400G,
            800: sdk.la_mac_port.port_speed_e_E_800G,
        }[int(speed_value)]

    def loopback_mode_value_to_enum(self, lb_mode_value):
        return {
            'none': sdk.la_mac_port.loopback_mode_e_NONE,
            'pma': sdk.la_mac_port.loopback_mode_e_PMA_CORE_CLK,
            'pma_serdes': sdk.la_mac_port.loopback_mode_e_PMA_SRDS_CLK,
            'mii': sdk.la_mac_port.loopback_mode_e_MII_CORE_CLK,
            'mii_serdes': sdk.la_mac_port.loopback_mode_e_MII_SRDS_CLK,
            'serdes': sdk.la_mac_port.loopback_mode_e_SERDES,
            'info': sdk.la_mac_port.loopback_mode_e_INFO_MAC_CLK,
        }[lb_mode_value]

    def fec_value_to_enum(self, fec_value):
        return {
            'none': sdk.la_mac_port.fec_mode_e_NONE,
            'kr': sdk.la_mac_port.fec_mode_e_KR,
            'rs-kr4': sdk.la_mac_port.fec_mode_e_RS_KR4,
            'rs-kp4': sdk.la_mac_port.fec_mode_e_RS_KP4,
        }[fec_value]

    def fc_value_to_enum(self, fc_value):
        return {
            'none': sdk.la_mac_port.fc_mode_e_NONE,
            'pause': sdk.la_mac_port.fc_mode_e_PAUSE,
            'pfc': sdk.la_mac_port.fc_mode_e_PFC,
            'cffc': sdk.la_mac_port.fc_mode_e_CFFC,
        }[fc_value]

    def run_snake(self, activate=True):
        self.init(self.args.path, self.args.id, self.args.board_cfg_path, self.args.hbm, self.args.line_card)
        args = self.args
        self.eth_port_loops = []

        if args.json_mix is not None:
            args.port_mix = 'json'
            self.load_port_mix_from_json(args.json_mix)

        if args.port_mix != 'none':
            if 'real_port' in self.port_mix[args.port_mix]:
                args.real_port = [self.port_mix[args.port_mix]['real_port']]
            else:
                args.real_port = []
            args.loop_count = 0
            args.p2p = 0

        fc_mode = self.fc_value_to_enum(args.fc)
        fabric_fc_mode = self.fc_value_to_enum(args.fabric_fc)
        loopback_fec = self.fec_value_to_enum(args.loop_fec)
        self.traffic_gen = False
        if not args.no_real_port:
            for real_port in args.real_port:
                self.traffic_gen = True
                traffic_gen_slice = real_port[0]
                traffic_gen_ifg = real_port[1]
                traffic_gen_serdes = real_port[2]
                traffic_gen_serdes_per_port = real_port[3]
                traffic_gen_speed = self.speed_value_to_enum(real_port[4])
                if (real_port[4] / traffic_gen_serdes_per_port) <= 10:
                    traffic_gen_fec = sdk.la_mac_port.fec_mode_e_NONE
                elif (real_port[4] / traffic_gen_serdes_per_port) < 50:
                    traffic_gen_fec = sdk.la_mac_port.fec_mode_e_RS_KR4
                else:
                    traffic_gen_fec = sdk.la_mac_port.fec_mode_e_RS_KP4
                traffic_gen_auto_negotiate = real_port[5] if len(real_port) > 5 else False

                self.initialize_entry_port(traffic_gen_slice, traffic_gen_ifg, traffic_gen_serdes, traffic_gen_speed,
                                           traffic_gen_serdes_per_port, traffic_gen_fec, fc_mode, traffic_gen_auto_negotiate)
                self.eth_port_loops.append(1)

        if args.port_mix != 'none':
            loopback_mode = self.loopback_mode_value_to_enum(args.loop_mode)
            for port_cfg in self.port_mix[args.port_mix]['loopback_ports']:
                if 'fec' in port_cfg:
                    cur_fec = port_cfg['fec']
                else:
                    cur_fec = loopback_fec

                if port_cfg['slice'] not in self.device.get_used_slices():
                    continue

                if port_cfg['fabric']:
                    self.initialize_fabric(
                        port_cfg['slice'],
                        port_cfg['ifg'],
                        port_cfg['serdes'],
                        port_cfg['serdes_count'],
                        port_cfg['speed'],
                        fabric_fc_mode,
                        self.loopback_mode_value_to_enum(args.loop_mode))
                else:

                    self.initialize_loopback(
                        port_cfg['slice'],
                        port_cfg['ifg'],
                        port_cfg['serdes'],
                        port_cfg['speed'],
                        port_cfg['serdes_count'],
                        cur_fec,
                        fc_mode,
                        loopback_mode,
                        port_cfg['an'],
                        1)
                    self.eth_port_loops.append(port_cfg['p2p_loops'])

        if args.loop_count > 0:
            loopback_slice = args.loop_port[0]
            assert (loopback_slice in self.device.get_used_slices())

            loopback_ifg = args.loop_port[1]
            loopback_serdes = args.loop_port[2]
            loopback_serdes_per_port = args.loop_type[0]
            loopback_speed = self.speed_value_to_enum(args.loop_type[1])
            loopback_mode = self.loopback_mode_value_to_enum(args.loop_mode)
            loopback_fec = self.fec_value_to_enum(args.loop_fec)
            loopback_auto_negotiate = False
            assert(loopback_slice in self.device.get_used_slices())
            self.initialize_loopback(loopback_slice, loopback_ifg, loopback_serdes, loopback_speed,
                                     loopback_serdes_per_port, loopback_fec, fc_mode,
                                     loopback_mode,
                                     loopback_auto_negotiate,
                                     args.loop_count)

        time.sleep(1)
        link_status = False
        if activate:
            print('Start activate')
            self.mph.mac_ports_activate(args.module_type, args.params_json)
            print('Finished activate')

            port_timeout = SLOW_PORT_TO_LINKUP_TIMEOUT
            if self.ll_device.is_gibraltar() or self.ll_device.is_graphene:
                # Port bringup time on GB/GR is much faster
                port_timeout = FAST_PORT_TO_LINKUP_TIMEOUT
            link_status = self.mph.wait_mac_ports_up(port_timeout)

            all_pcs_lock = self.mph.print_mac_up()

        if args.line_card:
            self.activate_fabric()

        if (args.p2p > 0 or args.port_mix != 'none'):
            if self.ll_device.is_gibraltar():
                eth_ports_24 = []
                eth_ports_16 = []
                for eth_port in self.eth_ports:
                    slice = eth_port.get_system_port().get_slice()
                    ifg = eth_port.get_system_port().get_ifg()
                    first_pif = eth_port.get_system_port().get_base_pif()
                    if self.device.get_num_of_serdes(slice, ifg) == 24:
                        eth_ports_24.append(eth_port)
                    else:
                        eth_ports_16.append(eth_port)
                        # since packet is injected to 2/0/0 for the 2nd flow, we need to calculate the
                        # proper dest mac and vlan id.
                        if (slice == 2 and ifg == 0 and first_pif == 0):
                            self.dst_id_offset = len(eth_ports_16) - 1

            if args.protocol == 'ipv4':
                '''
                flows = [{'vlan_id_base': 0x100,
                          'mac_addr_base': 0xcafecafecafe,
                          'eth_ports': eth_ports_24,
                          'vrf_gid_base': 0x200,
                          'nh_gid_base': 0x000,
                          'ip_dest_addr': 0xc0a80a00},
                         {'vlan_id_base': 0x200,
                          'mac_addr_base': 0x22222222260a,
                          'eth_ports': eth_ports_16,
                          'vrf_gid_base': 0x500,
                          'nh_gid_base': 0x400,
                          'ip_dest_addr': 0xc0a90a00}]
                '''
                flows = [{'vlan_id_base': 0x100, 'mac_addr_base': 0xcafecafecafe, 'eth_ports': self.eth_ports,
                          'vrf_gid_base': 0x200, 'nh_gid_base': 0x000, 'ip_dest_addr': 0xc0a80a00}]
                self.initialize_ipv4_snake(loops=args.p2p, use_external=args.p2p_ext, flows=flows)
            elif args.protocol == 'ipv6':
                if self.ll_device.is_gibraltar():

                    flows = [{'vlan_id_base': 0x100,
                              'mac_addr_base': 0xcafecafecafe,
                              'eth_ports': eth_ports_24,
                              'vrf_gid_base': 0x200,
                              'nh_gid_base': 0x000,
                              'ip_dest_addr': 0x11110db80a0b12f0},
                             {'vlan_id_base': 0x200,
                              'mac_addr_base': 0x22222222260a,
                              'eth_ports': eth_ports_16,
                              'vrf_gid_base': 0x500,
                              'nh_gid_base': 0x400,
                              'ip_dest_addr': 0x11220db80a0b12f0}]
                else:
                    flows = [{'vlan_id_base': 0x100,
                              'mac_addr_base': 0xcafecafecafe,
                              'eth_ports': self.eth_ports,
                              'vrf_gid_base': 0x200,
                              'nh_gid_base': 0x000,
                              'ip_dest_addr': 0x11110db80a0b12f0}]
                self.initialize_ipv6_snake(loops=args.p2p, use_external=args.p2p_ext, flows=flows)
            else:
                '''
                flows = [{'vlan_id_base':0x100,'eth_ports':eth_ports_24},
                         {'vlan_id_base':0x200,'eth_ports':eth_ports_16}]
                self.initialize_p2p(loops=args.p2p, use_external=args.p2p_ext, remote=args.device2device, flows=flows)
                '''
                flows = [{'vlan_id_base': 0x100, 'eth_ports': self.eth_ports}]
                self.initialize_p2p(
                    loops=args.p2p,
                    use_external=args.p2p_ext,
                    remote=args.device2device,
                    flows=flows,
                    punt_traffic=args.punt_traf)
        return link_status

    def check_sim_utils_exists(self):
        import sys
        modules = sys.modules.keys()
        if 'sim_utils' in modules:
            return True
        else:
            return False

    def init_parser(self):
        parser = argparse.ArgumentParser(description='Stand alone configuration.')

        parser.add_argument('--path', default='/dev/uio0',
                            help='Device path, default %(default)s')
        parser.add_argument('--id', type=int, default=0,
                            help='Device ID, default %(default)i')
        parser.add_argument(
            '--board_cfg_path',
            help='Add board specific configurations from json file, default %(default)s',
            default=None)
        self.real_port_default = [2, 0, 0, 2, 50]
        parser.add_argument('--real_port', type=int, nargs=5, action='append',
                            metavar=('Slice', 'IFG', 'first-SerDes', 'SerDes-count', 'port-speed'),
                            help='Real port definition, default {}'.format(self.real_port_default))
        parser.add_argument('--loop_count', type=int, default=0,
                            help='Loopback port count, default %(default)s')
        parser.add_argument(
            '--device_frequency_khz',
            type=int,
            default=None,
            help='Device frequency in KHz to configure. If not provided, use the device\'s default, default %(default)s')
        parser.add_argument('--loop_port', type=int, nargs=3, default=[2, 1, 0],
                            metavar=('Slice', 'IFG', 'SerDes'),
                            help='First loopback port, default %(default)s')
        parser.add_argument('--loop_type', type=int, nargs=2, default=[2, 50],
                            metavar=('SerDes-count', 'port-speed'),
                            help='Loopback port type (e.g. 2 50, 4 100), default %(default)s')
        parser.add_argument(
            '--loop_mode',
            choices=[
                'none',
                'pma',
                'pma_serdes',
                'mii',
                'mii_serdes',
                'serdes',
                'info'],
            default='pma',
            help='Loopback mode, default %(default)s')
        parser.add_argument('--loop_fec', choices=['none', 'kr', 'rs-kr4', 'rs-kp4'], default='rs-kp4',
                            help='Loopback FEC, default %(default)s')
        parser.add_argument('--fc', choices=['none', 'pause', 'pfc'], default='none',
                            help='FC (Flow Control) mode, default %(default)s')
        parser.add_argument('--fabric_fc', choices=['none', 'cffc'], default='none',
                            help='Fabric FC (Flow Control) mode, default %(default)s')
        parser.add_argument(
            '--p2p',
            type=int,
            nargs='?',
            const=1,
            default=0,
            metavar='N',
            help='Connect ports using Point2Point with N loops on each port, default disabled, if specified default N is 1')
        parser.add_argument('--p2p_ext', default=False, action='store_true', help='Port connected externally but not in loopback')
        parser.add_argument('--device2device', default=False, action='store_true',
                            help='Device connected externally to different device')
        parser.add_argument('--punt_traf', default=False, action='store_true',
                            help='Setup topology to punt traffic to the CPU')
        parser.add_argument(
            '--port_mix',
            choices=[
                'none',
                'sherman_4',
                'sherman_5'],
            default='none',
            help='Predefined port mix configuration, default %(default)s')
        parser.add_argument('--json_mix', default=None,
                            help='Port mix configuration using JSON file, default %(default)s')
        parser.add_argument('--cache', default=False, action='store_true',
                            help='enable cache mode')
        parser.add_argument('--hbm',
                            type=int,
                            nargs='?',
                            const=2,
                            default=0,
                            metavar='N',
                            choices=range(0, 2),
                            help='Enable HBM mode. Default is disabled. Modes: 0 - disabled, 1 - enabled, 2 - enabled and force')
        parser.add_argument('--pacific_b0_ifg', default=False, action='store_true', help='Enable Pacific B0 IFG fixes')
        parser.add_argument('--protocol', choices=['none', 'ipv4', 'ipv6'], default='none',
                            help='Protocol type, ipv4, ipv6 or none, default %(default)s')
        # Currently module type is global but need to be per-port, possible added to port mix
        parser.add_argument('--module_type', choices=['OPTIC', 'LOOPBACK', 'COPPER'], default='COPPER',
                            help='Connector module type, default %(default)s')
        parser.add_argument('--params_json', default=None,
                            help='Port definition JSON file, default %(default)s')
        parser.add_argument('--use_test_rom', default=None,
                            help='SerDes test ROM format (0xFW_REV_FW_BUILD), ex: 0x1097_2081')
        parser.add_argument('--line_card', default=False, action='store_true', help='LC snake')
        parser.add_argument('--serdes_low_power', default=False, action='store_true',
                            help='Enable SerDes low power mode')
        parser.add_argument('--disable_serdes_post_anlt_tune', default=False, action='store_true',
                            help='Disable SerDes Post ANLT Tune, default=False')
        parser.add_argument('--quiet', default=False, action='store_true',
                            help='Disable HLD verbosity')
        parser.add_argument('--debug_trace', default=False, action='store_true',
                            help='Enable HLD debug trace')
        parser.add_argument('--refclk', type=int, nargs=4, default=None,
                            metavar=('IFG0_1_2', 'IFG_3_4_5', 'IFG_6_7_8', 'IFG_9_10_11'),
                            help='Set REFCLK selector per IFG group for Pacific. Default doesnt is SDK default')
        parser.add_argument('--disable_ports_activate', default=False, action='store_true',
                            help='Disable Ports Activate, default=False')
        parser.add_argument('--no_real_port', default=False, action='store_true',
                            help='Do not create real port')
        parser.add_argument('--alpha_hbm_ports', default=[], type=lambda s: [int(item) for item in s.split(',')],
                            help='system_ports list to force evict to HBM, overrides PORTS_TO_EVICT variable')
        parser.add_argument('--fabric_200g', default=False, action='store_true',
                            help='Work with Fabric 200G ports, default=False')
        self.parser = parser

    def parse_args(self):
        self.init_parser()
        self.args = self.parser.parse_args()

        if self.args.real_port is None:
            self.args.real_port = [self.real_port_default]

    def set_default_args(self):
        self.args = argparse.Namespace()
        self.args.board_cfg_path = None
        self.args.device_frequency_khz = None
        self.args.serdes_low_power = False
        self.args.disable_serdes_post_anlt_tune = False
        self.args.fc = 'none'
        self.args.fabric_fc = 'none'
        self.args.hbm = HBM_MODE_DISABLE
        self.args.pacific_b0_ifg = False
        self.args.id = 0
        self.args.json_mix = None
        self.args.alpha_hbm_ports = None
        self.args.cache = False
        self.args.loop_count = 107
        self.args.loop_fec = 'rs-kp4'
        self.args.loop_mode = 'pma'
        self.args.loop_port = [5, 0, 0]
        self.args.loop_type = [2, 100]
        self.args.module_type = 'COPPER'
        self.args.p2p = 1
        self.args.p2p_ext = False
        self.args.params_json = None
        self.args.path = '/dev/uio0'
        self.args.port_mix = 'none'
        self.args.real_port = [[4, 1, 16, 2, 100]]
        self.args.protocol = 'none'
        self.args.use_test_rom = None
        self.args.line_card = False
        self.args.quiet = False
        self.args.debug_trace = False
        self.args.device2device = False
        self.args.refclk = None
        self.args.disable_ports_activate = False
        self.args.no_real_port = False
        self.args.punt_traf = False
        self.args.fabric_200g = False


if __name__ == '__main__':
    import sys
    tc = snake_base_topology()
    if len(sys.argv) > 1:
        # setup arg parser
        tc.parse_args()
    else:
        tc.set_default_args()
    tc.run_snake(not tc.args.disable_ports_activate)
    # Ready to inject traffic
