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


#
# Create network topology
#
######################################################
#
# reg - regular route
# def - default route
# ext - extra route
#
#
#                                           Global-VRF
#
#                                               VRF
#     ___________________________________________|__________________________________________________
#     |                                 |         |           |                 |                  |
#     |   rx-L3-AC-ONE-TAG-PORT         |         |           |                 |                  |
#     |           |               rx-SVI-PORT     |           |                 |                  |  FEC-svi-reg  FEC-svi-def   FEC-svi-ext
#     |           |                     |         |           |                 |                  |    |            |             |
#     |           |               rx-SWITCH       |           |                 |                  |  NH-svi-reg   NH-svi-def    NH-svi-ext
#     |           |                     |         |           |                 |                  |    |            |             |
#  rx-L3-AC-PORT  |               rx-L2-AC-PORT   |           |                 |                tx-SVI-PORT_________|_____________|
#     |           |                     |         |           |                 |                       |
#     |           |  ___________________/         |           |                 |                       |
#     |           | |                             |           |                 |                  tx-SWITCH________________________
#    rx-ETHERNET-PORT                             |           |                 |                     |             |               |
#                                                 |           |                 |                     |             |               |
#                                                 |           |                 |                     |             |               |
#                                                 |           |                 |                     |             |      tx-svi-L2-AC-PORT-reg
#                   FEC-l3-ac-reg                 |           |                 |                     |             |               |
#                        |                        |           |                 |                     |      tx-L2-AC-PORT-def      |
#                        |          _____________ |           |                 |                     |             |               |
#                    NH-l3-ac-reg   |                         |                 |                tx-L2-AC-PORT-ext  |               |
#                        |          |                         |                 |                      |            |               |
#                        |     _____|                         |                 |                      |            |          tx-svi-ETHERNET-PORT-reg
#                        |    |                               |                 |                      |            |
#                     tx-L3-AC-PORT-reg                       |                 |                      |         tx-svi-ETHERNET-PORT-def
#                          |                                  |                 |                      |
#                          |                                  |                 |                    tx-svi-ETHERNET-PORT-ext
#                          |                     _____________|                 |
#        tx-l3-ac-ETHERNET-PORT-reg              |                              |
#                                                |                              |
#                                                |  FEC-l3-ac-def               |  FEC-l3-ac-ext
#                                                |       |                      |       |
#                                                |       |                      |       |
#                                                |   NH-l3-ac-def               |   NH-l3-ac-ext
#                                                |_      |                      |       |
#                                                  |     |                      |       |
#                                                  |     |                      |       |
#                                                tx-L3-AC-PORT-def           tx-L3-AC-PORT-ext
#                                                         |                              |
#                                                         |                              |
#                                            tx-l3-ac-ETHERNET-PORT-def     tx-l3-ac-ETHERNET-PORT-ext
#
#
#
#
#


from leaba import sdk
import voq_allocator
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
import packet_test_utils as U
import decor

if decor.is_asic5():
    NUM_SLICES_PER_DEVICE = 1
elif decor.is_asic3():
    NUM_SLICES_PER_DEVICE = 8
else:
    NUM_SLICES_PER_DEVICE = 6

if decor.is_asic5():
    NUM_SLICE_PAIRS_PER_DEVICE = 1
else:
    NUM_SLICE_PAIRS_PER_DEVICE = NUM_SLICES_PER_DEVICE // 2

NETWORK_SLICES = NUM_SLICES_PER_DEVICE

FIRST_SERDES = 0
LAST_SERDES = 1
FIRST_SERDES1 = 2
LAST_SERDES1 = 3
NATIVE_VOQ_SET_SIZE = 16
NUM_IFGS_PER_SLICE = 2
NUM_NATIVE_VOQ_SETS = 24576 / 16  # MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE / NATIVE_VOQ_SET_SIZE
NUM_SERDES_PER_IFG = 18
NUM_OQ_PER_SERDES = 8
NUM_OQ_PER_IFG = NUM_OQ_PER_SERDES * NUM_SERDES_PER_IFG + NUM_OQ_PER_SERDES + \
    NUM_OQ_PER_SERDES  # Last two elements are: Recycle Host interfaces

KILO = 1000
MEGA = 1000 * KILO
GIGA = 1000 * MEGA
PORT_SPEED_VALUE = [10, 25, 40, 50, 100, 200, 400, 800]    # The value in Gbps (to translate the enum)
# Testing definitions for NPUH inject ports
INJECT_PORT_BASE_GID = 1200
INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "ca:fe:ca:fe:12:34"

MIN_SYSTEM_PORT_GID = 4

if decor.is_asic5():
    RCY_SYS_PORT_GID_BASE = (1 << 6) - 1  # TODO asic5 check this value
elif decor.is_asic3():
    RCY_SYS_PORT_GID_BASE = 640 - 2  # there's a test that uses DEVICE__MAX_SYSTEM_PORT_GID
else:
    RCY_SYS_PORT_GID_BASE = (1 << 12) - 2  # there's a test that uses DEVICE__MAX_SYSTEM_PORT_GID


global_svl_mode_flag = False

SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID = 10


def svl_mode_init(device):
    # stackwise virtual mode init and redefine
    svl_mode = device.get_bool_property(sdk.la_device_property_e_ENABLE_SVL_MODE)
    global RCY_SYS_PORT_GID_BASE
    global INJECT_PORT_BASE_GID
    global global_svl_mode_flag
    global_svl_mode_flag = svl_mode
    if svl_mode:
        device_id = device.get_ll_device().get_device_id()
        base_gid = ((1 << 10) - 1)
        RCY_SYS_PORT_GID_BASE = (base_gid | (device_id << 10))
        base_gid = ((1 << 10) - 12)
        INJECT_PORT_BASE_GID = (base_gid | (device_id << 10))


class device_mode(Enum):
    STANDALONE = 1,
    LINECARD = 2,
    FABRIC_ELEMENT = 3,


# The following helper functions are needed to accommodate the case
# where a platform needs to use a different value for slice/ifg/serdes
# when creating ports independent from default topology
# Main user is Asic5 which has 1 slice, 1 ifg and 48 serdes
def get_device_slice(pi_slice):
    if (decor.is_asic5()):
        return 0
    else:
        return pi_slice


def get_device_ifg(pi_ifg):
    if (decor.is_asic5()):
        return 0
    else:
        return pi_ifg


def get_device_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 20
    else:
        return pif_first


def get_device_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 21
    else:
        return pif_last


def get_device_next_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 22
    else:
        return pif_first


def get_device_next_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 23
    else:
        return pif_last


def get_device_next2_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 24
    else:
        return pif_first


def get_device_next2_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 25
    else:
        return pif_last


def get_device_out_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 26
    else:
        return pif_first


def get_device_out_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 27
    else:
        return pif_last


def get_device_out_next_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 28
    else:
        return pif_first


def get_device_out_next_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 29
    else:
        return pif_last


def get_device_out_next_next_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 30
    else:
        return pif_first


def get_device_out_next_next_last_serdes(pif_first):
    if (decor.is_asic5()):
        return 31
    else:
        return pif_first


def get_device_punt_inject_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 32
    else:
        return pif_first


def get_device_punt_inject_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 33
    else:
        return pif_last


def get_device_next3_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 34
    else:
        return pif_first


def get_device_next3_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 35
    else:
        return pif_last


def get_device_next4_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 36
    else:
        return pif_first


def get_device_next4_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 37
    else:
        return pif_last


def get_device_next5_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 38
    else:
        return pif_first


def get_device_next5_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 39
    else:
        return pif_last


def get_device_rx_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 0
    else:
        return pif_first


def get_device_rx_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 1
    else:
        return pif_last


def get_device_tx_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 2
    else:
        return pif_first


def get_device_tx_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 3
    else:
        return pif_last


def get_device_tx1_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 4
    else:
        return pif_first


def get_device_tx1_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 5
    else:
        return pif_last


def get_device_tx2_first_serdes(pif_first):
    if (decor.is_asic5()):
        return 6
    else:
        return pif_first


def get_device_tx2_last_serdes(pif_last):
    if (decor.is_asic5()):
        return 7
    else:
        return pif_last

# MATILDA_SAVE -- need review
# checks if the device is one of the
# Mathilda models 32 - in which case it does not support Fabric and Line-card modes


def can_be_used_as_fabric(device):
    return len(device.get_used_slices()) > 4


def is_matilda_model(device):
    prop = device.get_int_property(sdk.la_device_property_e_MATILDA_MODEL_TYPE)
    return prop > 0

# Chooses an id of an Enabled slice - to replace a Disabled slice, for the test.
# If the given default_slice_id points to a disabled slice, choose the first of the prefered_slice_ids
# that points to an Enabled slice. If all prefered_slice_ids are disabled as well, take
# device.get_used_slices()[falback_index]


def choose_active_slices(device, default_slice_id, prefered_slice_ids):
    # Asic5 has only 1 slice
    if decor.is_asic5():
        return 0
    used_slices = device.get_used_slices()
    if default_slice_id in used_slices:
        return default_slice_id
    for val in prefered_slice_ids:
        if val in used_slices:
            return val
    return default_slice_id


def resolve_ifg_conflict(slice, other_slice, ifg, other_ifg):
    if decor.is_asic5():
        return 0
    if slice != other_slice or ifg != other_ifg:
        return ifg
    ifg += 1
    if ifg > 1:
        ifg = 0
    return ifg


class topology:
    ingress_qos_profile_def = None
    egress_qos_profile_def = None
    uc_voq_cgm_profile_def = None
    mc_voq_cgm_profile_def = None
    uc_profile_def = None
    per_ifg_meter_profile_def = None
    pps_meter_profile_def = None
    global_meter_profile_def = None
    global_stat_meter_profile_def = None
    meter_action_profile_def = None
    voq_allocators = {}
    persistant_voq_allocators = {}
    recycle_ports = []
    inject_ports = []
    acl_profile_ipv4_def = None
    acl_profile_ipv6_def = None
    acl_profile_mac_def = None
    ingress_acl_key_profile_ipv4_def = None
    ingress_acl_key_profile_ipv6_def = None
    egress_acl_key_profile_ipv4_def = None
    egress_acl_key_profile_ipv6_def = None
    acl_command_profile_def = None

    def __init__(self, testcase, device, create_default_topology=True, use_exceptions=True):
        if use_exceptions:
            sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)

        self.testcase = testcase
        self.device = device

        slice_modes = {device.get_slice_mode(sid) for sid in device.get_used_slices()}
        if sdk.la_slice_mode_e_CARRIER_FABRIC in slice_modes and sdk.la_slice_mode_e_NETWORK in slice_modes:
            self.device_mode = device_mode.LINECARD
        elif sdk.la_slice_mode_e_CARRIER_FABRIC in slice_modes:
            self.device_mode = device_mode.FABRIC_ELEMENT
        else:
            self.device_mode = device_mode.STANDALONE

        if self.device_mode == device_mode.LINECARD or self.device_mode == device_mode.FABRIC_ELEMENT:
            # some devices can only be used in standalone mode
            if not can_be_used_as_fabric(self.device):
                testcase.skipTest("This device cannot be used in Line-card mode. Thus, this test is irrelevant.")
                return

            if self.device_mode == device_mode.FABRIC_ELEMENT:
                return

        self.init_topology_globals()
        # SVL
        svl_mode_init(device)

        self.create_default_profiles()
        if device.get_ll_device().is_pacific():
            self.init_default_mc_cgm()

        if create_default_topology:
            self.create_topology()
        self.topology_created = create_default_topology

        topology.create_voq_allocator(device)
        topology.init_voq_allocator(device)

    @staticmethod
    def tx_l2_ac_port_def(self):
        return self.topology.tx_l2_ac_port_def

    @staticmethod
    def tx_switch(self):
        return self.topology.tx_switch

    @staticmethod
    def get_oq_num(ifg, serdes):
        oq = ifg * NUM_OQ_PER_IFG + serdes * NUM_OQ_PER_SERDES
        return oq

    @staticmethod
    def create_voq_allocator(current_device_obj):
        if current_device_obj not in topology.voq_allocators.keys():
            slice_modes = NUM_SLICES_PER_DEVICE * [sdk.la_slice_mode_e_INVALID]
            for slice_id in current_device_obj.get_used_slices():
                slice_modes[slice_id] = current_device_obj.get_slice_mode(slice_id)

            if current_device_obj not in topology.persistant_voq_allocators.keys():
                first_voq = current_device_obj.get_limit(sdk.limit_type_e_DEVICE__FIRST_ALLOCATABLE_VOQ)
                topology.persistant_voq_allocators[current_device_obj] = voq_allocator.voq_allocator(
                    first_voq, slice_modes, is_persistant=True)

            first_voq = topology.persistant_voq_allocators[current_device_obj].maximal_voq_index
            topology.voq_allocators[current_device_obj] = voq_allocator.voq_allocator(first_voq, slice_modes)

    @staticmethod
    def init_voq_allocator(current_device_obj):
        for voq_set in current_device_obj.get_objects(sdk.la_object.object_type_e_VOQ_SET):
            topology.voq_allocators[current_device_obj].insert_voq_set(
                voq_set.get_destination_slice(),
                voq_set.get_base_voq_id(),
                voq_set.get_base_vsc_vec())

    @staticmethod
    def allocate_voq_set(
            current_device_obj,
            dest_device,
            dest_slice,
            dest_ifg,
            voq_set_size,
            is_mc=False,
            use_presistant_alocation=False):
        topology.create_voq_allocator(current_device_obj)
        if use_presistant_alocation:
            return topology.persistant_voq_allocators[current_device_obj].allocate_voq_set(
                dest_slice, dest_ifg, voq_set_size, dest_device)
        return topology.voq_allocators[current_device_obj].allocate_voq_set(dest_slice, dest_ifg, voq_set_size, dest_device)

    @staticmethod
    def deallocate_voq_set(
            current_device_obj,
            dest_device,
            dest_slice,
            dest_ifg,
            voq_set_size,
            base_voq_id,
            base_vsc_vec,
            is_mc=False):
        if current_device_obj in topology.voq_allocators.keys():
            topology.voq_allocators[current_device_obj].deallocate_voq_set(
                dest_slice, dest_ifg, voq_set_size, base_voq_id, base_vsc_vec, dest_device)

    @staticmethod
    def reset(device, keep_inject_ports=False):
        topology.ingress_qos_profile_def = None
        topology.egress_qos_profile_def = None
        topology.uc_voq_cgm_profile_def = None
        topology.mc_voq_cgm_profile_def = None
        topology.uc_profile_def = None
        topology.per_ifg_meter_profile_def = None
        topology.pps_meter_profile_def = None
        topology.global_meter_profile_def = None
        topology.meter_action_profile_def = None
        topology.acl_profile_ipv4_def = None
        topology.acl_profile_ipv6_def = None
        topology.acl_profile_mac_def = None
        topology.ingress_acl_key_profile_ipv4_def = None
        topology.ingress_acl_key_profile_ipv6_def = None
        topology.egress_acl_key_profile_ipv4_def = None
        topology.egress_acl_key_profile_ipv6_def = None
        topology.acl_command_profile_def = None
        topology.voq_allocators = {}
        if not keep_inject_ports:
            topology.destroy_inject_ports()
        if len(device.get_objects(sdk.la_object.object_type_e_SYSTEM_PORT)) == 0:
            topology.persistant_voq_allocators = {}

    def init_topology_globals(self):
        global NUM_SLICES_PER_DEVICE, NETWORK_SLICES, NUM_SLICE_PAIRS_PER_DEVICE, NUM_IFGS_PER_SLICE
        global RX_SLICE, TX_SLICE_REG, TX_SLICE_DEF, TX_SLICE_EXT
        global RX_IFG, RX_IFG1, TX_IFG_DEF, TX_IFG_EXT, TX_IFG_REG
        global FIRST_SERDES, LAST_SERDES, FIRST_SERDES1, LAST_SERDES1
        global FIRST_SERDES_L3_DEF, LAST_SERDES_L3_DEF
        global FIRST_SERDES_L3_REG, LAST_SERDES_L3_REG
        global FIRST_SERDES_L3_EXT, LAST_SERDES_L3_EXT
        global FIRST_SERDES_SVI_DEF, LAST_SERDES_SVI_DEF
        global FIRST_SERDES_SVI_REG, LAST_SERDES_SVI_REG
        global FIRST_SERDES_SVI_EXT, LAST_SERDES_SVI_EXT
        global RCY_SYS_PORT_GID_BASE, INJECT_PORT_BASE_GID

        if decor.is_asic5():
            NUM_SLICES_PER_DEVICE = 1
            NETWORK_SLICES = 1
            NUM_SLICE_PAIRS_PER_DEVICE = 1
            NUM_IFGS_PER_SLICE = 1

            RX_SLICE = 0
            RX_IFG = 0
            RX_IFG1 = 0

            TX_SLICE_REG = 0
            TX_SLICE_DEF = 0
            TX_SLICE_EXT = 0

            TX_IFG_DEF = 0
            TX_IFG_EXT = 0
            TX_IFG_REG = 0

            FIRST_SERDES = 0
            LAST_SERDES = 1
            FIRST_SERDES1 = 2
            LAST_SERDES1 = 3

            FIRST_SERDES_L3_DEF = 4
            LAST_SERDES_L3_DEF = 5

            FIRST_SERDES_L3_REG = 6
            LAST_SERDES_L3_REG = 7

            FIRST_SERDES_L3_EXT = 8
            LAST_SERDES_L3_EXT = 9

            FIRST_SERDES_SVI_DEF = 10
            LAST_SERDES_SVI_DEF = 11

            FIRST_SERDES_SVI_REG = 12
            LAST_SERDES_SVI_REG = 13

            FIRST_SERDES_SVI_EXT = 14
            LAST_SERDES_SVI_EXT = 15
            # The following 2 values have to looked at after Asic5 NPL code is complete
            RCY_SYS_PORT_GID_BASE = (1 << 6) - 1
            INJECT_PORT_BASE_GID = (1 << 6) - 2
        else:
            NUM_SLICES_PER_DEVICE = 8 if decor.is_asic3() else 6
            NETWORK_SLICES = NUM_SLICES_PER_DEVICE
            NUM_SLICE_PAIRS_PER_DEVICE = NUM_SLICES_PER_DEVICE // 2
            NUM_IFGS_PER_SLICE = 2

            RX_SLICE = choose_active_slices(self.device, 5, [0, NUM_SLICES_PER_DEVICE - 1])
            RX_IFG = 0
            RX_IFG1 = 1

            TX_SLICE_REG = choose_active_slices(self.device, 1, [1, NUM_SLICES_PER_DEVICE - 1])
            TX_SLICE_DEF = choose_active_slices(self.device, 2, [2, NUM_SLICES_PER_DEVICE - 2])
            TX_SLICE_EXT = choose_active_slices(self.device, 3, [3, 2])

            TX_IFG_DEF = 1
            TX_IFG_EXT = resolve_ifg_conflict(TX_SLICE_DEF, TX_SLICE_EXT, 1, TX_IFG_DEF)
            TX_IFG_REG = 1

            FIRST_SERDES = 0
            LAST_SERDES = 1
            FIRST_SERDES1 = 2
            LAST_SERDES1 = 3

            FIRST_SERDES_L3_DEF = 2
            FIRST_SERDES_L3_REG = 2
            FIRST_SERDES_L3_EXT = 2

            LAST_SERDES_L3_DEF = 3
            LAST_SERDES_L3_REG = 3
            LAST_SERDES_L3_EXT = 3

            FIRST_SERDES_SVI_DEF = 0
            FIRST_SERDES_SVI_REG = 0
            FIRST_SERDES_SVI_EXT = 0

            LAST_SERDES_SVI_DEF = 1
            LAST_SERDES_SVI_REG = 1
            LAST_SERDES_SVI_EXT = 1
            if self.device_mode == device_mode.LINECARD:
                RX_SLICE = 0
                TX_SLICE_EXT = 2
                TX_IFG_EXT = 0

    def create_default_meter_profile(self):
        topology.per_ifg_meter_profile_def = self.device.create_meter_profile(
            sdk.la_meter_profile.type_e_PER_IFG,
            sdk.la_meter_profile.meter_measure_mode_e_BYTES,
            sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
            sdk.la_meter_profile.color_awareness_mode_e_AWARE)
        for s in self.device.get_used_slices():
            for i in range(NUM_IFGS_PER_SLICE):
                si = sdk.la_slice_ifg()
                si.slice = s
                si.ifg = i
                topology.per_ifg_meter_profile_def.set_cbs(si, 10240)            # Arbitrary value
                topology.per_ifg_meter_profile_def.set_ebs_or_pbs(si, 2 * 10240)  # Arbitrary value

        topology.global_meter_profile_def = self.device.create_meter_profile(
            sdk.la_meter_profile.type_e_GLOBAL,
            sdk.la_meter_profile.meter_measure_mode_e_BYTES,
            sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
            sdk.la_meter_profile.color_awareness_mode_e_AWARE)
        topology.global_meter_profile_def.set_cbs(10240)            # Arbitrary value
        topology.global_meter_profile_def.set_ebs_or_pbs(2 * 10240)  # Arbitrary value

        topology.pps_meter_profile_def = self.device.create_meter_profile(
            sdk.la_meter_profile.type_e_GLOBAL,
            sdk.la_meter_profile.meter_measure_mode_e_PACKETS,
            sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
            sdk.la_meter_profile.color_awareness_mode_e_AWARE)
        topology.pps_meter_profile_def.set_cbs(1024)            # Arbitrary value
        topology.pps_meter_profile_def.set_ebs_or_pbs(2 * 1024)  # Arbitrary value

    def create_default_meter_action_profile(self):
        topology.meter_action_profile_def = self.device.create_meter_action_profile()
        # Pass green packets
        topology.meter_action_profile_def.set_action(sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_GREEN, False,
                                                     False, sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_GREEN)

        # When either meter or rate-limiter is not green
        # 1) Mark as congested
        # 2) Mark with highest input color
        topology.meter_action_profile_def.set_action(sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, False,
                                                     True, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_YELLOW)
        topology.meter_action_profile_def.set_action(sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_GREEN, False,
                                                     True, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_YELLOW)
        topology.meter_action_profile_def.set_action(sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_YELLOW, False,
                                                     True, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_YELLOW)

        # Mark as red when either meter or rate-limiter are red
        topology.meter_action_profile_def.set_action(sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_RED, True,
                                                     True, sdk.la_qos_color_e_RED, sdk.la_qos_color_e_YELLOW)
        topology.meter_action_profile_def.set_action(sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_RED, True,
                                                     True, sdk.la_qos_color_e_RED, sdk.la_qos_color_e_YELLOW)
        topology.meter_action_profile_def.set_action(sdk.la_qos_color_e_RED, sdk.la_qos_color_e_GREEN, True,
                                                     True, sdk.la_qos_color_e_RED, sdk.la_qos_color_e_YELLOW)
        topology.meter_action_profile_def.set_action(sdk.la_qos_color_e_RED, sdk.la_qos_color_e_YELLOW, True,
                                                     True, sdk.la_qos_color_e_RED, sdk.la_qos_color_e_YELLOW)
        topology.meter_action_profile_def.set_action(sdk.la_qos_color_e_RED, sdk.la_qos_color_e_RED, True,
                                                     True, sdk.la_qos_color_e_RED, sdk.la_qos_color_e_YELLOW)

    def create_default_ipv4_ingress_acl_key_profile(self):
        topology.ingress_acl_key_profile_ipv4_def = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV4, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_IPV4, 0)

    def create_default_ipv6_ingress_acl_key_profile(self):
        topology.ingress_acl_key_profile_ipv6_def = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV6, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_IPV6, 0)

    def create_default_ipv4_egress_acl_key_profile(self):
        topology.egress_acl_key_profile_ipv4_def = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV4, sdk.la_acl_direction_e_EGRESS, sdk.LA_ACL_KEY_IPV4, 0)

    def create_default_ipv6_egress_acl_key_profile(self):
        topology.egress_acl_key_profile_ipv6_def = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV6, sdk.la_acl_direction_e_EGRESS, sdk.LA_ACL_KEY_IPV6, 0)

    def create_default_acl_command_profile(self):
        topology.acl_command_profile_def = self.device.create_acl_command_profile(sdk.LA_ACL_COMMAND)

    def create_default_profiles(self):
        # Default QOS profiles
        topology.ingress_qos_profile_def = ingress_qos_profile(self.testcase, self.device)
        topology.ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_enabled(True)
        topology.ingress_qos_profile_def.set_default_values()
        topology.egress_qos_profile_def = egress_qos_profile(self.testcase, self.device)
        topology.egress_qos_profile_def.set_default_values()
        topology.uc_voq_cgm_profile_def = self.create_and_init_default_cgm_profile()
        topology.mc_voq_cgm_profile_def = self.create_and_init_default_cgm_profile()

        # Default TC profile
        topology.tc_profile_def = tc_profile(self.testcase, self.device)
        topology.tc_profile_def.set_default_values()

        # Default AC profile
        topology.ac_profile_def = ac_profile(self.testcase, self.device)

        # Default filter group
        topology.filter_group_def = self.device.create_filter_group()

        # MC profiles
        self.create_default_meter_profile()
        self.create_default_meter_action_profile()

        # Default ACL profile
        if decor.is_pacific() or decor.is_gibraltar() or decor.is_asic4() or decor.is_asic5():
            self.create_default_ipv4_ingress_acl_key_profile()
            self.create_default_ipv6_ingress_acl_key_profile()
            self.create_default_ipv4_egress_acl_key_profile()
            self.create_default_ipv6_egress_acl_key_profile()
            self.create_default_acl_command_profile()

    def create_and_init_default_cgm_profile(self):
        if decor.is_pacific():
            return self.create_and_init_default_cgm_profile_pacific()
        elif decor.is_asic4():
            return self.create_and_init_default_cgm_profile_asic4()
        return self.create_and_init_default_cgm_profile_gibraltar()

    def create_and_init_default_cgm_profile_asic4(self):
        voq_cgm_profile = self.device.create_voq_cgm_profile()
        max_buffer_pool_available_level = self.device.get_limit(
            sdk.limit_type_e_DEVICE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        max_buffer_voq_size_level = self.device.get_limit(
            sdk.limit_type_e_VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        max_age = self.device.get_limit(sdk.limit_type_e_VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        for buffer_pool_available_level in range(max_buffer_pool_available_level + 1):
            for buffer_voq_size_level in range(max_buffer_voq_size_level + 1):
                for age in range(max_age + 1):
                    for color in range(2):
                        key = sdk.la_voq_sms_size_in_bytes_color_key(buffer_pool_available_level, buffer_voq_size_level, age, color)
                        val = sdk.la_voq_sms_size_in_bytes_drop_val(0)
                        voq_cgm_profile.set_sms_size_in_bytes_drop_behavior(key, val)
                        val = sdk.la_voq_sms_size_in_bytes_mark_val(0)
                        voq_cgm_profile.set_sms_size_in_bytes_mark_behavior(key, val)

        max_packet_pool_available_level = self.device.get_limit(
            sdk.limit_type_e_DEVICE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        max_packet_voq_size_level = self.device.get_limit(
            sdk.limit_type_e_VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        for packet_pool_available_level in range(max_packet_pool_available_level + 1):
            for packet_voq_size_level in range(max_packet_voq_size_level + 1):
                for age in range(max_age + 1):
                    key = sdk.la_voq_sms_size_in_packets_key(packet_pool_available_level, packet_voq_size_level, age)
                    val = sdk.la_voq_sms_size_in_packets_drop_val(2)  # the color that starts drop is 2
                    voq_cgm_profile.set_sms_size_in_packets_drop_behavior(key, val)
                    val = sdk.la_voq_sms_size_in_packets_mark_val(2)  # the color that starts mark is 2
                    voq_cgm_profile.set_sms_size_in_packets_mark_behavior(key, val)
        return voq_cgm_profile

    def create_and_init_default_cgm_profile_gibraltar(self):
        voq_cgm_profile = self.device.create_voq_cgm_profile()

        max_buffer_pool_available_level = self.device.get_limit(
            sdk.limit_type_e_DEVICE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        max_buffer_voq_size_level = self.device.get_limit(
            sdk.limit_type_e_VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        max_age = self.device.get_limit(sdk.limit_type_e_VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS)
        for buffer_pool_available_level in range(max_buffer_pool_available_level):
            for buffer_voq_size_level in range(max_buffer_voq_size_level):
                for age in range(max_age):
                    for color in range(2):
                        key = sdk.la_voq_sms_size_in_bytes_color_key(buffer_pool_available_level, buffer_voq_size_level, age, color)
                        val = sdk.la_voq_sms_size_in_bytes_drop_val(0)
                        voq_cgm_profile.set_sms_size_in_bytes_drop_behavior(key, val)
                        val = sdk.la_voq_sms_size_in_bytes_mark_val(0)
                        voq_cgm_profile.set_sms_size_in_bytes_mark_behavior(key, val)
        return voq_cgm_profile

    def create_and_init_default_cgm_profile_pacific(self):
        voq_cgm_profile = self.device.create_voq_cgm_profile()
        for buffer_pool_available_level in range(sdk.LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS):
            for buffer_voq_size_level in range(sdk.la_voq_cgm_profile.SMS_NUM_BYTES_QUANTIZATION_REGIONS - 1):
                for free_dram_cntx in range(sdk.LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_REGIONS):
                    for age in range(sdk.la_voq_cgm_profile.SMS_NUM_AGE_QUANTIZATION_REGIONS):
                        voq_cgm_profile.set_sms_size_in_bytes_behavior(
                            buffer_pool_available_level,
                            buffer_voq_size_level,
                            age,
                            free_dram_cntx,
                            sdk.la_qos_color_e_NONE,
                            False,
                            False)
        return voq_cgm_profile

    def init_default_mc_cgm(self):
        if self.device_mode == device_mode.STANDALONE:
            # standlaone mode configures the multicast VOQs on all slices
            for slice_id in self.device.get_used_slices():
                mc_voq_set = self.device.get_egress_multicast_slice_replication_voq_set(slice_id)
                for voq in range(mc_voq_set.get_set_size()):
                    mc_voq_set.set_cgm_profile(voq, self.mc_voq_cgm_profile_def)

        elif self.device_mode == device_mode.LINECARD:
            # linecard mode configures the multicast fabric VOQ
            mc_voq_set = self.device.get_egress_multicast_fabric_replication_voq_set()
            for voq in range(mc_voq_set.get_set_size()):
                mc_voq_set.set_cgm_profile(voq, self.mc_voq_cgm_profile_def)

            # line mode configures the multicast VOQs for each network slice
            for slice_id in self.device.get_used_slices():
                slice_mode = self.device.get_slice_mode(slice_id)
                if slice_mode == sdk.la_slice_mode_e_NETWORK:
                    mc_voq_set = self.device.get_egress_multicast_slice_replication_voq_set(slice_id)
                    for voq in range(mc_voq_set.get_set_size()):
                        mc_voq_set.set_cgm_profile(voq, self.mc_voq_cgm_profile_def)

    def create_inject_rcy_ports(self):
        rcy_ports = self.device.get_objects(sdk.la_object.object_type_e_RECYCLE_PORT)
        if not any(rcy_ports):
            topology.recycle_ports = []
            recycle_ifgs = [PI_IFG]
            is_linecard_mode = self.device_mode == device_mode.LINECARD
            if is_linecard_mode and self.device.get_ll_device().is_gibraltar():
                # create recycle interfaces on both IFGs in linecard mode for gibraltar
                recycle_ifgs = range(0, NUM_IFGS_PER_SLICE)
            for slice_id in self.device.get_used_slices():
                for rcy_ifg in recycle_ifgs:
                    rcy_port = recycle_sys_port(self.testcase,
                                                self.device,
                                                slice_id,
                                                rcy_ifg,
                                                RCY_SYS_PORT_GID_BASE - (slice_id + (rcy_ifg * len(self.device.get_used_slices()))),
                                                use_presistant_alocation=True)
                    topology.recycle_ports.append(rcy_port)

    def create_single_inject_port(self, test_case, device, slice_id):
        pi_port = punt_inject_pci_port(
            test_case,
            device,
            slice_id,
            PI_IFG,
            INJECT_PORT_BASE_GID + slice_id,
            INJECT_PORT_MAC_ADDR,
            use_presistant_alocation=True)
        return pi_port

    def create_inject_ports(self):
        self.create_inject_rcy_ports()

        pci_ports = self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT)
        if not any(pci_ports):
            topology.inject_ports = [None] * NUM_SLICES_PER_DEVICE
            for slice_pair in self.device.get_used_slice_pairs():
                slice_id = slice_pair * 2
                if slice_id not in self.device.get_used_slices():
                    slice_id += 1
                pi_port = self.create_single_inject_port(self.testcase, self.device, slice_id)
                topology.inject_ports[slice_id] = pi_port

        # We need to know how to map from inject slice to the slice of the nearest rcy port
        # and vice versa.
        # Replaces the old hardcoded way of: if even slice, slice+=1 ...
        inject_to_rcy_slice = [None] * NUM_SLICES_PER_DEVICE
        rcy_to_inject_slice = [None] * NUM_SLICES_PER_DEVICE
        both = [inject_to_rcy_slice, rcy_to_inject_slice]
        for i in self.device.get_used_slices():
            for j in range(2):
                to_ports = [topology.recycle_ports, topology.inject_ports][j]
                # The nearest rcy/inject slice could be the curent slice, or the other slice in the pair
                if to_ports[i] is None:
                    assert (to_ports[i ^ 1] is not None)
                    both[j][i] = i ^ 1  # the other slice on the pair, simply flip the first bit.
                else:
                    both[j][i] = i

        self.device.inject_to_rcy_slice = both[0]
        self.device.rcy_to_inject_slice = both[1]

    def create_topology(self):
        # Create L2 objects

        self.rx_eth_port = ethernet_port(self.testcase, self.device, RX_SLICE, RX_IFG, RX_SYS_PORT_GID, FIRST_SERDES, LAST_SERDES)
        self.rx_eth_port1 = ethernet_port(self.testcase, self.device, RX_SLICE, RX_IFG1,
                                          RX_SYS_PORT_GID1, FIRST_SERDES1, LAST_SERDES1)

        self.tx_svi_eth_port_reg = ethernet_port(
            self.testcase,
            self.device,
            TX_SLICE_REG,
            TX_IFG_REG,
            TX_SVI_SYS_PORT_REG_GID,
            FIRST_SERDES_SVI_REG,
            LAST_SERDES_SVI_REG)
        self.tx_svi_eth_port_def = ethernet_port(
            self.testcase,
            self.device,
            TX_SLICE_DEF,
            TX_IFG_DEF,
            TX_SVI_SYS_PORT_DEF_GID,
            FIRST_SERDES_SVI_DEF,
            LAST_SERDES_SVI_DEF)

        if (decor.is_asic5()):
            # self.tx_svi_eth_port_ext = None
            self.tx_svi_eth_port_ext = ethernet_port(
                self.testcase,
                self.device,
                TX_SLICE_EXT,
                TX_IFG_EXT,
                TX_SVI_SYS_PORT_EXT_GID,
                FIRST_SERDES_SVI_EXT,
                LAST_SERDES_SVI_EXT)
        else:
            self.tx_svi_eth_port_ext = ethernet_port(
                self.testcase,
                self.device,
                TX_SLICE_EXT,
                TX_IFG_EXT,
                TX_SVI_SYS_PORT_EXT_GID,
                FIRST_SERDES_SVI_EXT,
                LAST_SERDES_SVI_EXT)

        self.tx_l3_ac_eth_port_reg = ethernet_port(
            self.testcase,
            self.device,
            TX_SLICE_REG,
            TX_IFG_REG,
            TX_L3_AC_SYS_PORT_REG_GID,
            FIRST_SERDES_L3_REG,
            LAST_SERDES_L3_REG)
        self.tx_l3_ac_eth_port_def = ethernet_port(
            self.testcase,
            self.device,
            TX_SLICE_DEF,
            TX_IFG_DEF,
            TX_L3_AC_SYS_PORT_DEF_GID,
            FIRST_SERDES_L3_DEF,
            LAST_SERDES_L3_DEF)
        self.tx_l3_ac_eth_port_ext = ethernet_port(
            self.testcase,
            self.device,
            TX_SLICE_EXT,
            TX_IFG_EXT,
            TX_L3_AC_SYS_PORT_EXT_GID,
            FIRST_SERDES_L3_EXT,
            LAST_SERDES_L3_EXT)

        self.rx_switch = switch(self.testcase, self.device, RX_SWITCH_GID)
        self.rx_switch1 = switch(self.testcase, self.device, RX_SWITCH_GID1)
        self.tx_switch = switch(self.testcase, self.device, TX_SWITCH_GID)
        self.tx_switch1 = switch(self.testcase, self.device, TX_SWITCH_GID1)

        self.rx_l2_ac_port = l2_ac_port(self.testcase, self.device,
                                        RX_L2_AC_PORT_GID,
                                        None,
                                        self.rx_switch,
                                        self.rx_eth_port,
                                        RX_MAC,
                                        RX_L2_AC_PORT_VID1,
                                        RX_L2_AC_PORT_VID2)
        self.rx_l2_ac_port1 = l2_ac_port(self.testcase, self.device,
                                         RX_L2_AC_PORT_GID1,
                                         None,
                                         self.rx_switch1,
                                         self.rx_eth_port1,
                                         RX_MAC,
                                         RX_L2_AC_PORT_VID1,
                                         RX_L2_AC_PORT_VID2)

        self.tx_l2_ac_port_reg = l2_ac_port(
            self.testcase, self.device,
            TX_L2_AC_PORT_REG_GID,
            None,
            self.tx_switch,
            self.tx_svi_eth_port_reg,
            NH_SVI_REG_MAC)
        self.tx_l2_ac_port_def = l2_ac_port(
            self.testcase, self.device,
            TX_L2_AC_PORT_DEF_GID,
            None,
            self.tx_switch,
            self.tx_svi_eth_port_def,
            NH_SVI_DEF_MAC)
        self.tx_l2_ac_port_ext = l2_ac_port(
            self.testcase, self.device,
            TX_L2_AC_PORT_EXT_GID,
            None,
            self.tx_switch1,
            self.tx_svi_eth_port_ext,
            NH_SVI_EXT_MAC)

        # Create VRF

        self.vrf = vrf(self.testcase, self.device, VRF_GID)
        self.vrf2 = vrf(self.testcase, self.device, VRF2_GID)
        self.global_vrf = vrf(self.testcase, self.device, 0)

        # Create L3 ports

        self.rx_svi = svi_port(self.testcase, self.device, RX_SVI_GID, self.rx_switch, self.vrf, RX_SVI_MAC)
        self.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        self.rx_svi1 = svi_port(self.testcase, self.device, RX_SVI_GID1, self.rx_switch1, self.vrf, RX_SVI_MAC1)
        self.rx_svi1.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_svi1.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        self.tx_svi = svi_port(self.testcase, self.device, TX_SVI_GID, self.tx_switch, self.vrf, TX_SVI_MAC)
        self.tx_svi_ext = svi_port(self.testcase, self.device, TX_SVI_EXT_GID, self.tx_switch1, self.vrf, TX_SVI_EXT_MAC)

        self.rx_l3_ac = l3_ac_port(self.testcase, self.device,
                                   RX_L3_AC_GID,
                                   self.rx_eth_port,
                                   self.vrf,
                                   RX_L3_AC_MAC,
                                   RX_L3_AC_PORT_VID1,
                                   RX_L3_AC_PORT_VID2)
        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        self.rx_l3_ac1 = l3_ac_port(self.testcase, self.device,
                                    RX_L3_AC_GID1,
                                    self.rx_eth_port1,
                                    self.vrf,
                                    RX_L3_AC_MAC1,
                                    RX_L3_AC_PORT_VID1,
                                    RX_L3_AC_PORT_VID2)
        self.rx_l3_ac1.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_l3_ac1.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        self.rx_l3_ac_one_tag = l3_ac_port(self.testcase, self.device,
                                           RX_L3_AC_ONE_TAG_GID,
                                           self.rx_eth_port,
                                           self.vrf,
                                           RX_L3_AC_ONE_TAG_MAC,
                                           RX_L3_AC_ONE_TAG_PORT_VID)
        self.rx_l3_ac_one_tag.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_l3_ac_one_tag.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        self.tx_l3_ac_reg = l3_ac_port(
            self.testcase,
            self.device,
            TX_L3_AC_REG_GID,
            self.tx_l3_ac_eth_port_reg,
            self.vrf,
            TX_L3_AC_REG_MAC)
        self.tx_l3_ac_def = l3_ac_port(
            self.testcase,
            self.device,
            TX_L3_AC_DEF_GID,
            self.tx_l3_ac_eth_port_def,
            self.vrf,
            TX_L3_AC_DEF_MAC)
        self.tx_l3_ac_ext = l3_ac_port(
            self.testcase,
            self.device,
            TX_L3_AC_EXT_GID,
            self.tx_l3_ac_eth_port_ext,
            self.global_vrf,
            TX_L3_AC_EXT_MAC)
        self.tx_l3_ac_ext.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.tx_l3_ac_ext.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        # Create L3 destinations

        self.forus_dest = forus_destination(self.testcase, self.device)

        self.nh_l3_ac_reg = next_hop(self.testcase, self.device, NH_L3_AC_REG_GID, NH_L3_AC_REG_MAC, self.tx_l3_ac_reg)
        self.nh_l3_ac_def = next_hop(self.testcase, self.device, NH_L3_AC_DEF_GID, NH_L3_AC_DEF_MAC, self.tx_l3_ac_def)
        self.nh_l3_ac_ext = next_hop(self.testcase, self.device, NH_L3_AC_EXT_GID, NH_L3_AC_EXT_MAC, self.tx_l3_ac_ext)
        self.nh_svi_reg = next_hop(self.testcase, self.device, NH_SVI_REG_GID, NH_SVI_REG_MAC, self.tx_svi)
        self.nh_svi_def = next_hop(self.testcase, self.device, NH_SVI_DEF_GID, NH_SVI_DEF_MAC, self.tx_svi)
        self.nh_svi_ext = next_hop(self.testcase, self.device, NH_SVI_EXT_GID, NH_SVI_EXT_MAC, self.tx_svi_ext)
        self.nh_l3_ac_glean = next_hop(
            self.testcase,
            self.device,
            NH_L3_AC_GLEAN_GID,
            NH_L3_AC_REG_MAC,
            self.tx_l3_ac_reg,
            sdk.la_next_hop.nh_type_e_GLEAN)
        self.nh_svi_glean = next_hop(
            self.testcase,
            self.device,
            NH_SVI_GLEAN_GID,
            NH_SVI_REG_MAC,
            self.tx_svi,
            sdk.la_next_hop.nh_type_e_GLEAN)
        self.nh_l3_ac_null_glean = next_hop(
            self.testcase,
            self.device,
            NH_L3_AC_GLEAN_NULL_GID,
            NH_L3_AC_REG_MAC,
            None,
            sdk.la_next_hop.nh_type_e_GLEAN)
        self.nh_svi_null_glean = next_hop(
            self.testcase,
            self.device,
            NH_SVI_GLEAN_NULL_GID,
            NH_SVI_REG_MAC,
            None,
            sdk.la_next_hop.nh_type_e_GLEAN)

        self.fec_l3_ac_reg = fec(self.testcase, self.device, self.nh_l3_ac_reg)
        self.fec_l3_ac_def = fec(self.testcase, self.device, self.nh_l3_ac_def)
        self.fec_l3_ac_ext = fec(self.testcase, self.device, self.nh_l3_ac_ext)
        self.fec_svi_reg = fec(self.testcase, self.device, self.nh_svi_reg)
        self.fec_svi_def = fec(self.testcase, self.device, self.nh_svi_def)
        self.fec_svi_ext = fec(self.testcase, self.device, self.nh_svi_ext)

        # create punt/inject ports
        self.create_inject_ports()

        self.topology_created = True

    def destroy(self):
        if self.topology_created:
            self.destroy_topology()

        self.destroy_default_profiles()
        topology.reset(self.device)

    def destroy_default_profiles(self):
        self.ingress_qos_profile_def.destroy()
        self.ingress_qos_profile_def = None
        self.egress_qos_profile_def.destroy()
        self.egress_qos_profile_def = None
        self.ac_profile_def.destroy()
        self.ac_profile_def = None
        self.tc_profile_def.destroy()
        self.tc_profile_def = None
        self.acl_profile_ipv4_def.destroy()
        self.acl_profile_ipv4_def = None
        self.acl_profile_ipv6_def.destroy()
        self.acl_profile_ipv6_def = None
        self.acl_profile_mac_def.destroy()
        self.acl_profile_mac_def = None
        self.ingress_acl_key_profile_ipv4_def.destroy()
        self.ingress_acl_key_profile_ipv4_def = None
        self.ingress_acl_key_profile_ipv6_def.destroy()
        self.ingress_acl_key_profile_ipv6_def = None
        self.egress_acl_key_profile_ipv4_def.destroy()
        self.egress_acl_key_profile_ipv4_def = None
        self.egress_acl_key_profile_ipv6_def.destroy()
        self.egress_acl_key_profile_ipv6_def = None
        self.acl_command_profile_def.destroy()
        self.acl_command_profile_def = None

    @staticmethod
    def destroy_inject_ports():
        for port in topology.inject_ports:
            if port is not None:
                port.destroy()
        topology.inject_ports = []
        for port in topology.recycle_ports:
            if port is not None:
                port.destroy()
        topology.recycle_ports = []

    def destroy_topology(self):
        # Destroy punt/inject ports

        topology.destroy_inject_ports()

        # Destroy L3 Destinations

        self.fec_l3_ac_reg.destroy()
        self.fec_l3_ac_reg = None
        self.fec_l3_ac_def.destroy()
        self.fec_l3_ac_def = None
        self.fec_l3_ac_ext.destroy()
        self.fec_l3_ac_ext = None
        self.fec_svi_reg.destroy()
        self.fec_svi_reg = None
        self.fec_svi_def.destroy()
        self.fec_svi_def = None
        self.fec_svi_ext.destroy()
        self.fec_svi_ext = None

        self.nh_l3_ac_reg.destroy()
        self.nh_l3_ac_reg = None
        self.nh_l3_ac_def.destroy()
        self.nh_l3_ac_def = None
        self.nh_l3_ac_ext.destroy()
        self.nh_l3_ac_ext = None
        self.nh_svi_reg.destroy()
        self.nh_svi_reg = None
        self.nh_svi_def.destroy()
        self.nh_svi_def = None
        self.nh_svi_ext.destroy()
        self.nh_svi_ext = None
        self.nh_l3_ac_glean.destroy()
        self.nh_l3_ac_glean = None
        self.nh_svi_glean.destroy()
        self.nh_svi_glean = None
        self.nh_l3_ac_null_glean.destroy()
        self.nh_l3_ac_null_glean = None
        self.nh_svi_null_glean.destroy()
        self.nh_svi_null_glean = None

        # Destroy L3 ports

        self.rx_svi.destroy()
        self.rx_svi = None
        self.rx_svi1.destroy()
        self.rx_svi1 = None
        self.tx_svi.destroy()
        self.tx_svi = None
        self.tx_svi_ext.destroy()
        self.tx_svi_ext = None

        self.rx_l3_ac.destroy()
        self.rx_l3_ac = None
        self.rx_l3_ac1.destroy()
        self.rx_l3_ac1 = None
        self.rx_l3_ac_one_tag.destroy()
        self.rx_l3_ac_one_tag = None

        self.tx_l3_ac_reg.destroy()
        self.tx_l3_ac_reg = None
        self.tx_l3_ac_def.destroy()
        self.tx_l3_ac_def = None
        self.tx_l3_ac_ext.destroy()
        self.tx_l3_ac_ext = None

        # Destroy VRF

        self.vrf.destroy()
        self.vrf = None
        self.global_vrf.destroy()
        self.global_vrf = None

        # Destroy L2 AC objects

        self.rx_l2_ac_port.destroy()
        self.rx_l2_ac_port1 = None
        self.rx_l2_ac_port1.destroy()
        self.rx_l2_ac_port = None
        self.tx_l2_ac_port_reg.destroy()
        self.tx_l2_ac_port_reg = None
        self.tx_l2_ac_port_def.destroy()
        self.tx_l2_ac_port_def = None
        self.tx_l2_ac_port_ext.destroy()
        self.tx_l2_ac_port_ext = None

        # Destroy switches
        self.rx_switch.destroy()
        self.rx_switch = None
        self.rx_switch1.destroy()
        self.rx_switch1 = None
        self.tx_switch.destroy()
        self.tx_switch = None
        self.tx_switch1.destroy()
        self.tx_switch1 = None

        # Destroy Ethernet ports

        self.rx_eth_port.destroy()
        self.rx_eth_port = None
        self.rx_eth_port1.destroy()
        self.rx_eth_port1 = None
        self.tx_svi_eth_port_reg.destroy()
        self.tx_svi_eth_port_reg = None
        self.tx_svi_eth_port_def.destroy()
        self.tx_svi_eth_port_def = None
        self.tx_svi_eth_port_ext.destroy()
        self.tx_svi_eth_port_ext = None
        self.tx_l3_ac_eth_port_reg.destroy()
        self.tx_l3_ac_eth_port_reg = None
        self.tx_l3_ac_eth_port_def.destroy()
        self.tx_l3_ac_eth_port_def = None
        self.tx_l3_ac_eth_port_ext.destroy()
        self.tx_l3_ac_eth_port_ext = None


class forus_destination:

    def __init__(self, testcase, device):

        self.testcase = testcase
        self.device = device

        forus_dest = self.device.get_forus_destination()
        testcase.assertNotEqual(forus_dest, None)

        self.hld_obj = forus_dest


class punt_inject_port:

    def __init__(self, testcase, device, slice, ifg, sys_port_gid, first_serdes, mac_addr_str, use_presistant_alocation=False):
        self.testcase = testcase
        self.device = device
        _mac_port = mac_port(testcase, device, slice, ifg, first_serdes, first_serdes + 1)
        sys_port = system_port(testcase, device, sys_port_gid, _mac_port, use_presistant_alocation=use_presistant_alocation)

        mac_address = mac_addr(mac_addr_str)
        pi_port = self.device.create_punt_inject_port(sys_port.hld_obj, mac_address.hld_obj)
        testcase.assertNotEqual(pi_port, None)

        self.mac_port = _mac_port
        self.sys_port = sys_port
        self.mac_address = mac_address
        self.hld_obj = pi_port

        self.mac_port.activate()

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None

        self.sys_port.destroy()
        self.sys_port = None

        self.mac_port.destroy()
        self.mac_port = None


class punt_inject_pci_port:

    def __init__(self, testcase, device, slice, ifg, sys_port_gid, mac_addr_str, use_presistant_alocation=False):
        self.testcase = testcase
        self.device = device
        _pci_port = pci_port(testcase, device, slice, ifg)
        sys_port = system_port(testcase, device, sys_port_gid, _pci_port, use_presistant_alocation=use_presistant_alocation)

        mac_address = mac_addr(mac_addr_str)
        pi_port = self.device.create_punt_inject_port(sys_port.hld_obj, mac_address.hld_obj)
        testcase.assertNotEqual(pi_port, None)

        _pci_port.hld_obj.activate()

        self.pci_port = _pci_port
        self.sys_port = sys_port
        self.mac_address = mac_address
        self.hld_obj = pi_port

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None

        self.sys_port.destroy()
        self.sys_port = None

        self.pci_port.destroy()
        self.pci_port = None


def create_l2_punt_destination(testcase, device, gid, punt_inject_port, mac_addr_str, vid):

    host_mac_addr = mac_addr(mac_addr_str)
    tag_tci = sdk.la_vlan_tag_tci_t()
    tag_tci.fields.pcp = 0
    tag_tci.fields.dei = 0
    tag_tci.fields.vid = vid

    punt_dest = device.create_l2_punt_destination(gid, punt_inject_port.hld_obj, host_mac_addr.hld_obj, tag_tci)
    testcase.assertNotEqual(punt_dest, None)

    return punt_dest


def create_meter_set(
        testcase,
        device,
        is_aggregate=False,
        is_statistical=False,
        set_size=1,
        meter_profile=None,
        meter_action_profile=None,
        cir=90 * GIGA,
        eir=180 * GIGA):

    # Create
    if is_statistical:
        meter_type = sdk.la_meter_set.type_e_STATISTICAL
    else:
        meter_type = sdk.la_meter_set.type_e_PER_IFG_EXACT if is_aggregate else sdk.la_meter_set.type_e_EXACT

    meter = device.create_meter(meter_type, set_size)

    # Set profiles
    if meter_profile is None:
        if is_statistical:
            meter_profile = topology.pps_meter_profile_def
        elif is_aggregate:
            meter_profile = topology.per_ifg_meter_profile_def
        else:
            meter_profile = topology.global_meter_profile_def

    if meter_action_profile is None:
        meter_action_profile = topology.meter_action_profile_def

    # Configure
    for meter_index in range(set_size):
        meter.set_committed_bucket_coupling_mode(meter_index, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
        meter.set_meter_action_profile(meter_index, meter_action_profile)
        meter.set_meter_profile(meter_index, meter_profile)

        if is_statistical or not is_aggregate:
            meter.set_cir(meter_index, cir)
            meter.set_eir(meter_index, eir)
        else:
            for slice_id in device.get_used_slices():
                for ifg in range(NUM_IFGS_PER_SLICE):
                    slice_ifg = sdk.la_slice_ifg()
                    slice_ifg.slice = slice_id
                    slice_ifg.ifg = ifg
                    meter.set_cir(meter_index, slice_ifg, cir)
                    meter.set_eir(meter_index, slice_ifg, eir)

    return meter


def create_l2_mirror_command(device, mirror_gid, punt_inject_port, mac_addr_str, vid, probability=1, voq_offset=0, meter=None):
    host_mac_addr = mac_addr(mac_addr_str)
    tag_tci = sdk.la_vlan_tag_tci_t()
    tag_tci.fields.pcp = 0
    tag_tci.fields.dei = 0
    tag_tci.fields.vid = vid

    return device.create_l2_mirror_command(
        mirror_gid,
        punt_inject_port.hld_obj,
        host_mac_addr.hld_obj,
        tag_tci,
        voq_offset,
        meter,
        probability)


class erspan_mirror_command:

    def __init__(
            self,
            testcase,
            device,
            mirror_gid,
            session_id, mac_addr_str,
            tunnel_dest_str, tunnel_source_str,
            ttl, dscp, tc,
            l3_port, l2_port, dsp,
            probability=1, is_v4=1):

        self.testcase = testcase
        self.device = device
        if is_v4:
            self.encap_data = sdk.ipv4_encapsulation()
            self.encap_data.type = sdk.la_erspan_mirror_command.type_e_ERSPAN
            self.encap_data.mac_addr = mac_addr(mac_addr_str).hld_obj
            self.encap_data.source_mac_addr = l3_port.get_mac()
            self.encap_data.vlan_tag = sdk.LA_VLAN_TAG_UNTAGGED
            self.encap_data.ipv4 = sdk.ipv4_transport_parameters()
            self.encap_data.ipv4.tunnel_dest_addr = (tunnel_dest_str).hld_obj
            self.encap_data.ipv4.tunnel_source_addr = (tunnel_source_str).hld_obj
            self.encap_data.ipv4.dscp = sdk.la_ip_dscp()
            self.encap_data.ipv4.dscp.value = dscp
            self.encap_data.ipv4.ttl = ttl
            self.encap_data.session = sdk.session_parameters()
            self.encap_data.session.session_id = session_id
        else:
            self.encap_data = sdk.ipv6_encapsulation()
            self.encap_data.type = sdk.la_erspan_mirror_command.type_e_ERSPAN
            self.encap_data.mac_addr = mac_addr(mac_addr_str).hld_obj
            self.encap_data.source_mac_addr = l3_port.get_mac()
            self.encap_data.vlan_tag = sdk.LA_VLAN_TAG_UNTAGGED
            self.encap_data.ipv6 = sdk.ipv6_transport_parameters()
            self.encap_data.ipv6.tunnel_dest_addr = (tunnel_dest_str).hld_obj
            self.encap_data.ipv6.tunnel_source_addr = (tunnel_source_str).hld_obj
            self.encap_data.ipv6.dscp = sdk.la_ip_dscp()
            self.encap_data.ipv6.dscp.value = dscp
            self.encap_data.ipv6.ttl = ttl
            self.encap_data.session = sdk.session_parameters()
            self.encap_data.session.session_id = session_id
        self.tc = tc
        self.probability = probability

        mirror_cmd = self.device.create_erspan_mirror_command(
            mirror_gid,
            self.encap_data,
            self.tc,
            dsp, probability)
        testcase.assertNotEqual(mirror_cmd, None)

        self.hld_obj = mirror_cmd

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class sflow_tunnel_mirror_command:

    def __init__(
            self,
            testcase,
            device,
            mirror_gid,
            sport, dport, mac_addr_str,
            tunnel_dest_str, tunnel_source_str,
            ttl, dscp, tc,
            l3_port, l2_port, dsp,
            probability=1, is_v4=1):

        self.testcase = testcase
        self.device = device
        if is_v4:
            self.encap_data = sdk.ipv4_encapsulation()
            self.encap_data.type = sdk.la_erspan_mirror_command.type_e_SFLOW_TUNNEL
            self.encap_data.mac_addr = mac_addr(mac_addr_str).hld_obj
            self.encap_data.source_mac_addr = l3_port.get_mac()
            self.encap_data.vlan_tag = sdk.LA_VLAN_TAG_UNTAGGED
            self.encap_data.ipv4 = sdk.ipv4_transport_parameters()
            self.encap_data.ipv4.tunnel_dest_addr = (tunnel_dest_str).hld_obj
            self.encap_data.ipv4.tunnel_source_addr = (tunnel_source_str).hld_obj
            self.encap_data.ipv4.dscp = sdk.la_ip_dscp()
            self.encap_data.ipv4.dscp.value = dscp
            self.encap_data.ipv4.ttl = ttl
            self.encap_data.session = sdk.session_parameters()
            self.encap_data.session.sflow.sport = sport
            self.encap_data.session.sflow.dport = dport
        else:
            self.encap_data = sdk.ipv6_encapsulation()
            self.encap_data.type = sdk.la_erspan_mirror_command.type_e_SFLOW_TUNNEL
            self.encap_data.mac_addr = mac_addr(mac_addr_str).hld_obj
            self.encap_data.source_mac_addr = l3_port.get_mac()
            self.encap_data.vlan_tag = sdk.LA_VLAN_TAG_UNTAGGED
            self.encap_data.ipv6 = sdk.ipv6_transport_parameters()
            self.encap_data.ipv6.tunnel_dest_addr = (tunnel_dest_str).hld_obj
            self.encap_data.ipv6.tunnel_source_addr = (tunnel_source_str).hld_obj
            self.encap_data.ipv6.dscp = sdk.la_ip_dscp()
            self.encap_data.ipv6.dscp.value = dscp
            self.encap_data.ipv6.ttl = ttl
            self.encap_data.session = sdk.session_parameters()
            self.encap_data.session.sflow.sport = sport
            self.encap_data.session.sflow.dport = dport
        self.tc = tc
        self.probability = probability

        mirror_cmd = self.device.create_erspan_mirror_command(
            mirror_gid,
            self.encap_data,
            self.tc,
            dsp, probability)
        testcase.assertNotEqual(mirror_cmd, None)

        self.hld_obj = mirror_cmd

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class recycle_sys_port:

    def __init__(self, testcase, device, slice, ifg, sys_port_gid, use_presistant_alocation=False):
        self.testcase = testcase
        self.device = device
        rcy_port = recycle_port(testcase, device, slice, ifg)
        sys_port = system_port(testcase, device, sys_port_gid, rcy_port, use_presistant_alocation=use_presistant_alocation)

        self.rcy_port = rcy_port
        self.sys_port = sys_port

    def destroy(self):
        self.sys_port.destroy()
        self.sys_port = None

        self.rcy_port.destroy()
        self.rcy_port = None


class pci_port:
    def __init__(self, testcase, device, slice, ifg):
        self.testcase = testcase
        self.device = device
        port = self.device.create_pci_port(slice, ifg, False)
        testcase.assertIsNotNone(port)

        self.hld_obj = port
        self.init_default_tm()

    def get_dest_device(self):
        return self.device.get_id()

    def get_dest_slice(self):
        return self.hld_obj.get_slice()

    def get_dest_ifg(self):
        return self.hld_obj.get_ifg()

    def init_default_tm(self):
        ifc_sch = self.hld_obj.get_scheduler()
        self.testcase.assertIsNotNone(ifc_sch)

        ifc_sch.set_credit_cir(self.get_speed())
        ifc_sch.set_transmit_cir(self.get_speed())
        ifc_sch.set_credit_eir_or_pir(self.get_speed(), False)
        ifc_sch.set_transmit_eir_or_pir(self.get_speed(), False)
        ifc_sch.set_cir_weight(1)
        ifc_sch.set_eir_weight(1)

    def get_speed(self):
        return 100 * GIGA

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class npu_host_port:
    def __init__(self, testcase, device, device_id, remote, system_port_gid):
        self.testcase = testcase
        self.device = device

        voq_set_size = 8

        dest_ifg = 0 if decor.is_asic5() else 1
        is_success, self.base_voq, self.base_vsc_vec = topology.allocate_voq_set(device, device_id, 0, dest_ifg, voq_set_size)
        self.voq_set = self.device.create_voq_set(self.base_voq, voq_set_size, self.base_vsc_vec, device_id, 0, dest_ifg)

        for voq in range(voq_set_size):
            self.voq_set.set_cgm_profile(voq, topology.uc_voq_cgm_profile_def)

        if remote:
            if self.device.get_ll_device().is_pacific():
                remote_dev = self.device.create_remote_device(device_id, sdk.la_device_revision_e_PACIFIC_B1)
            else:
                remote_dev = self.device.create_remote_device(device_id, sdk.la_device_revision_e_GIBRALTAR_A1)
            port = self.device.create_npu_host_port(remote_dev, system_port_gid, self.voq_set, topology.tc_profile_def.hld_obj)
        else:
            port = self.device.create_npu_host_port(None, system_port_gid, self.voq_set, topology.tc_profile_def.hld_obj)
        testcase.assertIsNotNone(port)

        self.hld_obj = port
        if device.get_id() == device_id:
            self.init_default_tm()

    def init_default_tm(self):
        ingress_device_id = self.device.get_id()

        sys_port = self.hld_obj.get_system_port()
        ifc_sch = self.hld_obj.get_scheduler()
        self.testcase.assertIsNotNone(ifc_sch)

        ifc_sch.set_credit_cir(self.get_speed())
        ifc_sch.set_transmit_cir(self.get_speed())
        ifc_sch.set_credit_eir_or_pir(self.get_speed(), False)
        ifc_sch.set_transmit_eir_or_pir(self.get_speed(), False)
        ifc_sch.set_cir_weight(1)
        ifc_sch.set_eir_weight(1)

        port_max_speed = self.get_speed()
        sp_sch = sys_port.get_scheduler()

        sp_sch.set_priority_propagation(False)
        if not decor.is_asic3():
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
        for oq_id in range(8):
            oq_sch = sp_sch.get_output_queue_scheduler(oq_id)
            if decor.is_akpg():
                oq_sch.set_scheduling_mode(sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_3SP_2WFQ)
            else:
                oq_sch.set_scheduling_mode(sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_2SP_3WFQ)
            for group in range(4):
                oq_sch.set_group_weight(group, 1)
            for slice_idx in range(len(self.base_vsc_vec)):
                if self.base_vsc_vec[slice_idx] == sdk.LA_VSC_GID_INVALID:
                    continue
                oq_sch.attach_vsc(self.base_vsc_vec[slice_idx] + oq_id,
                                  sdk.la_oq_vsc_mapping_e_RR1_RR3, ingress_device_id, slice_idx, self.base_voq + oq_id)
                oq_sch.set_vsc_pir(self.base_vsc_vec[slice_idx] + oq_id, sdk.LA_RATE_UNLIMITED)

    def get_speed(self):
        return 100 * GIGA


class recycle_port:
    def __init__(self, testcase, device, slice, ifg):
        self.testcase = testcase
        self.device = device
        port = self.device.create_recycle_port(slice, ifg)
        testcase.assertIsNotNone(port)

        self.hld_obj = port
        self.init_default_tm()

    def get_dest_device(self):
        return self.device.get_id()

    def get_dest_slice(self):
        return self.hld_obj.get_slice()

    def get_dest_ifg(self):
        return self.hld_obj.get_ifg()

    def init_default_tm(self):
        ifc_sch = self.hld_obj.get_scheduler()
        self.testcase.assertIsNotNone(ifc_sch)

        ifc_sch.set_credit_cir(self.get_speed())
        ifc_sch.set_transmit_cir(self.get_speed())
        ifc_sch.set_credit_eir_or_pir(self.get_speed(), False)
        ifc_sch.set_transmit_eir_or_pir(self.get_speed(), False)
        ifc_sch.set_cir_weight(1)
        ifc_sch.set_eir_weight(1)

    def get_speed(self):
        return 100 * GIGA

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class mac_port:
    def __init__(
            self,
            testcase,
            device,
            slice,
            ifg,
            first_serdes,
            last_serdes,
            hld_mac_port=None,
            is_extended=False,
            speed=sdk.la_mac_port.port_speed_e_E_50G,
            fec_mode=sdk.la_mac_port.fec_mode_e_RS_KR4):
        self.testcase = testcase
        self.device = device
        if (hld_mac_port is None):
            # MATILDA Save -- need review
            if is_matilda_model(self.device):
                num_serdices = last_serdes - first_serdes + 1
                if num_serdices < 2 and speed == sdk.la_mac_port.port_speed_e_E_50G:
                    speed = sdk.la_mac_port.port_speed_e_E_25G
            if(not is_extended):
                hld_mac_port = self.device.create_mac_port(slice, ifg, first_serdes, last_serdes,
                                                           speed,
                                                           sdk.la_mac_port.fc_mode_e_NONE,
                                                           fec_mode)
            else:
                hld_mac_port = self.device.create_channelized_mac_port(slice, ifg, first_serdes, last_serdes,
                                                                       speed,
                                                                       sdk.la_mac_port.fc_mode_e_NONE,
                                                                       fec_mode)
            testcase.assertIsNotNone(hld_mac_port)

        # Creating mac ports in loopback mode in HW device results in not using SerDes and faster execution of mac_port::activate.
        # In simulated device, ports work differently.
        if decor.is_hw_device():
            hld_mac_port.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_PMA_CORE_CLK)
        self.hld_obj = hld_mac_port
        self.init_default_tm()

    def activate(self):
        self.hld_obj.activate()

    def get_dest_device(self):
        return self.device.get_id()

    def get_dest_slice(self):
        return self.hld_obj.get_slice()

    def get_dest_ifg(self):
        return self.hld_obj.get_ifg()

    def init_default_tm(self):
        ifc_sch = self.hld_obj.get_scheduler()
        self.testcase.assertIsNotNone(ifc_sch)

        ifc_sch.set_credit_cir(self.get_speed())
        ifc_sch.set_transmit_cir(self.get_speed())
        ifc_sch.set_credit_eir_or_pir(self.get_speed(), False)
        ifc_sch.set_transmit_eir_or_pir(self.get_speed(), False)
        ifc_sch.set_cir_weight(1)
        ifc_sch.set_eir_weight(1)

    def get_speed(self):
        out_speed = self.hld_obj.get_speed()
        return PORT_SPEED_VALUE[out_speed] * GIGA

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class fabric_mac_port:
    def __init__(self, testcase, device, slice, ifg, first_serdes, last_serdes, fc_mode=sdk.la_mac_port.fc_mode_e_NONE):
        self.testcase = testcase
        self.device = device
        fabric_mac_port = self.device.create_fabric_mac_port(slice, ifg, first_serdes, last_serdes,
                                                             sdk.la_mac_port.port_speed_e_E_100G,
                                                             fc_mode)
        testcase.assertIsNotNone(fabric_mac_port)

        self.hld_obj = fabric_mac_port

    def get_dest_device(self):
        return self.device.get_id()

    def get_dest_slice(self):
        return self.hld_obj.get_slice()

    def get_dest_ifg(self):
        return self.hld_obj.get_ifg()

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class fabric_port:
    def __init__(self, testcase, device, fabric_mac_port):
        self.testcase = testcase
        self.device = device
        fabric_port = self.device.create_fabric_port(fabric_mac_port.hld_obj)
        testcase.assertIsNotNone(fabric_port)

        self.hld_obj = fabric_port

    def set_output_queue_weight_defaults(self):
        fabric_port_sch = self.hld_obj.get_scheduler()
        fabric_port_sch.set_output_queue_weight(sdk.la_fabric_port_scheduler.fabric_ouput_queue_e_PLB_UC_HIGH, 1)
        fabric_port_sch.set_output_queue_weight(sdk.la_fabric_port_scheduler.fabric_ouput_queue_e_PLB_UC_LOW, 5)
        fabric_port_sch.set_output_queue_weight(sdk.la_fabric_port_scheduler.fabric_ouput_queue_e_PLB_MC, 25)

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class remote_port:
    def __init__(
            self,
            testcase,
            device,
            remote_device,
            remote_slice,
            remote_ifg,
            remote_first_serdes,
            remote_last_serdes,
            remote_speed=sdk.la_mac_port.port_speed_e_E_50G):
        self.testcase = testcase
        self.device = device
        if self.device.get_ll_device().is_pacific():
            remote_dev = self.device.create_remote_device(remote_device, sdk.la_device_revision_e_PACIFIC_B1)
        else:
            remote_dev = self.device.create_remote_device(remote_device, sdk.la_device_revision_e_GIBRALTAR_A1)
        remote_port = self.device.create_remote_port(
            remote_dev,
            remote_slice,
            remote_ifg,
            remote_first_serdes,
            remote_last_serdes,
            remote_speed)
        testcase.assertIsNotNone(mac_port)

        self.hld_obj = remote_port

    def get_dest_device(self):
        remote_dev = self.hld_obj.get_remote_device()
        return remote_dev.get_remote_device_id()

    def get_dest_slice(self):
        return self.hld_obj.get_remote_slice()

    def get_dest_ifg(self):
        return self.hld_obj.get_remote_ifg()

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class spa_port:
    def __init__(self, testcase, device, spa_port_gid):
        self.testcase = testcase
        self.device = device
        spa_port = self.device.create_spa_port(spa_port_gid)
        testcase.assertIsNotNone(spa_port)

        self.hld_obj = spa_port

    def add(self, sys_port, transmit_enabled=True):
        self.hld_obj.add(sys_port.hld_obj)
        self.hld_obj.set_member_transmit_enabled(sys_port.hld_obj, transmit_enabled)

    def remove(self, sys_port, transmit_enabled=False):
        self.hld_obj.set_member_transmit_enabled(sys_port.hld_obj, transmit_enabled)
        self.hld_obj.remove(sys_port.hld_obj)

    def set_lb_mode(self, lb_mode_e):
        self.hld_obj.set_lb_mode(lb_mode_e)

    def get_lb_mode(self):
        out_lb_mode = self.hld_obj.get_lb_mode()
        return out_lb_mode

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class system_port:
    port_speed = 0
    speedup = 1.1
    port_max_speed = 0

    base_vsc_vec = []
    base_voq = 0

    def __init__(self, testcase, device, sys_port_gid, underlying_port, port_extender_vid=None, use_presistant_alocation=False):
        self.testcase = testcase
        self.device = device

        if global_svl_mode_flag:
            if underlying_port.hld_obj.type() == sdk.la_object.object_type_e_REMOTE_PORT:
                sys_port = self.device.create_system_port(sys_port_gid, underlying_port.hld_obj, None, None)
                testcase.assertIsNotNone(sys_port)
                self.hld_obj = sys_port
                self.underlying_port = underlying_port
                self.voq_set = None
                return

        # TODO: enahance for non-standalone mode.
        # Currently, device is ingress and egress device.
        dest_device = underlying_port.get_dest_device()
        dest_slice = underlying_port.get_dest_slice()
        dest_ifg = underlying_port.get_dest_ifg()
        voq_set_size = 8 if port_extender_vid is None else 2
        is_success, self.base_voq, self.base_vsc_vec = topology.allocate_voq_set(
            device, dest_device, dest_slice, dest_ifg, voq_set_size, use_presistant_alocation=use_presistant_alocation)
        testcase.assertTrue(is_success)

        # Ugly hack to account for different slice modes.
        # The la_device::create_voq_set() functions validates that the user doesn't allocate VOQs and VSC for an RX fabric slice.
        # The python helper topology.allocate_voq_set() is not aware of the device configuration, so it allocates VOQs and VSC for all slices
        # The following hack overwrites the unneeded VOQs and VSC with an INVALID.
        for slice_id in device.get_used_slices():
            slice_mode = device.get_slice_mode(slice_id)
            if slice_mode == sdk.la_slice_mode_e_CARRIER_FABRIC:
                self.base_vsc_vec[slice_id] = sdk.LA_VSC_GID_INVALID

        voq_set = self.device.create_voq_set(self.base_voq, voq_set_size, self.base_vsc_vec, dest_device, dest_slice, dest_ifg)
        for voq in range(voq_set_size):
            voq_set.set_cgm_profile(voq, topology.uc_voq_cgm_profile_def)

        if(port_extender_vid is None):
            sys_port = self.device.create_system_port(sys_port_gid,
                                                      underlying_port.hld_obj, voq_set,
                                                      topology.tc_profile_def.hld_obj)

        else:
            sys_port = self.device.create_system_port(sys_port_gid, port_extender_vid,
                                                      underlying_port.hld_obj, voq_set,
                                                      topology.tc_profile_def.hld_obj)

        testcase.assertIsNotNone(sys_port)

        self.hld_obj = sys_port
        self.underlying_port = underlying_port
        self.voq_set = voq_set
        if underlying_port.hld_obj.type() != sdk.la_object.object_type_e_REMOTE_PORT:
            self.port_max_speed = int(underlying_port.get_speed() * self.speedup)
            self.init_default_tm()

    def init_default_tm(self):
        ingress_device_id = self.device.get_id()

        sp_sch = self.hld_obj.get_scheduler()
        self.testcase.assertIsNotNone(sp_sch)

        sp_sch.set_priority_propagation(False)
        if not decor.is_asic3():
            sp_sch.set_logical_port_enabled(False)

        for oqpg in range(8):
            sp_sch.set_oq_priority_group(oqpg, sdk.la_system_port_scheduler.priority_group_e_SP8)
            sp_sch.set_credit_pir(oqpg, self.port_max_speed)
            sp_sch.set_transmit_pir(oqpg, self.port_max_speed)
            sp_sch.set_transmit_uc_mc_weight(oqpg, 1, 1)

        slice_id = self.hld_obj.get_slice()
        slice_mode = self.device.get_slice_mode(slice_id)
        for pg in range(sdk.la_system_port_scheduler.priority_group_e_SP8 + 1):
            sp_sch.set_priority_group_credit_cir(pg, self.port_max_speed)
            sp_sch.set_priority_group_eir_weight(pg, 7)
            if slice_mode == sdk.la_slice_mode_e_NETWORK:
                sp_sch.set_priority_group_transmit_cir(pg, self.port_max_speed)

        for oq_id in range(8):
            oq_sch = sp_sch.get_output_queue_scheduler(oq_id)
            self.testcase.assertIsNotNone(oq_sch)

            if decor.is_akpg():
                oq_sch.set_scheduling_mode(sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_3SP_2WFQ)
            else:
                oq_sch.set_scheduling_mode(sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_2SP_3WFQ)

            for group in range(4):
                oq_sch.set_group_weight(group, 1)

            for slice_idx in range(len(self.base_vsc_vec)):
                if self.base_vsc_vec[slice_idx] == sdk.LA_VSC_GID_INVALID:
                    continue
                vsc = self.base_vsc_vec[slice_idx] + oq_id
                if decor.is_asic3:
                    oq_vsc_mapping = sdk.la_oq_vsc_mapping_e_RR1
                else:
                    oq_vsc_mapping = sdk.la_oq_vsc_mapping_e_RR1_RR3
                oq_sch.attach_vsc(vsc,
                                  oq_vsc_mapping,
                                  ingress_device_id, slice_idx, self.base_voq + oq_id)

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None

        if self.voq_set is not None:
            self.voq_set.set_state(sdk.la_voq_set.state_e_DROPPING)
            self.device.destroy(self.voq_set)
            self.voq_set = None


class sa_ethernet_port:
    def __init__(self, testcase, device, sys_port, ac_prof=None):

        self.testcase = testcase
        self.device = device

        eth_port = self.device.create_ethernet_port(sys_port.hld_obj, sdk.la_ethernet_port.port_type_e_AC)
        testcase.assertIsNotNone(eth_port)

        self.hld_obj = eth_port

        if ac_prof is not None:
            self.set_ac_profile(ac_prof)
        else:
            self.set_ac_profile(topology.ac_profile_def)

    def set_ac_profile(self, ac_profile):
        self.hld_obj.set_ac_profile(ac_profile.hld_obj)

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.eth_port = None


class ethernet_port:

    def __init__(
            self,
            testcase,
            device,
            slice,
            ifg,
            sys_port_gid,
            first_serdes=FIRST_SERDES,
            last_serdes=LAST_SERDES,
            ac_prof=None,
            hld_mac_port=None,
            ext_system_port=None,
            speed=sdk.la_mac_port.port_speed_e_E_50G,
            fec_mode=sdk.la_mac_port.fec_mode_e_RS_KR4,
            set_loopback=False):
        self.is_external_system_port = True if ext_system_port is not None else False

        self.testcase = testcase
        self.device = device
        if(self.is_external_system_port is False):
            self.mac_port = mac_port(
                testcase,
                device,
                slice,
                ifg,
                first_serdes,
                last_serdes,
                hld_mac_port,
                speed=speed,
                fec_mode=fec_mode)
            self.sys_port = system_port(testcase, device, sys_port_gid, self.mac_port)

            self.eth_port = sa_ethernet_port(testcase, device, self.sys_port, ac_prof)

            if set_loopback:
                self.mac_port.hld_obj.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_INFO_MAC_CLK)

            self.mac_port.activate()

        else:
            self.sys_port = ext_system_port
            self.eth_port = sa_ethernet_port(testcase, device, self.sys_port, ac_prof)

        self.hld_obj = self.eth_port.hld_obj

    def set_ac_profile(self, ac_profile):
        self.hld_obj.set_ac_profile(ac_profile.hld_obj)

    def destroy(self):
        self.eth_port.destroy()
        self.eth_port = None
        self.hld_obj = None
        if(self.is_external_system_port is False):
            self.sys_port.destroy()
            self.mac_port.destroy()


class ac_profile:

    def __init__(self, testcase, device, with_fallback=False,
                 single_vlan_selector=sdk.la_ac_profile.key_selector_e_PORT_VLAN,
                 dual_vlan_selector=sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN):

        self.testcase = testcase
        self.device = device
        ac_profile = self.device.create_ac_profile()
        testcase.assertIsNotNone(ac_profile)

        # NO VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x0000
        pvf.tpid2 = 0x0000
        ac_profile.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT)

        # PORT VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x8100
        pvf.tpid2 = 0x0000
        ac_profile.set_key_selector_per_format(pvf, single_vlan_selector)

        # PORT VLAN VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x9100
        pvf.tpid2 = 0x8100

        if with_fallback:
            selector = sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN_WITH_FALLBACK
        else:
            selector = dual_vlan_selector

        ac_profile.set_key_selector_per_format(pvf, selector)

        self.hld_obj = ac_profile

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class tc_profile:
    def __init__(self, testcase, device):
        self.testcase = testcase
        self.device = device

        tc_profile = device.create_tc_profile()
        self.hld_obj = tc_profile

    def set_default_values(self):
        for tc in range(8):
            self.hld_obj.set_mapping(tc, tc)

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class ingress_qos_profile:

    def __init__(self, testcase, device):
        self.testcase = testcase
        self.device = device
        ingress_qos_profile = self.device.create_ingress_qos_profile()
        testcase.assertIsNotNone(ingress_qos_profile)
        self.hld_obj = ingress_qos_profile

    def set_default_values(self):
        # (PCP,DEI) mapping
        pcpdei = sdk.la_vlan_pcpdei()
        for pcp in range(0, 8):
            for dei in range(0, 2):
                pcpdei.fields.pcp = pcp
                pcpdei.fields.dei = dei
                self.hld_obj.set_qos_tag_mapping_pcpdei(pcpdei, pcpdei)

        # (DSCP) mapping for IPv4
        ip_dscp = sdk.la_ip_dscp()
        for dscp in range(0, 64):
            ip_dscp.value = dscp
            self.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, ip_dscp, ip_dscp)

        # (DSCP) mapping for IPv6
        ip_dscp = sdk.la_ip_dscp()
        for dscp in range(0, 64):
            ip_dscp.value = dscp
            self.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, ip_dscp, ip_dscp)

        # (MPLS_TC) mapping
        mpls_tc = sdk.la_mpls_tc()
        for tc in range(0, 8):
            mpls_tc.value = tc
            self.hld_obj.set_qos_tag_mapping_mpls_tc(mpls_tc, mpls_tc)

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class egress_qos_profile:

    def __init__(self, testcase, device, marking_source=sdk.la_egress_qos_marking_source_e_QOS_TAG):
        self.testcase = testcase
        self.device = device
        egress_qos_profile = self.device.create_egress_qos_profile(marking_source)
        testcase.assertIsNotNone(egress_qos_profile)
        out_marking_source = egress_qos_profile.get_marking_source()
        testcase.assertEqual(marking_source, out_marking_source)
        self.hld_obj = egress_qos_profile

    def set_default_values(self):
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        # mapping to (PCP,DEI)
        pcpdei = sdk.la_vlan_pcpdei()
        for pcp in range(0, 8):
            for dei in range(0, 2):
                pcpdei.fields.pcp = pcp
                pcpdei.fields.dei = dei
                self.hld_obj.set_qos_tag_mapping_pcpdei(pcpdei, pcpdei, encap_qos_values)

        # mapping to (DSCP)
        ip_dscp = sdk.la_ip_dscp()
        for dscp in range(0, 64):
            ip_dscp.value = dscp
            self.hld_obj.set_qos_tag_mapping_dscp(ip_dscp, ip_dscp, encap_qos_values)

        # mapping to (MPLS_TC)
        mpls_tc = sdk.la_mpls_tc()
        for tc in range(0, 8):
            encap_qos_values.tc.value = tc
            mpls_tc.value = tc
            self.hld_obj.set_qos_tag_mapping_mpls_tc(mpls_tc, mpls_tc, encap_qos_values)

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class l2_ac_port:

    def __init__(self, testcase, device, gid, filter_group, switch, eth_port, mac_addr, vid1=0, vid2=0, ingress_qos_profile=None,
                 egress_qos_profile=None, egress_feature_mode=None, class_id=None):
        self.testcase = testcase
        self.device = device

        if ingress_qos_profile is None:
            ingress_qos_profile = topology.ingress_qos_profile_def

        if egress_qos_profile is None:
            egress_qos_profile = topology.egress_qos_profile_def

        if filter_group is None:
            filter_group = topology.filter_group_def

        ac_port = self.device.create_ac_l2_service_port(
            gid,
            eth_port.hld_obj,
            vid1,
            vid2,
            filter_group,
            ingress_qos_profile.hld_obj,
            egress_qos_profile.hld_obj)
        testcase.assertIsNotNone(ac_port)

        ac_port.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)

        if switch is not None:
            ac_port.attach_to_switch(switch.hld_obj)

            if mac_addr is not None:
                if class_id is None:
                    switch.hld_obj.set_mac_entry(mac_addr.hld_obj, ac_port, sdk.LA_MAC_AGING_TIME_NEVER)
                else:
                    switch.hld_obj.set_mac_entry(mac_addr.hld_obj, ac_port, sdk.LA_MAC_AGING_TIME_NEVER, class_id)

        if egress_feature_mode is None:
            egress_feature_mode = sdk.la_l2_service_port.egress_feature_mode_e_L2

        ac_port.set_egress_feature_mode(egress_feature_mode)

        self.hld_obj = ac_port

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class filter_group:

    def __init__(self, testcase, device):
        self.testcase = testcase
        self.device = device
        grp1 = self.device.create_filter_group()
        self.hld_obj = grp1

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class l2_pwe_port:

    def __init__(
            self,
            testcase,
            device,
            gid,
            local_label,
            remote_label,
            pwe_gid,
            l3_destination,
            ingress_qos_profile=None,
            egress_qos_profile=None):
        self.testcase = testcase
        self.device = device

        if ingress_qos_profile is None:
            ingress_qos_profile = topology.ingress_qos_profile_def

        if egress_qos_profile is None:
            egress_qos_profile = topology.egress_qos_profile_def

        pwe_port = self.device.create_pwe_l2_service_port(gid, local_label, remote_label, pwe_gid, l3_destination,
                                                          ingress_qos_profile.hld_obj, egress_qos_profile.hld_obj)
        testcase.assertIsNotNone(pwe_port)

        pwe_port.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
        self.hld_obj = pwe_port

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class switch:

    def __init__(self, testcase, device, gid):
        self.testcase = testcase
        self.device = device

        switch = self.device.create_switch(gid)
        testcase.assertIsNotNone(switch)

        self.hld_obj = switch

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class vrf:

    def __init__(self, testcase, device, gid):
        self.testcase = testcase
        self.device = device
        vrf = self.device.create_vrf(gid)
        testcase.assertIsNotNone(vrf)

        self.hld_obj = vrf

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class svi_port:

    def __init__(self, testcase, device, gid, switch, vrf, mac_addr, ingress_qos_profile=None,
                 egress_qos_profile=None):
        self.testcase = testcase
        self.device = device

        if ingress_qos_profile is None:
            ingress_qos_profile = topology.ingress_qos_profile_def

        if egress_qos_profile is None:
            egress_qos_profile = topology.egress_qos_profile_def

        svi = self.device.create_svi_port(gid, switch.hld_obj, vrf.hld_obj, mac_addr.hld_obj,
                                          ingress_qos_profile.hld_obj, egress_qos_profile.hld_obj)
        testcase.assertIsNotNone(svi)

        svi.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        self.hld_obj = svi

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class l3_ac_port:

    def __init__(self, testcase, device, gid, eth_port, vrf, mac_addr, vid1=0, vid2=0, ingress_qos_profile=None,
                 egress_qos_profile=None):
        self.testcase = testcase
        self.device = device

        if ingress_qos_profile is None:
            ingress_qos_profile = topology.ingress_qos_profile_def

        if egress_qos_profile is None:
            egress_qos_profile = topology.egress_qos_profile_def

        hld_obj = self.device.create_l3_ac_port(
            gid,
            eth_port.hld_obj,
            vid1,
            vid2,
            mac_addr.hld_obj,
            vrf.hld_obj,
            ingress_qos_profile.hld_obj,
            egress_qos_profile.hld_obj)
        testcase.assertIsNotNone(hld_obj)

        hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        self.hld_obj = hld_obj

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class ip_over_ip_tunnel_port:

    def __init__(self, testcase, device, gid, underlay_vrf, prefix, ip_addr, vrf, mode=sdk.la_ip_tunnel_mode_e_DECAP_ONLY):
        self.testcase = testcase
        self.device = device

        ingress_qos_profile = topology.ingress_qos_profile_def
        egress_qos_profile = topology.egress_qos_profile_def

        hld_obj = self.device.create_ip_over_ip_tunnel_port(
            gid,
            mode,
            underlay_vrf.hld_obj,
            prefix,
            ip_addr.hld_obj,
            vrf.hld_obj,
            ingress_qos_profile.hld_obj,
            egress_qos_profile.hld_obj)
        testcase.assertIsNotNone(hld_obj)

        self.hld_obj = hld_obj

        hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class gre_port:

    def __init__(self, testcase, device, gid, mode, underlay_vrf, sip, dip, vrf):
        self.testcase = testcase
        self.device = device

        ingress_qos_profile = topology.ingress_qos_profile_def
        egress_qos_profile = topology.egress_qos_profile_def

        hld_obj = self.device.create_gre_port(
            gid,
            mode,
            underlay_vrf.hld_obj,
            sip.hld_obj,
            dip.hld_obj,
            vrf.hld_obj,
            ingress_qos_profile.hld_obj,
            egress_qos_profile.hld_obj)
        testcase.assertIsNotNone(hld_obj)

        self.hld_obj = hld_obj

        hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class gue_port:

    def __init__(self, testcase, device, gid, mode, underlay_vrf, prefix, ip_addr, vrf):
        self.testcase = testcase
        self.device = device

        ingress_qos_profile = topology.ingress_qos_profile_def
        egress_qos_profile = topology.egress_qos_profile_def

        hld_obj = self.device.create_gue_port(
            gid,
            mode,
            underlay_vrf.hld_obj,
            prefix,
            ip_addr.hld_obj,
            vrf.hld_obj,
            ingress_qos_profile.hld_obj,
            egress_qos_profile.hld_obj)
        testcase.assertIsNotNone(hld_obj)

        self.hld_obj = hld_obj

        hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class next_hop:

    def __init__(self, testcase, device, gid, mac_addr, l3_port, nh_type=sdk.la_next_hop.nh_type_e_NORMAL):
        self.testcase = testcase
        self.device = device
        self.mac_addr = mac_addr
        if l3_port is None:
            next_hop = self.device.create_next_hop(gid, mac_addr.hld_obj, None, nh_type)
        else:
            next_hop = self.device.create_next_hop(gid, mac_addr.hld_obj, l3_port.hld_obj, nh_type)
        testcase.assertIsNotNone(next_hop)
        self.hld_obj = next_hop

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class fec:

    def __init__(self, testcase, device, next_hop):
        self.testcase = testcase
        self.device = device
        fec = self.device.create_l3_fec(next_hop.hld_obj)
        testcase.assertIsNotNone(fec)
        self.hld_obj = fec

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class prefix_object:

    def __init__(self, testcase, device, gid, dest):
        self.testcase = testcase
        self.device = device

        pfx_obj = device.create_prefix_object(gid, dest, type=sdk.la_prefix_object.prefix_type_e_NORMAL)
        testcase.assertIsNotNone(pfx_obj)
        self.hld_obj = pfx_obj

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class global_prefix_object:

    def __init__(self, testcase, device, gid, dest):
        self.testcase = testcase
        self.device = device

        pfx_obj = device.create_prefix_object(gid, dest, type=sdk.la_prefix_object.prefix_type_e_GLOBAL)
        testcase.assertIsNotNone(pfx_obj)
        self.hld_obj = pfx_obj

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class destination_pe:

    def __init__(self, testcase, device, gid, destination):
        self.testcase = testcase
        self.device = device

        dpe = device.create_destination_pe(gid, destination)
        testcase.assertIsNotNone(dpe)
        self.hld_obj = dpe

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class asbr_lsp:

    def __init__(self, testcase, device, asbr, l3_dest):
        self.testcase = testcase
        self.device = device

        asbr_lsp = device.create_asbr_lsp(asbr, l3_dest)
        testcase.assertIsNotNone(asbr_lsp)
        self.hld_obj = asbr_lsp

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class inter_as_destination:

    def __init__(self, testcase, device, asbr, dpe):
        self.testcase = testcase
        self.device = device

        inter_as_destination = device.create_inter_as_destination(asbr, dpe)
        testcase.assertIsNotNone(inter_as_destination)
        self.hld_obj = inter_as_destination

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class te_tunnel:

    def __init__(self, testcase, device, gid, dest):
        self.testcase = testcase
        self.device = device

        te_tunnel = device.create_te_tunnel(gid, dest, type=sdk.la_te_tunnel.tunnel_type_e_NORMAL)
        testcase.assertIsNotNone(te_tunnel)
        self.hld_obj = te_tunnel

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class ldp_over_te_tunnel:

    def __init__(self, testcase, device, gid, dest):
        self.testcase = testcase
        self.device = device

        te_tunnel = device.create_te_tunnel(gid, dest, type=sdk.la_te_tunnel.tunnel_type_e_LDP_ENABLED)
        testcase.assertIsNotNone(te_tunnel)
        self.hld_obj = te_tunnel

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class protection_monitor:

    def __init__(self, testcase, device):
        self.testcase = testcase
        self.device = device

        protection_monitor = device.create_protection_monitor()
        testcase.assertIsNotNone(protection_monitor)
        self.hld_obj = protection_monitor

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class l3_protection_group:

    def __init__(self, testcase, device, gid, primary, backup, monitor):
        self.testcase = testcase
        self.device = device

        l3_protection_group = self.device.create_l3_protection_group(gid, primary, backup, monitor)
        testcase.assertIsNotNone(l3_protection_group)
        self.hld_obj = l3_protection_group

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class mac_addr:

    def __init__(self, addr_str):
        self.addr_str = addr_str
        self.hld_obj = sdk.la_mac_addr_t()
        self.hld_obj.flat = self.to_num()

    def to_num(self):
        bytes = self.addr_str.split(':')
        assert(len(bytes) == 6)  # 6 bytes
        for b in bytes:
            assert(len(b) == 2)  # 2 digits for each byte

        hex_str = self.addr_str.replace(':', '')
        n = int(hex_str, 16)

        return n

    def create_offset_mac(self, offset):
        mac_dec = self.to_num() + offset
        hex_str = self.mac_num_to_str(mac_dec)
        return mac_addr(hex_str)

    @staticmethod
    def mac_num_to_str(mac_dec):
        hex_str = format(mac_dec, 'x')
        hex_str = ':'.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))
        return hex_str


class ipv4_addr:

    NUM_OF_BYTES = 4
    BITS_IN_BYTE = 8

    def __init__(self, addr_str):
        self.addr_str = IPv4Address(addr_str).exploded
        self.hld_obj = sdk.la_ipv4_addr_t()
        self.hld_obj.s_addr = self.to_num()

    def to_num(self):
        bytes = self.addr_str.split('.')
        assert(len(bytes) == ipv4_addr.NUM_OF_BYTES)
        c = ipv4_addr.NUM_OF_BYTES - 1
        n = 0
        for b in bytes:
            bn = int(b)
            assert(bn < (1 << ipv4_addr.BITS_IN_BYTE))
            n += (1 << ipv4_addr.BITS_IN_BYTE) ** c * bn
            c -= 1

        return n


class ipv6_addr:

    NUM_OF_SHORTS = 8
    BITS_IN_SHORT = 16
    BITS_IN_QWORD = 64
    NUM_OF_BYTES = 16

    def __init__(self, addr_str):
        self.addr_str = IPv6Address(addr_str).exploded
        self.hld_obj = sdk.la_ipv6_addr_t()
        q0 = self.to_num() & ((1 << ipv6_addr.BITS_IN_QWORD) - 1)
        q1 = (self.to_num() >> ipv6_addr.BITS_IN_QWORD) & ((1 << ipv6_addr.BITS_IN_QWORD) - 1)
        sdk.set_ipv6_addr(self.hld_obj, q0, q1)

    def to_num(self):
        shorts = self.addr_str.split(':')
        assert(len(shorts) == ipv6_addr.NUM_OF_SHORTS)
        c = ipv6_addr.NUM_OF_SHORTS - 1
        n = 0
        for s in shorts:
            if len(s) > 0:
                sn = int(s, 16)
                n += (1 << ipv6_addr.BITS_IN_SHORT) ** c * sn
            c -= 1

        return n


class counter:

    def __init__(self, testcase, device, size):
        self.testcase = testcase
        self.device = device
        counter1 = self.device.create_counter(size)
        self.hld_obj = counter1

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None

# Objects ID's and addresses


RX_SLICE = 5
RX_IFG = 0
RX_IFG1 = 1

TX_SLICE_REG = 1
TX_SLICE_DEF = 2
TX_SLICE_EXT = 3
TX_IFG_REG = 1
TX_IFG_DEF = 1
TX_IFG_EXT = 1

FIRST_SERDES_SVI = 0
LAST_SERDES_SVI = 1
FIRST_SERDES_L3 = 2
LAST_SERDES_L3 = 3

FIRST_SERDES_L3_DEF = 2
FIRST_SERDES_L3_REG = 2
FIRST_SERDES_L3_EXT = 2

LAST_SERDES_L3_DEF = 3
LAST_SERDES_L3_REG = 3
LAST_SERDES_L3_EXT = 3

FIRST_SERDES_SVI_DEF = 0
FIRST_SERDES_SVI_REG = 0
FIRST_SERDES_SVI_EXT = 0

LAST_SERDES_SVI_DEF = 1
LAST_SERDES_SVI_REG = 1
LAST_SERDES_SVI_EXT = 1

# INJECT_PIF_FIRST = 8
PI_IFG = 0
PI_PIF = 18
PACIFIC_PCI_SERDES = 18
PACIFIC_RCY_SERDES = 19
GIBRALTAR_PCI_SERDES = 24
GIBRALTAR_RCY_SERDES = 25
# Note internal PIFs are used on HW, which are translated using internal PIF to external PIF mapping
ASIC4_PCI_SERDES = 17
ASIC4_RCY_SERDES = 18
if decor.is_hw_device():
    ASIC4_PCI_SERDES = 33
    ASIC4_RCY_SERDES = 34
# For Asic5, those two need to be the PIFs of PKTDMA/RECYCLE in src/hld/hld_types.h
ASIC5_PCI_SERDES = 81
ASIC5_RCY_SERDES = 82
# For ASIC3, those two need to be the PIFs of PKTDMA/RECYCLE in src/hld/hld_types.h
ASIC3_PCI_SERDES = 33
ASIC3_RCY_SERDES = 34
RX_SYS_PORT_GID = 0x21
RX_SYS_PORT_GID1 = 0x31


# Bug in NPL: when packet is punted it gets an SSP on PacketDmaWaHeader8/16 header. This is WA to pass the tests.
PUNT_DUMMY_SSP = 36

TX_SVI_SYS_PORT_REG_GID = 0x22
TX_SVI_SYS_PORT_DEF_GID = 0x23
TX_SVI_SYS_PORT_EXT_GID = 0x24

TX_L3_AC_SYS_PORT_REG_GID = 0x25
TX_L3_AC_SYS_PORT_DEF_GID = 0x26
TX_L3_AC_SYS_PORT_EXT_GID = 0x27

RX_SWITCH_GID = 0xa0a
RX_SWITCH_GID1 = 0xa0b
TX_SWITCH_GID = 0xa0c
TX_SWITCH_GID1 = 0xa0d

RX_L2_AC_PORT_GID = 0x211
RX_L2_AC_PORT_GID1 = 0x212
RX_L2_AC_PORT_VID1 = 0xa
RX_L2_AC_PORT_VID2 = 0x0

TX_L2_AC_PORT_REG_GID = 0x190
TX_L2_AC_PORT_DEF_GID = 0x231
TX_L2_AC_PORT_EXT_GID = 0x241


VRF_GID = 0x3cc if not decor.is_gibraltar() else 0x7ff
VRF2_GID = 0x3dd if not decor.is_gibraltar() else 0x7dd

RX_SVI_GID = 0x711
RX_SVI_GID1 = 0x712
TX_SVI_GID = 0x721
TX_SVI_EXT_GID = 0x731

RX_L3_AC_GID = 0x811
RX_L3_AC_GID1 = 0x812
RX_L3_AC_ONE_TAG_GID = 0x851
TX_L3_AC_REG_GID = 0x821
TX_L3_AC_DEF_GID = 0x831
TX_L3_AC_EXT_GID = 0x841
TX_L3_AC_REG_SPA_GID = 0x861

RX_SVI_MAC = mac_addr('10:12:13:14:15:16')
RX_SVI_MAC1 = mac_addr('10:17:18:19:1a:1b')
TX_SVI_MAC = mac_addr('20:22:23:24:25:26')
TX_SVI_EXT_MAC = mac_addr('28:29:2a:2b:2c:2d')

RX_L3_AC_MAC = mac_addr('30:32:33:34:35:36')
RX_L3_AC_MAC1 = mac_addr('30:37:38:39:3a:3b')
RX_L3_AC_PORT_VID1 = 0x1
RX_L3_AC_PORT_VID2 = 0x3

RX_L3_AC_IPv4_MC_MAC = mac_addr('01:00:5e:00:00:05')
RX_L3_AC_IPv6_MC_MAC = mac_addr('33:33:00:00:00:05')

RX_L3_AC_ONE_TAG_MAC = mac_addr('30:32:11:11:11:11')
RX_L3_AC_ONE_TAG_PORT_VID = 0x5

TX_L3_AC_REG_MAC = mac_addr('40:42:43:44:45:46')
TX_L3_AC_DEF_MAC = mac_addr('50:52:53:54:55:56')
TX_L3_AC_EXT_MAC = mac_addr('60:62:63:64:65:66')

NH_L3_AC_REG_GID = 0x611
NH_L3_AC_DEF_GID = 0x621
NH_L3_AC_EXT_GID = 0x631
NH_SVI_REG_GID = 0x641
NH_SVI_DEF_GID = 0x651
NH_SVI_EXT_GID = 0x661
NH_L3_AC_GLEAN_GID = 0x671
NH_SVI_GLEAN_GID = 0x681
NH_L3_AC_GLEAN_NULL_GID = 0x672
NH_SVI_GLEAN_NULL_GID = 0x682

NH_L3_AC_REG_MAC = mac_addr('70:72:73:74:75:76')
NH_L3_AC_DEF_MAC = mac_addr('80:82:83:84:85:86')
NH_L3_AC_EXT_MAC = mac_addr('90:92:93:94:95:96')
NH_SVI_REG_MAC = mac_addr('a0:a2:a3:a4:a5:a6')
NH_SVI_DEF_MAC = mac_addr('b0:b2:b3:b4:b5:b6')
NH_SVI_EXT_MAC = mac_addr('c0:c2:c3:c4:c5:c6')

RX_MAC = mac_addr('00:00:00:00:00:00')

L2_PUNT_DESTINATION1_GID = 0x0
L2_PUNT_DESTINATION2_GID = 0x1

# FHRP MAC addresses
RX_HSRP_V1_IPV4_VMAC1 = mac_addr('00:00:0c:07:ac:01')
RX_HSRP_V1_IPV4_VMAC2 = mac_addr('00:00:0c:07:ac:02')
RX_HSRP_V2_IPV4_VMAC1 = mac_addr('00:00:0C:9F:F0:01')
RX_HSRP_V2_IPV4_VMAC2 = mac_addr('00:00:0C:9F:F0:02')
RX_HSRP_V2_IPV6_VMAC1 = mac_addr('00:05:73:a0:00:01')
RX_HSRP_V2_IPV6_VMAC2 = mac_addr('00:05:73:a0:00:02')
RX_VRRP_IPV4_VMAC1 = mac_addr('00:00:5E:00:01:01')
RX_VRRP_IPV4_VMAC2 = mac_addr('00:00:5E:00:01:02')
RX_VRRP_IPV6_VMAC1 = mac_addr('00:00:5E:00:02:01')
RX_VRRP_IPV6_VMAC2 = mac_addr('00:00:5E:00:02:02')


class ip_svi_base:

    def __init__(self, topology):
        self.topology = topology

    @property
    def rx_port(self):
        return self.topology.rx_svi

    @property
    def rx_port1(self):
        return self.topology.rx_svi1

    @property
    def rx_one_tag_port(self):
        return self.topology.rx_svi

    @property
    def tx_port(self):
        return self.topology.tx_svi

    @property
    def tx_port_def(self):
        return self.topology.tx_svi

    @property
    def tx_port_ext(self):
        return self.topology.tx_svi_ext

    @property
    def reg_fec(self):
        return self.topology.fec_svi_reg

    @property
    def ext_fec(self):
        return self.topology.fec_svi_ext

    @property
    def reg_nh(self):
        return self.topology.nh_svi_reg

    @property
    def def_nh(self):
        return self.topology.nh_svi_def

    @property
    def ext_nh(self):
        return self.topology.nh_svi_ext

    @property
    def glean_nh(self):
        return self.topology.nh_svi_glean

    @property
    def glean_null_nh(self):
        return self.topology.nh_svi_null_glean

    @property
    def serdes_def(self):
        return FIRST_SERDES_SVI_DEF

    @property
    def serdes_reg(self):
        return FIRST_SERDES_SVI_REG

    @property
    def serdes_ext(self):
        return FIRST_SERDES_SVI_EXT

    @property
    def is_svi(self):
        return True


class ip_l3_ac_base:

    def __init__(self, topology):
        self.topology = topology

    @property
    def rx_port(self):
        return self.topology.rx_l3_ac

    @property
    def rx_port1(self):
        return self.topology.rx_l3_ac1

    @property
    def rx_one_tag_port(self):
        return self.topology.rx_l3_ac_one_tag

    @property
    def tx_port(self):
        return self.topology.tx_l3_ac_reg

    @property
    def tx_port_def(self):
        return self.topology.tx_l3_ac_def

    @property
    def tx_port_ext(self):
        return self.topology.tx_l3_ac_ext

    @property
    def reg_fec(self):
        return self.topology.fec_l3_ac_reg

    @property
    def ext_fec(self):
        return self.topology.fec_l3_ac_ext

    @property
    def reg_nh(self):
        return self.topology.nh_l3_ac_reg

    @property
    def def_nh(self):
        return self.topology.nh_l3_ac_def

    @property
    def ext_nh(self):
        return self.topology.nh_l3_ac_ext

    @property
    def glean_nh(self):
        return self.topology.nh_l3_ac_glean

    @property
    def glean_null_nh(self):
        return self.topology.nh_l3_ac_null_glean

    @property
    def serdes_reg(self):
        return FIRST_SERDES_L3_REG

    @property
    def serdes_def(self):
        return FIRST_SERDES_L3_DEF

    @property
    def serdes_ext(self):
        return FIRST_SERDES_L3_EXT

    @property
    def is_svi(self):
        return False
