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

import os
import sys
import socket
import lldcli
import test_lldcli
from leaba import sdk
try:
    import test_nsim_providercli as nsim
except BaseException:
    import test_packet_provider as nsim
import packet_test_utils as U
from scapy.all import *
from packet_test_defs import *
from binascii import hexlify, unhexlify
import time
from copy import deepcopy
import decor
import topology as T
import nplapicli as nplapi
import warm_boot_test_utils as wb
import gc
import inspect
import importlib
import logging

# enable auto warm boot
if decor.is_auto_warm_boot_enabled():
    wb.enable_auto_warm_boot()

NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS = 0x26

DUMMY_DST_MAC = "00:00:00:00:00:38"  # Dummy address
DUMMY_SRC_MAC = "00:00:00:00:00:39"  # Dummy address
DUMMY_VLAN = 0xAB9  # Dummy VLAN
BYTES_IN_DQWORD = 16

INJECT_DOWN_HEADER = Ether(dst=DUMMY_DST_MAC, src=DUMMY_SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=DUMMY_VLAN, type=Ethertype.Inject.value) / \
    InjectDown(type=1)

INJECT_UP_STD_HEADER = Ether(dst=DUMMY_DST_MAC, src=DUMMY_SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=DUMMY_VLAN, type=Ethertype.Inject.value) / \
    InjectUpStd(pif_id=0, ifg_id=0)

INJECT_UP_STD_LAYER_INDEX = 2

INJECT_UP_STD_HEADER_LEN = len(INJECT_UP_STD_HEADER)

# Below objects are only created automatically by SDK and destroyed automatically. No need to destroy them manually
TEARDOWN_FILTER_LIST = {
    sdk.la_object.object_type_e_IFG_SCHEDULER,
    sdk.la_object.object_type_e_SYSTEM_PORT_SCHEDULER,
    sdk.la_object.object_type_e_LOGICAL_PORT_SCHEDULER,
    sdk.la_object.object_type_e_INTERFACE_SCHEDULER}


def restart_asic_if_required():
    device_revision = os.environ.get('ASIC', None)
    if (device_revision != 'GIBRALTAR_A0'):
        return
    script_path = os.environ.get('ASIC_RESTART_SCRIPT', None)
    if script_path is None:
        return
    import subprocess
    rc = subprocess.run(script_path, shell=True)
    assert(rc.returncode == 0)


class uut_provider_base():
    @property
    def m_ll_device(self):
        return self.device.get_ll_device()

    def init_matilda_model(self, is_hw_dev):
        if not decor.is_gibraltar():
            return None
        eFuse_values = self.device.get_device_int_capabilities()
        eFuse_matilda_value = eFuse_values[self.device.device_int_capability_e_MATILDA_MODEL]

        if is_hw_dev and eFuse_matilda_value:
            assert self.matilda_model[1], "On a real Matilda hw device, you have to run in matilda_hw mode!"

        if eFuse_matilda_value == 0 and self.matilda_model[0]:
            # Do not set the property for value of GB, and Do not attempt to override value from efuse
            self.device.set_int_property(sdk.la_device_property_e_MATILDA_MODEL_TYPE, self.matilda_model[0])

        if self.matilda_model[1]:
            # runing in matilda_hw mode - set the device frequency acordingly
            self.device.set_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY, 900 * 1000)

    def clear_traps(self):
        # Clear all existing trap configurations.
        # Iterate over events in reverse order to avoid multiple pop operations.
        for event in reversed(range(sdk.LA_EVENT_ETHERNET_FIRST, sdk.LA_EVENT_APP_LAST)):
            try:
                self.device.clear_trap_configuration(event)
            except sdk.BaseException as STATUS:
                if (STATUS.args[0] != sdk.la_status_e_E_NOTFOUND):
                    print('TearDown ERROR: Trap configuration %s can not be cleared!' % event)
                    self.assertFail()

    def clear_snoops(self):
        # Clear all existing trap configurations
        for event in range(sdk.LA_EVENT_ETHERNET_FIRST, sdk.LA_EVENT_APP_LAST):
            try:
                self.device.clear_snoop_configuration(event)
            except sdk.BaseException as STATUS:
                if (STATUS.args[0] != sdk.la_status_e_E_NOTFOUND):
                    print('TearDown ERROR: Snoop configuration %s can not be cleared!' % event)
                    self.assertFail()

    def clear_routes(self):
        # Clear existing routes
        for curr_obj in self.device.get_objects(sdk.la_object.object_type_e_LSR):
            curr_obj.clear_all_routes()

    def clear_counters(self):
        for curr_obj in self.device.get_objects(sdk.la_object.object_type_e_COUNTER_SET):
            set_size = curr_obj.get_set_size()
            for i in range(set_size):
                curr_obj.read(i, True, True)

    def get_ethernet_port(self, slice_val, ifg, base_pif):
        for curr_obj in self.device.get_objects(sdk.la_object.object_type_e_ETHERNET_PORT):
            sys_port = curr_obj.get_system_port()
            if sys_port and (
                (sys_port.get_slice() == slice_val) and (
                    sys_port.get_ifg() == ifg) and (
                    sys_port.get_base_pif() == base_pif)):
                return curr_obj
        return 0

    def get_ethernet_port_from_serdes(self, slice_val, ifg, serdes_id):
        return self.get_ethernet_port(slice_val, ifg, U.serdes_to_pif(self.device, serdes_id))

    def clear_mc_voqs_cgm_profile(self):
        used_slices = range(6)
        # used_slices = self.device.get_used_slices()
        slice_modes_set = {self.device.get_slice_mode(sid) for sid in used_slices}
        # LC mode
        if sdk.la_slice_mode_e_CARRIER_FABRIC in slice_modes_set and sdk.la_slice_mode_e_NETWORK in slice_modes_set:
            # linecard mode configures the multicast fabric VOQ
            voq_set = self.device.get_egress_multicast_fabric_replication_voq_set()
            for voq in range(voq_set.get_set_size()):
                voq_set.set_cgm_profile(voq, None)

            # line mode configures the multicast VOQs for each network slice
            for slice_id in used_slices:
                slice_mode = self.device.get_slice_mode(slice_id)
                if slice_mode == sdk.la_slice_mode_e_NETWORK:
                    voq_set = self.device.get_egress_multicast_slice_replication_voq_set(slice_id)
                    if voq_set is None:
                        continue
                    for voq in range(voq_set.get_set_size()):
                        voq_set.set_cgm_profile(voq, None)

        # standalone mode
        elif sdk.la_slice_mode_e_NETWORK in slice_modes_set:
            # standlaone mode configures the multicast VOQs on all slices
            invalid_modes = [sdk.la_slice_mode_e_INVALID, sdk.la_slice_mode_e_DISABLED]
            for sid in used_slices:
                if self.device.get_slice_mode(sid) in invalid_modes:
                    continue
                voq_set = self.device.get_egress_multicast_slice_replication_voq_set(sid)
                if voq_set is None:
                    continue
                for voq in range(voq_set.get_set_size()):
                    voq_set.set_cgm_profile(voq, None)

    def set_voqs_to_dropping_state(self):
        voq_sets = self.device.get_objects(sdk.la_object.object_type_e_VOQ_SET)
        for voq_set in voq_sets:
            voq_set.set_state(sdk.la_voq_set.state_e_DROPPING)

    def teardown_object(self, obj):
        obj_type = obj.type()
        if (obj_type == sdk.la_object.object_type_e_L2_SERVICE_PORT):
            obj.detach()
            obj.set_destination(None)

        if (obj_type == sdk.la_object.object_type_e_VRF):
            obj.clear_all_ipv4_routes()
            obj.clear_all_ipv6_routes()

        is_voq = (obj_type == sdk.la_object.object_type_e_VOQ_SET)
        if is_voq:
            voq_state = obj.get_state()
            obj.set_state(sdk.la_voq_set.state_e_DROPPING)

        try:
            self.destroy(obj, invalidate_py_refs=False)
            return True
        except sdk.BaseException:
            if is_voq:
                obj.set_state(voq_state)
            return False

    def destroy(self, obj, invalidate_py_refs=True):
        # when objects are torn down, all references to swig proxy objects need to be invalidated,
        # otherwise there will be problems in warm boot because proxy object will have invalid reference
        # to underlying cpp object (which is freed).

        if wb.is_warm_boot_supported() and invalidate_py_refs:
            wb.set_ignore_auto_wb(True)
            gc.collect()
            all_objects = gc.get_objects()
            la_objects_dict = {}
            ignore = [id(inspect.currentframe()), id(all_objects)]
            device_id = self.device.get_id()
            for o in all_objects:
                if wb.is_swig_object(o) and \
                   wb.is_la_object(o) and \
                   not wb.is_la_device(o):
                    refs = wb.get_obj_referrers(o, ignore)
                    if len(refs) and o.get_device().get_id() == device_id:
                        la_objects_dict.setdefault(o.oid(), []).append((o, refs))

            objs_before_teardown = set(o.oid() for o in self.device.get_objects())
            wb.set_ignore_auto_wb(False)

        # destroy sdk object
        self.device.destroy(obj)

        # invalidate proxy object references after underlying object is destroyed;
        # references should be invalidated only if underlyng objects are destroyed
        # successfully (if previous call did not raise exception)
        if wb.is_warm_boot_supported() and invalidate_py_refs:
            wb.set_ignore_auto_wb(True)
            objs_after_teardown = set(o.oid() for o in self.device.get_objects())
            destroyed_objs = objs_before_teardown - objs_after_teardown

            for oid in destroyed_objs:
                if oid in la_objects_dict:
                    wb.invalidate_objs_refs(la_objects_dict[oid])
            wb.set_ignore_auto_wb(False)

    def filter_teardown_list(self, *, teardown_list, objects_to_keep):
        out_teardown_list = []
        output_queue_scheduler_list = []
        for curr_obj in teardown_list:
            if curr_obj.oid() in objects_to_keep:
                continue
            obj_type = curr_obj.type()
            if obj_type not in TEARDOWN_FILTER_LIST:
                # Below object type is created in SDK and can be created by user. We push
                # them to top of list to avoid segmentation faults during auto teardown.
                if (obj_type != sdk.la_object.object_type_e_OUTPUT_QUEUE_SCHEDULER):
                    out_teardown_list.append(curr_obj)
                else:
                    output_queue_scheduler_list.append(curr_obj)

        out_teardown_list.extend(output_queue_scheduler_list)
        return out_teardown_list

    def tearDownObjects(self, objects_to_keep):

        # disable auto-WB for this function, things can go bad if WB is called while objects
        # are being destroyed
        if decor.is_auto_warm_boot_enabled():
            wb.set_ignore_auto_wb(True)

        # Get list of all SDK la_object objects before some of them are destroyed
        if wb.is_warm_boot_supported():
            gc.collect()
            all_objects = gc.get_objects()
            ignore = [id(inspect.currentframe()), id(all_objects)]
            la_objects_dict = {}
            device_id = self.device.get_id()
            for obj in all_objects:
                if wb.is_swig_object(obj) and \
                   wb.is_la_object(obj) and \
                   not wb.is_la_device(obj):
                    refs = wb.get_obj_referrers(obj, ignore)
                    if len(refs) and obj.get_device().get_id() == device_id and not obj.oid() in objects_to_keep:
                        la_objects_dict.setdefault(obj.oid(), []).append((obj, refs))

            objs_before_teardown = set(obj.oid() for obj in self.device.get_objects())

        # There's a circular dependency between L3-AC, VRF and IP-MCG,
        # which cannot be broken by the code below -
        for vrf in self.device.get_objects(sdk.la_object.object_type_e_VRF):
            vrf.clear_all_ipv4_multicast_routes()
            vrf.clear_all_ipv6_multicast_routes()

        for voq_set in reversed(self.device.get_objects(sdk.la_object.object_type_e_VOQ_SET)):
            if voq_set.oid() not in objects_to_keep:
                T.topology.deallocate_voq_set(
                    self,
                    voq_set.get_destination_device(),
                    voq_set.get_destination_slice(),
                    voq_set.get_destination_ifg(),
                    voq_set.get_set_size(),
                    voq_set.get_base_voq_id(),
                    voq_set.get_base_vsc_vec())

        while True:
            objects_destroyed = 0
            local_teardown_list = self.filter_teardown_list(
                teardown_list=self.device.get_objects(), objects_to_keep=objects_to_keep)
            for curr_obj in reversed(local_teardown_list):
                if self.teardown_object(curr_obj):
                    objects_destroyed += 1
                    # If we deleted an object we may need to get a new list since
                    # this list may contain objects already deleted.
                    break

            if (objects_destroyed == 0):
                break

        # Invalidate python references to all SDK la_object objects except
        # the ones from objects_to_keep list
        if wb.is_warm_boot_supported():
            destroyed_objs = objs_before_teardown - set(objects_to_keep)

            for oid in destroyed_objs:
                if oid in la_objects_dict:
                    wb.invalidate_objs_refs(la_objects_dict[oid])

        # enable auto-WB again
        if decor.is_auto_warm_boot_enabled():
            wb.set_ignore_auto_wb(False)

    def clear_device(self, objects_to_keep=[]):
        if self.device.get_ll_device().is_pacific():
            self.clear_mc_voqs_cgm_profile()
        self.clear_traps()
        self.clear_snoops()
        self.clear_routes()
        self.tearDownObjects(objects_to_keep=objects_to_keep)
        # Ensure device interaction with hardware/simulator is done before exiting
        self.device.flush()

    def tearDown(self):
        self.set_voqs_to_dropping_state()
        self.clear_device(objects_to_keep=[])
        self.device.disconnect()
        # Wrap-up
        sdk.la_destroy_device(self.device)
        self.device = None

    def get_wrapper_headers_len(self, scapy_packet, slice_id):
        return 0

    def get_pci_serdes(self):
        if self.m_ll_device.is_pacific():
            return T.PACIFIC_PCI_SERDES
        elif self.m_ll_device.is_gibraltar():
            return T.GIBRALTAR_PCI_SERDES
        elif self.m_ll_device.is_asic4():
            return T.ASIC4_PCI_SERDES
        elif self.m_ll_device.is_asic5():
            return T.ASIC5_PCI_SERDES
        elif self.m_ll_device.is_asic3():
            return T.ASIC3_PCI_SERDES
        else:
            raise Exception('ASIC revision is not supported')

    def get_oq_num(self, ifg, serdes):
        if self.m_ll_device.is_pacific():
            NUM_SERDES_PER_IFG = 18
        elif self.m_ll_device.is_gibraltar():
            NUM_SERDES_PER_IFG = 24
        elif self.m_ll_device.is_asic4():
            NUM_SERDES_PER_IFG = 16
        elif self.ll_device.is_asic5():
            NUM_SERDES_PER_IFG = 48
        else:
            raise Exception('ASIC revision is not supported')
        NUM_OQ_PER_IFG = T.NUM_OQ_PER_SERDES * NUM_SERDES_PER_IFG + T.NUM_OQ_PER_SERDES + \
            T.NUM_OQ_PER_SERDES  # Last two elements are: Recycle Host interfaces
        oq = ifg * NUM_OQ_PER_IFG + serdes * T.NUM_OQ_PER_SERDES
        return oq

    def flush(self):
        if self.device and not (hasattr(self, 'warm_boot_disconnected') and self.warm_boot_disconnected):
            self.device.flush()

    def strip_std_inject_header(self, scapy_packet, slice, ifg, pif):
        res_packet = nsim.sim_packet_info_desc()
        device_family = self.device_family
        if (device_family == sdk.la_device_family_e_PACIFIC and pif == T.PACIFIC_RCY_SERDES):
            res_packet.pif = pif - 1
            res_packet.slice = slice - 1
        elif ((device_family == sdk.la_device_family_e_GIBRALTAR and pif == T.GIBRALTAR_RCY_SERDES) or
                (device_family == sdk.la_device_family_e_ASIC4 and pif == T.ASIC4_RCY_SERDES)):
            res_packet.pif = pif - 1
            inject_slice = self.rcy_to_inject_slice[slice]
            res_packet.slice = inject_slice
        else:
            res_packet.pif = pif
            res_packet.slice = slice

        res_packet.ifg = get_physical_ifg(device_family, slice, ifg)

        # If there is no Punt NPL should remove the prefix layers
        if (not scapy_packet.haslayer('Punt')):
            res_packet.packet = U.scapy_to_hex(scapy_packet)
            return res_packet

        scapy_iterator = scapy_packet
        while True:
            if scapy_iterator.name == 'Punt':
                punt_layer = scapy_iterator
                break
            scapy_iterator = scapy_iterator.payload

        punt_layer.time_stamp = 0
        punt_layer.receive_time = 0

        if (not scapy_packet.haslayer('InjectUpStd')):
            res_packet.packet = U.scapy_to_hex(scapy_packet)
            return res_packet

        # Check the UDP destination port for sflow. sflow Tunnel feature uses port
        # number 6343 and adds a Punt header as an erspan encapsulation. Skip
        # stripping out the InjectUpStd layer in that case.
        if (scapy_packet.haslayer('UDP')):
            if (scapy_packet[UDP].dport == 6343):
                res_packet.packet = U.scapy_to_hex(scapy_packet)
                return res_packet

        # Learn notification detection
        if scapy_iterator[3].name == 'InjectUpStd' and scapy_iterator[3].type == sdk.la_packet_types.LA_PACKET_INJECT_TYPE_UP_LEARN_RECORD:
            res_packet.packet = U.scapy_to_hex(scapy_packet)
            return res_packet

        # Offset includes the InjectUpStd size. If '0' - don't care, leave as '0'.
        if punt_layer.next_header_offset != 0:
            punt_layer.next_header_offset -= INJECT_UP_STD_HEADER_LEN

        # In case of ingress Punt the egress packet includes the InjectUpStd
        # header 3 layers should be removed: Ether() / Dot1Q / InjectUpStd()
        while scapy_iterator[3].name is not 'Raw':
            if scapy_iterator[3].name == 'InjectUpStd':
                inject_up_std_layer = scapy_iterator[3]
                break
            scapy_iterator = scapy_iterator.payload

        pkt_tail = deepcopy(inject_up_std_layer.payload)
        if (inject_up_std_layer.trailer_size != 0):
            punt_layer.next_header_offset -= inject_up_std_layer.trailer_size
            pkt_tail = pkt_tail.payload

        layer_type = pkt_tail.type
        scapy_iterator.type = layer_type
        scapy_iterator.remove_payload()
        scapy_packet = scapy_packet / pkt_tail

        res_packet.packet = U.scapy_to_hex(scapy_packet)
        return res_packet


class hw_device(uut_provider_base):
    ETH_P_ALL = 3

    def init(self, device_path, dev_id, initialize, slice_modes, device_config_func):
        restart_asic_if_required()
        self.device_path = device_path
        self.device = sdk.la_create_device(self.device_path, dev_id)
        self.ll_device = self.device.get_ll_device()
        self.device_family = self.ll_device.get_device_family()
        self.device_revision = self.ll_device.get_device_revision()
        self.warm_boot_disconnected = False

        # This map stores info about PCI ports needed to inject packets. Can be updated from 2 places:
        # 1. hw_device.open_sockets()
        # 2. warm_boot_test_utils.store_pci_ports_info() - if warm_boot_test_utils.warm_boot_disconnect() is called
        #    before injecting first packet. That allows to inject packets while SDK is unloaded (SDK PCI port objects
        #    don't exist)
        self.pci_port_slice_to_network_interface_name = {}

        self.device.set_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST, True)
        if os.getenv('IGNORE_MBIST_ERRORS'):
            self.device.set_bool_property(sdk.la_device_property_e_IGNORE_MBIST_ERRORS, True)

        if os.getenv('LEABA_EMULATED_DEVICE'):
            self.device.set_bool_property(sdk.la_device_property_e_EMULATED_DEVICE, True)

        # MSI does not propagate to CPU on Blacktip board with Kontron Compact chipset.
        self.POLL_MSI = (self.m_ll_device.is_gibraltar() and decor.is_hw_kontron_compact_cpu())
        print('Setting POLL_MSI={}'.format(self.POLL_MSI))
        self.device.set_bool_property(sdk.la_device_property_e_POLL_MSI, self.POLL_MSI)

        self.init_matilda_model(True)

        # Forwarding caches are enabled only on Pacific B0 and B1 due to multiple cache correctness issues on Pacific A0.
        if self.device_revision == sdk.la_device_revision_e_PACIFIC_A0:
            self.device.set_bool_property(sdk.la_device_property_e_ENABLE_LPM_IP_CACHE, False)

        # Initialize device
        if initialize:
            initialize_device(self.device, slice_modes, device_config_func)

        self.sockets_opened = False
        self.sockets = T.NUM_SLICES_PER_DEVICE * [None]

    def clear_device(self, objects_to_keep=[]):
        self.close_sockets()
        super().clear_device(objects_to_keep=objects_to_keep)

    def tearDown(self):
        # Close sockets
        self.close_sockets()

        super().tearDown()

    def __getattr__(self, item):
        if item in self.__dir__():
            return self.__getattribute__(item)

        return self.device.__getattribute__(item)

    def open_sockets(self):
        if self.device and self.m_ll_device:
            for pci_port in self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT):
                slice = pci_port.get_slice()
                interface_name = self.m_ll_device.get_network_interface_name(slice)
                self.pci_port_slice_to_network_interface_name[slice] = interface_name

        for slice, if_name in self.pci_port_slice_to_network_interface_name.items():
            os.system('echo 0 > /proc/sys/net/ipv6/conf/%s/router_solicitations' %
                      if_name)  # Avoid router-solicitation messages from kernel
            os.system('ifconfig %s up mtu 6000' % if_name)
            self.sockets[slice] = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self.sockets[slice].settimeout(0.01)
            self.sockets[slice].bind((if_name, self.ETH_P_ALL))

        self.sockets_opened = True

    def close_sockets(self):
        if not self.sockets_opened:
            return
        for slice in self.pci_port_slice_to_network_interface_name.keys():
            self.sockets[slice].close()
            self.sockets[slice] = None
        self.pci_port_slice_to_network_interface_name.clear()
        self.sockets_opened = False

    def step_packet(self):
        time.sleep(0.2)
        return True

    def step_learn_notify_packet(self):
        time.sleep(0.2)
        return True

    def inject_packet(self, in_packet, initial_values={}):
        # Open sockets if not done yet
        if (not self.sockets_opened):
            self.open_sockets()

        # Add inject header if needed
        in_packet = get_inject_packet(self.device_family, in_packet)
        ipacket = bytes(U.hex_to_scapy(in_packet.packet))
        s = self.sockets[in_packet.slice]
        bytes_num = s.send(ipacket)
        if bytes_num != len(ipacket):
            print('Error: send failed len(ipacket)=%d bytes_num=%d' % (len(ipacket), bytes_num))
            return False

        return True

    def pacific_b1_hw_padding_compensation(self, packet):
        if self.device_revision != sdk.la_device_revision_e_PACIFIC_B1:
            return packet

        # HW padding used in pacific B1 is added after the packet-DMA WA header.
        # this header is removed by the kernel-module, so the packet may become too short

        packet_size = len(packet)
        kernel_hdr_size = len(KernelHeader())  # KernelHeader is removed later
        net_size = packet_size - kernel_hdr_size
        diff = U.MIN_PKT_SIZE_WITHOUT_CRC - net_size

        if diff < 0:
            # packet size is valid
            return packet

        # if the packet is too short then pad it up to MIN_PKT_SIZE
        return packet + b'\xff' * diff

    def get_packets(self):
        packets = []
        opacket = nsim.sim_packet_info_desc()
        for port_slice in self.pci_port_slice_to_network_interface_name.keys():
            while (True):
                try:
                    packet_data = self.sockets[port_slice].recv(1000000)  # Very big number
                except socket.timeout as ex:
                    # Polling a port that does't receive any packet will timeout.
                    break
                # no other exception should occur.

                pre = hexlify(bytes(packet_data[0:4])).decode('ascii')
                if (pre == 'ffffffff' or pre == '33330000'):
                    continue

                packet_data = self.pacific_b1_hw_padding_compensation(packet_data)
                tmp_packet = KernelHeader(bytes(packet_data))
                ifg = tmp_packet.ifg
                pif = tmp_packet.pif
                slice = tmp_packet.slice_id
                res_packet = self.strip_std_inject_header(tmp_packet.getlayer(1), slice, ifg, pif)
                # We don't know which header we get
                res_packet = reset_punt_time_fields(res_packet)
                packets.append(res_packet)

        return packets

    def get_packet(self):
        packets = self.get_packets()
        if len(packets) != 1:
            return (False, "")

        return (True, packets[0])

    def inject_db_trigger(self, line):
        self.device.flush()

    def system_learn_trigger(self):
        self.device.flush()

    def get_wrapper_headers_len(self, scapy_packet, slice_id):
        if ((scapy_packet.type == Ethertype.Dot1Q.value) and (scapy_packet[1].type == Ethertype.Inject.value)):
            return 0

        result = INJECT_UP_STD_HEADER_LEN
        if self.device_family == sdk.la_device_family_e_PACIFIC:
            # checking if additional 8 bytes are added to the packet (by packet dma wa for pacific bug)
            total_packet_size = len(scapy_packet) + result
            if (total_packet_size % 16 > 0) and (total_packet_size % 16 < 9) and (slice_id % 2 == 0):
                # dma bug wa appears only in even slices (in odd slices the 8 bytes are
                # added to the inject down header, which disappears before getting to the
                # odd slice)
                result += 8
        return result


class nsim_device(uut_provider_base):

    def formatter(self, verbosity=logging.INFO):
        format_string = "%(asctime)s.%(msecs)03d "
        format_string += "uut_provider.py: "
        datefmt = "%d-%m-%Y %H:%M:%S"
        format_string += "%(levelname)4s: "
        format_string += "(pid {}) ".format(os.getpid())
        # format_string += "({}) ".format(self)
        format_string += "%(message)s"
        return logging.Formatter(format_string, datefmt=datefmt)

    def __init__(self):
        self.handler = None
        self.nsim_rpc_client = None

    def __del__(self):
        if self.logger and self.handler:
            self.logger.removeHandler(self.handler)

    def init(
            self,
            device_path,
            dev_id,
            initialize,
            slice_modes,
            nsim_accurate_scale_model,
            enable_logging,
            device_config_func,
            test_mode_punt_egress_packets_to_host,
            enable_logging_from_env):
        if self.handler is None:
            self.handler = logging.StreamHandler()
            self.handler.setLevel(logging.INFO)
            self.handler.setFormatter(self.formatter(logging.INFO))
            self.handler.setFormatter(self.formatter(logging.DEBUG))
            self.handler.setFormatter(self.formatter(logging.ERROR))

            self.logger = logging.getLogger(__name__)
            self.logger.addHandler(self.handler)
            self.logger.setLevel(logging.INFO)
            self.logger.propagate = False  # avoid multiple logs:

        self.punt_egress_packets = test_mode_punt_egress_packets_to_host
        self.nsim_accurate_scale_model = nsim_accurate_scale_model

        # Create device (with internal translator creator and simulator)
        nsim.set_nsim_flow_debug(False)

        self.logger.debug("Starting simulator with device_path {}".format(device_path))
        tic = time.time()
        self.nsim_provider = nsim.create_and_run_simulator_server(None, 0, device_path)
        toc = time.time()
        self.logger.debug('Create simulator took {:.3f} ms'.format((toc - tic) * 1000.0))

        if self.nsim_provider is None:
            self.logger.error("Failed to start nsim")
            sys.exit(1)

        #
        # NOTE: the following apis exist to save/restore DSIM state.
        #
        # self.nsim_provider.dump_config_to_file("dsim_status.json")
        # self.nsim_provider.read_config_from_file("dsim_status.json", update_table_entry_if_exists=True)
        #
        self.nsim = self.nsim_provider

        #
        # Support more granular logging for ENABLE_NSIM_LOG
        #
        if enable_logging_from_env:
            self.logger.debug("Will use ENABLE_NSIM_LOG env for logging")
            enable_logging = self.nsim_provider.set_log_level_from_env()
        else:
            self.nsim_provider.set_logging(enable_logging)

        self.device_path = self.nsim_provider.get_connection_handle()

        use_ref_model = os.getenv('NSIM_REFERENCE_MODEL') is not None

        if enable_logging:
            test_log_path, test_log_file_name = os.path.split(sys.argv[0])
            test_log_file_suffix = ".nsim.log"
            if use_ref_model:
                test_log_file_suffix = ".nsim.ref.log"
            test_log_file_name = os.path.splitext(test_log_file_name)[0] + test_log_file_suffix
            if os.getenv('NSIM_LOG_BASE_DIR'):
                log_base_dir = os.getenv('NSIM_LOG_BASE_DIR') + os.path.sep + test_log_path + os.path.sep
            elif os.getenv('BASE_OUTPUT_DIR'):
                log_base_dir = os.getenv('BASE_OUTPUT_DIR') + os.path.sep + test_log_path + os.path.sep
            else:
                log_base_dir = ""

            if not os.path.exists(log_base_dir) and log_base_dir != "":
                os.makedirs(log_base_dir)

            log_file_name = log_base_dir + test_log_file_name
            self.logger.info("Enable log file {}".format(log_file_name))
            self.nsim_provider.set_log_file(log_file_name, True)


        if use_ref_model:
            self.nsim_accurate_scale_model = True
            print('USING NSIM ACCURATE SCALE MODEL')

        sdk_api_log_file = os.getenv('SDK_API_LOG_FILE')
        if sdk_api_log_file:
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_SIM, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_file(sdk_api_log_file)

        tic = time.time()
        self.device = sdk.la_create_device(self.device_path, dev_id)
        toc = time.time()
        self.logger.info('Create device took {:.3f} ms'.format((toc - tic) * 1000.0))

        current_property = self.device.get_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)
        if current_property != self.punt_egress_packets:
            self.device.set_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST, self.punt_egress_packets)

        current_property = self.device.get_bool_property(sdk.la_device_property_e_ENABLE_NSIM_ACCURATE_SCALE_MODEL)
        if current_property != self.nsim_accurate_scale_model:
            self.device.set_bool_property(sdk.la_device_property_e_ENABLE_NSIM_ACCURATE_SCALE_MODEL, self.nsim_accurate_scale_model)

        self.init_matilda_model(False)

        self.ll_device = self.device.get_ll_device()
        self.device_family = self.ll_device.get_device_family()
        self.device_revision = self.ll_device.get_device_revision()
        self.warm_boot_disconnected = False

        # Initialize device
        if initialize:
            tic = time.time()
            #
            # Commented out for now until we support nsim provider daemon mode.
            #
            # if self.ll_device.get_device_simulator():
            #     # e.g. SDK sdk:pacific:1.74.0
            #     snapshot_name = "sdk:" + self.nsim_provider.get_device_name() + ":" + self.nsim_provider.get_release_version() + \
            #         ":" + sdk.la_get_version_string()
            #
            #     if self.nsim_provider.snapshot_find(snapshot_name):
            #         self.logger.debug("Restore snapshot {}".format(snapshot_name))
            #         if self.nsim_provider.snapshot_load(snapshot_name):
            #             self.ll_device.get_device_simulator().add_property("SDK_RE_INITIALIZING", "1")
            #             self.logger.debug("Re-initialize device {}".format(device_path))
            #             initialize_device(self.device, slice_modes, device_config_func)
            #             self.ll_device.get_device_simulator().add_property("SDK_RE_INITIALIZING", "0")
            #         else:
            #             self.logger.error("Failed to restore snapshot {}".format(snapshot_name))
            #             initialize_device(self.device, slice_modes, device_config_func)
            #     elif hasattr(self.nsim_provider, "started_daemon") and self.nsim_provider.started_daemon:
            #         initialize_device(self.device, slice_modes, device_config_func)
            #         self.logger.debug("Save snapshot {}".format(snapshot_name))
            #         self.nsim_provider.snapshot_save(snapshot_name)
            #     else:
            #         initialize_device(self.device, slice_modes, device_config_func)
            # else:
            #     initialize_device(self.device, slice_modes, device_config_func)

            initialize_device(self.device, slice_modes, device_config_func)
            toc = time.time()
            self.logger.debug('Initialize device took {:.3f} ms'.format((toc - tic) * 1000.0))

    def tearDown(self):
        super().tearDown()

        #
        # Destroy the NSIM object
        #
        if self.nsim_provider is not None:
            self.logger.debug("Simulation teardown")
            self.nsim_provider.destroy_simulator()
            self.nsim_provider = None

        self.logger.info("Simulation teardown complete")

    def get_field_value(self, value):
        return self.nsim_provider.get_field_value(value).to_string()

    def __getattr__(self, item):
        if item in self.__dir__():
            return self.__getattribute__(item)

        return self.device.__getattribute__(item)

    def get_simulator(self):
        return self.nsim_provider

    def inject_packet(self, ipacket, initial_values={}):

        if self.punt_egress_packets:
            # Add inject header if needed
            ipacket = get_inject_packet(self.device_family, ipacket)
            ipacket.ifg = 0
            ipacket.pif = self.get_pci_serdes()

        self.nsim_provider.inject_packet(ipacket, initial_values)
        return True

    def step_packet(self):
        return self.nsim_provider.step_packet()

    def step_learn_notify_packet(self):
        return self.nsim_provider.step_learn_notify_packet()

    def get_packet(self):
        out_packet = self.nsim_provider.get_packet()
        if out_packet.packet == '':
            return (False, out_packet)

        out_packet = self.strip_headers(out_packet)
        out_packet = reset_punt_time_fields(out_packet)

        return (True, out_packet)

    def get_packets(self):
        tmp_out_packets = self.nsim_provider.get_packets()
        out_packets = []
        for i in range(len(tmp_out_packets)):
            out_packets.append(self.strip_headers(tmp_out_packets[i]))

        ret_packets = []
        for i in range(len(out_packets)):
            tmp_packet = reset_punt_time_fields(out_packets[i])
            ret_packets.append(tmp_packet)

        return ret_packets

    def inject_db_trigger(self, line):
        trigger_info = nsim.nsim_db_trigger_info_t()
        trigger_info.set_args(line, nsim.DB_TRIGGER_TYPE_MP, nsim.DB_TRIGGER_MP_TABLE_TYPE_INJECT_CCM)

        self.device.flush()
        self.nsim_provider.inject_db_trigger(trigger_info)

    def system_learn_trigger(self):
        self.device.flush()
        self.nsim_provider.trigger_lrc_fifo()

    def strip_headers(self, packet):
        scapy_packet = U.hex_to_scapy(packet.packet, PacketDmaWaHeader8)
        if (scapy_packet.size != 8 or scapy_packet.padding1 != 0 or scapy_packet.padding2 != 0):
            scapy_packet = U.hex_to_scapy(packet.packet, PacketDmaWaHeader16)
            if (scapy_packet.size != 16 or scapy_packet.padding1 != 0 or scapy_packet.padding2 != 0):
                return packet

        if not self.punt_egress_packets:
            packet.packet = U.scapy_to_hex(scapy_packet[1])
            return packet

        packet = self.strip_std_inject_header(
            scapy_packet[1],
            scapy_packet.slice_id,
            scapy_packet.ifg_id,
            scapy_packet.pif_id)
        return packet

    def get_wrapper_headers_len(self, scapy_packet, slice_id):
        if not self.punt_egress_packets:
            return 0
        if ((scapy_packet.type == Ethertype.Dot1Q.value) and (scapy_packet[1].type == Ethertype.Inject.value)):
            return 0
        return INJECT_UP_STD_HEADER_LEN


def reset_punt_time_fields(pkt):
    tmp_packet = reset_punt_time_fields_one_header(pkt, first_header=Ether)
    tmp_packet = reset_punt_time_fields_one_header(tmp_packet, first_header=PacketDmaWaHeader8)
    tmp_packet = reset_punt_time_fields_one_header(tmp_packet, first_header=PacketDmaWaHeader16)
    return tmp_packet


def reset_punt_time_fields_one_header(pkt, first_header=Ether):
    scapy_packet = U.hex_to_scapy(pkt.packet, first_header)
    if (not scapy_packet.haslayer('Punt')):
        return pkt

    scapy_iterator = scapy_packet
    while True:
        if scapy_iterator.name == 'Punt':
            punt_layer = scapy_iterator
            break
        scapy_iterator = scapy_iterator.payload

    punt_layer.time_stamp = 0
    punt_layer.receive_time = 0

    pkt.packet = U.scapy_to_hex(scapy_packet)
    return pkt


def get_physical_ifg(device_family, slice, ifg):
    if decor.is_pacific():
        slices_with_flipped_ifgs = [0, 3, 4]
    elif decor.is_gibraltar():
        slices_with_flipped_ifgs = [1, 2, 5]
    elif decor.is_akpg():
        return ifg
    else:
        assert False

    if (slice in slices_with_flipped_ifgs):
        return ifg ^ 1

    return ifg


def get_inject_packet(device_family, orig_packet):
    scapy_packet = U.hex_to_scapy(orig_packet.packet)
    if (scapy_packet.type == Ethertype.Dot1Q.value) and (scapy_packet[1].type == Ethertype.Inject.value):
        return orig_packet

    if (scapy_packet.type == Ethertype.Dot1Q.value) and (scapy_packet[1].type == Ethertype.SVL.value):
        return orig_packet

    inject_packet = INJECT_UP_STD_HEADER / scapy_packet
    inject_packet[INJECT_UP_STD_LAYER_INDEX].pif_id = orig_packet.pif
    inject_packet[INJECT_UP_STD_LAYER_INDEX].ifg_id = get_physical_ifg(device_family, orig_packet.slice, orig_packet.ifg)

    if (orig_packet.slice % 2 == 1):
        inject_down_packet_prefix = INJECT_DOWN_HEADER
        inject_down_packet_prefix.dest = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP, T.RCY_SYS_PORT_GID_BASE - orig_packet.slice)
        inject_packet = inject_down_packet_prefix / inject_packet
        orig_packet.slice -= 1  # Inject down from PCI port on slice (i-1) to RCY port on slice i

    orig_packet.packet = U.scapy_to_hex(inject_packet)
    return orig_packet


def initialize_device(device, slice_modes, device_config_func):
    if device_config_func is not None:
        device_config_func(device, sdk.la_device.init_phase_e_CREATED)

    if decor.is_pacific():
        device.set_bool_property(sdk.la_device_property_e_ENABLE_PACIFIC_B0_IFG_CHANGES, True)
        device.set_bool_property(sdk.la_device_property_e_TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES, True)
    elif decor.is_asic3():  # GR-HW WA
        print("Asic3: IGNORING MBIST ERRORS, NOT PROCESSING INTERRUPTS")
        device.set_bool_property(sdk.la_device_property_e_IGNORE_MBIST_ERRORS, True)
        device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, False)
        device.set_bool_property(sdk.la_device_property_e_ENABLE_INFO_PHY, False)
    device.initialize(sdk.la_device.init_phase_e_DEVICE)

    fabric_device = True

    for slice_mode in slice_modes:
        if slice_mode != sdk.la_slice_mode_e_CARRIER_FABRIC:
            fabric_device = False
    for sid in device.get_used_slices():
        device.set_slice_mode(sid, slice_modes[sid])
        if fabric_device:
            device.set_fabric_slice_clos_direction(sid, sdk.la_clos_direction_e_DOWN)

    if device_config_func is not None:
        device_config_func(device, sdk.la_device.init_phase_e_DEVICE)

    device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

    if device_config_func is not None:
        device_config_func(device, sdk.la_device.init_phase_e_TOPOLOGY)
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

import os
import sys
import socket
import lldcli
import test_lldcli
from leaba import sdk
try:
    import test_nsim_providercli as nsim
except BaseException:
    import test_packet_provider as nsim
import packet_test_utils as U
from scapy.all import *
from packet_test_defs import *
from binascii import hexlify, unhexlify
import time
from copy import deepcopy
import decor
import topology as T
import nplapicli as nplapi
import warm_boot_test_utils as wb
import gc
import inspect
import importlib
import logging

# enable auto warm boot
if decor.is_auto_warm_boot_enabled():
    wb.enable_auto_warm_boot()

NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS = 0x26

DUMMY_DST_MAC = "00:00:00:00:00:38"  # Dummy address
DUMMY_SRC_MAC = "00:00:00:00:00:39"  # Dummy address
DUMMY_VLAN = 0xAB9  # Dummy VLAN
BYTES_IN_DQWORD = 16

INJECT_DOWN_HEADER = Ether(dst=DUMMY_DST_MAC, src=DUMMY_SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=DUMMY_VLAN, type=Ethertype.Inject.value) / \
    InjectDown(type=1)

INJECT_UP_STD_HEADER = Ether(dst=DUMMY_DST_MAC, src=DUMMY_SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=DUMMY_VLAN, type=Ethertype.Inject.value) / \
    InjectUpStd(pif_id=0, ifg_id=0)

INJECT_UP_STD_LAYER_INDEX = 2

INJECT_UP_STD_HEADER_LEN = len(INJECT_UP_STD_HEADER)

# Below objects are only created automatically by SDK and destroyed automatically. No need to destroy them manually
TEARDOWN_FILTER_LIST = {
    sdk.la_object.object_type_e_IFG_SCHEDULER,
    sdk.la_object.object_type_e_SYSTEM_PORT_SCHEDULER,
    sdk.la_object.object_type_e_LOGICAL_PORT_SCHEDULER,
    sdk.la_object.object_type_e_INTERFACE_SCHEDULER}


def restart_asic_if_required():
    device_revision = os.environ.get('ASIC', None)
    if (device_revision != 'GIBRALTAR_A0'):
        return
    script_path = os.environ.get('ASIC_RESTART_SCRIPT', None)
    if script_path is None:
        return
    import subprocess
    rc = subprocess.run(script_path, shell=True)
    assert(rc.returncode == 0)


class uut_provider_base():
    @property
    def m_ll_device(self):
        return self.device.get_ll_device()

    def init_matilda_model(self, is_hw_dev):
        if not decor.is_gibraltar():
            return None
        eFuse_values = self.device.get_device_int_capabilities()
        eFuse_matilda_value = eFuse_values[self.device.device_int_capability_e_MATILDA_MODEL]

        if is_hw_dev and eFuse_matilda_value:
            assert self.matilda_model[1], "On a real Matilda hw device, you have to run in matilda_hw mode!"

        if eFuse_matilda_value == 0 and self.matilda_model[0]:
            # Do not set the property for value of GB, and Do not attempt to override value from efuse
            self.device.set_int_property(sdk.la_device_property_e_MATILDA_MODEL_TYPE, self.matilda_model[0])

        if self.matilda_model[1]:
            # runing in matilda_hw mode - set the device frequency acordingly
            self.device.set_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY, 900 * 1000)

    def clear_traps(self):
        # Clear all existing trap configurations.
        # Iterate over events in reverse order to avoid multiple pop operations.
        for event in reversed(range(sdk.LA_EVENT_ETHERNET_FIRST, sdk.LA_EVENT_APP_LAST)):
            try:
                self.device.clear_trap_configuration(event)
            except sdk.BaseException as STATUS:
                if (STATUS.args[0] != sdk.la_status_e_E_NOTFOUND):
                    print('TearDown ERROR: Trap configuration %s can not be cleared!' % event)
                    self.assertFail()

    def clear_snoops(self):
        # Clear all existing trap configurations
        for event in range(sdk.LA_EVENT_ETHERNET_FIRST, sdk.LA_EVENT_APP_LAST):
            try:
                self.device.clear_snoop_configuration(event)
            except sdk.BaseException as STATUS:
                if (STATUS.args[0] != sdk.la_status_e_E_NOTFOUND):
                    print('TearDown ERROR: Snoop configuration %s can not be cleared!' % event)
                    self.assertFail()

    def clear_routes(self):
        # Clear existing routes
        for curr_obj in self.device.get_objects(sdk.la_object.object_type_e_LSR):
            curr_obj.clear_all_routes()

    def clear_counters(self):
        for curr_obj in self.device.get_objects(sdk.la_object.object_type_e_COUNTER_SET):
            set_size = curr_obj.get_set_size()
            for i in range(set_size):
                curr_obj.read(i, True, True)

    def get_ethernet_port(self, slice_val, ifg, base_pif):
        for curr_obj in self.device.get_objects(sdk.la_object.object_type_e_ETHERNET_PORT):
            sys_port = curr_obj.get_system_port()
            if sys_port and (
                (sys_port.get_slice() == slice_val) and (
                    sys_port.get_ifg() == ifg) and (
                    sys_port.get_base_pif() == base_pif)):
                return curr_obj
        return 0

    def get_ethernet_port_from_serdes(self, slice_val, ifg, serdes_id):
        return self.get_ethernet_port(slice_val, ifg, U.serdes_to_pif(self.device, serdes_id))

    def clear_mc_voqs_cgm_profile(self):
        used_slices = range(6)
        # used_slices = self.device.get_used_slices()
        slice_modes_set = {self.device.get_slice_mode(sid) for sid in used_slices}
        # LC mode
        if sdk.la_slice_mode_e_CARRIER_FABRIC in slice_modes_set and sdk.la_slice_mode_e_NETWORK in slice_modes_set:
            # linecard mode configures the multicast fabric VOQ
            voq_set = self.device.get_egress_multicast_fabric_replication_voq_set()
            for voq in range(voq_set.get_set_size()):
                voq_set.set_cgm_profile(voq, None)

            # line mode configures the multicast VOQs for each network slice
            for slice_id in used_slices:
                slice_mode = self.device.get_slice_mode(slice_id)
                if slice_mode == sdk.la_slice_mode_e_NETWORK:
                    voq_set = self.device.get_egress_multicast_slice_replication_voq_set(slice_id)
                    if voq_set is None:
                        continue
                    for voq in range(voq_set.get_set_size()):
                        voq_set.set_cgm_profile(voq, None)

        # standalone mode
        elif sdk.la_slice_mode_e_NETWORK in slice_modes_set:
            # standlaone mode configures the multicast VOQs on all slices
            invalid_modes = [sdk.la_slice_mode_e_INVALID, sdk.la_slice_mode_e_DISABLED]
            for sid in used_slices:
                if self.device.get_slice_mode(sid) in invalid_modes:
                    continue
                voq_set = self.device.get_egress_multicast_slice_replication_voq_set(sid)
                if voq_set is None:
                    continue
                for voq in range(voq_set.get_set_size()):
                    voq_set.set_cgm_profile(voq, None)

    def set_voqs_to_dropping_state(self):
        voq_sets = self.device.get_objects(sdk.la_object.object_type_e_VOQ_SET)
        for voq_set in voq_sets:
            voq_set.set_state(sdk.la_voq_set.state_e_DROPPING)

    def teardown_object(self, obj):
        obj_type = obj.type()
        if (obj_type == sdk.la_object.object_type_e_L2_SERVICE_PORT):
            obj.detach()
            obj.set_destination(None)

        if (obj_type == sdk.la_object.object_type_e_VRF):
            obj.clear_all_ipv4_routes()
            obj.clear_all_ipv6_routes()

        is_voq = (obj_type == sdk.la_object.object_type_e_VOQ_SET)
        if is_voq:
            voq_state = obj.get_state()
            obj.set_state(sdk.la_voq_set.state_e_DROPPING)

        try:
            self.destroy(obj, invalidate_py_refs=False)
            return True
        except sdk.BaseException:
            if is_voq:
                obj.set_state(voq_state)
            return False

    def destroy(self, obj, invalidate_py_refs=True):
        # when objects are torn down, all references to swig proxy objects need to be invalidated,
        # otherwise there will be problems in warm boot because proxy object will have invalid reference
        # to underlying cpp object (which is freed).

        if wb.is_warm_boot_supported() and invalidate_py_refs:
            wb.set_ignore_auto_wb(True)
            gc.collect()
            all_objects = gc.get_objects()
            la_objects_dict = {}
            ignore = [id(inspect.currentframe()), id(all_objects)]
            device_id = self.device.get_id()
            for o in all_objects:
                if wb.is_swig_object(o) and \
                   wb.is_la_object(o) and \
                   not wb.is_la_device(o):
                    refs = wb.get_obj_referrers(o, ignore)
                    if len(refs) and o.get_device().get_id() == device_id:
                        la_objects_dict.setdefault(o.oid(), []).append((o, refs))

            objs_before_teardown = set(o.oid() for o in self.device.get_objects())
            wb.set_ignore_auto_wb(False)

        # destroy sdk object
        self.device.destroy(obj)

        # invalidate proxy object references after underlying object is destroyed;
        # references should be invalidated only if underlyng objects are destroyed
        # successfully (if previous call did not raise exception)
        if wb.is_warm_boot_supported() and invalidate_py_refs:
            wb.set_ignore_auto_wb(True)
            objs_after_teardown = set(o.oid() for o in self.device.get_objects())
            destroyed_objs = objs_before_teardown - objs_after_teardown

            for oid in destroyed_objs:
                if oid in la_objects_dict:
                    wb.invalidate_objs_refs(la_objects_dict[oid])
            wb.set_ignore_auto_wb(False)

    def filter_teardown_list(self, *, teardown_list, objects_to_keep):
        out_teardown_list = []
        output_queue_scheduler_list = []
        for curr_obj in teardown_list:
            if curr_obj.oid() in objects_to_keep:
                continue
            obj_type = curr_obj.type()
            if obj_type not in TEARDOWN_FILTER_LIST:
                # Below object type is created in SDK and can be created by user. We push
                # them to top of list to avoid segmentation faults during auto teardown.
                if (obj_type != sdk.la_object.object_type_e_OUTPUT_QUEUE_SCHEDULER):
                    out_teardown_list.append(curr_obj)
                else:
                    output_queue_scheduler_list.append(curr_obj)

        out_teardown_list.extend(output_queue_scheduler_list)
        return out_teardown_list

    def tearDownObjects(self, objects_to_keep):

        # disable auto-WB for this function, things can go bad if WB is called while objects
        # are being destroyed
        if decor.is_auto_warm_boot_enabled():
            wb.set_ignore_auto_wb(True)

        # Get list of all SDK la_object objects before some of them are destroyed
        if wb.is_warm_boot_supported():
            gc.collect()
            all_objects = gc.get_objects()
            ignore = [id(inspect.currentframe()), id(all_objects)]
            la_objects_dict = {}
            device_id = self.device.get_id()
            for obj in all_objects:
                if wb.is_swig_object(obj) and \
                   wb.is_la_object(obj) and \
                   not wb.is_la_device(obj):
                    refs = wb.get_obj_referrers(obj, ignore)
                    if len(refs) and obj.get_device().get_id() == device_id and not obj.oid() in objects_to_keep:
                        la_objects_dict.setdefault(obj.oid(), []).append((obj, refs))

            objs_before_teardown = set(obj.oid() for obj in self.device.get_objects())

        # There's a circular dependency between L3-AC, VRF and IP-MCG,
        # which cannot be broken by the code below -
        for vrf in self.device.get_objects(sdk.la_object.object_type_e_VRF):
            vrf.clear_all_ipv4_multicast_routes()
            vrf.clear_all_ipv6_multicast_routes()

        for voq_set in reversed(self.device.get_objects(sdk.la_object.object_type_e_VOQ_SET)):
            if voq_set.oid() not in objects_to_keep:
                T.topology.deallocate_voq_set(
                    self,
                    voq_set.get_destination_device(),
                    voq_set.get_destination_slice(),
                    voq_set.get_destination_ifg(),
                    voq_set.get_set_size(),
                    voq_set.get_base_voq_id(),
                    voq_set.get_base_vsc_vec())

        while True:
            objects_destroyed = 0
            local_teardown_list = self.filter_teardown_list(
                teardown_list=self.device.get_objects(), objects_to_keep=objects_to_keep)
            for curr_obj in reversed(local_teardown_list):
                if self.teardown_object(curr_obj):
                    objects_destroyed += 1
                    # If we deleted an object we may need to get a new list since
                    # this list may contain objects already deleted.
                    break

            if (objects_destroyed == 0):
                break

        # Invalidate python references to all SDK la_object objects except
        # the ones from objects_to_keep list
        if wb.is_warm_boot_supported():
            destroyed_objs = objs_before_teardown - set(objects_to_keep)

            for oid in destroyed_objs:
                if oid in la_objects_dict:
                    wb.invalidate_objs_refs(la_objects_dict[oid])

        # enable auto-WB again
        if decor.is_auto_warm_boot_enabled():
            wb.set_ignore_auto_wb(False)

    def clear_device(self, objects_to_keep=[]):
        if self.device.get_ll_device().is_pacific():
            self.clear_mc_voqs_cgm_profile()
        self.clear_traps()
        self.clear_snoops()
        self.clear_routes()
        self.tearDownObjects(objects_to_keep=objects_to_keep)
        # Ensure device interaction with hardware/simulator is done before exiting
        self.device.flush()

    def tearDown(self):
        self.set_voqs_to_dropping_state()
        self.clear_device(objects_to_keep=[])
        self.device.disconnect()
        # Wrap-up
        sdk.la_destroy_device(self.device)
        self.device = None

    def get_wrapper_headers_len(self, scapy_packet, slice_id):
        return 0

    def get_pci_serdes(self):
        if self.m_ll_device.is_pacific():
            return T.PACIFIC_PCI_SERDES
        elif self.m_ll_device.is_gibraltar():
            return T.GIBRALTAR_PCI_SERDES
        elif self.m_ll_device.is_asic4():
            return T.ASIC4_PCI_SERDES
        elif self.m_ll_device.is_asic5():
            return T.ASIC5_PCI_SERDES
        elif self.m_ll_device.is_asic3():
            return T.ASIC3_PCI_SERDES
        else:
            raise Exception('ASIC revision is not supported')

    def get_oq_num(self, ifg, serdes):
        if self.m_ll_device.is_pacific():
            NUM_SERDES_PER_IFG = 18
        elif self.m_ll_device.is_gibraltar():
            NUM_SERDES_PER_IFG = 24
        elif self.m_ll_device.is_asic4():
            NUM_SERDES_PER_IFG = 16
        elif self.ll_device.is_asic5():
            NUM_SERDES_PER_IFG = 48
        else:
            raise Exception('ASIC revision is not supported')
        NUM_OQ_PER_IFG = T.NUM_OQ_PER_SERDES * NUM_SERDES_PER_IFG + T.NUM_OQ_PER_SERDES + \
            T.NUM_OQ_PER_SERDES  # Last two elements are: Recycle Host interfaces
        oq = ifg * NUM_OQ_PER_IFG + serdes * T.NUM_OQ_PER_SERDES
        return oq

    def flush(self):
        if self.device and not (hasattr(self, 'warm_boot_disconnected') and self.warm_boot_disconnected):
            self.device.flush()

    def strip_std_inject_header(self, scapy_packet, slice, ifg, pif):
        res_packet = nsim.sim_packet_info_desc()
        device_family = self.device_family
        if (device_family == sdk.la_device_family_e_PACIFIC and pif == T.PACIFIC_RCY_SERDES):
            res_packet.pif = pif - 1
            res_packet.slice = slice - 1
        elif ((device_family == sdk.la_device_family_e_GIBRALTAR and pif == T.GIBRALTAR_RCY_SERDES) or
                (device_family == sdk.la_device_family_e_ASIC4 and pif == T.ASIC4_RCY_SERDES)):
            res_packet.pif = pif - 1
            inject_slice = self.rcy_to_inject_slice[slice]
            res_packet.slice = inject_slice
        else:
            res_packet.pif = pif
            res_packet.slice = slice

        res_packet.ifg = get_physical_ifg(device_family, slice, ifg)

        # If there is no Punt NPL should remove the prefix layers
        if (not scapy_packet.haslayer('Punt')):
            res_packet.packet = U.scapy_to_hex(scapy_packet)
            return res_packet

        scapy_iterator = scapy_packet
        while True:
            if scapy_iterator.name == 'Punt':
                punt_layer = scapy_iterator
                break
            scapy_iterator = scapy_iterator.payload

        punt_layer.time_stamp = 0
        punt_layer.receive_time = 0

        if (not scapy_packet.haslayer('InjectUpStd')):
            res_packet.packet = U.scapy_to_hex(scapy_packet)
            return res_packet

        # Check the UDP destination port for sflow. sflow Tunnel feature uses port
        # number 6343 and adds a Punt header as an erspan encapsulation. Skip
        # stripping out the InjectUpStd layer in that case.
        if (scapy_packet.haslayer('UDP')):
            if (scapy_packet[UDP].dport == 6343):
                res_packet.packet = U.scapy_to_hex(scapy_packet)
                return res_packet

        # Learn notification detection
        if scapy_iterator[3].name == 'InjectUpStd' and scapy_iterator[3].type == sdk.la_packet_types.LA_PACKET_INJECT_TYPE_UP_LEARN_RECORD:
            res_packet.packet = U.scapy_to_hex(scapy_packet)
            return res_packet

        # Offset includes the InjectUpStd size. If '0' - don't care, leave as '0'.
        if punt_layer.next_header_offset != 0:
            punt_layer.next_header_offset -= INJECT_UP_STD_HEADER_LEN

        # In case of ingress Punt the egress packet includes the InjectUpStd
        # header 3 layers should be removed: Ether() / Dot1Q / InjectUpStd()
        while scapy_iterator[3].name is not 'Raw':
            if scapy_iterator[3].name == 'InjectUpStd':
                inject_up_std_layer = scapy_iterator[3]
                break
            scapy_iterator = scapy_iterator.payload

        pkt_tail = deepcopy(inject_up_std_layer.payload)
        if (inject_up_std_layer.trailer_size != 0):
            punt_layer.next_header_offset -= inject_up_std_layer.trailer_size
            pkt_tail = pkt_tail.payload

        layer_type = pkt_tail.type
        scapy_iterator.type = layer_type
        scapy_iterator.remove_payload()
        scapy_packet = scapy_packet / pkt_tail

        res_packet.packet = U.scapy_to_hex(scapy_packet)
        return res_packet


class hw_device(uut_provider_base):
    ETH_P_ALL = 3

    def init(self, device_path, dev_id, initialize, slice_modes, device_config_func):
        restart_asic_if_required()
        self.device_path = device_path
        self.device = sdk.la_create_device(self.device_path, dev_id)
        self.ll_device = self.device.get_ll_device()
        self.device_family = self.ll_device.get_device_family()
        self.device_revision = self.ll_device.get_device_revision()
        self.warm_boot_disconnected = False

        # This map stores info about PCI ports needed to inject packets. Can be updated from 2 places:
        # 1. hw_device.open_sockets()
        # 2. warm_boot_test_utils.store_pci_ports_info() - if warm_boot_test_utils.warm_boot_disconnect() is called
        #    before injecting first packet. That allows to inject packets while SDK is unloaded (SDK PCI port objects
        #    don't exist)
        self.pci_port_slice_to_network_interface_name = {}

        self.device.set_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST, True)
        if os.getenv('IGNORE_MBIST_ERRORS'):
            self.device.set_bool_property(sdk.la_device_property_e_IGNORE_MBIST_ERRORS, True)

        if os.getenv('LEABA_EMULATED_DEVICE'):
            self.device.set_bool_property(sdk.la_device_property_e_EMULATED_DEVICE, True)

        # MSI does not propagate to CPU on Blacktip board with Kontron Compact chipset.
        self.POLL_MSI = (self.m_ll_device.is_gibraltar() and decor.is_hw_kontron_compact_cpu())
        print('Setting POLL_MSI={}'.format(self.POLL_MSI))
        self.device.set_bool_property(sdk.la_device_property_e_POLL_MSI, self.POLL_MSI)

        self.init_matilda_model(True)

        # Forwarding caches are enabled only on Pacific B0 and B1 due to multiple cache correctness issues on Pacific A0.
        if self.device_revision == sdk.la_device_revision_e_PACIFIC_A0:
            self.device.set_bool_property(sdk.la_device_property_e_ENABLE_LPM_IP_CACHE, False)

        # Initialize device
        if initialize:
            initialize_device(self.device, slice_modes, device_config_func)

        self.sockets_opened = False
        self.sockets = T.NUM_SLICES_PER_DEVICE * [None]

    def clear_device(self, objects_to_keep=[]):
        self.close_sockets()
        super().clear_device(objects_to_keep=objects_to_keep)

    def tearDown(self):
        # Close sockets
        self.close_sockets()

        super().tearDown()

    def __getattr__(self, item):
        if item in self.__dir__():
            return self.__getattribute__(item)

        return self.device.__getattribute__(item)

    def open_sockets(self):
        if self.device and self.m_ll_device:
            for pci_port in self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT):
                slice = pci_port.get_slice()
                interface_name = self.m_ll_device.get_network_interface_name(slice)
                self.pci_port_slice_to_network_interface_name[slice] = interface_name

        for slice, if_name in self.pci_port_slice_to_network_interface_name.items():
            os.system('echo 0 > /proc/sys/net/ipv6/conf/%s/router_solicitations' %
                      if_name)  # Avoid router-solicitation messages from kernel
            os.system('ifconfig %s up mtu 6000' % if_name)
            self.sockets[slice] = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self.sockets[slice].settimeout(0.01)
            self.sockets[slice].bind((if_name, self.ETH_P_ALL))

        self.sockets_opened = True

    def close_sockets(self):
        if not self.sockets_opened:
            return
        for slice in self.pci_port_slice_to_network_interface_name.keys():
            self.sockets[slice].close()
            self.sockets[slice] = None
        self.pci_port_slice_to_network_interface_name.clear()
        self.sockets_opened = False

    def step_packet(self):
        time.sleep(0.2)
        return True

    def step_learn_notify_packet(self):
        time.sleep(0.2)
        return True

    def inject_packet(self, in_packet, initial_values={}):
        # Open sockets if not done yet
        if (not self.sockets_opened):
            self.open_sockets()

        # Add inject header if needed
        in_packet = get_inject_packet(self.device_family, in_packet)
        ipacket = bytes(U.hex_to_scapy(in_packet.packet))
        s = self.sockets[in_packet.slice]
        bytes_num = s.send(ipacket)
        if bytes_num != len(ipacket):
            print('Error: send failed len(ipacket)=%d bytes_num=%d' % (len(ipacket), bytes_num))
            return False

        return True

    def pacific_b1_hw_padding_compensation(self, packet):
        if self.device_revision != sdk.la_device_revision_e_PACIFIC_B1:
            return packet

        # HW padding used in pacific B1 is added after the packet-DMA WA header.
        # this header is removed by the kernel-module, so the packet may become too short

        packet_size = len(packet)
        kernel_hdr_size = len(KernelHeader())  # KernelHeader is removed later
        net_size = packet_size - kernel_hdr_size
        diff = U.MIN_PKT_SIZE_WITHOUT_CRC - net_size

        if diff < 0:
            # packet size is valid
            return packet

        # if the packet is too short then pad it up to MIN_PKT_SIZE
        return packet + b'\xff' * diff

    def get_packets(self):
        packets = []
        opacket = nsim.sim_packet_info_desc()
        for port_slice in self.pci_port_slice_to_network_interface_name.keys():
            while (True):
                try:
                    packet_data = self.sockets[port_slice].recv(1000000)  # Very big number
                except socket.timeout as ex:
                    # Polling a port that does't receive any packet will timeout.
                    break
                # no other exception should occur.

                pre = hexlify(bytes(packet_data[0:4])).decode('ascii')
                if (pre == 'ffffffff' or pre == '33330000'):
                    continue

                packet_data = self.pacific_b1_hw_padding_compensation(packet_data)
                tmp_packet = KernelHeader(bytes(packet_data))
                ifg = tmp_packet.ifg
                pif = tmp_packet.pif
                slice = tmp_packet.slice_id
                res_packet = self.strip_std_inject_header(tmp_packet.getlayer(1), slice, ifg, pif)
                # We don't know which header we get
                res_packet = reset_punt_time_fields(res_packet)
                packets.append(res_packet)

        return packets

    def get_packet(self):
        packets = self.get_packets()
        if len(packets) != 1:
            return (False, "")

        return (True, packets[0])

    def inject_db_trigger(self, line):
        self.device.flush()

    def system_learn_trigger(self):
        self.device.flush()

    def get_wrapper_headers_len(self, scapy_packet, slice_id):
        if ((scapy_packet.type == Ethertype.Dot1Q.value) and (scapy_packet[1].type == Ethertype.Inject.value)):
            return 0

        result = INJECT_UP_STD_HEADER_LEN
        if self.device_family == sdk.la_device_family_e_PACIFIC:
            # checking if additional 8 bytes are added to the packet (by packet dma wa for pacific bug)
            total_packet_size = len(scapy_packet) + result
            if (total_packet_size % 16 > 0) and (total_packet_size % 16 < 9) and (slice_id % 2 == 0):
                # dma bug wa appears only in even slices (in odd slices the 8 bytes are
                # added to the inject down header, which disappears before getting to the
                # odd slice)
                result += 8
        return result


class nsim_device(uut_provider_base):

    def formatter(self, verbosity=logging.INFO):
        format_string = "%(asctime)s.%(msecs)03d "
        format_string += "uut_provider.py: "
        datefmt = "%d-%m-%Y %H:%M:%S"
        format_string += "%(levelname)4s: "
        format_string += "(pid {}) ".format(os.getpid())
        # format_string += "({}) ".format(self)
        format_string += "%(message)s"
        return logging.Formatter(format_string, datefmt=datefmt)

    def __init__(self):
        self.handler = None
        self.nsim_rpc_client = None

    def __del__(self):
        if self.logger and self.handler:
            self.logger.removeHandler(self.handler)

    def init(
            self,
            device_path,
            dev_id,
            initialize,
            slice_modes,
            nsim_accurate_scale_model,
            enable_logging,
            device_config_func,
            test_mode_punt_egress_packets_to_host,
            enable_logging_from_env):
        if self.handler is None:
            self.handler = logging.StreamHandler()
            self.handler.setLevel(logging.INFO)
            self.handler.setFormatter(self.formatter(logging.INFO))
            self.handler.setFormatter(self.formatter(logging.DEBUG))
            self.handler.setFormatter(self.formatter(logging.ERROR))

            self.logger = logging.getLogger(__name__)
            self.logger.addHandler(self.handler)
            self.logger.setLevel(logging.INFO)
            self.logger.propagate = False  # avoid multiple logs:

        self.punt_egress_packets = test_mode_punt_egress_packets_to_host
        self.nsim_accurate_scale_model = nsim_accurate_scale_model

        # Create device (with internal translator creator and simulator)
        nsim.set_nsim_flow_debug(False)

        self.logger.debug("Starting simulator with device_path {}".format(device_path))
        tic = time.time()
        self.nsim_provider = nsim.create_and_run_simulator_server(None, 0, device_path)
        toc = time.time()
        self.logger.debug('Create simulator took {:.3f} ms'.format((toc - tic) * 1000.0))

        if self.nsim_provider is None:
            self.logger.error("Failed to start nsim")
            sys.exit(1)

        #
        # NOTE: the following apis exist to save/restore DSIM state.
        #
        # self.nsim_provider.dump_config_to_file("dsim_status.json")
        # self.nsim_provider.read_config_from_file("dsim_status.json", update_table_entry_if_exists=True)
        #
        self.nsim = self.nsim_provider

        #
        # Support more granular logging for ENABLE_NSIM_LOG
        #
        if enable_logging_from_env:
            self.logger.debug("Will use ENABLE_NSIM_LOG env for logging")
            enable_logging = self.nsim_provider.set_log_level_from_env()
        else:
            self.nsim_provider.set_logging(enable_logging)

        self.device_path = self.nsim_provider.get_connection_handle()

        use_ref_model = os.getenv('NSIM_REFERENCE_MODEL') is not None

        if enable_logging:
            test_log_path, test_log_file_name = os.path.split(sys.argv[0])
            test_log_file_suffix = ".nsim.log"
            if use_ref_model:
                test_log_file_suffix = ".nsim.ref.log"
            test_log_file_name = os.path.splitext(test_log_file_name)[0] + test_log_file_suffix
            if os.getenv('NSIM_LOG_BASE_DIR'):
                log_base_dir = os.getenv('NSIM_LOG_BASE_DIR') + os.path.sep + test_log_path + os.path.sep
            elif os.getenv('BASE_OUTPUT_DIR'):
                log_base_dir = os.getenv('BASE_OUTPUT_DIR') + os.path.sep + test_log_path + os.path.sep
            else:
                log_base_dir = ""

            if not os.path.exists(log_base_dir) and log_base_dir != "":
                os.makedirs(log_base_dir)

            log_file_name = log_base_dir + test_log_file_name
            self.logger.info("Enable log file {}".format(log_file_name))
            self.nsim_provider.set_log_file(log_file_name, True)

        record_dir = os.getenv('SDK_NSIM_RECORD_DIR')
        if record_dir:
            os.makedirs(record_dir, exist_ok=True)
            self.nsim_provider.set_rerun_info_folder(record_dir, True)

        if use_ref_model:
            self.nsim_accurate_scale_model = True
            print('USING NSIM ACCURATE SCALE MODEL')

        sdk_api_log_file = os.getenv('SDK_API_LOG_FILE')
        if sdk_api_log_file:
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_SIM, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_file(sdk_api_log_file)

        tic = time.time()
        self.device = sdk.la_create_device(self.device_path, dev_id)
        toc = time.time()
        self.logger.info('Create device took {:.3f} ms'.format((toc - tic) * 1000.0))

        current_property = self.device.get_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)
        if current_property != self.punt_egress_packets:
            self.device.set_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST, self.punt_egress_packets)

        current_property = self.device.get_bool_property(sdk.la_device_property_e_ENABLE_NSIM_ACCURATE_SCALE_MODEL)
        if current_property != self.nsim_accurate_scale_model:
            self.device.set_bool_property(sdk.la_device_property_e_ENABLE_NSIM_ACCURATE_SCALE_MODEL, self.nsim_accurate_scale_model)

        self.init_matilda_model(False)

        self.ll_device = self.device.get_ll_device()
        self.device_family = self.ll_device.get_device_family()
        self.device_revision = self.ll_device.get_device_revision()
        self.warm_boot_disconnected = False

        # Initialize device
        if initialize:
            tic = time.time()
            #
            # Commented out for now until we support nsim provider daemon mode.
            #
            # if self.ll_device.get_device_simulator():
            #     # e.g. SDK sdk:pacific:1.74.0
            #     snapshot_name = "sdk:" + self.nsim_provider.get_device_name() + ":" + self.nsim_provider.get_release_version() + \
            #         ":" + sdk.la_get_version_string()
            #
            #     if self.nsim_provider.snapshot_find(snapshot_name):
            #         self.logger.debug("Restore snapshot {}".format(snapshot_name))
            #         if self.nsim_provider.snapshot_load(snapshot_name):
            #             self.ll_device.get_device_simulator().add_property("SDK_RE_INITIALIZING", "1")
            #             self.logger.debug("Re-initialize device {}".format(device_path))
            #             initialize_device(self.device, slice_modes, device_config_func)
            #             self.ll_device.get_device_simulator().add_property("SDK_RE_INITIALIZING", "0")
            #         else:
            #             self.logger.error("Failed to restore snapshot {}".format(snapshot_name))
            #             initialize_device(self.device, slice_modes, device_config_func)
            #     elif hasattr(self.nsim_provider, "started_daemon") and self.nsim_provider.started_daemon:
            #         initialize_device(self.device, slice_modes, device_config_func)
            #         self.logger.debug("Save snapshot {}".format(snapshot_name))
            #         self.nsim_provider.snapshot_save(snapshot_name)
            #     else:
            #         initialize_device(self.device, slice_modes, device_config_func)
            # else:
            #     initialize_device(self.device, slice_modes, device_config_func)

            initialize_device(self.device, slice_modes, device_config_func)
            toc = time.time()
            self.logger.debug('Initialize device took {:.3f} ms'.format((toc - tic) * 1000.0))

    def tearDown(self):
        super().tearDown()

        #
        # Destroy the NSIM object
        #
        if self.nsim_provider is not None:
            self.logger.debug("Simulation teardown")
            self.nsim_provider.destroy_simulator()
            self.nsim_provider = None

        self.logger.info("Simulation teardown complete")

    def __getattr__(self, item):
        if item in self.__dir__():
            return self.__getattribute__(item)

        return self.device.__getattribute__(item)

    def get_simulator(self):
        return self.nsim_provider

    def inject_packet(self, ipacket, initial_values={}):

        if self.punt_egress_packets:
            # Add inject header if needed
            ipacket = get_inject_packet(self.device_family, ipacket)
            ipacket.ifg = 0
            ipacket.pif = self.get_pci_serdes()

        self.nsim_provider.inject_packet(ipacket, initial_values)
        return True

    def step_packet(self):
        return self.nsim_provider.step_packet()

    def step_learn_notify_packet(self):
        return self.nsim_provider.step_learn_notify_packet()

    def get_packet(self):
        out_packet = self.nsim_provider.get_packet()
        if out_packet.packet == '':
            return (False, out_packet)

        out_packet = self.strip_headers(out_packet)
        out_packet = reset_punt_time_fields(out_packet)

        return (True, out_packet)

    def get_packets(self):
        tmp_out_packets = self.nsim_provider.get_packets()
        out_packets = []
        for i in range(len(tmp_out_packets)):
            out_packets.append(self.strip_headers(tmp_out_packets[i]))

        ret_packets = []
        for i in range(len(out_packets)):
            tmp_packet = reset_punt_time_fields(out_packets[i])
            ret_packets.append(tmp_packet)

        return ret_packets

    def inject_db_trigger(self, line):
        trigger_info = nsim.nsim_db_trigger_info_t()
        trigger_info.set_args(line, nsim.DB_TRIGGER_TYPE_MP, nsim.DB_TRIGGER_MP_TABLE_TYPE_INJECT_CCM)

        self.device.flush()
        self.nsim_provider.inject_db_trigger(trigger_info)

    def system_learn_trigger(self):
        self.device.flush()
        self.nsim_provider.trigger_lrc_fifo()

    def strip_headers(self, packet):
        scapy_packet = U.hex_to_scapy(packet.packet, PacketDmaWaHeader8)
        if (scapy_packet.size != 8 or scapy_packet.padding1 != 0 or scapy_packet.padding2 != 0):
            scapy_packet = U.hex_to_scapy(packet.packet, PacketDmaWaHeader16)
            if (scapy_packet.size != 16 or scapy_packet.padding1 != 0 or scapy_packet.padding2 != 0):
                return packet

        if not self.punt_egress_packets:
            packet.packet = U.scapy_to_hex(scapy_packet[1])
            return packet

        packet = self.strip_std_inject_header(
            scapy_packet[1],
            scapy_packet.slice_id,
            scapy_packet.ifg_id,
            scapy_packet.pif_id)
        return packet

    def get_wrapper_headers_len(self, scapy_packet, slice_id):
        if not self.punt_egress_packets:
            return 0
        if ((scapy_packet.type == Ethertype.Dot1Q.value) and (scapy_packet[1].type == Ethertype.Inject.value)):
            return 0
        return INJECT_UP_STD_HEADER_LEN


def reset_punt_time_fields(pkt):
    tmp_packet = reset_punt_time_fields_one_header(pkt, first_header=Ether)
    tmp_packet = reset_punt_time_fields_one_header(tmp_packet, first_header=PacketDmaWaHeader8)
    tmp_packet = reset_punt_time_fields_one_header(tmp_packet, first_header=PacketDmaWaHeader16)
    return tmp_packet


def reset_punt_time_fields_one_header(pkt, first_header=Ether):
    scapy_packet = U.hex_to_scapy(pkt.packet, first_header)
    if (not scapy_packet.haslayer('Punt')):
        return pkt

    scapy_iterator = scapy_packet
    while True:
        if scapy_iterator.name == 'Punt':
            punt_layer = scapy_iterator
            break
        scapy_iterator = scapy_iterator.payload

    punt_layer.time_stamp = 0
    punt_layer.receive_time = 0

    pkt.packet = U.scapy_to_hex(scapy_packet)
    return pkt


def get_physical_ifg(device_family, slice, ifg):
    if decor.is_pacific():
        slices_with_flipped_ifgs = [0, 3, 4]
    elif decor.is_gibraltar():
        slices_with_flipped_ifgs = [1, 2, 5]
    elif decor.is_akpg():
        return ifg
    else:
        assert False

    if (slice in slices_with_flipped_ifgs):
        return ifg ^ 1

    return ifg


def get_inject_packet(device_family, orig_packet):
    scapy_packet = U.hex_to_scapy(orig_packet.packet)
    if (scapy_packet.type == Ethertype.Dot1Q.value) and (scapy_packet[1].type == Ethertype.Inject.value):
        return orig_packet

    if (scapy_packet.type == Ethertype.Dot1Q.value) and (scapy_packet[1].type == Ethertype.SVL.value):
        return orig_packet

    inject_packet = INJECT_UP_STD_HEADER / scapy_packet
    inject_packet[INJECT_UP_STD_LAYER_INDEX].pif_id = orig_packet.pif
    inject_packet[INJECT_UP_STD_LAYER_INDEX].ifg_id = get_physical_ifg(device_family, orig_packet.slice, orig_packet.ifg)

    if (orig_packet.slice % 2 == 1):
        inject_down_packet_prefix = INJECT_DOWN_HEADER
        inject_down_packet_prefix.dest = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP, T.RCY_SYS_PORT_GID_BASE - orig_packet.slice)
        inject_packet = inject_down_packet_prefix / inject_packet
        orig_packet.slice -= 1  # Inject down from PCI port on slice (i-1) to RCY port on slice i

    orig_packet.packet = U.scapy_to_hex(inject_packet)
    return orig_packet


def initialize_device(device, slice_modes, device_config_func):
    if device_config_func is not None:
        device_config_func(device, sdk.la_device.init_phase_e_CREATED)

    if decor.is_pacific():
        device.set_bool_property(sdk.la_device_property_e_ENABLE_PACIFIC_B0_IFG_CHANGES, True)
        device.set_bool_property(sdk.la_device_property_e_TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES, True)
    elif decor.is_asic3():  # GR-HW WA
        print("Asic3: IGNORING MBIST ERRORS, NOT PROCESSING INTERRUPTS")
        device.set_bool_property(sdk.la_device_property_e_IGNORE_MBIST_ERRORS, True)
        device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, False)
        device.set_bool_property(sdk.la_device_property_e_ENABLE_INFO_PHY, False)
    device.initialize(sdk.la_device.init_phase_e_DEVICE)

    fabric_device = True

    for slice_mode in slice_modes:
        if slice_mode != sdk.la_slice_mode_e_CARRIER_FABRIC:
            fabric_device = False
    for sid in device.get_used_slices():
        device.set_slice_mode(sid, slice_modes[sid])
        if fabric_device:
            device.set_fabric_slice_clos_direction(sid, sdk.la_clos_direction_e_DOWN)

    if device_config_func is not None:
        device_config_func(device, sdk.la_device.init_phase_e_DEVICE)

    device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

    if device_config_func is not None:
        device_config_func(device, sdk.la_device.init_phase_e_TOPOLOGY)
