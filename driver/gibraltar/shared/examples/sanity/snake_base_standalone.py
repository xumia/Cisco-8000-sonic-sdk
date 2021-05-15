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
# Create the low-level ports for the snake tests
###

import time

from leaba import sdk
import network_objects

from sanity_constants import *
import voq_allocator
import tm_utils

NUM_PIF_PER_PORT = 8  # Number of PIFs reserved for each port
ACTUAL_NUM_PIF_PER_PORT = 8  # Number of PIFs actually used by each port


def max_num_ports_per_ifg(num_pif_per_port):
    return int(NUM_PIF_PER_IFG / num_pif_per_port)


REAL_PORT_SPEED = {
    sdk.la_mac_port.port_speed_e_E_10G: 10 * GIGA,
    sdk.la_mac_port.port_speed_e_E_25G: 25 * GIGA,
    sdk.la_mac_port.port_speed_e_E_40G: 40 * GIGA,
    sdk.la_mac_port.port_speed_e_E_50G: 50 * GIGA,
    sdk.la_mac_port.port_speed_e_E_100G: 100 * GIGA,
    sdk.la_mac_port.port_speed_e_E_200G: 200 * GIGA,
    sdk.la_mac_port.port_speed_e_E_400G: 400 * GIGA,
    sdk.la_mac_port.port_speed_e_E_800G: 800 * GIGA
}


class snake_base_topology:
    SYS_PORT_BASE_GID = 0x110
    INJECT_PORT_MAC_ADDR = network_objects.mac_addr('12:34:56:78:9a:bc')
    MAX_RETUNE = 3

    def __init__(self, la_dev, is_simulator=False):
        self.la_dev = la_dev
        self.is_simulator = is_simulator
        self.reset()
        self.loopback_num = 0

    def reset(self):

        self.pci_ports = []
        self.rcy_ports = []
        self.pi_ports = []
        self.mac_ports = []
        self.voq_sets = []
        self.sys_ports = []
        self.eth_ports = []
        self.sys_port_gid = snake_base_topology.SYS_PORT_BASE_GID
        self.voq_allocator = voq_allocator.voq_allocator()

    @property
    def mac_ports_num(self):
        return len(self.mac_ports)

    def create_system_port(self, slice_id, ifg, underlying_port, underlying_port_speed):
        (is_success, base_voq, base_vsc_vec) = self.voq_allocator.allocate_voq_set(slice_id, ifg, VOQ_SET_SIZE)
        if not is_success:
            raise Exception('Error: allocate_voq_set failed.' % i)

        (status, voq_set) = self.la_dev.create_voq_set(base_voq, VOQ_SET_SIZE, base_vsc_vec, self.la_dev.get_id(), slice_id, ifg)
        if (status != sdk.LA_STATUS_SUCCESS) or (voq_set is None):
            raise Exception('Error: create_voq_set failed. status=%d' % (status))
        self.voq_sets.append(voq_set)

        # System port
# print('create_system_port: slice=%d gid=%d base_voq=%d base_vsc=%s' %
# (slice_id, self.sys_port_gid, base_voq, str(base_vsc_vec)))
        (status, sys_port) = self.la_dev.create_system_port(self.sys_port_gid,
                                                            underlying_port, voq_set, network_objects.tc_profile_def.hld_obj)
        if (status != sdk.LA_STATUS_SUCCESS) or (sys_port is None):
            raise Exception('Error: create_sys_port failed. status=%d' % (status))
        self.sys_ports.append(sys_port)
        self.sys_port_gid += 1

        tm_utils.init_system_port_default_tm(self.la_dev, sys_port, base_voq, base_vsc_vec, underlying_port_speed)

        return sys_port

    def create_punt_inject_port(self, slice_id, ifg):
        speed = 100 * GIGA

        ############# PACKET-DMA-WA ####################
        (status, rcy_port) = self.la_dev.create_recycle_port(slice_id, ifg)
        if status != sdk.LA_STATUS_SUCCESS:
            raise Exception('Error: create_rcy_port failed. status=%d' % (status))
        self.rcy_ports.append(rcy_port)

        tm_utils.init_port_default_tm(rcy_port, speed)

        self.create_system_port(slice_id, ifg, rcy_port, speed)
        ############# PACKET-DMA-WA ####################

        (status, pci_port) = self.la_dev.create_pci_port(slice_id, ifg, False)
        if (status != sdk.LA_STATUS_SUCCESS) or (pci_port is None):
            raise Exception('Error: create_pci_port failed. status=%d' % (status))
        self.pci_ports.append(pci_port)

        tm_utils.init_port_default_tm(pci_port, speed)

        sys_port = self.create_system_port(slice_id, ifg, pci_port, speed)

        (status, pi_port) = self.la_dev.create_punt_inject_port(sys_port, snake_base_topology.INJECT_PORT_MAC_ADDR.hld_obj)
        if (status != sdk.LA_STATUS_SUCCESS) or (pi_port is None):
            raise Exception('Error: create_punt_inject_port failed. status=%d' % (status))
        self.pi_ports.append(pi_port)

    def tune_mac_port(self, mac_port):
        if not self.is_simulator:
            status = mac_port.activate()
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('Error: mac_port::activate failed. status=%d' % (status))

            status = mac_port.tune(True)
            if status != sdk.LA_STATUS_SUCCESS:
                print('Warning: mac_port.tune failed. status=%d' % (status))

            # Retune
            for retry in range(snake_base_topology.MAX_RETUNE):
                time.sleep(1)
                (status, mac_status) = mac_port.read_mac_status()
                if status != sdk.LA_STATUS_SUCCESS:
                    raise Exception('Error: mac_port::read_mac_status failed. status=%d' % (status))
                if (mac_status.link_state == False):
                    raise Exception('Error: mac_port::link_state failed. status=%d' % (status))

                if (mac_status.link_state):
                    break

                status = mac_port.tune(True)
                if status != sdk.LA_STATUS_SUCCESS:
                    print('Warning: mac_port.tune failed. status=%d' % (status))

    def create_mac_port(self, slice_id, ifg, first_pif, do_loopback, speed):
        last_pif = first_pif + ACTUAL_NUM_PIF_PER_PORT - 1
        (status, mac_port) = self.la_dev.create_mac_port(slice_id,
                                                         ifg,
                                                         first_pif,
                                                         last_pif,
                                                         speed,
                                                         sdk.la_mac_port.fc_mode_e_NONE,
                                                         sdk.la_mac_port.fec_mode_e_RS_KR4)

        if (status != sdk.LA_STATUS_SUCCESS) or (mac_port is None):
            raise Exception('Error: create_mac_port failed. slice=%d ifg=%d first_pif=%d last_pif=%d status=%d' %
                            (slice_id, ifg, first_pif, last_pif, status))
        self.mac_ports.append(mac_port)

        if do_loopback:
            status = mac_port.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_PMA_CORE_CLK)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('Error: set_loopback_mode failed. status=%d' % (status))

        else:  # no loopback
            self.tune_mac_port(mac_port)

        # Init TM
        tm_utils.init_port_default_tm(mac_port, REAL_PORT_SPEED[speed])

        return mac_port

    @staticmethod
    def get_next_pif(slice_id, ifg, pif, num_pif_per_port):
        next_slice = slice_id
        next_ifg = ifg
        next_pif = pif + num_pif_per_port
        if next_pif + num_pif_per_port <= NUM_PIF_PER_IFG:
            return next_slice, next_ifg, next_pif

        next_pif = 0
        next_ifg += 1
        if next_ifg < NUM_IFGS_PER_SLICE:
            return next_slice, next_ifg, next_pif

        next_ifg = 0
        next_slice = (next_slice + 1) % NUM_SLICES_PER_DEVICE

        return next_slice, next_ifg, next_pif

    def init_body(self, is_on_chip_loopbacks, max_loopback_num):

        tm_utils.init_default_tm(self.la_dev)

        loopback_num = 0
        slice_id = self.first_slice
        ifg = self.first_ifg
        first_pif = self.first_pif

        # Create punt-inject ports for all the slices (for NPU-host injection)
        for s in range(NUM_SLICES_PER_DEVICE):
            self.create_punt_inject_port(s, 0)

        # Create the base topology
        for i in range(max_loopback_num + 2):

            is_entry_or_exit = (i == 0)
            do_loopback = is_on_chip_loopbacks and not is_entry_or_exit

            speed = sdk.la_mac_port.port_speed_e_E_400G

            mac_port = self.create_mac_port(slice_id, ifg, first_pif, do_loopback, speed)
            sys_port = self.create_system_port(slice_id, ifg, mac_port, REAL_PORT_SPEED[speed])

            # Ethernet port
            (status, eth_port) = self.la_dev.create_ethernet_port(sys_port, sdk.la_ethernet_port.port_type_e_AC)
            if (status != sdk.LA_STATUS_SUCCESS) or (eth_port is None):
                raise Exception('Error: create_ethernet_port failed. status=%d' % (status))
            status = eth_port.set_ac_profile(network_objects.ac_profile_def.hld_obj)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('Error: set_ac_profile failed. status=%d' % (status))
            self.eth_ports.append(eth_port)

            # Update loop vars
            (slice_id, ifg, first_pif) = snake_base_topology.get_next_pif(slice_id, ifg, first_pif, NUM_PIF_PER_PORT)
            if do_loopback:
                loopback_num += 1

        self.loopback_num = loopback_num
        self.la_dev.flush()

    def initialize(self, first_slice, first_ifg, first_pif, is_on_chip_loopbacks, max_loopback_num):
        if (first_pif % NUM_PIF_PER_PORT) != 0:
            raise Exception('Error: entry PIF must be aligned on %d' % NUM_PIF_PER_PORT)
        if (first_pif + NUM_PIF_PER_PORT) > NUM_PIF_PER_IFG:
            raise Exception('Error: illegal entry PIF')

        if is_on_chip_loopbacks:
            self.first_slice = first_slice
            self.first_ifg = first_ifg
            self.first_pif = first_pif
        else:
            self.first_slice = 0
            self.first_ifg = 0
            self.first_pif = 0

        network_objects.initialize(self.la_dev, self.voq_allocator)

        upper_bound_on_num_of_mac_ports = NUM_SLICES_PER_DEVICE * \
            NUM_IFGS_PER_SLICE * \
            max_num_ports_per_ifg(NUM_PIF_PER_PORT)
        upper_bound_on_loopback_num = upper_bound_on_num_of_mac_ports - 2

        if max_loopback_num > upper_bound_on_loopback_num:
            print('Warning: max_loopback_num too large. Upper bound on number of loopbacks=%d' %
                  upper_bound_on_loopback_num)

        if max_loopback_num == -1 or \
                max_loopback_num > upper_bound_on_loopback_num or \
                not is_on_chip_loopbacks:  # Create all ports for board test
            max_loopback_num = upper_bound_on_loopback_num

        try:
            self.init_body(is_on_chip_loopbacks, max_loopback_num)
        except Exception as e:
            print(e)
            self.teardown()
            raise

    def teardown(self):
        for eth_port in self.eth_ports:
            self.la_dev.destroy(eth_port)
        for sys_port in self.sys_ports:
            self.la_dev.destroy(sys_port)
        for voq_set in self.voq_sets:
            self.la_dev.destroy(voq_set)
        for mac_port in self.mac_ports:
            self.la_dev.destroy(mac_port)
        for pci_port in self.pci_ports:
            self.la_dev.destroy(pci_port)
        for pi_port in self.pi_ports:
            self.la_dev.destroy(pi_port)
        for rcy_port in self.rcy_ports:
            self.la_dev.destroy(rcy_port)

        network_objects.teardown(self.la_dev)

        self.la_dev.flush()
        self.reset()
