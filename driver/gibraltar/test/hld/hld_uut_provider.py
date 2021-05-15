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

import test_lldcli
from leaba import sdk
import test_racli as ra
import packet_test_utils as U
import rtl_test_utils
from uut_provider import *


class rtl_device(uut_provider_base):
    def init(self, device_path, dev_id, slice_modes, initialize, simulation_mode, device_config_func):
        # Create device
        self.device = sdk.la_create_device(device_path, dev_id)

        # Create simulator
        simulator = test_lldcli.create_socket_simulator(device_path)

        if simulator is None:
            return sdk.la_status_e_E_UNKNOWN

        ll_device = self.device.get_ll_device()
        ll_device.set_device_simulator(simulator, simulation_mode)
        self.ll_device = ll_device

        # Initialize device
        if initialize:
            initialize_device(self.device, slice_modes, device_config_func)

    def __getattr__(self, item):
        if item in self.__dir__():
            return self.__getattribute__(item)

        return self.device.__getattribute__(item)


class ra_device(uut_provider_base):
    def init(
            self,
            device_path,
            dev_id,
            initialize,
            slice_modes,
            block_filter_getter,
            create_sim,
            enable_hbm_lpm,
            device_config_func,
            inject_from_npu_host,
            sim_options,
            add_inject_up_header_if_inject_from_npuh):

        # Create device
        self.device = sdk.la_create_device(device_path, dev_id)
        self.device_id = dev_id

        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM, enable_hbm_lpm)
        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM_ROUTE_EXTENSION, enable_hbm_lpm)

        # Create ll_device and simulator
        ll_device = self.device.get_ll_device()
        self.ll_device = ll_device
        block_filter = block_filter_getter(ll_device)
        simulator = ra.create_ra_simulator(block_filter, dev_id, sim_options)
        ll_device.set_device_simulator(simulator)

        if not initialize:
            self.device.acquire_device_lock(True)
            simulator.init_device_done()
            self.device.release_device_lock()
            return self.device

        if ll_device.is_pacific():
            ra.init_buggy_dynamic_memories(ll_device)

        # Initialize device
        initialize_device(self.device, slice_modes, device_config_func)

        self.sim = None
        if create_sim:
            self.sim = rtl_test_utils.ra_npu_rtl_sim_provider(
                self.device,
                sim_options.use_socket,
                inject_from_npu_host,
                add_inject_up_header_if_inject_from_npuh)

        self.device.acquire_device_lock(True)
        simulator.init_device_done()
        self.device.release_device_lock()

    def __getattr__(self, item):
        if item in self.__dir__():
            return self.__getattribute__(item)

        return self.device.__getattribute__(item)

    def get_simulator(self):
        return self.sim

    def inject_packet(self, ipacket, initial_values={}):
        if self.sim is None:
            return False

        self.sim.inject_packet(ipacket, initial_values=initial_values)
        return True

    def step_packet(self):
        if self.sim is None:
            return False

        return self.sim.step_packet()

    def get_packet(self):
        if self.sim is None:
            return False

        out_packet = self.sim.get_packet()
        if out_packet.packet == '':
            return (False, out_packet)

        return (True, out_packet)

    def logger_off(self):
        ra.ra_logger_off(self.device_id)
