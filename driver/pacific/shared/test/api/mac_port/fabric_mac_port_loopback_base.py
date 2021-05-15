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

import time
import unittest
from leaba import sdk

import sim_utils
import mac_port_helper
import topology as T

from loopback_base import *


class fabric_mac_port_loopback_base(loopback_base):
    # Add all MAC port valid configurations
    def create_mac_port_profiles(self):
        mac_port_profiles = []
        mac_port_profiles.append({'name': "2x50G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                  'fc_modes': [
                                      sdk.la_mac_port.fc_mode_e_CFFC,  # A single fc_mode must be used for all fabric mac ports
                                      sdk.la_mac_port.fc_mode_e_CFFC]
                                  })

        mac_port_profiles.append({'name': "2x50G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                  'fc_modes': [
                                      sdk.la_mac_port.fc_mode_e_CFFC,  # A single fc_mode must be used for all fabric mac ports
                                      sdk.la_mac_port.fc_mode_e_CFFC]
                                  })

        mac_port_profiles.append({'name': "2x50G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                  'fc_modes': [
                                      sdk.la_mac_port.fc_mode_e_CFFC,  # A single fc_mode must be used for all fabric mac ports
                                      sdk.la_mac_port.fc_mode_e_CFFC]
                                  })

        return mac_port_profiles

    def create_fabric_mac_port_mix_from_profiles(self, mac_port_profiles, first_device_serdes):
        current_device_serdes = first_device_serdes

        port_mix = []

        for mac_port_profile in mac_port_profiles:
            serdes_count = mac_port_profile['serdes_count']
            for fc_mode in mac_port_profile['fc_modes']:
                current_device_serdes.find_first_valid(serdes_count)

                port_mix.append({'slice': current_device_serdes.slice,
                                 'ifg': current_device_serdes.ifg,
                                 'serdes': current_device_serdes.serdes,
                                 'serdes_count': serdes_count,
                                 'speed': mac_port_profile['speed'],
                                 'fc': fc_mode})

                current_device_serdes.advance(serdes_count)

        return port_mix

    def create_fabric_mac_ports_from_mix(self, port_mix, loopback_mode):
        for port_cfg in port_mix:
            mac_port = self.mph.create_fabric_mac_port(
                port_cfg['slice'],
                port_cfg['ifg'],
                port_cfg['serdes'],
                port_cfg['serdes_count'],
                port_cfg['speed'],
                port_cfg['fc'],
                loopback_mode)

    def parallel_loopback_test(self, loopback_mode, slice_modes=sim_utils.LINECARD_3N_3F_DEV):
        self.device = sim_utils.create_device(self.device_id, slice_modes=slice_modes)
        self.mph.init(self.device)

        mac_port_profiles = self.create_mac_port_profiles()
        first_serdes = device_serdes(self.device, 3, 0, 0)
        mac_port_mix = self.create_fabric_mac_port_mix_from_profiles(mac_port_profiles, first_serdes)

        self.create_fabric_mac_ports_from_mix(mac_port_mix, loopback_mode)

        self.mph.mac_ports_activate('LOOPBACK', None)
        self.assertTrue(self.mph.wait_mac_ports_up())
