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
import lldcli
import topology as T

import sim_utils
import mac_port_helper

from mac_port.loopback_base import *

import warm_boot_test_utils as wb


class mac_port_loopback_base(loopback_base):
    # Add all MAC port valid configurations
    def create_mac_port_profiles(self):
        mac_port_profiles = []
        mac_port_profiles.append({'name': "1x10G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_10G,
                                  'fec_modes': [
                                      sdk.la_mac_port.fec_mode_e_NONE,
                                      sdk.la_mac_port.fec_mode_e_KR],
                                  'fc_modes': [
                                      sdk.la_mac_port.fc_mode_e_NONE,
                                      sdk.la_mac_port.fc_mode_e_PAUSE,
                                      sdk.la_mac_port.fc_mode_e_PFC]
                                  })

        mac_port_profiles.append({'name': "1x25G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_25G,
                                  'fec_modes': [
                                      sdk.la_mac_port.fec_mode_e_NONE,
                                      sdk.la_mac_port.fec_mode_e_RS_KR4,
                                      sdk.la_mac_port.fec_mode_e_RS_KP4],
                                  'fc_modes': [
                                      sdk.la_mac_port.fc_mode_e_NONE,
                                      sdk.la_mac_port.fc_mode_e_PAUSE,
                                      sdk.la_mac_port.fc_mode_e_PFC]
                                  })
        if not T.is_matilda_model(self.device):
            mac_port_profiles.append({'name': "1x50G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                      'fec_modes': [
                                          sdk.la_mac_port.fec_mode_e_RS_KR4,
                                          sdk.la_mac_port.fec_mode_e_RS_KP4],
                                      'fc_modes': [
                                          sdk.la_mac_port.fc_mode_e_NONE,
                                          sdk.la_mac_port.fc_mode_e_PAUSE,
                                          sdk.la_mac_port.fc_mode_e_PFC]
                                      })

        mac_port_profiles.append({'name': "2x25G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                  'fec_modes': [
                                      sdk.la_mac_port.fec_mode_e_NONE,
                                      sdk.la_mac_port.fec_mode_e_RS_KR4],
                                  'fc_modes': [
                                      sdk.la_mac_port.fc_mode_e_NONE,
                                      sdk.la_mac_port.fc_mode_e_PAUSE,
                                      sdk.la_mac_port.fc_mode_e_PFC]
                                  })
        if not T.is_matilda_model(self.device):
            mac_port_profiles.append({'name': "2x50G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                      'fec_modes': [
                                          sdk.la_mac_port.fec_mode_e_RS_KR4,
                                          sdk.la_mac_port.fec_mode_e_RS_KP4],
                                      'fc_modes': [
                                          sdk.la_mac_port.fc_mode_e_NONE,
                                          sdk.la_mac_port.fc_mode_e_PAUSE,
                                          sdk.la_mac_port.fc_mode_e_PFC]
                                      })

        mac_port_profiles.append({'name': "4x25G", 'serdes_count': 4, 'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                  'fec_modes': [
                                      sdk.la_mac_port.fec_mode_e_NONE,
                                      sdk.la_mac_port.fec_mode_e_RS_KR4],
                                  'fc_modes': [
                                      sdk.la_mac_port.fc_mode_e_NONE,
                                      sdk.la_mac_port.fc_mode_e_PAUSE,
                                      sdk.la_mac_port.fc_mode_e_PFC]
                                  })

        mac_port_profiles.append({'name': "8x25G", 'serdes_count': 8, 'speed': sdk.la_mac_port.port_speed_e_E_200G,
                                  'fec_modes': [
                                      sdk.la_mac_port.fec_mode_e_RS_KP4],
                                  'fc_modes': [
                                      sdk.la_mac_port.fc_mode_e_NONE,
                                      sdk.la_mac_port.fc_mode_e_PAUSE,
                                      sdk.la_mac_port.fc_mode_e_PFC]
                                  })
        if not T.is_matilda_model(self.device):
            mac_port_profiles.append({'name': "8x50G", 'serdes_count': 8, 'speed': sdk.la_mac_port.port_speed_e_E_400G,
                                      'fec_modes': [
                                          sdk.la_mac_port.fec_mode_e_RS_KP4],
                                      'fc_modes': [
                                          sdk.la_mac_port.fc_mode_e_NONE,
                                          sdk.la_mac_port.fc_mode_e_PAUSE,
                                          sdk.la_mac_port.fc_mode_e_PFC]
                                      })

        if self.mph.ll_device.is_gibraltar() and not T.is_matilda_model(self.device):
            mac_port_profiles.append({'name': "4x50G", 'serdes_count': 4, 'speed': sdk.la_mac_port.port_speed_e_E_200G,
                                      'fec_modes': [
                                          sdk.la_mac_port.fec_mode_e_RS_KP4],
                                      'fc_modes': [
                                          sdk.la_mac_port.fc_mode_e_NONE,
                                          sdk.la_mac_port.fc_mode_e_PAUSE,
                                          sdk.la_mac_port.fc_mode_e_PFC]
                                      })

        return mac_port_profiles

    def create_mac_port_mix_from_profiles(self, mac_port_profiles, first_device_serdes):
        current_device_serdes = first_device_serdes
        port_mix_sets = []
        port_mix = []

        for mac_port_profile in mac_port_profiles:
            serdes_count = mac_port_profile['serdes_count']
            for fec_mode in mac_port_profile['fec_modes']:
                for fc_mode in mac_port_profile['fc_modes']:
                    was_wraped = current_device_serdes.find_first_valid(serdes_count)
                    if was_wraped:
                        port_mix_sets.append(port_mix)
                        port_mix = []

                    port_mix.append({'slice': current_device_serdes.slice,
                                     'ifg': current_device_serdes.ifg,
                                     'serdes': current_device_serdes.serdes,
                                     'serdes_count': serdes_count,
                                     'speed': mac_port_profile['speed'],
                                     'fc': fc_mode,
                                     'fec': fec_mode})

                    was_wraped = current_device_serdes.advance(serdes_count)
                    if was_wraped:
                        port_mix_sets.append(port_mix)
                        port_mix = []
        if len(port_mix) > 0:
            port_mix_sets.append(port_mix)
        return port_mix_sets

    def create_mac_ports_from_mix(self, port_mix, loopback_mode):
        for port_cfg in port_mix:
            mac_port = self.mph.create_mac_port(
                port_cfg['slice'],
                port_cfg['ifg'],
                port_cfg['serdes'],
                port_cfg['serdes_count'],
                port_cfg['speed'],
                port_cfg['fec'],
                port_cfg['fc'],
                loopback_mode)

    def parallel_loopback_test(self, loopback_mode, do_warm_boot=False):
        self.device = sim_utils.create_device(self.device_id)
        self.mph.init(self.device)

        mac_port_profiles = self.create_mac_port_profiles()
        first_serdes = device_serdes(self.device, 0, 0, 0)
        mac_port_mix_sets = self.create_mac_port_mix_from_profiles(mac_port_profiles, first_serdes)

        # in case that the number of configurations is so big that you cannot create a single port of each type on the
        # device at the same time - run the test in batches
        test_counter = 0
        for mac_port_mix in mac_port_mix_sets:
            test_counter += 1
            if test_counter > 1:
                self.reset_device()
            self.do_parallel_loopback_test_max_serdes(mac_port_mix, loopback_mode, do_warm_boot)

    def do_parallel_loopback_test_max_serdes(self, mac_port_mix, loopback_mode, do_warm_boot):
        self.create_mac_ports_from_mix(mac_port_mix, loopback_mode)

        if do_warm_boot:
            wb.warm_boot(self.device.device)
            # Restore notification pipes manually
            self.mph.critical_fd, self.mph.normal_fd = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

        self.mph.mac_ports_activate('LOOPBACK', None)
        all_up = self.mph.wait_mac_ports_up()
        if not all_up:
            self.mph.print_mac_up()
        self.assertTrue(all_up)

    def reset_device(self):
        self.mph.teardown()
        self.device.clear_device()
        self.device.close_notification_fds()
        self.mph = mac_port_helper.mac_port_helper()
        self.mph.init(self.device)


if __name__ == '__main__':
    unittest.main()
