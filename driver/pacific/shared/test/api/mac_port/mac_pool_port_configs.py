#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import topology as T
import copy


class mac_pool_port_configs():
    def __init__(self):
        self._all_conf = {}
        self._default_conf = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_count': 0, 'ports_per_ifg': 0,
                              'serdes_spd': 0, 'speed': sdk.la_mac_port.port_speed_e_E_10G, 'fec_modes': [], 'fc_modes': []}
        self._current_config = copy.copy(self._default_conf)
        self._cfg_string = 'unknown'
        self.set_all_configs_pacific()

    @property
    def slice_id(self):
        return self._current_config['slice_id']

    @property
    def ifg_id(self):
        return self._current_config['ifg_id']

    @property
    def first_serdes_id(self):
        return self._current_config['first_serdes_id']

    @property
    def name(self):
        return self._cfg_string

    @property
    def serdes_count(self):
        return self._current_config['serdes_count']

    @property
    def ports_per_ifg(self):
        return self._current_config['ports_per_ifg']

    @property
    def serdes_speed(self):
        return self._current_config['serdes_spd']

    @property
    def speed(self):
        return self._current_config['speed']

    @property
    def fec_modes(self):
        return self._current_config['fec_modes']

    @property
    def fc_modes(self):
        return self._current_config['fc_modes']

    def all_configuration_options(self):
        all_keys = list(self._all_conf.keys())
        all_keys.remove('unknown')
        return all_keys

    def config_mac_pool(self, cfg_string):
        self._cfg_string = cfg_string
        if cfg_string not in self._all_conf:
            self._cfg_string = 'unknown'
        self._current_config = copy.copy(self._all_conf[self._cfg_string])

    def default_fc_modes(self):
        return [sdk.la_mac_port.fc_mode_e_NONE, sdk.la_mac_port.fc_mode_e_PAUSE, sdk.la_mac_port.fc_mode_e_PFC]

    # this function actually holds all the configurations for the GIBRALTAR ASIC
    def set_all_configs_GB(self, device):
        is_matilda = T.is_matilda_model(device)
        self._all_conf = {}
        self._all_conf['mac_pool2_1x10'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 10,
                                            'serdes_count': 1, 'ports_per_ifg': 16,
                                            'speed': sdk.la_mac_port.port_speed_e_E_10G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE,
                                                          sdk.la_mac_port.fec_mode_e_KR],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool2_1x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 1, 'ports_per_ifg': 16,
                                            'speed': sdk.la_mac_port.port_speed_e_E_25G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE, sdk.la_mac_port.fec_mode_e_KR,
                                                          sdk.la_mac_port.fec_mode_e_RS_KR4, sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}
        if not is_matilda:
            self._all_conf['mac_pool2_1x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                                'serdes_count': 1, 'ports_per_ifg': 16,
                                                'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                                'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KR4,
                                                              sdk.la_mac_port.fec_mode_e_RS_KP4],
                                                'fc_modes': self.default_fc_modes()}
        self._all_conf['mac_pool2_2x20'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 20,
                                            'serdes_count': 2, 'ports_per_ifg': 8,
                                            'speed': sdk.la_mac_port.port_speed_e_E_40G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool2_2x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 2, 'ports_per_ifg': 8,
                                            'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE, sdk.la_mac_port.fec_mode_e_RS_KP4,
                                                          sdk.la_mac_port.fec_mode_e_RS_KR4],
                                            'fc_modes': self.default_fc_modes()}
        if not is_matilda:
            self._all_conf['mac_pool_2x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                               'serdes_count': 2, 'ports_per_ifg': 8,
                                               'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                               'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KR4,
                                                             sdk.la_mac_port.fec_mode_e_RS_KP4],  # add RS_KP4_FI ??
                                               'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_4x10'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 10,
                                            'serdes_count': 4, 'ports_per_ifg': 4,
                                            'speed': sdk.la_mac_port.port_speed_e_E_40G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE,
                                                          sdk.la_mac_port.fec_mode_e_KR],
                                            'fc_modes': self.default_fc_modes()}
        self._all_conf['mac_pool8_4x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 4, 'ports_per_ifg': 4,
                                            'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE, sdk.la_mac_port.fec_mode_e_RS_KP4,
                                                          sdk.la_mac_port.fec_mode_e_RS_KR4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_8x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 8, 'ports_per_ifg': 2,
                                            'speed': sdk.la_mac_port.port_speed_e_E_200G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}

        if not is_matilda:
            self._all_conf['mac_pool8_4x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                                'serdes_count': 4, 'ports_per_ifg': 4,
                                                'speed': sdk.la_mac_port.port_speed_e_E_200G,
                                                'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                                'fc_modes': self.default_fc_modes()}
        if not is_matilda:
            self._all_conf['mac_pool8_8x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                                'serdes_count': 8, 'ports_per_ifg': 2,
                                                'speed': sdk.la_mac_port.port_speed_e_E_400G,
                                                'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                                'fc_modes': self.default_fc_modes()}
        if not is_matilda:
            self._all_conf['mac_pool8_16x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                                 'serdes_count': 16, 'ports_per_ifg': 1,
                                                 'speed': sdk.la_mac_port.port_speed_e_E_800G,
                                                 'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                                 'fc_modes': self.default_fc_modes()}

        self._all_conf['unknown'] = self._default_conf

    # this function actually holds all the configurations for the PACIFIC ASIC
    def set_all_configs_pacific(self):
        self._all_conf = {}
        self._all_conf['mac_pool2_1x10'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 10,
                                            'serdes_count': 1, 'ports_per_ifg': 18, 'speed': sdk.la_mac_port.port_speed_e_E_10G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE, sdk.la_mac_port.fec_mode_e_KR],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool2_1x25'] = {
            'slice_id': 0,
            'ifg_id': 0,
            'first_serdes_id': 0,
            'serdes_spd': 25,
            'serdes_count': 1,
            'ports_per_ifg': 18,
            'speed': sdk.la_mac_port.port_speed_e_E_25G,
            'fec_modes': [
                sdk.la_mac_port.fec_mode_e_NONE,
                sdk.la_mac_port.fec_mode_e_KR,
                sdk.la_mac_port.fec_mode_e_RS_KR4],
            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool2_1x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                            'serdes_count': 1, 'ports_per_ifg': 18,
                                            'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KR4, sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool2_2x20'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 20,
                                            'serdes_count': 2, 'ports_per_ifg': 9,
                                            'speed': sdk.la_mac_port.port_speed_e_E_40G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool2_2x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 2, 'ports_per_ifg': 9,
                                            'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE, sdk.la_mac_port.fec_mode_e_RS_KR4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_4x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 4, 'ports_per_ifg': 4,
                                            'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE,
                                                          sdk.la_mac_port.fec_mode_e_RS_KR4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_8x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 8, 'ports_per_ifg': 2,
                                            'speed': sdk.la_mac_port.port_speed_e_E_200G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}
        self._all_conf['mac_pool8_8x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                            'serdes_count': 8, 'ports_per_ifg': 2,
                                            'speed': sdk.la_mac_port.port_speed_e_E_400G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_16x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                             'serdes_count': 16, 'ports_per_ifg': 1,
                                             'speed': sdk.la_mac_port.port_speed_e_E_800G,
                                             'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                             'fc_modes': self.default_fc_modes()}
        self._all_conf['mac_pool_2x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                           'serdes_count': 2, 'ports_per_ifg': 9,
                                           'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                           'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KR4, sdk.la_mac_port.fec_mode_e_RS_KP4],
                                           'fc_modes': self.default_fc_modes()}
        self._all_conf['unknown'] = self._default_conf

    def set_all_configs_asic3(self):
        self._all_conf = {}
        self._all_conf['mac_pool8_1x10'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 10,
                                            'serdes_count': 1, 'ports_per_ifg': 16,
                                            'speed': sdk.la_mac_port.port_speed_e_E_10G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE,
                                                          sdk.la_mac_port.fec_mode_e_KR],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_1x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 1, 'ports_per_ifg': 16,
                                            'speed': sdk.la_mac_port.port_speed_e_E_25G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE, sdk.la_mac_port.fec_mode_e_KR,
                                                          sdk.la_mac_port.fec_mode_e_RS_KR4, sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_1x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                            'serdes_count': 1, 'ports_per_ifg': 16,
                                            'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KR4,
                                                          sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_2x20'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 20,
                                            'serdes_count': 2, 'ports_per_ifg': 8,
                                            'speed': sdk.la_mac_port.port_speed_e_E_40G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_2x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 2, 'ports_per_ifg': 8,
                                            'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE, sdk.la_mac_port.fec_mode_e_RS_KP4,
                                                          sdk.la_mac_port.fec_mode_e_RS_KR4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_2x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                            'serdes_count': 2, 'ports_per_ifg': 8,
                                            'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KR4,
                                                          sdk.la_mac_port.fec_mode_e_RS_KP4,
                                                          sdk.la_mac_port.fec_mode_e_RS_KP4_FI],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_4x10'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 10,
                                            'serdes_count': 4, 'ports_per_ifg': 4,
                                            'speed': sdk.la_mac_port.port_speed_e_E_40G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE,
                                                          sdk.la_mac_port.fec_mode_e_KR],
                                            'fc_modes': self.default_fc_modes()}
        self._all_conf['mac_pool8_4x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 4, 'ports_per_ifg': 4,
                                            'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_NONE, sdk.la_mac_port.fec_mode_e_RS_KP4,
                                                          sdk.la_mac_port.fec_mode_e_RS_KR4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_8x25'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 25,
                                            'serdes_count': 8, 'ports_per_ifg': 2,
                                            'speed': sdk.la_mac_port.port_speed_e_E_200G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_4x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                            'serdes_count': 4, 'ports_per_ifg': 4,
                                            'speed': sdk.la_mac_port.port_speed_e_E_200G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_8x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                            'serdes_count': 8, 'ports_per_ifg': 2,
                                            'speed': sdk.la_mac_port.port_speed_e_E_400G,
                                            'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                            'fc_modes': self.default_fc_modes()}

        self._all_conf['mac_pool8_16x50'] = {'slice_id': 0, 'ifg_id': 0, 'first_serdes_id': 0, 'serdes_spd': 50,
                                             'serdes_count': 16, 'ports_per_ifg': 1,
                                             'speed': sdk.la_mac_port.port_speed_e_E_800G,
                                             'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KP4],
                                             'fc_modes': self.default_fc_modes()}

        self._all_conf['unknown'] = self._default_conf

    def set_all_configs_asic4(self):
        self._all_conf = {}
        self._all_conf['unknown'] = self._default_conf

    def set_all_configs_asic5(self):
        self._all_conf = {}
        self._all_conf['unknown'] = self._default_conf

    def expected_packet_test_db_entry(self):
        expected = {k: 1 for k in self._all_conf.keys()}
        expected['mac_pool8_4x10'] = 0
        expected['mac_pool8_4x25'] = 0
        expected['mac_pool8_8x25'] = 0
        expected['mac_pool8_4x25'] = 0
        expected['mac_pool8_4x50'] = 0
        expected['unknown'] = 0
        return expected
