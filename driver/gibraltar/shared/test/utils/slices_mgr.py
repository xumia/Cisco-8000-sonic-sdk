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


import singleton
import decor
import os
import json
from copy import deepcopy
#from slices_mgr import SLICE_MGR
#Sm = SLICE_MGR()


class slice_ifg_python():
    def __init__(self, slice, ifg):
        self.slice = slice
        self.ifg = ifg


def dynamic_cast(className, obj):
    castobj = className()
    castobj.this = obj.this
    return castobj

# Python3


def help_load_s_map(mapp, from_s, to_s):
    mapp[from_s]['to'] = to_s
    if mapp[to_s]['to'] == to_s:
        mapp[to_s]['to'] = from_s
    assert mapp[to_s]['to'] == from_s


def help_load_ifg_map(mapp, from_i, to_i):
    mapp[from_i]['to'] = to_i
    if mapp[to_i]['to'] == to_i:
        mapp[to_i]['to'] = from_i
    assert mapp[to_i]['to'] == from_i


class SLICE_MGR(metaclass=singleton.Singleton):
    available_slices = []

    def __init__(self):
        self.slices_mappings_data = None
        self.internal_matilda_mode = None
        if len(self.available_slices) == 0:
            self.__initialize_mapping()

    def __initialize_mapping(self):
        self._set_slice_values()
        if self.get_matilda_model_type() in ['6.4', '3.2B']:
            f_path = os.getenv('MATILDA_MAP_F')
            with open(f_path) as json_file:
                self.slices_mappings_data = json.load(json_file)
        self._initialize_slice_mappings()

    def set_internal_matilda_mode(self, mode):
        self.internal_matilda_mode = mode
        self.__initialize_mapping()

    def get_matilda_model_type(self):
        matilda_model_t = self.internal_matilda_mode or decor.matilda_model_type()
        return matilda_model_t

    def _initialize_slice_mappings(self):
        # first, initialize all on the trivial mapp
        map_f = {}
        for sid in range(6):
            ifg_map = {}
            for ifg_id in range(2):
                ifg_map[ifg_id] = {'to': ifg_id, 'serdices': [i for i in range(25)]}
            map_f[sid] = {'to': sid, 'IFGs': ifg_map}
        map_b = deepcopy(map_f)

        if self.slices_mappings_data is None:
            self._mapping_is_forward = {True: map_f, False: map_b}
            return
        for s_data in self.slices_mappings_data["slices_mapping"]:
            from_s, to_s, ifgs = s_data["from_slice"], s_data["to_slice"], s_data["IFGs"]
            help_load_s_map(map_f, from_s, to_s)
            help_load_s_map(map_b, to_s, from_s)

            for ifg_data in ifgs:
                from_i, to_i, sers = ifg_data["from_ifg"], ifg_data["to_ifg"], ifg_data["serdices"]
                help_load_ifg_map(map_f[from_s]["IFGs"], from_i, to_i)
                help_load_ifg_map(map_b[to_s]["IFGs"], to_i, from_i)
                if len(sers) > 0:
                    new_sers = deepcopy(sers)
                    reverse_map = deepcopy(new_sers)
                    for i, val in enumerate(new_sers):
                        reverse_map[val] = i
                    new_sers.append(24)
                    reverse_map.append(24)
                    map_f[from_s]["IFGs"][from_i]['serdices'] = new_sers
                    map_b[to_s]["IFGs"][to_i]['serdices'] = reverse_map

        self._mapping_is_forward = {True: map_f, False: map_b}
        # print("mappping:")
        # print(self._mapping_is_forward[True][2])

    def _set_slice_values(self):
        self._map_available_slicess()

        self.INJECT_SLICE = self.choose_active_slice(0, [4, 2])
        self.PI_SLICE = self.choose_active_slice(3, [1, 3, 5])
        self.s_rx_slice_inject_up = self.choose_active_slice(2, [4])
        self.s_rx_slice = self.choose_active_slice(0, [0, 5])
        self.PCI_PUNT_SLICE = self.choose_active_slice(0, [0, 2, 4])

    def _map_available_slicess(self):
        self.available_slices = range(6)
        if decor.is_asic3():
            self.available_slices = range(8)
        elif decor.is_asic5():
            self.available_slices = [0]
        elif self.get_matilda_model_type() != -1:
            if self.get_matilda_model_type() == "3.2A":
                self.available_slices = [0, 1, 2]
            elif self.get_matilda_model_type() == "3.2B":
                #self.available_slices = [5, 4, 3]
                self.available_slices = [0, 1, 2]

    def set_slices_to_object(self, obj):
        obj.INJECT_SLICE = self.INJECT_SLICE
        obj.PI_SLICE = self.PI_SLICE
        obj.s_rx_slice_inject_up = self.s_rx_slice_inject_up
        obj.s_rx_slice = self.s_rx_slice
        obj.PCI_PUNT_SLICE = self.PCI_PUNT_SLICE

    def choose_active_slice(self, def_val, other_slices):
        if def_val in self.available_slices:
            return def_val
        for slice in other_slices:
            if slice in self.available_slices:
                return slice

    def npu_host_port_s_ifg(self):
        s_ifg = self.map_slice_ifg(0, 1)
        return slice_ifg_python(0, 1)

    def map_slice_ifg(self, slice, ifg, forward=True):
        # if not self.get_matilda_model_type() == "3.2B":
        if self.get_matilda_model_type() == -1:
            return slice, ifg

        if self.get_matilda_model_type() == 3 or True:
            map1 = self._mapping_is_forward[forward][slice]
            map2 = map1['IFGs'][ifg]
            return map1['to'], map2['to']

        return slice, ifg

    def map_slice_ifg_serdes(self, slice, ifg, serdes, forward=True):
        # if not self.get_matilda_model_type() == "3.2B":
        if self.get_matilda_model_type() == -1:
            return slice, ifg, serdes

        if self.get_matilda_model_type() == 3 or True:
            map1 = self._mapping_is_forward[forward][slice]
            map2 = map1['IFGs'][ifg]
            new_serdes = serdes
            if serdes < len(map2['serdices']):
                new_serdes = map2['serdices'][serdes]
            return map1['to'], map2['to'], new_serdes

        return slice, ifg, serdes

    def max_num_fabric_ports(self, slice, ifg):
        slice, ifg = self.map_slice_ifg(slice, ifg)
        max_serdes = [9] * 12
        if decor.is_gibraltar():
            max_serdes = [10, 8, 10, 8, 8, 10, 10, 8, 8, 10, 8, 10]

        return max_serdes[slice * 2 + ifg]

    # def punt_source_sp_by_slice(self, slice):
    #     slice, ifg = self.map_slice_ifg(slice, 0)
    #     return 1200 + slice


SLICE_MGR_inst = SLICE_MGR()
