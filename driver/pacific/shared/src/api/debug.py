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

import json
import os.path
import lldcli
from leaba import sdk
from copy import deepcopy
import re
from enum import Enum
import datetime

_is_graphviz_installed = True
try:
    from graphviz import Graph
except Exception:
    _is_graphviz_installed = False


def _ensure_graphviz():
    if _is_graphviz_installed:
        return True
    print("ERROR: Could not find graphviz python package on this machine.\n"
          "Please install it by typing: 'pip3 install graphviz' and then try again.")
    return False


def enum_value_to_field_name(obj, enum_prefix, value):
    """Convert the int value to its matching field's name.

    :param obj: the la object which contains the enum values.

    :param enum_prefix: The prefix of the enum fields in the obj properties.

    :param value: The int value of the enum field.

    :return: A string contains the enum field name, if not found, it will return ``str(value)``.
    """
    for p in dir(obj):
        if p.startswith(enum_prefix) and getattr(obj, p, None) == value:
            return p.replace(enum_prefix, '')
    return str(value)


def get_bits(v, msb, lsb):
    """
    Return v[msb:lsb].

    :param int v: value to get bits from.
    :param int msb: MSB of range to be queried.
    :param int lsb: LSB of range to be queried.

    :return: v[msb:lsb].
    """
    temp_num = (v >> lsb)
    mask = (1 << (1 + msb - lsb)) - 1
    return temp_num & mask


def get_bit(v, b):
    """
    Return v[b].

    :param int v: value to get bits from.
    :param int b: bit to be queried.

    :return: v[b].
    """
    return get_bits(v, b, b)


def set_bits(base_v, msb, lsb, v):
    """
    Replace bits [msb:lsb] of base_v with v.

    :param int base_v: Base value to modify.
    :param int msb: MSB of range to modify.
    :param int lsb: LSB of range to modify.
    :param int v: New value to replace base_v[msb:lsb].

    :return: base_v with bits [msb:lsb] replaced with v.
    """
    temp_num = v << lsb
    mask = ((1 << (1 + msb - lsb)) - 1) << lsb
    base_v &= ~mask
    return base_v | temp_num


_nppd_types_regexps = {
    'uint': re.compile(r'uint:(\d+)'),
    'padding': re.compile(r'padding:(\d+)'),
    'array': re.compile(r'(.+?)\[(\d+)\]')
}


def npl_instance_clone_with_value(npl_instance, bit_vector_value):
    """Clone ``npl_instance`` and set bit vector of the cloned instance and its descendants to ``bit_vector_value``."""
    other = npl_instance.clone()
    other._data_bit_vector.set_value(bit_vector_value)
    return other


class npl_bit_vector:
    """Represents a bit vector.

    .. py:attribute:: length: int

        The length of vector.
    """

    def __init__(self, data, length):
        if length is None or length < 0:
            raise ValueError('ERROR: length of npl_bit_vector must be a nonnegative integer.')
        self._data = data
        self.length = length

    def get_bits(self, offset, width):
        """
        :param offset: The lsb bit offset of the desired value.
        :param width: Number of the bits to read beginning from ``offset``.
        :return: The value of the read bits as int.
        """
        return get_bits(self._data, offset + width - 1, offset)

    def get_bits_from_msb(self, offset_from_msb, width):
        """
        :param offset_from_msb: The offset from msb to start reading from. This will be the msb bit of the
            returned value.
        :param width: Number of the bits to read before the ``offset_from_msb``.
        :return: The value of the read bits as int.
        """
        msb = self.length - offset_from_msb - 1
        lsb = msb - width + 1
        return get_bits(self._data, msb, lsb)

    def set_value(self, new_value):
        """Set the value of this vector to ``new_value``."""
        self._data = new_value

    def set_bits(self, *, new_value, msb, lsb):
        """Change the value of specific range in the vector.

        :param new_value: The new value (as int) to be set instead of the current value.
        :param msb: The msb of the range to change.
        :param lsb: The lsb of the range to change.
        """
        self._data = set_bits(self._data, msb, lsb, new_value)


class npl_instance_type(Enum):
    """Available types for ``npl_type_instance`` instances."""
    Struct = 0,
    Union = 1,
    Array = 2,
    Enum = 3,
    Uint = 4,
    Padding = 5


class npl_type_instance:
    """Represent one NPL field.

    .. py:attribute:: name: str

        The name of the instance, which is the name of the npl field that this instance represents.

    .. py:attribute:: width: int

        The width (number of bits) of this instance.

    .. py:attribute:: relative_offset: int

        The offset of this instance relatively to its parent.

    .. py:attribute:: parent: Optional[:py:class:`.npl_type_instance`].

        The parent npl instance of the current instance. If the current instance is the root, then its ``parent`` will be ``None``.

    .. py:attribute:: type: :py:class:`.npl_instance_type`.

        The type of the current instance.

    """

    def __init__(self, *, name, width, relative_offset, data_bit_vector, fields=None, instance_type=npl_instance_type.Struct):
        self.name = name
        self.width = width
        self.relative_offset = relative_offset
        self.parent = None

        self.type = instance_type

        self._offset = -1
        self._field_value = None
        self._data_bit_vector = data_bit_vector
        self._path = None
        self._fields = dict()

        if fields is not None:
            for field_name, field_property in fields.items():
                setattr(self, field_name, field_property)
                field_property.parent = self
                self._fields[field_name] = field_property

    def get_value(self):
        """Get the value of this field"""
        if self._field_value is None and self._data_bit_vector is not None:
            self._field_value = self._data_bit_vector.get_bits_from_msb(self.field_offset, self.width)
        return self._field_value

    def _set_bit_vector_of_children(self, bit_vector):
        for field in self.fields.values():
            field._data_bit_vector = bit_vector
            if field.fields:
                field._set_bit_vector_of_children(bit_vector)

    def clone(self, bit_vector=None):
        """Generate a new copy of the current instance and return it.

        If ``bit_vector`` is given, then the cloned instance and all its descendants will point to it.
        """
        other = deepcopy(self)
        if bit_vector is not None and self.fields:
            other._data_bit_vector = bit_vector
            other._set_bit_vector_of_children(bit_vector)
        return other

    def __repr__(self):
        value = self.get_value()
        if value is None:
            return 'Data vector was not set'
        return str(self.get_value())

    @property
    def field_offset(self):
        """The offset of the current instance."""
        if self._offset == -1:
            if self.parent is None:
                return 0
            self._offset = self.relative_offset + self.parent.field_offset
        return self._offset

    @property
    def path(self):
        """The full path of the current instance."""
        if self.parent is None:
            return self.name
        if self._path is None:
            if self.parent.type == npl_instance_type.Array and self.parent.parent is not None:
                self._path = '%s.%s' % (self.parent.parent.path, self.name)
            else:
                self._path = '%s.%s' % (self.parent.path, self.name)
        return self._path

    @property
    def fields(self):
        """Get a dictionary that maps the names of this instance's fields to their appropriate
        :py:class:`.npl_type_instance` instances."""
        return self._fields


class npl_enum_type:
    """Represent NPL enum type."""

    def __init__(self, enum_type_name, enum_fields):
        self._name = enum_type_name
        self._enum_fields_to_value = dict()
        self._value_to_enum_fields = dict()
        for field in enum_fields:
            int_val = field['value']
            field_name = field['name']
            self._enum_fields_to_value[field_name] = int_val
            self._value_to_enum_fields[int_val] = field_name

    def get_field_name_by_value(self, value):
        """Get the enum field name of the given ``value``.

        :param value: The value to get its name.
        :return: The field name if the value is legal, otherwise ``None`` is returned.
        """
        return self._value_to_enum_fields.get(value, None)

    def __repr__(self):
        return '%s : %s' % (self._name, self._enum_fields_to_value)


class npl_enum_instance(npl_type_instance):
    """Represent a field of NPL enum.

    .. py:attribute:: enum_type: :py:class:`.npl_enum_type`.

        This attribute represents the NPL enum that this NPL instance is of its type.
    """

    def __init__(self, *, name, width, enum_fields, relative_offset, data_bit_vector, enum_type_name):
        super().__init__(name=name, width=width, relative_offset=relative_offset, data_bit_vector=data_bit_vector,
                         instance_type=npl_instance_type.Enum)
        self.enum_type = npl_enum_type(enum_type_name, enum_fields)

    def __repr__(self):
        return self.enum_type.get_field_name_by_value(self.get_value()) or 'UNKNOWN'

    def clone(self, bit_vector=None):
        """Generate a new copy of the current instance and return it.

        If ``bit_vector`` is given, then the cloned instance and all its descendants will point to it.
        """
        other = deepcopy(self)
        other.enum_type = self.enum_type
        if bit_vector is not None:
            other._data_bit_vector = bit_vector
        return other


class npl_array_instance(npl_type_instance):
    """Represent NPL field of type array."""

    def __init__(self, *, name, child_property, size, relative_offset, data_bit_vector):
        super().__init__(name=name, width=child_property.width * size, relative_offset=relative_offset,
                         data_bit_vector=data_bit_vector, instance_type=npl_instance_type.Array)
        offset = 0
        for i in range(size - 1, -1, -1):
            cp = child_property.clone(data_bit_vector)
            cp.relative_offset = offset
            cp.parent = self
            cp.name = '%s[%d]' % (name, i)
            self._fields[i] = cp
            offset += cp.width

    def __getitem__(self, index):
        return self._fields[index]

    def __setitem__(self, index, value):
        self._fields[index] = value


class reg_mem_base():
    """
    Base class for wrapping register/memory objects.
    It enables bit-field query and manipulation.
    """

    def __init__(self, template, parsed_data, value=0):
        """
        Initialize a register/memory object.

        :param str template: template name of this object.
        :param dict parsed_data: object's descriptor.
        :param int value: Register/Memory value.
        """
        object.__setattr__(self, 'desc', parsed_data)
        object.__setattr__(self, 'template', template)
        object.__setattr__(self, 'flat', value)

        self.__unpack__(value)

    def __repr__(self):
        str = ""
        for field in self.desc['fields']:
            (field_name, lsb, length) = field
            field_data = getattr(self, field_name)
            str += "%s [%d:%d] = {0:#0{1}x}\n".format(field_data, 3 + int(length / 4)) % (field_name, lsb + length - 1, lsb)

        return str

    def __setattr__(self, name, value):
        if (not hasattr(self, name) or name in ['desc', 'template']):
            raise KeyError('Variable {0} can not be changed or doesn\'t exist'.format(name))

        object.__setattr__(self, name, value)

        if (name == 'flat'):
            self.__unpack__(value)
            return

        for field in self.desc['fields']:
            (field_name, lsb, length) = field
            if (name == field_name):
                object.__setattr__(self, 'flat', set_bits(self.flat, length + lsb - 1, lsb, value))

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __unpack__(self, value):
        for field in self.desc['fields']:
            (field_name, lsb, length) = field
            object.__setattr__(self, field_name, get_bits(value, lsb + length - 1, lsb))


class register(reg_mem_base):
    pass


class memory(reg_mem_base):
    pass


class debug_device:
    """
    Wrapper class providing debug capabilities around an la_device.
    """

    DRAM_IFGS = 14

    def __init__(self, device):
        """
        Initialize a debug_device.

        :param la_device device: an la_device to be wrapped.
        """
        self.device = device

        self.ll_device = self.device.get_ll_device()
        self.pacific_tree = self.ll_device.get_pacific_tree()
        if self.ll_device.is_gibraltar():
            self.device_tree = self.ll_device.get_gibraltar_tree()
        elif self.ll_device.is_pacific():
            self.device_tree = self.ll_device.get_pacific_tree()
        elif self.ll_device.is_asic5():
            self.device_tree = self.ll_device.get_asic5_tree()
        elif self.ll_device.is_asic4():
            self.device_tree = self.ll_device.get_asic4_tree()
        elif self.ll_device.is_asic3():
            self.device_tree = self.ll_device.get_asic3_tree()
        else:
            raise Exception("Unknown device")

        self._read_lbr_json()

        self._read_nppd_fields_json()

        self._read_interrupts_json()

        self._init_constants()

    def _init_constants(self):
        # Stage register paths & num of indices
        self.stage_paths_indices = {
            'termination': ['npu.rxpp_term.npe', 3],
            'forwarding': ['npu.rxpp_fwd.npe', 3],
            'transmit': ['npu.txpp.npe', 2]}

        if self.ll_device.is_asic5():
            self.NUM_SLICES = 1
            self.NUM_IFG_PER_SLICE = 1
            self.NUM_SERDES_PER_IFG = 48
        elif self.ll_device.is_asic4():
            self.NUM_SLICES = 6
            self.NUM_IFG_PER_SLICE = 2
            self.NUM_SERDES_PER_IFG = 16
        else:
            self.NUM_SLICES = 6
            self.NUM_IFG_PER_SLICE = 2
            self.NUM_SERDES_PER_IFG = 18

    def _get_resources_file_path(self, file_name):
        file_path = os.path.join(os.environ['BASE_OUTPUT_DIR'], 'res', file_name)
        if not os.path.isfile(file_path):
            raise Exception('File %s does not exist.' % file_path)
        return file_path

    def _read_nppd_fields_json(self):
        nppd_fields_file = self._get_resources_file_path('nppd_fields_types.json')
        with open(nppd_fields_file) as nppd_file:
            fields_types = json.load(nppd_file)
            all_types_json = fields_types['types']
            length = all_types_json['pd_t']['width']
            self._nppd_fields = self._create_npl_instance_from_json('pd', 'pd_t', all_types_json, dict(), 0,
                                                                    npl_bit_vector(0, length))

    def _create_npl_instance_from_json(self, prop_name, type_name, all_types_json, created_properties, relative_offset,
                                       data_vector):
        field_property = created_properties.get(type_name, None)
        if field_property is not None:
            cp = field_property.clone(data_vector)
            cp.name = prop_name
            cp.relative_offset = relative_offset
            return cp

        uint_match = _nppd_types_regexps['uint'].match(type_name)
        if uint_match is not None:
            return npl_type_instance(name=prop_name, width=int(uint_match.group(1)), relative_offset=relative_offset,
                                     instance_type=npl_instance_type.Uint, data_bit_vector=data_vector)

        padding_match = _nppd_types_regexps['padding'].match(type_name)
        if padding_match is not None:
            return npl_type_instance(name=prop_name, width=int(padding_match.group(1)), relative_offset=relative_offset,
                                     instance_type=npl_instance_type.Padding, data_bit_vector=data_vector)

        array_match = _nppd_types_regexps['array'].match(type_name)
        if array_match is not None:
            return self._create_npl_array_instance(prop_name, array_match.group(1), int(array_match.group(2)), all_types_json,
                                                   created_properties, relative_offset, data_vector)

        type_data_json = all_types_json[type_name]
        if type_data_json['type'] == 'enum':
            return self._create_npl_enum_instance(prop_name, type_name, type_data_json, created_properties, relative_offset,
                                                  data_vector)
        if type_data_json['type'] == 'union':
            return self._create_npl_union_instance(prop_name, type_name, type_data_json, all_types_json, created_properties,
                                                   relative_offset, data_vector)

        return self._create_npl_struct_instance(prop_name, type_name, type_data_json, all_types_json, created_properties,
                                                relative_offset, data_vector)

    def _create_npl_array_instance(self, prop_name, type_name, size, all_types_json, created_properties, relative_offset,
                                   data_vector):
        array_element_property = self._create_npl_instance_from_json(prop_name, type_name, all_types_json, created_properties, 0,
                                                                     data_vector)
        array_property = npl_array_instance(name=prop_name, child_property=array_element_property, size=size,
                                            relative_offset=relative_offset, data_bit_vector=data_vector)
        return array_property

    def _create_npl_struct_instance(self, prop_name, type_name, type_data_json, all_types_json, created_properties,
                                    relative_offset, data_vector):
        offset = 0
        fields = dict()
        for field in type_data_json['fields']:
            field_property = self._create_npl_instance_from_json(field['name'], field['type'], all_types_json, created_properties,
                                                                 offset, data_vector)
            fields[field['name']] = field_property
            offset += field_property.width
        complex_property = npl_type_instance(name=prop_name, width=type_data_json['width'], relative_offset=relative_offset,
                                             fields=fields, data_bit_vector=data_vector)
        created_properties[type_name] = complex_property.clone(data_vector)
        return complex_property

    def _create_npl_enum_instance(self, prop_name, enum_name, enum_data_json, created_properties, relative_offset, data_vector):
        enum_property = npl_enum_instance(name=prop_name, width=enum_data_json['width'], data_bit_vector=data_vector,
                                          enum_fields=enum_data_json['fields'], relative_offset=relative_offset,
                                          enum_type_name=enum_name)
        created_properties[enum_name] = enum_property.clone(data_vector)
        return enum_property

    def _create_npl_union_instance(self, prop_name, union_name, union_json_data, all_types_json, created_properties,
                                   relative_offset, data_vector):
        assert union_json_data['type'] == 'union'
        fields = dict()
        width = union_json_data['width']
        for field in union_json_data['fields']:
            align_to_lsb = field['align_to_lsb']
            field_property = self._create_npl_instance_from_json(field['name'], field['type'], all_types_json, created_properties,
                                                                 0, data_vector)
            if align_to_lsb:
                field_property.relative_offset = width - field_property.width
            fields[field['name']] = field_property
        union_property = npl_type_instance(name=prop_name, width=width, relative_offset=relative_offset, fields=fields,
                                           instance_type=npl_instance_type.Union, data_bit_vector=data_vector)
        created_properties[union_name] = union_property.clone(data_vector)
        return union_property

    def _read_json(self, filename):
        json_file = self._get_resources_file_path(filename)
        with open(json_file, 'r', errors='replace') as fd:
            json_str = fd.read()
            # in case the JSON parsing fails, add a custom message to the raised exception
            try:
                json_data = json.loads(json_str)
            except Exception as inst:
                new_msg = "Failed to parse '{0}' as a JSON file after translation".format(json_file)
                reraise(inst, new_msg)
        return json_data

    def _read_lbr_json(self):
        if self.ll_device.is_gibraltar():
            self.parsed_data = self._read_json('gibraltar_tree.json')
        elif self.ll_device.is_pacific():
            self.parsed_data = self._read_json('pacific_tree.json')
        elif self.ll_device.is_asic5():
            self.parsed_data = self._read_json('asic5_tree.json')
        elif self.ll_device.is_asic3():
            self.parsed_data = self._read_json('asic3_tree.json')
        elif self.ll_device.is_asic4():
            self.parsed_data = self._read_json('asic4_tree.json')
        else:
            raise Exception("Unknown device")

    def _read_interrupts_json(self):
        if self.ll_device.is_gibraltar():
            self.interrupt_tree = self._read_json('gibraltar_interrupt_tree.json')
        elif self.ll_device.is_pacific():
            self.interrupt_tree = self._read_json('pacific_interrupt_tree.json')
        elif self.ll_device.is_asic5():
            self.interrupt_tree = self._read_json('asic5_interrupt_tree.json')
        elif self.ll_device.is_asic3():
            self.interrupt_tree = self._read_json('asic3_interrupt_tree.json')
        elif self.ll_device.is_asic4():
            self.interrupt_tree = self._read_json('asic4_interrupt_tree.json')
        else:
            raise Exception("Unknown device")

    def traverse_interrupt_tree(self, nodes, node_cb, node_cb_args, bit_cb, bit_cb_args):
        if not len(nodes):
            return
        for node in nodes:
            node_cb(node, node_cb_args)
            bits = node['bits']
            for i in bits:
                bit = bits[i]
                bit_cb(node, bit, i, bit_cb_args)
                if bit['children']:
                    self.traverse_interrupt_tree(bit['children'], node_cb, node_cb_args, bit_cb, bit_cb_args)

    def create_register(self, reg):
        """
        Creates a '0' initialized class of register 'reg' according to lbr fields without reading the actual register from hardware.

        :param lld_register reg: register that appears in lbr.

        :returns: Register class.
        """
        template = self._get_lbr_name(reg)
        return register(template, self.parsed_data[template])

    def _get_lbr_name(self, obj):
        name = obj.get_desc().name.lower()

        keys = ['lld_register_', 'lld_memory_']
        for key in keys:
            if name.startswith(key):
                name = name.replace(key, '', 1)

        return name

    def read_register(self, reg):
        """
        Get a register class with values of a register.

        :param lld_register reg: Register to read.

        :returns: debug.register class
        """
        read_value = self.ll_device.read_register(reg)

        template = self._get_lbr_name(reg)
        reg = register(template, self.parsed_data[template], read_value)

        return reg

    def peek_register(self, reg):
        """
        Get a register class with values of a register.

        :param lld_register reg: Register to read.

        :returns: debug.register class
        """
        read_value = self.ll_device.peek_register(reg)

        template = self._get_lbr_name(reg)
        reg = register(template, self.parsed_data[template], read_value)

        return reg

    def write_register(self, reg, value):
        """
        Write value to register.

        :param lld_register reg: Register to write to.
        :param int/string/debug.register class value: Value to write to register.

        :returns: None.
        """

        if isinstance(value, register):
            value = value.flat

        return self.ll_device.write_register(reg, value)

    def read_memory(self, mem, index):
        """
        Get a memory class with values of a register.

        :param lld_memory mem: Memory to read.
        :param int index: memory line.

        :returns: debug.memory class.
        """
        read_value = self.ll_device.read_memory(mem, index)

        template = self._get_lbr_name(mem)
        mem = memory(template, self.parsed_data[template], read_value)

        return mem

    def write_memory(self, mem, index, value):
        """
        Write a value line in memory.

        :param lld_memory mem: Memory to write.
        :param int index: memory line.
        :param int/string/debug.memory value:Value to write.

        :returns: None.
        """

        if isinstance(value, memory):
            value = value.flat

        return self.ll_device.write_memory(mem, index, value)

    def _get_npe_counters_npuh(self):

        return self._get_npe_counters_register(self.device_tree.npuh.npe)

    def _get_npu_counters_slice(self, slice):

        slice_data = {}

        slice_data['rxpp'] = self._get_npu_counters_rxpp(slice)
        slice_data['txpp'] = self._get_npu_counters_txpp(slice)

        return slice_data

    def _get_npu_counters_rxpp(self, slice):

        if self.ll_device.is_asic4():
            term_ifg_debug_features = self.read_register(
                self.device_tree.slice[slice].npu.rxpp_term.fi_stage.term_ifg_debug_counters)
        else:
            term_ifg_debug_features = self.read_register(
                self.device_tree.slice[slice].npu.rxpp_term.fi_stage.term_ifg_debug_features)

        incoming_counter = term_ifg_debug_features.ifg0_input_sop_counter + term_ifg_debug_features.ifg1_input_sop_counter

        if self.ll_device.is_asic4():
            outgoing_counter = 0
            rxpp_fwd_debug_counter = [0, 0]
            for index in range(0, 2):
                rxpp_fwd_debug_counter[index] = self.read_register(
                    self.device_tree.slice[slice].npu.rxpp_fwd.post_npe.ifg_rxpp_output_counters[index])
                outgoing_counter += rxpp_fwd_debug_counter[index].ifg_output_sop_counter
        else:
            rxpp_sms_debug_features = self.read_register(
                self.device_tree.slice[slice].npu.rxpp_fwd.rxpp_fwd.rxpp_sms_debug_features)
            outgoing_counter = rxpp_sms_debug_features.ifg0_output_sop_counter + rxpp_sms_debug_features.ifg1_output_sop_counter

        return ({'incoming': incoming_counter, 'outgoing': outgoing_counter})

    def _get_npu_counters_txpp(self, slice):

        # Same registers as in get_npe_counters
        stage_data = self._get_npe_counters_stage('transmit', slice)

        incoming_counter = 0
        outgoing_counter = 0

        for index in stage_data:
            incoming_counter += index['incoming']
            outgoing_counter += index['outgoing']

        return ({'incoming': incoming_counter, 'outgoing': outgoing_counter})

    def _get_npe_counters_slice(self, slice):

        slice_data = {}

        for stage in self.stage_paths_indices:
            slice_data[stage] = self._get_npe_counters_stage(stage, slice)

        return slice_data

    def _get_stage_regs(self, stage, slice, npe_instances=[]):

        (path, indices) = self.stage_paths_indices[stage]
        npe_instances = npe_instances or range(indices)

        stage_regs = []

        int_path = eval('self.device_tree.slice[slice].' + path)
        for index in npe_instances:
            stage_regs.append(int_path[index])

        return stage_regs

    def _get_npe_counters_stage(self, stage, slice):

        # Check if stage exists
        assert (stage in self.stage_paths_indices), 'Stage {} not recognized. Supported stages are '.format(
            stage) + ','.join([k for k in self.stage_paths_indices.keys()])

        return [self._get_npe_counters_register(reg) for reg in self._get_stage_regs(stage, slice)]

    def _get_npe_counters_register(self, block):

        npe_counters_reg = self.read_register(block.npe_counters)

        incoming_counter = npe_counters_reg.incoming_packets_counter
        outgoing_counter = npe_counters_reg.outgoing_packets_counter
        loopback_counter = npe_counters_reg.loopback_packets_counter

        return ({'incoming': incoming_counter, 'outgoing': outgoing_counter, 'loopback': loopback_counter})

    def get_npe_counters(self) -> list:
        """
        Get NPE counters for incoming/outgoing/loopback packets going through each NP engine, per each slice, as well as the NPU host.

        :returns: List of per-slice NPE counters. For each slice, returns a dictionary containing incoming/outgoing/loopback packets per stage.
        """
        data_list = [self._get_npe_counters_slice(slice) for slice in range(self.NUM_SLICES)]
        data_list.append(self._get_npe_counters_npuh())
        return data_list

    def _get_npe_macro_id_counters_register(self, block):
        micro_id_counters = {}

        for index in range(64):
            npe_counters_reg = self.read_register(block.npe_macro_id_counters[index])
            if (npe_counters_reg.macro_id_counter > 0):
                micro_id_counters[index] = npe_counters_reg.macro_id_counter

        return micro_id_counters

    def _get_npe_macro_id_counters_stage(self, stage, slice):

        # Check if stage exists
        assert (stage in self.stage_paths_indices), 'Stage {} not recognized. Supported stages are '.format(
            stage) + ','.join([k for k in self.stage_paths_indices.keys()])

        return [self._get_npe_macro_id_counters_register(reg) for reg in self._get_stage_regs(stage, slice)]

    def _get_npe_macro_id_counters_slice(self, slice, stage):
        slice_data = {}
        if (stage != ''):
            slice_data[stage] = self._get_npe_macro_id_counters_stage(stage, slice)
        else:
            for stage in self.stage_paths_indices:
                slice_data[stage] = self._get_npe_macro_id_counters_stage(stage, slice)

        return slice_data

    def get_npe_macro_id_counters(self, slce=-1, stage='') -> list:
        """
        Get NPE Macro id counters for each NP engine.

        :return: List of per-slice NPE counters. For each slice, return a dictonary containing index and counter.
        """
        data_list = []
        if self.ll_device.is_asic4():
            if slce == -1:
                data_list = [self._get_npe_macro_id_counters_slice(slice, stage) for slice in range(self.NUM_SLICES)]
            else:
                data_list = [self._get_npe_macro_id_counters_slice(slce, stage)]
            if (stage == ''):
                data_list.append(self._get_npe_macro_id_counters_register(self.device_tree.npuh.npe))
        return data_list

    def _get_npe_cbt_if_counters_register(self, block):
        cbt_if_counters = {}
        cbt_if_a_counters = {}
        cbt_if_b_counters = {}
        cbt_if_c_counters = {}
        cbt_if_d_counters = {}

        for index in range(12):
            npe_counters_reg = self.read_register(block.npe_cbt_if_a_counters[index])
            cbt_if_a_counters[index] = npe_counters_reg.cbt_if_a_counter

            npe_counters_reg = self.read_register(block.npe_cbt_if_b_counters[index])
            cbt_if_b_counters[index] = npe_counters_reg.cbt_if_b_counter

            npe_counters_reg = self.read_register(block.npe_cbt_if_c_counters[index])
            cbt_if_c_counters[index] = npe_counters_reg.cbt_if_c_counter

            npe_counters_reg = self.read_register(block.npe_cbt_if_d_counters[index])
            cbt_if_d_counters[index] = npe_counters_reg.cbt_if_d_counter

        cbt_if_counters['a'] = cbt_if_a_counters
        cbt_if_counters['b'] = cbt_if_b_counters
        cbt_if_counters['c'] = cbt_if_c_counters
        cbt_if_counters['d'] = cbt_if_d_counters
        return cbt_if_counters

    def _get_npe_cbt_if_counters_stage(self, stage, slice):

        # Check if stage exists
        assert (stage in self.stage_paths_indices), 'Stage {} not recognized. Supported stages are '.format(
            stage) + ','.join([k for k in self.stage_paths_indices.keys()])

        return [self._get_npe_cbt_if_counters_register(reg) for reg in self._get_stage_regs(stage, slice)]

    def _get_npe_cbt_if_counters_slice(self, slice):
        slice_data = {}

        for stage in self.stage_paths_indices:
            slice_data[stage] = self._get_npe_cbt_if_counters_stage(stage, slice)

        return slice_data

    def get_npe_cbt_if_counters(self) -> list:
        """
        Get NPE cbt if counters for each NP engine.

        :return: List of per-slice NPE counters. For each slice, return a dictonary containing index and counter.
        """
        data_list = []
        if self.ll_device.is_asic4():
            data_list = [self._get_npe_cbt_if_counters_slice(slice) for slice in range(self.NUM_SLICES)]
            data_list.append(self._get_npe_cbt_if_counters_register(self.device_tree.npuh.npe))
        return data_list

    def _get_npe_incoming_error_packets_counter_register(self, block):
        npe_counters_reg = self.read_register(block.npe_incoming_error_packets_counter)
        npe_incoming_error_counter = npe_counters_reg.incoming_error_packets_counter

        return npe_incoming_error_counter

    def _get_npe_incoming_error_packets_counter_stage(self, stage, slice):

        # Check if stage exists
        assert (stage in self.stage_paths_indices), 'Stage {} not recognized. Supported stages are '.format(
            stage) + ','.join([k for k in self.stage_paths_indices.keys()])

        return [self._get_npe_incoming_error_packets_counter_register(reg) for reg in self._get_stage_regs(stage, slice)]

    def _get_npe_incoming_error_packets_counters_slice(self, slice):
        slice_data = {}

        for stage in self.stage_paths_indices:
            slice_data[stage] = self._get_npe_incoming_error_packets_counter_stage(stage, slice)

        return slice_data

    def get_npe_incoming_error_packets_counters(self) -> list:
        """
        Get NPE incoming error packet counters for each NP engine.

        :return: List of per-slice NPE counters. For each slice, return a dictonary containing index and counter.
        """
        data_list = []
        if self.ll_device.is_asic4():
            data_list = [self._get_npe_incoming_error_packets_counters_slice(slice) for slice in range(self.NUM_SLICES)]
            data_list.append(self._get_npe_incoming_error_packets_counter_register(self.device_tree.npuh.npe))
        return data_list

    def _get_npe_outgoing_error_packets_counter_register(self, block):
        npe_counters_reg = self.read_register(block.npe_outgoing_error_packets_counter)
        npe_outgoing_error_counter = npe_counters_reg.outgoing_error_packets_counter

        return npe_outgoing_error_counter

    def _get_npe_outgoing_error_packets_counter_stage(self, stage, slice):

        # Check if stage exists
        assert (stage in self.stage_paths_indices), 'Stage {} not recognized. Supported stages are '.format(
            stage) + ','.join([k for k in self.stage_paths_indices.keys()])

        return [self._get_npe_outgoing_error_packets_counter_register(reg) for reg in self._get_stage_regs(stage, slice)]

    def _get_npe_outgoing_error_packets_counters_slice(self, slice):
        slice_data = {}

        for stage in self.stage_paths_indices:
            slice_data[stage] = self._get_npe_outgoing_error_packets_counter_stage(stage, slice)

        return slice_data

    def get_npe_outgoing_error_packets_counters(self) -> list:
        """
        Get NPE outgoing error packet counters for each NP engine.

        :return: List of per-slice NPE counters. For each slice, return a dictonary containing index and counter.
        """
        data_list = []
        if self.ll_device.is_asic4():
            data_list = [self._get_npe_outgoing_error_packets_counters_slice(slice) for slice in range(self.NUM_SLICES)]
            data_list.append(self._get_npe_outgoing_error_packets_counter_register(self.device_tree.npuh.npe))
        return data_list

    def _get_npe_lookup_error_counter_register(self, block):
        npe_lookup_error_counter = {}
        npe_counters_reg = self.read_register(block.npe_lookup_error_counter_a)
        npe_lookup_error_counter['a'] = npe_counters_reg.lookup_error_counter_a

        npe_counters_reg = self.read_register(block.npe_lookup_error_counter_b)
        npe_lookup_error_counter['b'] = npe_counters_reg.lookup_error_counter_b

        npe_counters_reg = self.read_register(block.npe_lookup_error_counter_c)
        npe_lookup_error_counter['c'] = npe_counters_reg.lookup_error_counter_c

        npe_counters_reg = self.read_register(block.npe_lookup_error_counter_d)
        npe_lookup_error_counter['d'] = npe_counters_reg.lookup_error_counter_d

        return npe_lookup_error_counter

    def _get_npe_lookup_error_counter_stage(self, stage, slice):

        # Check if stage exists
        assert (stage in self.stage_paths_indices), 'Stage {} not recognized. Supported stages are '.format(
            stage) + ','.join([k for k in self.stage_paths_indices.keys()])

        return [self._get_npe_lookup_error_counter_register(reg) for reg in self._get_stage_regs(stage, slice)]

    def _get_npe_lookup_error_counters_slice(self, slice):
        slice_data = {}

        for stage in self.stage_paths_indices:
            slice_data[stage] = self._get_npe_lookup_error_counter_stage(stage, slice)

        return slice_data

    def get_npe_lookup_error_counters(self) -> list:
        """
        Get NPE lookup error packet counters for each NP engine.

        :return: List of per-slice NPE counters. For each slice, return a dictonary containing index and counter.
        """
        data_list = []
        if self.ll_device.is_asic4():
            data_list = [self._get_npe_lookup_error_counters_slice(slice) for slice in range(self.NUM_SLICES)]
            data_list.append(self._get_npe_lookup_error_counter_register(self.device_tree.npuh.npe))
        return data_list

    def get_npu_counters(self) -> list:
        """
        Get NPU counters for incoming/outgoing packets going through RXPP/TXPP, per each slice.

        :returns: List of per-slice NPU counters. For each slice, returns a dictionary containing incoming/outgoing packets per RXPP/TXPP.
        """
        return [self._get_npu_counters_slice(slice) for slice in range(self.NUM_SLICES)]

    def get_hbm_error_counters(self):
        """
        Get HBM error counters.

        :returns: List of HBM interface error counters. Each HBM interface contains a list of errors per channel.
                  Each channel contains dictionary of various errors.
        """
        hbm_error_counters = []
        hbm_h = self.device.get_hbm_handler()
        for intf in range(2):
            hbm_intf_error_counters = []
            for chnl in range(8):
                hbm_errors = hbm_h.read_error_counters(intf, chnl)
                if self.ll_device.is_pacific():
                    error_info = {'channel': chnl,
                                  'write_parity': hbm_errors.write_data_parity,
                                  'addr_parity': hbm_errors.addr_parity,
                                  '1bit_ecc': hbm_errors.one_bit_ecc,
                                  '2bit_ecc': hbm_errors.two_bit_ecc,
                                  'read_parity': hbm_errors.read_data_parity,
                                  }
                    hbm_intf_error_counters.append(error_info)
                elif self.ll_device.is_gibraltar():
                    error_info = {'channel': chnl,
                                  'write_parity0': hbm_errors.write_data_parity_per_dword[0],
                                  'write_parity1': hbm_errors.write_data_parity_per_dword[1],
                                  'write_parity2': hbm_errors.write_data_parity_per_dword[2],
                                  'write_parity3': hbm_errors.write_data_parity_per_dword[3],
                                  'addr_parity': hbm_errors.addr_parity,
                                  '1bit_ecc_pseudo_channel0': hbm_errors.pseudo_channel_one_bit_ecc[0],
                                  '1bit_ecc_pseudo_channel1': hbm_errors.pseudo_channel_one_bit_ecc[1],
                                  'read_parity_pseudo_channel0': hbm_errors.pseudo_channel_read_data_parity[0],
                                  'read_parity_pseudo_channel1': hbm_errors.pseudo_channel_read_data_parity[1],
                                  'crc_error_pseudo_channel0': hbm_errors.pseudo_channel_crc_error[0],
                                  'crc_error_pseudo_channel1': hbm_errors.pseudo_channel_crc_error[1],
                                  }
                    hbm_intf_error_counters.append(error_info)
                else:
                    raise("Not supported ASIC family")

            hbm_error_counters.append(hbm_intf_error_counters)

        return hbm_error_counters

    def get_dram_counters(self):
        """
        Get DRAM counters.

        :returns: List of DRAM counter per IFG interface. Each entry contains dictionary of read and write packets.
                  Note that there are Network slices and the last slice is an HBM slice.
        """
        dram_counters = []
        for ifg in range(debug_device.DRAM_IFGS):
            write_pkts = self.ll_device.read_register(self.device_tree.sms_main.sms_total_write_pkts_reg[ifg])

            # This is total number that was read out towards the MMU (i.e. SMS -> MMU) , in DRAM slice
            read_pkts = self.ll_device.read_register(self.device_tree.sms_main.sms_total_read_pkts_reg[ifg])

            ifg_counter = {'slice': int(ifg / 2), 'ifg': (ifg % 2), 'write_packets': write_pkts, 'read_packets': read_pkts}

            dram_counters.append(ifg_counter)

        return dram_counters

    def print_dram_counters(self):
        """
        Print DRAM counters.
        """
        dram_counters = self.get_dram_counters()

        for ifg_counter in dram_counters:
            print('Slice {slice}, IFG {ifg}: write packets {write_packets}, read packets {read_packets}'.format(**ifg_counter))

    def get_ifgbe_mac_port_counters(self):
        device_ifgbe_mac_port_counters = []
        for slice in range(self.NUM_SLICES):
            slice_ifgb_port_counters = []
            for ifg in range(self.NUM_IFG_PER_SLICE):
                ifg_ifgb_port_counters = []
                for serdes in range(self.NUM_SERDES_PER_IFG):
                    ifgb_port_counters = {
                        'slice': slice,
                        'ifg': ifg,
                        'serdes': serdes
                    }
                    for reg_name in [
                        'rx_port_cgm_tc0_drop_counter',
                        'rx_port_cgm_tc1_drop_counter',
                        'rx_port_cgm_tc2_drop_counter',
                        'rx_port_cgm_tc3_drop_counter',
                        'rx_port_cgm_tc0_partial_drop_counter',
                        'rx_port_cgm_tc1_partial_drop_counter',
                        'rx_port_cgm_tc2_partial_drop_counter',
                            'rx_port_cgm_tc3_partial_drop_counter']:
                        reg = getattr(self.device_tree.slice[slice].ifg[ifg].ifgbe_mac, reg_name)
                        ifgb_port_counters[reg_name] = self.ll_device.read_register(reg[serdes])
                    ifg_ifgb_port_counters.append(ifgb_port_counters)
                slice_ifgb_port_counters.append(ifg_ifgb_port_counters)
            device_ifgbe_mac_port_counters.append(slice_ifgb_port_counters)
        return device_ifgbe_mac_port_counters

    def get_ifgbe_core_counters(self):
        device_ifgbe_core_counters = []
        for slice in range(self.NUM_SLICES):
            slice_ifgbe_counters = []
            for ifg in range(self.NUM_IFG_PER_SLICE):
                ifg_ifgbe_counters = []
                for serdes in range(self.NUM_SERDES_PER_IFG):
                    ifgbe_counters = {
                        'slice': slice,
                        'ifg': ifg,
                        'serdes': serdes
                    }
                    for reg_name in [
                            'rx_fifo_fd_wmk']:
                        reg = getattr(self.device_tree.slice[slice].ifg[ifg].ifgbe_core, reg_name)
                        ifgbe_counters[reg_name] = self.ll_device.read_register(reg[serdes])
                    ifg_ifgbe_counters.append(ifgbe_counters)
                slice_ifgbe_counters.append(ifg_ifgbe_counters)
            device_ifgbe_core_counters.append(slice_ifgbe_counters)
        return device_ifgbe_core_counters

    def get_ifgbe_core_configs(self):
        device_ifgbe_core_configs = []
        for slice in range(self.NUM_SLICES):
            slice_ifgbe_configs = []
            for ifg in range(self.NUM_IFG_PER_SLICE):
                ifgbe_configs = {
                    'slice': slice,
                    'ifg': ifg,
                }
                for reg_name in [
                        'rx_cfg0', 'tx_cfg0', 'rx_rstn_reg', 'tx_rstn_reg']:
                    reg = getattr(self.device_tree.slice[slice].ifg[ifg].ifgbe_core, reg_name)
                    ifgbe_configs[reg_name] = self.ll_device.read_register(reg)
                slice_ifgbe_configs.append(ifgbe_configs)
            device_ifgbe_core_configs.append(slice_ifgbe_configs)
        return device_ifgbe_core_configs

    def get_ifgbe_core_configs_per_serdes(self):
        device_ifgbe_core_configs = []
        for slice in range(self.NUM_SLICES):
            slice_ifgbe_configs = []
            for ifg in range(self.NUM_IFG_PER_SLICE):
                ifg_ifgbe_configs = []
                for serdes in range(self.NUM_SERDES_PER_IFG):
                    ifgbe_configs = {
                        'slice': slice,
                        'ifg': ifg,
                        'serdes': serdes
                    }
                    for reg_name in [
                            'rx_port_fifo_cfg']:
                        reg = getattr(self.device_tree.slice[slice].ifg[ifg].ifgbe_core, reg_name)
                        ifgbe_configs[reg_name] = self.ll_device.read_register(reg[serdes])

                    ifg_ifgbe_configs.append(ifgbe_configs)
                slice_ifgbe_configs.append(ifg_ifgbe_configs)
            device_ifgbe_core_configs.append(slice_ifgbe_configs)
        return device_ifgbe_core_configs

    def get_ifgb_port_counters(self):
        device_ifgb_port_counters = []
        for slice in range(self.NUM_SLICES):
            slice_ifgb_port_counters = []
            for ifg in range(self.NUM_IFG_PER_SLICE):
                ifg_ifgb_port_counters = []
                for serdes in range(self.NUM_SERDES_PER_IFG):
                    ifgb_port_counters = {
                        'slice': slice,
                        'ifg': ifg,
                        'serdes': serdes
                    }
                    for reg_name in [
                        'tx_in_pkt_counter',
                        'rxpp_port_pkt_counter',
                        'rxpp_port_trans_counter',
                        'rx_port_cgm_tc0_drop_counter',
                        'rx_port_cgm_tc1_drop_counter',
                        'rx_port_cgm_tc2_drop_counter',
                        'rx_port_cgm_tc3_drop_counter',
                        'rx_port_cgm_tc0_partial_drop_counter',
                        'rx_port_cgm_tc1_partial_drop_counter',
                        'rx_port_cgm_tc2_partial_drop_counter',
                        'rx_port_cgm_tc3_partial_drop_counter',
                        'rx_fifo_wmk',
                            'rx_fifo_bytes_wmk']:
                        reg = getattr(self.device_tree.slice[slice].ifg[ifg].ifgb, reg_name)
                        ifgb_port_counters[reg_name] = self.ll_device.read_register(reg[serdes])

                    ifg_ifgb_port_counters.append(ifgb_port_counters)
                slice_ifgb_port_counters.append(ifg_ifgb_port_counters)
            device_ifgb_port_counters.append(slice_ifgb_port_counters)
        return device_ifgb_port_counters

    def get_ifgbi_counters(self):
        device_ifgb_counters = []
        for slice in range(self.NUM_SLICES):
            slice_ifgb_counters = []
            for ifg in range(self.NUM_IFG_PER_SLICE):
                ifg_ifgb_counters = {
                    'slice': slice,
                    'ifg': ifg
                }
                for reg_name in ['rx_reassembly_bp_counter', 'rx_rxpp_bp_counter', 'rcontext_alloc_err_cnt']:
                    reg = getattr(self.device_tree.slice[slice].ifg[ifg].ifgbi, reg_name)
                    ifg_ifgb_counters[reg_name] = self.ll_device.read_register(reg)

                ifgbi_counter_mem = {'txpp_cntrs_cfg': 'ifgbi_txpp_cntrs_mem', 'rxpp_cntrs_cfg': 'ifgbi_rxpp_cntrs_mem'}
                for key in ifgbi_counter_mem:
                    reg = getattr(self.device_tree.slice[slice].ifg[ifg].ifgbi, key)
                    mem_sel_val = self.ll_device.read_register(reg)
                    self.ll_device.write_register(reg, (1 - mem_sel_val))
                    mem_name = ifgbi_counter_mem[key]
                    mem = getattr(self.device_tree.slice[slice].ifg[ifg].ifgbi, mem_name)
                    ifg_ifgb_counters[mem_name] = self.read_memory(mem[mem_sel_val], 0)
                slice_ifgb_counters.append(ifg_ifgb_counters)
            device_ifgb_counters.append(slice_ifgb_counters)
        return device_ifgb_counters

    def get_ifgb_counters(self):
        device_ifgb_counters = []
        for slice in range(self.NUM_SLICES):
            slice_ifgb_counters = []
            for ifg in range(self.NUM_IFG_PER_SLICE):
                ifg_ifgb_counters = {
                    'slice': slice,
                    'ifg': ifg
                }
                for reg_name in ['rx_reassembly_bp_counter', 'rx_rxpp_bp_counter', 'rcontext_alloc_err_cnt']:
                    reg = getattr(self.device_tree.slice[slice].ifg[ifg].ifgb, reg_name)
                    ifg_ifgb_counters[reg_name] = self.ll_device.read_register(reg)

                slice_ifgb_counters.append(ifg_ifgb_counters)
            device_ifgb_counters.append(slice_ifgb_counters)
        return device_ifgb_counters

    def print_ifgbe_core_configs_per_serdes(self):
        if self.ll_device.is_asic4():
            core_configs = self.get_ifgbe_core_configs_per_serdes()
            for slice_configs in core_configs:
                for ifg_configs in slice_configs:
                    for serdes_configs in ifg_configs:
                        print(
                            'Slice {slice}, IFG {ifg}, Serdes {serdes}, rx_port_fifo_cfg {rx_port_fifo_cfg}'.format(
                                **serdes_configs))

    def print_ifgbe_core_configs(self):
        if self.ll_device.is_asic4():
            core_configs = self.get_ifgbe_core_configs()
            for slice_configs in core_configs:
                for ifg_configs in slice_configs:
                    print('Slice {slice}, IFG {ifg}, rx_cfg0 {rx_cfg0}, tx_cfg0 {tx_cfg0}, '
                          'rx_rstn_reg {rx_rstn_reg}, tx_rstn_reg {tx_rstn_reg}'.format(**ifg_configs))

    def print_ifgb_counters(self):
        if self.ll_device.is_asic4():
            port_counters = self.get_ifgbe_mac_port_counters()
            total_counters = self.get_ifgbi_counters()
            core_counters = self.get_ifgbe_core_counters()
        else:
            port_counters = self.get_ifgb_port_counters()
            total_counters = self.get_ifgb_counters()

        for slice_port_counters in port_counters:
            for ifg_port_counters in slice_port_counters:
                for serdes_port_counter in ifg_port_counters:
                    if self.ll_device.is_asic4():
                        print(
                            'Slice {slice}, IFG {ifg}, SerDes {serdes:2}: '
                            'DROP: {rx_port_cgm_tc0_drop_counter}, {rx_port_cgm_tc1_drop_counter}, {rx_port_cgm_tc2_drop_counter}, {rx_port_cgm_tc3_drop_counter}, '
                            'PDROP: {rx_port_cgm_tc0_partial_drop_counter}, {rx_port_cgm_tc1_partial_drop_counter}, {rx_port_cgm_tc2_partial_drop_counter}, {rx_port_cgm_tc3_partial_drop_counter}, '
                            ''.format(
                                **serdes_port_counter))
                    else:
                        if serdes_port_counter['tx_in_pkt_counter'] > 0 or serdes_port_counter['rxpp_port_pkt_counter'] > 0 or serdes_port_counter[
                                'rxpp_port_trans_counter'] > 0 or serdes_port_counter['rx_fifo_wmk'] > 0 or serdes_port_counter['rx_fifo_bytes_wmk'] > 0:
                            print(
                                'Slice {slice}, IFG {ifg}, SerDes {serdes:2}: tx {tx_in_pkt_counter}, rx pkt {rxpp_port_pkt_counter}, rx trans {rxpp_port_trans_counter}, '
                                'DROP: {rx_port_cgm_tc0_drop_counter}, {rx_port_cgm_tc1_drop_counter}, {rx_port_cgm_tc2_drop_counter}, {rx_port_cgm_tc3_drop_counter}, '
                                'PDROP: {rx_port_cgm_tc0_partial_drop_counter}, {rx_port_cgm_tc1_partial_drop_counter}, {rx_port_cgm_tc2_partial_drop_counter}, {rx_port_cgm_tc3_partial_drop_counter}, '
                                'WMK: {rx_fifo_wmk}, {rx_fifo_bytes_wmk}'.format(
                                    **serdes_port_counter))
        if self.ll_device.is_asic4():
            for slice_counters in core_counters:
                for ifg_counters in slice_counters:
                    for serdes_counter in ifg_counters:
                        print(
                            'Slice {slice}, IFG {ifg}, SerDes {serdes:2}: '
                            'WMK: {rx_fifo_fd_wmk}'.format(**serdes_counter))

        for slice_total_counters in total_counters:
            for ifg_total_counters in slice_total_counters:
                print(
                    'Slice {slice}, IFG {ifg}: Reassembly back presure {rx_reassembly_bp_counter}, RxPP back presure {rx_rxpp_bp_counter}, Alloc ERR {rcontext_alloc_err_cnt}'.format(
                        **ifg_total_counters))
                if self.ll_device.is_asic4():
                    print(
                        'txpp {ifgbi_txpp_cntrs_mem}, rxpp {ifgbi_rxpp_cntrs_mem}'.format(**ifg_total_counters))

    def notification_to_string(self, notification_desc):
        notification_ts = datetime.datetime.fromtimestamp(notification_desc.timestamp_ns / 1e9).strftime("%H:%M:%S.%f")
        notification_name = enum_value_to_field_name(sdk, 'la_notification_type_e_', notification_desc.type)
        notification_base_info = '{} ({}): {}'.format(notification_ts, notification_desc.id, notification_name)
        if notification_desc.type == sdk.la_notification_type_e_LINK:
            notification_link_type_str = ['UP', 'DOWN', 'ERROR'][notification_desc.u.link.type]
            notification_link_info = '{}: {}: Slice {}, IFG {}, SerDes {}'.format(
                notification_base_info,
                notification_link_type_str,
                notification_desc.u.link.slice_id,
                notification_desc.u.link.ifg_id,
                notification_desc.u.link.first_serdes_id)
            if notification_desc.u.link.type == sdk.la_link_notification_type_e_DOWN:
                down_reasons = []
                if notification_desc.u.link.u.link_down.rx_link_status_down:
                    down_reasons.append('MAC link')
                    if notification_desc.u.link.u.link_down.rx_remote_link_status_down:
                        down_reasons.append('Remote fault')
                    else:
                        down_reasons.append('Local fault')
                if notification_desc.u.link.u.link_down.rx_pcs_link_status_down:
                    down_reasons.append('PCS link')
                if notification_desc.u.link.u.link_down.rx_pcs_align_status_down:
                    down_reasons.append('Alignment marker')
                if notification_desc.u.link.u.link_down.rx_pcs_hi_ber_up:
                    down_reasons.append('PCS high BER')
                if notification_desc.u.link.u.link_down.rsf_rx_high_ser_interrupt_register:
                    down_reasons.append('FEC high SER')
                for rx_skew in notification_desc.u.link.u.link_down.rx_deskew_fifo_overflow:
                    if rx_skew:
                        down_reasons.append('Skew overflow {}'.format(notification_desc.u.link.u.link_down.rx_deskew_fifo_overflow))
                        break

                for signal in notification_desc.u.link.u.link_down.rx_pma_sig_ok_loss_interrupt_register:
                    if signal:
                        down_reasons.append(
                            'Signal OK loss {}'.format(
                                notification_desc.u.link.u.link_down.rx_pma_sig_ok_loss_interrupt_register))
                        break

                return '{} due to: {}'.format(notification_link_info, ','.join(down_reasons))
            elif notification_desc.u.link.type == sdk.la_link_notification_type_e_ERROR:
                error_reasons = []
                if notification_desc.u.link.u.link_error.rx_code_error:
                    error_reasons.append('Rx code')
                if notification_desc.u.link.u.link_error.rx_crc_error:
                    error_reasons.append('Rx CRC')
                if notification_desc.u.link.u.link_error.rx_invert_crc_error:
                    error_reasons.append('Rx inverted CRC')
                if notification_desc.u.link.u.link_error.rx_oob_invert_crc_error:
                    error_reasons.append('Rx OOBI inverted CRC')
                if notification_desc.u.link.u.link_error.rx_oversize_error:
                    error_reasons.append('Rx oversize')
                if notification_desc.u.link.u.link_error.rx_undersize_error:
                    error_reasons.append('Rx undersize')

                if notification_desc.u.link.u.link_error.tx_crc_error:
                    error_reasons.append('Tx CRC')
                if notification_desc.u.link.u.link_error.tx_underrun_error:
                    error_reasons.append('Tx underrun')
                if notification_desc.u.link.u.link_error.tx_missing_eop_error:
                    error_reasons.append('Tx missing EOP')

                if notification_desc.u.link.u.link_error.rsf_rx_degraded_ser:
                    error_reasons.append('RS-FEC degraded SER')
                if notification_desc.u.link.u.link_error.rsf_rx_remote_degraded_ser:
                    error_reasons.append('RS-FEC remote degraded SER')

                if notification_desc.u.link.u.link_error.device_time_override:
                    error_reasons.append('Device time failed to read')
                if notification_desc.u.link.u.link_error.ptp_time_stamp_error:
                    error_reasons.append('PTP time stamp operation failed')

                return '{} due to: {}'.format(notification_link_info, ','.join(error_reasons))
            else:
                return notification_link_info

        elif notification_desc.type == sdk.la_notification_type_e_LPM_SRAM_MEM_PROTECT:
            cdb_core = self.device_tree.get_block(notification_desc.u.lpm_sram_mem_protect.cdb_core_block_id)
            mem_error = enum_value_to_field_name(sdk, 'la_mem_protect_error_e_', notification_desc.u.lpm_sram_mem_protect.error)
            return '{}: core: {}, lpm_index: {}, error: {}'.format(
                notification_base_info,
                cdb_core.get_name(),
                notification_desc.u.lpm_sram_mem_protect.lpm_index,
                mem_error)
        elif notification_desc.type == sdk.la_notification_type_e_MEM_PROTECT:
            block = self.device_tree.get_block(notification_desc.block_id)
            mem = block.get_memory(notification_desc.u.mem_protect.instance_addr)
            mem_error = enum_value_to_field_name(sdk, 'la_mem_protect_error_e_', notification_desc.u.mem_protect.error)
            return '{}: {} (block id: {}, addr: 0x{}), entry: {}, error: {}'.format(
                notification_base_info,
                mem.get_name(),
                hex(notification_desc.block_id),
                hex(notification_desc.u.mem_protect.instance_addr),
                hex(notification_desc.u.mem_protect.entry),
                mem_error)
        elif notification_desc.type == sdk.la_notification_type_e_RESOURCE_MONITOR:
            return '{}: Resource type: {}, max size: {}, in use: {}'.format(
                notification_base_info,
                notification_desc.u.resource_monitor.resource_usage.desc.m_resource_type,
                notification_desc.u.resource_monitor.resource_usage.total,
                notification_desc.u.resource_monitor.resource_usage.used)
        elif notification_desc.type == sdk.la_notification_type_e_BFD:
            return '{}: Local discriminator: {}, reason {}'.format(
                notification_base_info,
                notification_desc.u.bfd.local_discriminator,
                notification_desc.u.bfd.reason)
        elif notification_desc.type == sdk.la_notification_type_e_PFC_WATCHDOG:
            return '{}: Slice {}, IFG {}, SerDes {}, PFC Priority {}'.format(
                notification_base_info,
                notification_desc.u.pfc_watchdog.slice_id,
                notification_desc.u.pfc_watchdog.ifg_id,
                notification_desc.u.pfc_watchdog.first_serdes_id,
                notification_desc.u.pfc_watchdog.pfc_priority)
        elif notification_desc.type == sdk.la_notification_type_e_OTHER:
            block = self.device_tree.get_block(notification_desc.block_id)
            reg = block.get_register(notification_desc.addr)
            reg_name = reg.get_name()
            return '{}: {} (block_id: {}, addr: {}), bit_i: {}'.format(
                notification_base_info,
                reg_name,
                hex(notification_desc.block_id),
                hex(notification_desc.addr),
                notification_desc.bit_i)
        elif notification_desc.type == sdk.la_notification_type_e_DRAM_CORRUPTED_BUFFER:
            return '{}: row={}, col={}, channel_base={}, bank_base={}, corrupted_cells={}'.format(
                notification_base_info,
                notification_desc.u.dram_corrupted_buffer.row,
                notification_desc.u.dram_corrupted_buffer.col,
                notification_desc.u.dram_corrupted_buffer.channel_base,
                notification_desc.u.dram_corrupted_buffer.bank_base,
                hex(notification_desc.u.dram_corrupted_buffer.bad_cells))
        else:
            return '{}: unexpected notification type={}'.format(notification_base_info, notification_desc.type)

    def bitvec_rev(self, bv, offset, len):
        """
        Reverse len bits starting at offset in bit_vector bv
        """
        rval = 0
        bv = bv >> offset
        while len > 0:
            rval = (rval << 1) | (bv & 1)
            bv = bv >> 1
            len -= 1
        return rval

    def print_pacific_manufacture_info(self):
        """
        Print Pacific manufacturing information recorded on the device.
        """

        efuse_reg = self.device.get_fuse_userbits()

        efuse = 0
        for idx, val in enumerate(efuse_reg):
            print('EFuse[{}:{}]: 0x{:08X}'.format((idx + 1) * 32 - 1, idx * 32, val))
            efuse |= val << (idx * 32)

        if efuse == 0:
            return
        data = self.get_pacific_manufacture_info(efuse)
        print('Wafer number {}{}{}-{}'.format(data['fab'], data['lot_designation'], data['lot_number'], data['wafer_num']))
        print('     Fab:             {}'.format(data['fab']))
        print('     Lot designation: {}'.format(data['lot_designation']))
        print('     Lot number:      {}'.format(data['lot_number']))
        print('     Wafer:           {}'.format(data['wafer_num']))
        print('     Die X location:  {}{}'.format(data['x_sign_ch'], data['x_coord']))
        print('     Die Y location:  {}{}'.format(data['y_sign_ch'], data['y_coord']))
        print('     REFCLK burned:   {}'.format(data['refclk_is_valid']))
        if data['refclk_is_valid'] == 'Y':
            print('     REFCLK settings: {:04b}'.format(data['refclk_settings']))

    def get_pacific_manufacture_info(self, efuse):
        data = dict()
        fab = chr(self.bitvec_rev(efuse, 0, 7))
        data['fab'] = fab
        lot_designation = chr(self.bitvec_rev(efuse, 7, 7))
        data['lot_designation'] = lot_designation
        lot_number = ''
        for i in range(4):
            lot_number = lot_number + chr(self.bitvec_rev(efuse, 14 + i * 7, 7))
        data['lot_number'] = lot_number
        wafer_num = self.bitvec_rev(efuse, 42, 5)
        data['wafer_num'] = wafer_num
        x_sign = (efuse >> 47) & 1
        x_sign_ch = '+' if x_sign else '-'
        data['x_sign_ch'] = x_sign_ch
        y_sign = (efuse >> 55) & 1
        y_sign_ch = '+' if y_sign else '-'
        data['y_sign_ch'] = y_sign_ch
        x_coord = self.bitvec_rev(efuse, 48, 7)
        data['x_coord'] = x_coord
        y_coord = self.bitvec_rev(efuse, 56, 7)
        data['y_coord'] = y_coord
        refclk_is_valid = self.bitvec_rev(efuse, 111, 1)
        data['refclk_is_valid'] = 'Y' if refclk_is_valid == 1 else 'N'
        refclk_settings = self.bitvec_rev(efuse, 107, 4)
        data['refclk_settings'] = refclk_settings
        return data

    def print_gibraltar_manufacture_info(self):
        """
        Print Gibraltar manufacturing information recorded on the device.
        """

        efuse_reg = self.device.get_fuse_userbits()

        efuse = 0
        for idx, val in enumerate(efuse_reg):
            print('EFuse[{}:{}]: 0x{:08X}'.format((idx + 1) * 32 - 1, idx * 32, val))
            efuse |= val << (idx * 32)

        efuse = self.bitvec_rev(efuse, 0, 6 * 32)

        if efuse == 0:
            return

        lot_id = ''
        for i in range(6):
            msb = (17 + (i + 1) * 6) - 1
            lsb = 17 + (i * 6)
            lot_id = chr(get_bits(efuse, msb, lsb)) + lot_id

        efuse_info_type = get_bits(efuse, 61, 61)
        main_ver = get_bits(efuse, 60, 57)
        sub_ver = get_bits(efuse, 56, 54)
        dev_type = get_bits(efuse, 53, 53)
        wafer_num = get_bits(efuse, 16, 12)
        die_row = get_bits(efuse, 11, 6)
        die_col = get_bits(efuse, 5, 0)

        if (efuse_info_type):
            str = '2DBarcode'
        else:
            str = 'SerNum'
        if (dev_type):
            dev_type_str = '2p5D'
        else:
            dev_type_str = 'mono'

        print('EFUSE Info Type: {} - {}'.format(efuse_info_type, str))
        print('Wafer number {}.{} {}-{}'.format(main_ver, sub_ver, lot_id, wafer_num))
        print('     Main Version:    {}'.format(main_ver))
        print('     Sub Version:     {}'.format(sub_ver))
        print('     Lot ID:          {}'.format(lot_id))
        print('     Device Type:     {} - {}'.format(dev_type, dev_type_str))
        print('     Wafer:           {}'.format(wafer_num))
        print('     Die X location:  {}'.format(die_col))
        print('     Die Y location:  {}'.format(die_row))

    def print_manufacture_info(self):
        """
        Print Pacific/Gibraltar manufacturing information recorded on the device.
        """

        if self.ll_device.is_pacific():
            self.print_pacific_manufacture_info()
        else:
            self.print_gibraltar_manufacture_info()

    def oq_debug(self):
        """
        Check TM related status/debug registers. Print hazards and other useful information for analysis of packet drop.
        """

        PDIF_NR = 40

        for slice_id in range(self.NUM_SLICES):
            # PDIF TO TX-SCHEDULER PER INTERFACE FLOW CONTROL ###########
            pdif_fc = self.read_register(self.device_tree.slice[slice_id].pdoq.fdoq.pdif_fc_debug)
            if pdif_fc.pdif_fc_sch != 0:
                print("Slice %d, PDIF to TX-Scheduler Flow control per interface:" % (slice_id))
                for index in range(PDIF_NR):
                    if (pdif_fc.pdif_fc_sch & (1 << index)) != 0:
                        print("   Slice %d, PDIF to TX-Scheduler flow control interface number is %d" % (slice_id, index))

            # PDIF TO TX-SCHEDULER PER INTERFACE FLOW CONTROL ###########
            total_counter = self.read_register(self.device_tree.slice[slice_id].pdoq.fdoq.total_counter_debug)
            if (total_counter.total_counter_fc & (1 << 38)) != 0:
                print("Slice %d, Flow control from PDIF to TX-Scheduler for IFG0" % (slice_id))
            if (total_counter.total_counter_fc & (1 << 39)) != 0:
                print("Slice %d, Flow control from PDIF to TX-Scheduler for IFG1" % (slice_id))

            # IFG to PDIF (no credits) FLOW CONTROL ###########
            if (pdif_fc.pdif_fc_sch != 0) or (total_counter.total_counter_fc != 0):
                ifg_credit = self.read_register(self.device_tree.slice[slice_id].pdoq.fdoq.ifg_credit_debug)
                for index in range(PDIF_NR):
                    if (ifg_credit.ifg_credit_flow_control & (1 << index)) != 0:
                        print("Slice %d, Flow control from IFG to PDIF (no credits), interface number is %d" % (slice_id, index))

            #######TXPP 2 PDIF flow control ##################
            txpp_flow_control = self.read_register(self.device_tree.slice[slice_id].pdoq.fdoq.txpp_flow_control_debug)
            for index in range(PDIF_NR):
                if (txpp_flow_control.txpp_flow_control & (1 << index)) != 0:
                    print("Slice %d, Flow control from TXPP to PDIF, interface number is %d" % (slice_id, index))

            # Scheduler FLOW CONTROL ###########
            flow_control = self.read_register(self.device_tree.slice[slice_id].tx.cgm.flow_control_debug)
            ifg0_flow_control_set = (flow_control.ifg_flow_control_set & 0x1) != 0
            ifg1_flow_control_set = (flow_control.ifg_flow_control_set & 0x2) != 0
            oq_flow_control_set = flow_control.oq_flow_control_set != 0
            oq_set_value = flow_control.oq_set_value
            oqg_flow_control_set = flow_control.oqg_flow_control_set != 0
            oqg_set_value = flow_control.oqg_set_value

            if ((ifg0_flow_control_set or ifg1_flow_control_set or oq_flow_control_set or oqg_flow_control_set) == 0):
                print("Slice %d, NO flow control from PDOQ to Scheduler" % (slice_id))

            if (ifg0_flow_control_set):
                print("Slice %d, Flow control from PDOQ to Scheduler for IFG0!!!!" % (slice_id))

            if (ifg1_flow_control_set):
                print("Slice %d, Flow control from PDOQ to Scheduler for IFG1!!!!" % (slice_id))

            if (oq_flow_control_set):
                print("Slice %d, Flow control from PDOQ to Scheduler per OQ, captured OQ number is %d!!!!" % (slice_id, oq_set_value))

            if (oqg_flow_control_set):
                print(
                    "Slice %d, Flow control from PDOQ to Scheduler per OQG, captured OQ-Group number is %d!!!!" %
                    (slice_id, oqg_set_value))

            #MAX OQ SIZE ###########
            max_queue_size_status = self.read_register(self.device_tree.slice[slice_id].pdoq.top.max_queue_size_status)
            max_queue_size = max_queue_size_status.max_queue_size
            max_queue_number = max_queue_size_status.max_queue_number
            print("Slice %d, PDOQ biggest Queue is %d queue size is %d BYTES" % (slice_id, max_queue_number, max_queue_size))

            #MAX DELETE OQ SIZE ###########
            max_delete_queue_size_status = self.read_register(
                self.device_tree.slice[slice_id].pdoq.top.max_delete_queue_size_status)
            print("Slice %d, PDOQ Delete fifo watermark is %d in BYTES" %
                  (slice_id, max_delete_queue_size_status.max_delete_queue_size))

            ###### TXCGM DROP DEBUG ########
            cgm_reject_bitmap = self.read_register(self.device_tree.slice[slice_id].tx.cgm.cgm_reject_bitmap)

            if (cgm_reject_bitmap.oq_uc_reject != 0):
                print("TXCGM Reject as a result of UC OQ test. slice=%d" % slice_id)

            if (cgm_reject_bitmap.oq_mc_pd_green_reject != 0):
                print("TXCGM Reject as a result of Green MC OQ PDs test. slice=%d" % slice_id)

            if (cgm_reject_bitmap.oq_mc_pd_yellow_reject != 0):
                print("TXCGM Reject as a result of Yellow MC OQ PDs test. slice=%d" % slice_id)

            if (cgm_reject_bitmap.oq_mc_byte_green_reject != 0):
                print("TXCGM Reject as a result of Green MC OQ Bytes test . slice=%d" % slice_id)

            if (cgm_reject_bitmap.oq_mc_byte_yellow_reject != 0):
                print("TXCGM Reject as a result of Yellow MC OQ Bytes test . slice=%d" % slice_id)

            if (cgm_reject_bitmap.oqg_uc_reject != 0):
                print("TXCGM Reject as a result of UC OQG test. slice=%d" % slice_id)

            if (cgm_reject_bitmap.color_uc_reject != 0):
                print("TXCGM Reject as a result of UC OutColor test. slice=%d" % slice_id)

            if (cgm_reject_bitmap.color_mc_reject != 0):
                print("TXCGM Reject as a result of MC OutColor test. slice=%d" % slice_id)

            if (cgm_reject_bitmap.oq_static_reject != 0):
                print("TXCGM Reject as a result of OQ static test (set by OqDropBitmap). slice=%d" % slice_id)

            if (cgm_reject_bitmap.global_total_reject != 0):
                print("TXCGM Reject as a result of global total PDs test. slice=%d" % slice_id)

            if self.ll_device.is_asic4():
                if (cgm_reject_bitmap.global_uc_buffers_reject != 0):
                    print("TXCGM Reject as a result of global UC Buffers test. slice=%d" % slice_id)
                if (cgm_reject_bitmap.global_uc_pds_reject != 0):
                    print("TXCGM Reject as a result of global UC PDs test. slice=%d" % slice_id)
            else:
                if (cgm_reject_bitmap.global_uc_reject != 0):
                    print("TXCGM Reject as a result of global UC PDs and Buffers test. slice=%d" % slice_id)

            if (cgm_reject_bitmap.global_mc_reject != 0):
                print("TXCGM Reject as a result of global MC PDs test. slice=%d" % slice_id)

        ##### TX-CGM UNICAST VALUE BUFFERS #############
        total_sch_uc_buffers = self.read_register(self.device_tree.tx_cgm_top.total_sch_uc_buffers_debug)
        total_sch_uc_buffers_max_value = total_sch_uc_buffers.total_sch_uc_buffers_max_value
        total_sch_uc_local_buffers_max_value = total_sch_uc_buffers.total_sch_uc_local_buffers_max_value
        total_sch_uc_remote_buffers_max_value = total_sch_uc_buffers.total_sch_uc_remote_buffers_max_value

        print("TXCGM Watermark Total UNICAST BUFFERS (C+D) %d, Loacl(C) %d Remote(D) %d" %
              (total_sch_uc_buffers_max_value, total_sch_uc_local_buffers_max_value, total_sch_uc_remote_buffers_max_value))

        ##### TX-CGM UNICAST VALUE PDs #############
        total_pd = self.read_register(self.device_tree.tx_cgm_top.total_pd_debug)
        total_pd_max_value = total_pd.total_pd_max_value
        delete_pd_max_value = total_pd.delete_pd_max_value

        total_sch_uc_pd_cnt = self.read_register(self.device_tree.tx_cgm_top.total_sch_uc_pd_cnt_debug)
        total_sch_uc_pd_max_value = total_sch_uc_pd_cnt.total_sch_uc_pd_max_value

        total_mc_cnt = self.read_register(self.device_tree.tx_cgm_top.total_mc_cnt_debug)
        total_mc_pd_max_value = total_mc_cnt.total_mc_pd_max_value

        total_fab_cnt = self.read_register(self.device_tree.tx_cgm_top.total_fab_cnt_debug)
        total_fab_pd_max_value = total_fab_cnt.total_fab_pd_max_value

        total_ms_cnt = self.read_register(self.device_tree.tx_cgm_top.total_ms_cnt_debug)
        total_ms_voq_pd_max_value = total_ms_cnt.total_ms_voq_pd_max_value
        total_ms_oq_pd_max_value = total_ms_cnt.total_ms_oq_pd_max_value

        print("TXCGM Watermark Total PDs %d, Total delete PDs %d Total Unicast PDs %d, Total Multicast PDs %d" %
              (total_pd_max_value, delete_pd_max_value, total_sch_uc_pd_max_value, total_mc_pd_max_value))
        print("TXCGM Watermark Total Fabric PDs %d, Total MS-VOQs PDs %d Total MS-OQs PDs %d" %
              (total_fab_pd_max_value, total_ms_voq_pd_max_value, total_ms_oq_pd_max_value))

        ##### TX-CGM DROP and FC events #############
        global_cgm_indication = self.read_register(self.device_tree.tx_cgm_top.global_cgm_indication_debug)
        global_drop_total_pds = global_cgm_indication.global_drop_total_pds
        global_drop_sch_uc_pds = global_cgm_indication.global_drop_sch_uc_pds
        global_block_sch_uc_pds = global_cgm_indication.global_block_sch_uc_pds
        global_drop_mc_pds = global_cgm_indication.global_drop_mc_pds
        global_fc_fab_pds = global_cgm_indication.global_fc_fab_pds
        global_block_fab_pds = global_cgm_indication.global_block_fab_pds
        global_device_fc = global_cgm_indication.global_device_fc

        if (global_drop_total_pds != 0):
            print("TXCGM Dropped packet due to: Total number of PDs is above threshold")

        if (global_drop_sch_uc_pds != 0):
            print("TXCGM Dropped Unicast packet due to: Total number of Unicast PDs is above threshold (Z)  ")

        if (global_block_sch_uc_pds != 0):
            print("TXCGM Blocked the XBAR due to: Total number of Unicast PDs is above threshold (Z) ")

        if (global_drop_mc_pds != 0):
            print("TXCGM dropped Multicast packet due to: Total number of Multicast PDs is above threshold (W) ")

        if (global_fc_fab_pds != 0):
            print("TXCGM raised flow control to ICS due to: Total number of PDs in Fabric links OQ is above threshold (V)  ")

        if (global_block_fab_pds != 0):
            print("TXCGM Blockes the XBAR due to: Total number of PDs in Fabric links OQ is above threshold (V)  ")

        if (global_device_fc != 0):
            print("TXCGM raised device flow control")

        ##### Fabric Flow control #############
        fabric_flow_control = self.read_register(self.device_tree.tx_cgm_top.fabric_flow_control_debug)
        fabric_flow_control_uch = (fabric_flow_control.fabric_ics_flow_control & 0x1) != 0
        fabric_flow_control_ucl = (fabric_flow_control.fabric_ics_flow_control & 0x2) != 0
        fabric_flow_control_mc = (fabric_flow_control.fabric_ics_flow_control & 0x4) != 0
        fabric_flow_control_sch = fabric_flow_control.fabric_sch_flow_control != 0

        if fabric_flow_control_uch:
            print("TXCGM raised flow control from fabric links to Network-ICS for Unicast-HP context")

        if fabric_flow_control_ucl:
            print("TXCGM raised flow control from fabric links to Network-ICS for Unicast-LP context")

        if fabric_flow_control_mc:
            print("TXCGM raised flow control from fabric links to Network-ICS for Multicast context")

        if fabric_flow_control_sch:
            print("TXCGM raised flow control from fabric links to Multicast-Local-Scheduler")

        ##### SMS registers ###############

        ### SMS, min total free buffers###
        sms_min_total_free_buff_sum_reg = self.read_register(self.device_tree.sms_main.sms_min_total_free_buff_sum_reg)
        print("SMS, Minimum total number of free SMS Buffers is %d out of 97920" %
              (sms_min_total_free_buff_sum_reg.sms_min_total_free_buff_sum))

        ### SMS, per BANK min total free buffers###
        total_min_buff = 100000
        bank_index = 100

        for bank in range(36):
            curr_bank_min = self.read_register(self.device_tree.sms_main.sms_total_free_buff_minreg[bank])
            if curr_bank_min.sms_total_free_buff_min < total_min_buff:
                total_min_buff = curr_bank_min.sms_total_free_buff_min
                bank_index = bank

        print("SMS, Minimum free SMS buffers are %d in BANK# %d out of 2720" % (total_min_buff, bank_index))

        ### SMS, per interface maximum FDOQ2SMS###
        curr_max_fdoq = 0
        total_max_fdoq = 0
        interface_num = 0

        for interface in range(14):
            curr_max_fdoq = self.read_register(self.device_tree.sms_main.sms_fdoq_fifo_max_reg[interface])
            if (curr_max_fdoq.sms_fdoq_fifo_max > total_max_fdoq):
                total_max_fdoq = curr_max_fdoq.sms_fdoq_fifo_max
                interface_num = interface

        print("SMS, Maximum FDOQ2SMS FIFO size is %d in Interface# %d" % (total_max_fdoq, interface_num))

    ### DVOQ Queue Size Memory ###
    def read_dvoq_qsm(self):
        num_active = 0
        num_qsm_entries = 4096
        if self.ll_device.is_gibraltar():
            max_oq = 208
            entries_to_map_vsc = 4096
        else:
            max_oq = 160
            entries_to_map_vsc = 2560

        for idx in range(num_qsm_entries):
            queue_size = self.read_memory(self.device_tree.dvoq.qsm, idx)
            queue_size_in_buffer = queue_size.dcm
            if(queue_size_in_buffer > 0):
                num_active += 1
                dramcontext2smscontext = self.read_memory(self.device_tree.dics.dramcontext2smscontext, idx)
                slice_id = dramcontext2smscontext.slicenum
                context = dramcontext2smscontext.smscontext

                if (slice_id > self.NUM_SLICES):
                    continue

                voq = self.read_memory(self.device_tree.slice[slice_id].ics.context2voq, context)
                voq_num = voq.voqnum

                voq_mapping_data = self.read_memory(self.device_tree.slice[slice_id].filb.voq_mapping, voq_num)
                dest_oq = voq_mapping_data.dest_oq

                (dest_ifg, oq) = divmod(dest_oq, max_oq)
                dest_port = oq / 8

                if (slice_id < 4):
                    voq_idx = int(voq_num / 16) + entries_to_map_vsc
                    data = self.read_memory(self.device_tree.csms.voq_vsc_dst_map_mem[slice_id], voq_idx)
                    vsc = get_bits(data.dst_slice_voq_or_ifg_vsc, 10, 0) * 16 + voq_num % 16
                else:
                    voq_idx = int(voq_num / 16)
                    data = self.read_memory(self.device_tree.csms.voq_dst_map_mem[slice_id - 4], voq_idx)
                    vsc = get_bits(data.dst_ifg_vsc, 10, 0) * 16 + voq_num % 16

                print("Queue index = #%0d, Queue size in buffers = %0d, Queue size in bytes = %0d, SMS VOQ context = %0d, slice = %0d, VOQ = #%0d, Dest device = %0d, Dest slice = %0d, Dest IFG = %0d, Dest port = %0d, VSC = #%0d" % (
                    idx, queue_size_in_buffer, queue_size.qsize_bytes, context, slice_id, voq_num, voq_mapping_data.dest_dev, voq_mapping_data.dest_slice, dest_ifg, dest_port, vsc))
        print("Number of non-empty Queues = %0d" % (num_active))


#################################### TOPOLOGY REPORT GENERATOR #######################

    class la_object_properties:

        node_properties = {'style': 'filled, rounded', 'shape': 'rectangle', 'width': '1.2'}
        edge_properties = {'arrowtail': 'vee', 'arrowhead': 'vee', 'dir': 'both', 'color': 'grey30'}

        def get_label(self, obj):
            return 'oid = %d' % obj.oid()

        def get_edges(self, obj):
            other_node = self._get_other_node_of_edge(obj)
            if other_node is None:
                return []
            return [(str(obj.oid()), str(other_node.oid()), self._get_edges_properties())]

        def _get_other_node_of_edge(self, obj):
            return None

        def _get_edges_properties(self):
            return self.edge_properties

    class pci_port_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'forestgreen'

        def get_label(self, pci_port):
            labels = []
            labels.append('oid = %d' % pci_port.oid())
            labels.append('slice = %d' % pci_port.get_slice())
            labels.append('ifg = %d' % pci_port.get_ifg())
            return os.linesep.join(labels)

    class rcy_port_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'limegreen'

        def get_label(self, rcy_port):
            labels = []
            labels.append('oid = %d' % rcy_port.oid())
            labels.append('slice = %d' % rcy_port.get_slice())
            labels.append('ifg = %d' % rcy_port.get_ifg())
            return os.linesep.join(labels)

    class mac_port_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'palegreen'

        def get_label(self, mac_port):
            labels = []
            labels.append('oid = %d' % mac_port.oid())
            labels.append('slice = %d' % mac_port.get_slice())
            labels.append('ifg = %d' % mac_port.get_ifg())
            labels.append('pif = %d' % mac_port.get_num_of_serdes())
            labels.append('speed = %s' % enum_value_to_field_name(mac_port, 'port_speed_e_E_', mac_port.get_speed()))
            return os.linesep.join(labels)

    class system_port_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'gold'

        def get_label(self, sys_port):
            labels = []
            labels.append('oid = %d' % sys_port.oid())
            labels.append('gid = %d' % sys_port.get_gid())
            return os.linesep.join(labels)

        def _get_other_node_of_edge(self, sys_port):
            underlying_ports = [sdk.la_object.object_type_e_MAC_PORT,
                                sdk.la_object.object_type_e_PCI_PORT,
                                sdk.la_object.object_type_e_RECYCLE_PORT,
                                sdk.la_object.object_type_e_NPU_HOST_PORT]
            other_port = sys_port.get_underlying_port()
            if other_port is not None and other_port.type() in underlying_ports:
                return other_port
            return None

    class ethernet_port_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'orchid'

        def _get_other_node_of_edge(self, eth_port):
            return eth_port.get_system_port()

    class l3_ac_port_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'cyan'

        def get_label(self, l3_ac_ports):
            labels = []
            vid1, vid2 = l3_ac_ports.get_service_mapping_vids()
            labels.append('oid = %d' % l3_ac_ports.oid())
            labels.append('vid1 = %d' % vid1)
            labels.append('vid2 = %d' % vid2)
            return os.linesep.join(labels)

        def get_edges(self, ac_port):
            result = []
            if ac_port.get_ethernet_port() is not None:
                ac_ethernet_edge = (str(ac_port.oid()), str(ac_port.get_ethernet_port().oid()), self._get_edges_properties())
                result.append(ac_ethernet_edge)
            if ac_port.get_vrf() is not None:
                legal_vids = [str(v) for v in ac_port.get_service_mapping_vids() if v != 0]
                ac_vrf_edge = (str(ac_port.get_vrf().oid()), str(ac_port.oid()), self._get_edges_properties())
                result.append(ac_vrf_edge)
            return result

    class l2_ac_port_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'deepskyblue'
            self.edge_p2p = {'dir': 'forward', 'constraint': 'false', 'arrowhead': 'vee'}
            self.edge_ac_switch = {'dir': 'back', 'arrowtail': 'vee'}

        def get_label(self, l2_ac_ports):
            labels = []
            vid1, vid2 = l2_ac_ports.get_service_mapping_vids()
            labels.append('oid = %d' % l2_ac_ports.oid())
            labels.append('vid1 = %d' % vid1)
            labels.append('vid2 = %d' % vid2)
            return os.linesep.join(labels)

        def get_edges(self, ac_port):
            result = []
            if ac_port.get_ethernet_port() is not None:
                ac_ethernet_edge = (str(ac_port.oid()), str(ac_port.get_ethernet_port().oid()), self._get_edges_properties())
                result.append(ac_ethernet_edge)
            if ac_port.get_attached_switch() is not None:
                ac_switch_edge = (str(ac_port.get_attached_switch().oid()), str(ac_port.oid()), self.edge_ac_switch)
                result.append(ac_switch_edge)
            if ac_port.get_destination() is not None:
                if ac_port.get_destination().type() == sdk.la_object.object_type_e_L2_SERVICE_PORT:
                    p2p_edge = (str(ac_port.get_destination().oid()), str(ac_port.oid()), self.edge_p2p)
                result.append(p2p_edge)
            return result

    class switch_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'crimson'

    class punt_inject_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'darkorchid'

        def _get_other_node_of_edge(self, punt_inject_port):
            return punt_inject_port.get_system_port()

    class vrf_port_properties(la_object_properties):

        def __init__(self):
            self.node_properties['fillcolor'] = 'coral'

    def _add_subgraph(self, graph, sub_name, nodes, object_properties):
        with graph.subgraph(name=sub_name) as subgraph:
            subgraph.attr(color='white', rank='max', label='')
            for node in nodes:
                subgraph.node(str(node.oid()), label=object_properties.get_label(node), **object_properties.node_properties)
                for v1, v2, props in object_properties.get_edges(node):
                    graph.edge(v1, v2, **props)

    def _add_legend(self, graph):
        with graph.subgraph(name='cluster_legend') as legend:
            legend.attr(label='legend')
            legend.node('sys_legend', label='System port', **self.system_port_properties().node_properties)
            legend.node('l2_ac_legend', label='L2 AC port', **self.l2_ac_port_properties().node_properties)
            legend.node('eth_legend', label='Ethernet port', **self.ethernet_port_properties().node_properties)
            legend.node('l3_ac_legend', label='L3 AC port', **self.l3_ac_port_properties().node_properties)
            legend.node('mac_legend', label='MAC port', **self.mac_port_properties().node_properties)
            legend.node('vrf_legend', label='VRF', **self.vrf_port_properties().node_properties)
            legend.node('pci_legend', label='PCI port', **self.pci_port_properties().node_properties)
            legend.node('rcy_legend', label='RCY port', **self.rcy_port_properties().node_properties)
            legend.node('punt_legend', label='Punt inject port', **self.punt_inject_properties().node_properties)
            legend.node('switch_legend', label='Switch', **self.switch_properties().node_properties)
            legend.edge('vrf_legend', 'l3_ac_legend', style='invis')
            legend.edge('l3_ac_legend', 'eth_legend', style='invis')
            legend.edge('eth_legend', 'mac_legend', style='invis')
            legend.edge('switch_legend', 'l2_ac_legend', style='invis')
            legend.edge('l2_ac_legend', 'punt_legend', style='invis')
            legend.edge('punt_legend', 'sys_legend', style='invis')
            legend.edge('sys_legend', 'pci_legend', style='invis')
            legend.edge('mac_legend', 'rcy_legend', style='invis')

    def generate_topology(self, out_file='topology_report', out_format='png'):
        """Generates a graph that represents the configuration topology.

        This function uses ``graphviz`` package, if not installed, an error message will be printed and nothing will happen.

        :param out_file: The name of the output file. Default name is 'topology_report'.

        :param out_format: The format of the output, it can be any format supported by ``graphviz``. Default format is ``png``.

        :return: The generated graph object, of type ``graphviz.Graph``.
        """
        if not _ensure_graphviz():
            return None

        pci_ports = self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT)
        recycle_ports = self.device.get_objects(sdk.la_object.object_type_e_RECYCLE_PORT)
        mac_ports = self.device.get_objects(sdk.la_object.object_type_e_MAC_PORT)
        system_ports = self.device.get_objects(sdk.la_object.object_type_e_SYSTEM_PORT)
        ethernet_ports = self.device.get_objects(sdk.la_object.object_type_e_ETHERNET_PORT)
        l3_ac_ports = self.device.get_objects(sdk.la_object.object_type_e_L3_AC_PORT)
        l2_ac_ports = self.device.get_objects(sdk.la_object.object_type_e_L2_SERVICE_PORT)
        switch_ports = self.device.get_objects(sdk.la_object.object_type_e_SWITCH)
        punt_inject_ports = self.device.get_objects(sdk.la_object.object_type_e_PUNT_INJECT_PORT)
        vrf_ports = self.device.get_objects(sdk.la_object.object_type_e_VRF)

        topology_graph = Graph('topology_report', format=out_format)
        topology_graph.attr(label='Topology report', splines='line')

        self._add_legend(topology_graph)

        self._add_subgraph(topology_graph, 'cluster_pci', pci_ports, self.pci_port_properties())
        self._add_subgraph(topology_graph, 'cluster_rcy', recycle_ports, self.rcy_port_properties())
        self._add_subgraph(topology_graph, 'cluster_mac', mac_ports, self.mac_port_properties())
        self._add_subgraph(topology_graph, 'cluster_sys', system_ports, self.system_port_properties())
        self._add_subgraph(topology_graph, 'cluster_eth', ethernet_ports, self.ethernet_port_properties())
        self._add_subgraph(topology_graph, 'cluster_l3_ac', l3_ac_ports, self.l3_ac_port_properties())
        self._add_subgraph(topology_graph, 'cluster_l2_ac', l2_ac_ports, self.l2_ac_port_properties())
        self._add_subgraph(topology_graph, 'cluster_switch', switch_ports, self.switch_properties())
        self._add_subgraph(topology_graph, 'cluster_punt_inject', punt_inject_ports, self.punt_inject_properties())
        self._add_subgraph(topology_graph, 'cluster_vrf', vrf_ports, self.vrf_port_properties())

        topology_graph.render(out_file)
        return topology_graph

#################################### GET NPE NPPD #######################

    def _get_npdd_stage_data(self, stage, slice, npe_instance):
        # Check if stage exists
        assert (stage in self.stage_paths_indices), 'Stage {} not recognized. Supported stages are '.format(
            stage) + ','.join([k for k in self.stage_paths_indices.keys()])
        reg = self._get_stage_regs(stage, slice, [npe_instance])[0]
        return self._get_npe_nppd_register(reg)

    def _get_npe_nppd_register(self, block):
        incoming_or_loopback = self.get_debug_bus(block.debug_data_select_register, block.debug_data_bus_register, 1, 58)
        outgoing = self.get_debug_bus(block.debug_data_select_register, block.debug_data_bus_register, 262, 58)
        return ({'incoming_or_loopback': incoming_or_loopback, 'outgoing': outgoing})

    def get_debug_bus(self, select_reg, bus_reg, start_offset, word_amount, word_width=32) -> int:
        """
        Get data from a debug bus.
        We write the offset on the bus we want to read in select_reg and then read the data from the bus_reg.

        :param lld_register select_reg: Select register to configure word offset to read from.
        :param lld_register bus_reg: Data register to retrieve the data.
        :param int start_offset: Word offset on the bus.
        :param int word_amount: Amount of words to read.
        :param int word_width: Num of bits in word. Default=32.

        :return: Data in field of a debug bus.
        """
        out_data = 0

        for offset in range(start_offset, start_offset + word_amount):
            current_word_num = offset - start_offset
            curr_msb = (current_word_num + 1) * word_width
            curr_lsb = current_word_num * word_width

            # Write to selector
            self.write_register(select_reg, offset)

            # Read data
            curr_selected_data = self.read_register(bus_reg)

            out_data = set_bits(out_data, curr_msb, curr_lsb, curr_selected_data.flat)

        return out_data

    def get_npe_nppd(self, stage, npe_instance, slce) -> list:
        """
        Get last NPE NPPD for incoming/outgoing/loopback packets going through each NP engine, per slice.

        :param str stage: Stage to get data from.
        :param npe_instance: The npe instance to get the data from.
        :param int slce: Slice to get data from.

        :return: A dictionary that maps ``incoming_or_loopback`` and outgoing_nppd`` keys to their nppds.
        """
        data = self._get_npdd_stage_data(stage, slce, npe_instance)
        incoming_nppd = npl_instance_clone_with_value(self._nppd_fields, data.get('incoming_or_loopback', None))
        outgoing_nppd = npl_instance_clone_with_value(self._nppd_fields, data.get('outgoing', None))
        return {'incoming_or_loopback': incoming_nppd, 'outgoing': outgoing_nppd}

    def set_slice_pair_idb_debug_capture(self, slice_pair, block, capture_mode=0, capture_select=0):
        supported_blocks = ['res_fb', 'res', 'macdb', 'macdb_fb', 'encdb_fb', 'encdb']
        if block in supported_blocks:
            int_path = eval('self.device_tree.slice_pair[slice_pair].idb' + '.' + block)
            self.ll_device.write_register(int_path.debug_req_rsp_capture_cfg_register, capture_mode)
            self.ll_device.write_register(int_path.debug_req_rsp_select_register, capture_select)

    def get_slice_pair_idb_debug_capture_status(self, slice_pair, block):
        supported_blocks = ['res_fb', 'res', 'macdb', 'macdb_fb', 'encdb_fb', 'encdb']
        if block in supported_blocks:
            int_path = eval('self.device_tree.slice_pair[slice_pair].idb' + '.' + block)
            reg = self.read_register(int_path.debug_req_rsp_capture_status)
            return ({'debug_capture_valid': reg.debug_capture_valid, 'debug_captured_value': reg.debug_captured_value})

    def get_slice_pair_idb_debug_capture_cnt(self, slice_pair, block):
        supported_blocks = ['res_fb', 'res', 'macdb', 'macdb_fb', 'encdb_fb', 'encdb']
        if block in supported_blocks:
            int_path = eval('self.device_tree.slice_pair[slice_pair].idb' + '.' + block)
            return self.read_register(int_path.debug_req_rsp_capture_cnt).debug_capture_cnt

    def dump_idb_mem(self, slice_pair, block, in_mem='', start=-1, end=-1):
        supported_blocks = ['res_fb', 'res', 'macdb', 'macdb_fb', 'encdb_fb', 'encdb']
        if block in supported_blocks:
            int_path = eval('self.device_tree.slice_pair[slice_pair].idb' + '.' + block)
            for mem in int_path.get_memories():
                entries = mem.get_desc().entries
                start_index = 0
                mem_name = mem.get_name()

                if in_mem != '' and mem_name.find(in_mem) == -1:
                    continue

                if start >= 0 and end >= 0 and start <= end:
                    start_index = start
                    if end < entries:
                        entries = end + 1

                for entry_num in range(start_index, entries):
                    value = self.read_memory(mem, entry_num)
                    print("{0}: index {1}: ".format(mem_name, entry_num))
                    print(value)

    def _dump_block_interrupts(self, block_path):
        for reg in block_path.get_registers():
            list = reg.get_name().split(".")
            if (list[-1] == "soft_reset_configuration"):
                soft_reset = self.ll_device.read_register(reg)
                if soft_reset == 0:
                    print("Block {0} in soft reset mode".format(list[-2]))
                    break
            if (list[-1] == "interrupt_register"):
                continue
            desc = reg.get_desc()
            if (desc.type == 3 or "mem_protect_err_status" in reg.get_name()):  # 3 = interrupt
                fields = self.ll_device.read_register(reg)
                print("{0}:  {1}:  0x{2:X}".format(block_path.get_name(), list[-1], fields))

    def dump_idb_interrupts(self, slice_pair):
        supported_blocks = ['res_fb', 'res', 'macdb', 'macdb_fb', 'encdb_fb', 'encdb']
        for block in supported_blocks:
            int_path = eval('self.device_tree.slice_pair[slice_pair].idb' + '.' + block)
            print('slice pair {0}, block name {1}.'.format(slice_pair, int_path.get_name()))
            self._dump_block_interrupts(int_path)

    def dump_slice_pair_interrupts(self, slice_pair, leaf_block):
        block_list = self.device_tree.get_leaf_blocks()
        for block in block_list[:]:
            name = block.get_name().split(".")
            if leaf_block == name[-1] and name[0] == 'slice_pair[{}]'.format(slice_pair):
                self._dump_block_interrupts(block)

    def dump_rxpdr_debug(self, slice_pair):
        self.dump_slice_pair_interrupts(slice_pair, 'rx_pdr')
        int_path = eval('self.device_tree.rx_pdr' + '.' + 'cgm_counters_status')
        print("{0}: ".format(int_path.get_name()))
        print(self.read_register(int_path))
        for i in range(8):
            int_path = eval('self.device_tree.slice_pair[slice_pair].rx_pdr.' + 'rx_pdr_debug_conf')
            self.write_register(int_path, i)
            int_path = eval('self.device_tree.slice_pair[slice_pair].rx_pdr.' + 'rx_pdr_last_in_pd')
            print("iteration {0}: {1}".format(i, int_path.get_name()))
            print(self.read_register(int_path))

    def dump_pdvoq_drop_counters(self, slice, clear=True):
        debug_counter_reg = eval('self.device_tree.slice[slice].pdvoq.' + 'debug_counters')
        mma_voq_drop_counter_reg = eval('self.device_tree.pdvoq_shared_mma.' + 'voq_drop_counters')
        mma_voq_counter_range_reg = eval('self.device_tree.pdvoq_shared_mma.' + 'voq_counter_range[slice * 4]')

        if (clear):
            debug_counter = self.read_register(debug_counter_reg)
            mma_voq_drop_counter = self.read_register(mma_voq_drop_counter_reg)
            mma_voq_counter_range = self.read_register(mma_voq_counter_range_reg)
        else:
            debug_counter = self.peek_register(debug_counter_reg)
            mma_voq_drop_counter = self.peek_register(mma_voq_drop_counter_reg)
            mma_voq_counter_range = self.peek_register(mma_voq_counter_range_reg)

        print('slice {}: debug_counter:'.format(slice))
        print(debug_counter)
        print('voq drop counter:')
        print(mma_voq_drop_counter)
        print('voq_counter_range:')
        print(mma_voq_counter_range)
