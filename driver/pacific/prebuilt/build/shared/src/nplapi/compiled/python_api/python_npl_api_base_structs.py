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


class data_container:
    def __init__(self):
        self._data = 0

    def get_data(self, offset, width):
        mask = (1 << width) - 1
        return (self._data >> offset) & mask

    def modify_data(self, offset, width, val):
        mask = ((1 << width) - 1) << offset
        val_to_set = val << offset
        self._data = (self._data & ~mask) | (val_to_set & mask)


class basic_npl_struct:
    @property
    def width(self):
        """Get the struct's width"""
        return self._width

    def __init__(self, width):
        self._data = data_container()
        self._offset_in_data = 0
        self._width = width
        self._frozen = True

    def _set_data_pointer(self, data, offset_in_data):
        if data is not None:
            self._data = data
        self._offset_in_data = offset_in_data

    def __setattr__(self, name, value):
        if hasattr(self, '_frozen') and not hasattr(self, name):
            raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, name))
        object.__setattr__(self, name, value)

    def get_value(self):
        return self._get_field_value(0, self._width)

    def _get_field_value(self, offset, width):
        return self._data.get_data(self._offset_in_data + offset, width)

    def set_value(self, val):
        self._set_field_value(self.__class__.__name__, 0, self._width, self.__class__, val)

    def _set_field_value(self, field_name, offset, width, type, val):
        if isinstance(val, int):
            val_to_set = val
        elif isinstance(val, type):
            val_to_set = val.get_value()
        else:
            raise TypeError(
                "wrong type assignment for '%s', expected type - '%s', received type - '%s'" %
                (field_name, type.__name__, val.__class__.__name__))
        self._data.modify_data(self._offset_in_data + offset, width, val_to_set)


class basic_npl_array(basic_npl_struct):
    def __init__(self, total_width, num_of_elements, element_type, data=None, offset_in_data=0):
        self._num_of_elements = num_of_elements
        self._element_size = total_width // num_of_elements
        self._element_type = element_type
        super().__init__(total_width)
        self._set_data_pointer(data, offset_in_data)

    def _check_index(self, index):
        if not isinstance(index, int):
            raise TypeError("array indices must be integers, not %s" % index.__class__.__name__)
        if index < 0 or index >= len(self):
            raise IndexError("array index out of range")

    def _calc_element_offset_in_array(self, index):
        return index * self._element_size

    def __getitem__(self, index):
        self._check_index(index)
        if self.element_type == int:
            return self._get_field_value(self._calc_element_offset_in_array(index), self._element_size)
        return self._element_type._get_as_sub_field(self._data, self._offset_in_data + self._calc_element_offset_in_array(index))

    def __setitem__(self, index, value):
        self._check_index(index)
        super()._set_field_value("index " + str(index), self._calc_element_offset_in_array(index), self._element_size, self._element_type, value)

    def __len__(self):
        return self._num_of_elements

    def _set_field_value(self, field_name, offset, width, type, val):

        if val.__class__ == self.__class__:  # checking type only when assigning full array
            if len(val) != len(self) or val.element_type != self.element_type:
                raise TypeError(
                    "wrong type assignment for '%s', expected type - 'array(len=%d, type=%s)', received type - 'array(len=%d, type=%s)'" %
                    (field_name, len(self), self.element_type.__name__, len(val), val.element_type.__name__))

        if offset != 0 or width != self.width:
            raise ValueError("setting array can be done only to the whole array or to an element!")

        return super()._set_field_value(field_name, offset, width, type, val)

    @property
    def element_type(self):
        return self._element_type
