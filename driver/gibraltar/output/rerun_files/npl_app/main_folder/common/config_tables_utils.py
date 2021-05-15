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

# Static initialization for hardware tables defined in hardware.npl

# Since we manually indented tables in this file, we don't want pep8 to mess with spaces
# This directive is read by leaba_format.py script
# pep8_extra_args = "--ignore=E2"
import os
import sys
from tabulate import tabulate
from collections.abc import Iterable

ALL_1 = (1 << 128) - 1

# define a dummy config_tables func as a temporary workaround, since the compiler always asks for this function once the python file
# is included from the main.npl
# need to be removed once a "check if config_tables exists" in the npsuite is added


def config_tables():
    pass


class Key():
    def __init__(self, value, mask=ALL_1):
        self.key  = value
        self.mask = mask


class TableBaseCls():
    def __init__(self, table_name):
        self.table_name = table_name
        self.num_entries = {}
        self.table      = getattr(sys.modules[__name__], self.table_name)
        self.key_type   = getattr(sys.modules[__name__], self.table_name + "_key_t")
        self.value_type = getattr(sys.modules[__name__], self.table_name + "_value_t")
        self.table_width = self.key_type().width
        self.table_type = None
        self.payload_args_name = []
        self.keys_name = []
        # for printing table purpose
        self.tabulate_data = {}
        self.tabulate_hdrs = {}

    def create_table(self, table_data, context, key_func=None, value_func=None, init_table=False, args_map={}):
        '''
        configre the hw table according to given table_data
        table_data:
        context: NETWORK_CONTEXT, HOST_CONTEXT...
        key_func:
        value_func:
        init_table: init all table entries to zero value
        args_map:
        '''
        if isinstance(context, Iterable):
            context_list = context
        else:
            context_list = [context]

        for ctx in context_list:
            self.payload_args_name = []
            self.keys_name = []
            self.create_table_by_type(table_data, ctx, self.key_type, self.value_type, key_func, value_func, init_table, args_map)

    def create_table_by_type(
            self,
            table_data,
            context,
            key_type,
            value_type,
            key_func=None,
            value_func=None,
            init_table=False,
            args_map={}):
        pass

    def get_num_configured_entries(self, context):
        '''
        return the number of configured entries per context
        '''
        return self.num_entries[context]

    def get_table_size(self):
        pass

    def print_table(self, context):
        print("========= Dump {} table: {} ========== ".format(self.table_type, self.table_name))
        print(tabulate(self.tabulate_data[context] , headers=self.tabulate_hdrs[context] , tablefmt='psql'))


# TCAM Tables
class TcamTableConfig(TableBaseCls):
    def __init__(self, table_name):
        super().__init__(table_name)
        self.table_type = "TCAM"
        self.table_size = self.table_width

    def create_table_by_type(
            self,
            table_data,
            context,
            key_type,
            value_type,
            key_func=None,
            value_func=None,
            init_table=False,
            args_map={}):
        self.table_data = table_data
        self.num_entries[context] = 0
        self.tabulate_data[context] = []
        self.tabulate_hdrs[context] = []
        for field_name in table_data[0]['key']:
            if field_name in args_map:
                field_name = args_map[field_name]
            self.keys_name.append(field_name)
            self.tabulate_hdrs[context].append(field_name)

        # set '' as a delimiter between the key,mask and value
        self.tabulate_hdrs[context].append('')
        for field_name in table_data[0]['value']:
            if field_name in args_map:
                field_name = args_map[field_name]
            self.payload_args_name.append(field_name)
            self.tabulate_hdrs[context].append(field_name)

        for line in self.table_data[1::]:
            key_args = {}
            mask_args = {}
            line_data = []
            for pos, v in enumerate(line['key']):
                if v is None: # DONT_CARE
                    key  = 0
                    mask = 0
                    line_data.append(None)
                elif isinstance(v, Key): # Key + mask
                    key  = v.key
                    mask = v.mask
                    if mask:
                        line_data.append((key,'mask=' + str(bin(mask))))
                    else:
                        line_data.append(None)
                else: # constant
                    key = v
                    mask = ALL_1
                    line_data.append(key)
                key_args[self.keys_name[pos]]  = key
                mask_args[self.keys_name[pos]] = mask

            # add a delimiter
            line_data.append('>')

            payload_args = {}
            for pos, v in enumerate(line['value']):
                payload_args[self.payload_args_name[pos]] = v
                line_data.append(v)

            self.tabulate_data[context].append(line_data)

            if key_func:
                key, mask = key_func(key_args, mask_args)
            else:
                key  = key_type(**key_args)
                mask = key_type(**mask_args)

            if value_func:
                value = value_func(payload_args)
            else:
                value = value_type(**payload_args)

            self.table.insert(context, self.num_entries[context], key, mask, value)
            self.num_entries[context] += 1

    def get_table_size(self):
        return self.table_size

# Direct Tables


class DirectTableConfig(TableBaseCls):
    def __init__(self, table_name):
        super().__init__(table_name)
        self.table_type = "Direct"
        self.table_size = 2 ** self.table_width

    def create_table_by_type(
            self,
            table_data,
            context,
            key_type,
            value_type,
            key_func=None,
            value_func=None,
            init_table=False,
            args_map={}):
        self.table_data = table_data
        self.num_entries[context] = 0
        self.tabulate_data[context] = []
        self.tabulate_hdrs[context] = []
        if table_data[0]['key']:
            for field_name in table_data[0]['key']:
                if field_name in args_map.keys():
                    field_name = args_map[field_name]
                self.keys_name.append(field_name)
                self.tabulate_hdrs[context].append(field_name)
        else:
            self.keys_name = ['key']
            self.tabulate_hdrs[context].append('key')

        # set '' as a delimiter between the key,mask and value
        self.tabulate_hdrs[context].append('')
        for field_name in table_data[0]['value']:
            if field_name in args_map:
                field_name = args_map[field_name]
            self.payload_args_name.append(field_name)
            self.tabulate_hdrs[context].append(field_name)

        if init_table:
            # init table with zeros before configuring it
            payload_args = {}
            for field in self.payload_args_name:
                payload_args[field] = 0

            if value_func:
                value = value_func(payload_args)
            else:
                value = value_type(**payload_args)

            for line_num in range(0, self.table_size):
                if key_func:
                    key = key_func(line_num)
                else:
                    key = key_type(line_num)
                self.table.insert(context, key, value)

        for line in self.table_data[1::]:
            payload_args = {}
            key_args = {}
            line_data = []
            if isinstance(line['key'], Iterable):
                for pos, value in enumerate(line['key']):
                    key_args[self.keys_name[pos]] = value
                    line_data.append(value)
            else:
                key_args[self.keys_name[0]] = line['key']
                line_data.append(line['key'])

            # add a delimiter
            line_data.append('>')

            if isinstance(line['value'], Iterable):
                for pos, value in enumerate(line['value']):
                    payload_args[self.payload_args_name[pos]] = value
                    line_data.append(value)
            else:
                payload_args[self.payload_args_name[0]] = line['value']
                line_data.append(line['value'])

            self.tabulate_data[context].append(line_data)

            if key_func:
                key = key_func(key_args)
            else:
                if isinstance(line['key'], Iterable):
                    key = key_type(**key_args)
                else:
                    key = key_type(line['key']) if line['key'] else key_type()

            if value_func:
                value = value_func(payload_args)
            else:
                value = value_type(**payload_args)
            self.table.insert(context, key, value)
            self.num_entries[context] += 1

    def get_table_size(self):
        return self.table_size
