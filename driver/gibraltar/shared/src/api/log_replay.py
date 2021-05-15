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

import sys
import os
import re
import time
from leaba import sdk
from itertools import zip_longest

ignore_data_types = ['unsigned int', 'char', 'unsigned long', 'unsigned short', 'double', 'float']

LOG_INFO_SEPARATOR = '#'
LOG_API_PARAM_SEPARATOR = ' '
LOG_STRUCT_START = '('
LOG_STRUCT_END = ')'
LOG_STRUCT_SEPARATOR = ','
LOG_VEC_START = '['
LOG_VEC_END = ']'
LOG_VEC_ELEM_SEPARATOR = ';'
LOG_DATA_TYPE_START = '<'
LOG_DATA_TYPE_END = '>'

nullptr = None
true = True
false = False


class log_replay():

    def set_replay_log_file(self, device_id, replay_log_file):
        sdk.la_set_logging_level(device_id, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
        sdk.la_set_logging_file(replay_log_file)
        sdk.la_set_logger_function(None)

    def replay_commands(self, replay_cmd_file, device=None, verbose=0):
        start_time = time.time()
        self.verbosity = verbose
        with open(replay_cmd_file, 'r') as f:
            for index, line in enumerate(f):
                print("Replaying line: ", index, end='\r', flush=True)
                line = line.strip()

                if line.startswith('sdk.la_create_device'):
                    if device is None:
                        print('Error: Creating device from logs not supported yet', file=sys.stderr)
                        print('       device must be passed in to replay_commands', file=sys.stderr)
                        return
                elif line.startswith('sdk.la_destroy_device'):
                    sdk.la_destroy_device(device)
                    device = None
                else:
                    try:
                        exec(line)
                    except sdk.BaseException as STATUS:
                        if (STATUS.args[0] != sdk.la_status_e_SUCCESS) and self.verbosity > 0:
                            print('Error: API %s at line %d in %s returned error status: ' %
                                  (line, index, replay_cmd_file), STATUS, file=sys.stderr)
                    except Exception as e:
                        print('Error: %s, while replaying cmd: ' % (str(e)), line, file=sys.stderr)
                        print('\treplay_file %s,# line %d' % (replay_cmd_file, index), file=sys.stderr)
                        raise
        print('Done in %s seconds' % (time.time() - start_time))

    def compare_in_out_logs(self, device_id, input_log_file, replay_log_file, verbose=0):
        self.verbosity = verbose
        compare_success = True
        result_str = 'Compare Passed'
        with open(input_log_file, 'r') as file1, open(replay_log_file, 'r') as file2:
            index1, index2 = 0, 0
            for line1, line2 in zip_longest(file1, file2, fillvalue='EOF'):
                index1, index2 = index1 + 1, index2 + 1
                while line1 and line1.find('-D-API-' + str(device_id)) == -1:
                    if self.verbosity > 2:
                        print('Skippining non API log line1: ', line1)
                    index1 = index1 + 1
                    line1 = file1.readline()
                while line2 and line2.find('-D-API-' + str(device_id)) == -1:
                    if self.verbosity > 2:
                        print('Skippining non API log line2: ', line2)
                    index2 = index2 + 1
                    line2 = file2.readline()

                if (line1.find('la_create_device') != -1 and line2.find('la_create_device') != -
                        1) or (line1.find('register_object:') != -1 and line2.find('register_object:') != -1):
                    continue

                # Strip off timestamp and all leading characters before '-D-API-'
                line1 = re.sub(r'^.*?-D-API-', '-D-API-', line1)
                line1 = line1.strip()
                line2 = line2.strip()

                if line1 != line2:
                    result_str = 'Compare Failed:\n'
                    result_str += input_log_file + ':' + str(index1) + ' ' + line1 + '\n'
                    result_str += replay_log_file + ':' + str(index2) + ' ' + line2 + '\n'
                    compare_success = False
                    break

        print(result_str, file=sys.stderr)

    def get_device_id(self, api_log_file):
        with open(api_log_file, 'r') as input_log_file:
            for line in input_log_file:
                line = line.strip()
                if line.find('-D-API-') == -1:
                    continue
                info = re.search('.*?-D-API-([0-9]+?)- .*', line)
                if info is None:
                    print('Error: get_device_id(): Failed to get device id.', file=sys.stderr)
                    print(line, file=sys.stderr)
                    return None
                device_id = info.group(1)
                break
        return int(device_id)

    def create_replay_commands(self, device_id, api_log_file, replay_cmd_file, replay_on_nsim=False, verbose=0):
        start_time = time.time()
        self.verbosity = verbose
        self.output_replay_cmd_file = replay_cmd_file
        self.input_log_file = api_log_file
        self.device_id = str(device_id)
        self.bad_oid = None
        api_commands = []
        with open(self.output_replay_cmd_file, 'w') as output_replay_cmd_file:
            output_replay_cmd_file.write('#!/usr/bin/env python3\n')
            output_replay_cmd_file.write('# This file is auto-generated by log_replay.py tool\n\n')
            output_replay_cmd_file.write('from leaba import sdk\n')

        with open(self.input_log_file, 'r') as input_log_file, open(self.output_replay_cmd_file, 'a') as output_replay_cmd_file:
            print("Generating replay commands for API log file %s" % (self.input_log_file))
            for index, line in enumerate(iter(input_log_file.readline, '')):
                print("Processing line: ", index, end='\r', flush=True)

                line = self.__check_and_prepare_line(line, device_id)
                if line is None:
                    continue

                # Skip enabling HBM on nsim.
                if line.find('set_bool_property(device_property= <silicon_one::la_device_property_e>ENABLE_HBM') != - \
                        1 and replay_on_nsim:
                    continue

                if not line.startswith('-D-API-') or line.endswith("successfully") or line.find('register_object') != - \
                        1 or '#Recursive API call#' in line:
                    continue

                # Skip generating la_create_device replay command.
                if line.find('la_create_device') != -1:
                    continue

                # TBD ALOK this is fixed in master, remove it when fixed in other branches.
                if line.find("out_count_success") != -1:
                    continue

                if line.find('bulk_updates') != -1:  # Special handling for bulk_update APIs.
                    api_command, input_log_file = self.__create_bulk_update_replay_api(line, input_log_file)
                else:
                    api_command = self.__create_replay_api(line)
                if api_command is None:
                    print('Error: creating replay command for API.', file=sys.stderr)
                    print('\t', line, file=sys.stderr)
                    break
                output_replay_cmd_file.write(api_command + '\n')

            print('Done in %s seconds' % (time.time() - start_time))

    def __check_and_prepare_line(self, line, device_id):
        if '-D-API-' not in line:
            return None

        # Strip off timestamp and all leading characters before '-D-API-'
        line = re.sub(r'^.*?-D-API-', '-D-API-', line)
        line = line.strip()

        # Skip logs for device except device_id.
        dev_id = re.search('-D-API-([0-9]+?)- .*', line).group(1)
        if dev_id != self.device_id:
            return None

        return line

    def __create_bulk_update_replay_api(self, line, input_log_file):
        api_command, api_params = self.__create_replay_api(line)
        is_v4_route = False
        if line.find("ipv4_route_bulk_update") != -1:
            is_v4_route = True

        param_name, count = api_params.split('=')
        if self.verbosity > 2:
            print('API %s has %s bulk updates' % (api_command, count))
        param_vec_name = 'param_vec'
        parameter_objects = param_vec_name + '= []' + '\n'
        vec_elem_count = 0
        for line in iter(input_log_file.readline, ''):
            line = self.__check_and_prepare_line(line, self.device_id)
            if line is None:
                continue
            if line.find('#Bulk update#') != -1:
                line = self.__remove_info_from_log(line)
                device_id, api_params = re.search('-D-API-([0-9]+?)-  (.*)', line).group(1, 2)
                if api_params.strip() == '':  # Everything was informational logs.
                    continue
                if device_id != self.device_id:
                    print(
                        "Error: Invalid device_id in API log, expected %s, found %s" %
                        (self.device_id, device_id), file=sys.stderr)
                    return None

                vec_elem_count += 1
                param_name = 'route_entry'
                param_object = self.__parse_and_create_bulk_update_route_entry_parameter(param_name, api_params, is_v4_route)
                param_object += param_vec_name + '.append(' + param_name + ')' + '\n'
            else:
                input_log_file.seek(input_log_file.tell() - len(line) - 1)
                break
            parameter_objects += param_object
            if self.verbosity > 2:
                print('__create_bulk_update_replay_api(): param_object: %s\napi_params: %s' % (param_object, api_params))
        if vec_elem_count != int(count):
            print('Error: vec_elem_count %d does not match count %s' % (vec_elem_count, count), file=sys.stderr)
            return None, input_log_file
        # Add parameter to API command.
        api_command += param_vec_name + ','
        if self.verbosity > 1:
            print(
                '__create_bulk_update_replay_api(): paramameter_objects: \n %s' %
                (parameter_objects))
            print('  api_command: ', api_command)
        api_command = parameter_objects + api_command[:-1] + ')\n'

        return api_command, input_log_file

    def __parse_and_create_bulk_update_route_entry_parameter(self, param_name, value, is_v4_route):
        if (is_v4_route):
            param_object = param_name + '= sdk.la_ipv4_route_entry_parameters()' + '\n'
        else:
            param_object = param_name + '= sdk.la_ipv6_route_entry_parameters()' + '\n'

        route_entry_dict = dict((f.strip(), v.strip()) for f, v in (item.split('=', 1) for item in value.split(',')))
        for f, v in route_entry_dict.items():
            value = v
            if f == 'action':
                value = 'sdk.la_route_entry_action_e_' + v
            elif f == 'prefix':
                if is_v4_route:
                    value = 'sdk.la_ipv4_prefix_t()' + '\n'
                    addr, length = v.split('/')
                    b_addr3, b_addr2, b_addr1, b_addr0 = self.__extract_ipv4_b_addr(addr)
                    value += 'sdk.set_ipv4_addr(' + param_name + '.' + f + '.addr' + ',' + b_addr0 + \
                        ',' + b_addr1 + ',' + b_addr2 + ',' + b_addr3 + ')' + '\n'
                else:
                    value = 'sdk.la_ipv6_prefix_t()' + '\n'
                    addr, length = v.split('/')
                    w_addr7, w_addr6, w_addr5, w_addr4, w_addr3, w_addr2, w_addr1, w_addr0 = self.__extract_ipv6_w_addr(addr)
                    value += 'sdk.set_ipv6_w_addr(' + param_name + '.' + f + '.addr' + ',' + w_addr0 + ',' + w_addr1 + ',' + \
                        w_addr2 + ',' + w_addr3 + ',' + w_addr4 + ',' + w_addr5 + ',' + w_addr6 + ',' + w_addr7 + ')' + '\n'

                value += param_name + '.' + f + '.length' + '=' + length
            elif f == 'destination':
                if v != 'nullptr':
                    oid = self.__get_oid_from_string(value)
                    oid = self.__adjust_object_id(oid)
                    value = 'device.get_object(' + oid + ')'

            param_object += param_name + '.' + f + '=' + value + '\n'

        return param_object

    def __create_replay_api(self, api_message):
        api_command = ''

        # Strip off informational logs from API log message.
        api_message = self.__remove_info_from_log(api_message).strip()

        api_parser = re.compile(
            '^-D-API-(?P<device_id>[0-9]+?)- (?:(?P<object_type>la_.*?)\(oid=(?P<object_oid>[0-9]+?)\)::)?(?P<api>.+?)\((?P<api_params>.*?\)?)\)$')
        api_info = api_parser.search(api_message)
        if api_info is None:
            print('Error: __create_replay_api(): Failed to parse API message', file=sys.stderr)
            print(api_message)
            return None

        device_id, object_type, object_oid, api, api_params = api_info.groups()
        if self.verbosity > 1:
            print("{0:-<80s}".format('-'))
            print('__create_replay_api(): device_id: %s object_type: %s, object_oid: %s, api: %s, api_params: %s\n' %
                  (device_id, object_type, object_oid, api, api_params))

        if device_id != self.device_id:
            print("Error: Invalid device_id in API log, expected %s, found %s" % (self.device_id, device_id), file=sys.stderr)
            print("\t API log: ", api_message)
            return None

        object_oid = self.__adjust_object_id(object_oid)

        # Create API command.
        if object_type is None:
            api_command += 'sdk.' + api + '('
        elif object_type.strip() == 'la_device_impl':
            api_command += 'device.' + api + '('
        else:
            api_command += 'device.get_object(' + object_oid + ').' + api + '('

        # Handle APIs with no parameters to pass.
        if (len(api_params) == 0):
            api_command += ')'
            return api_command

        # Special handling for xxx_bulk_updates API parameters.
        if api.find('bulk_updates') != -1:
            return api_command, api_params

        # Create parameter objects. Expected parameter string format:
        # "param1=<data_type>value1 param2=<data_type>value2 paramN=valueN"
        api_command, parameter_objects = self.__parse_and_create_api_parameters(api_command, api_params)

        # Create complete API command;
        #   param1 = <param1_object>
        #   paramN = <paramN_object>
        #   <object>.<api>(param1, paramN)
        api_command = parameter_objects + api_command[:-1] + ')\n'

        return api_command

    def __parse_and_create_api_parameters(self, api_command, api_params):
        parameter_objects = ''
        while api_params is not None and len(api_params) != 0:
            # Parameter encoding is param=<data_type>value where data_type is optional.
            param_name, api_params = api_params.split('=', 1)
            api_params, param_object = self.__parse_and_create_parameter(param_name, api_params, LOG_API_PARAM_SEPARATOR)
            parameter_objects += param_object
            # Add parameter to API command.
            api_command += param_object.split('=')[0] + ','
            if self.verbosity > 2:
                print('parse_and_create_api_parameters(): param_object: %s\napi_params: %s' % (param_object, api_params))

        if self.verbosity > 1:
            print('parse_and_create_api_parameters(): paramameter_objects: \n %s' % (parameter_objects))
            print('  api_command: ', api_command)

        return api_command, parameter_objects

    def __parse_and_create_parameter(self, param_name, api_params, param_separator):
        param_name = param_name.strip()
        api_params = api_params.strip()

        if api_params.startswith(LOG_DATA_TYPE_START):
            data_type, api_params = self.__extract_parameter_value(api_params, LOG_DATA_TYPE_START, LOG_DATA_TYPE_END)
            data_type = data_type.strip(LOG_DATA_TYPE_START + LOG_DATA_TYPE_END)
        else:
            data_type = None

        if self.verbosity > 2:
            print('parse_and_create_parameter(): api_params: %s, data_type' % (api_params), data_type)

        if api_params.startswith(LOG_STRUCT_START):
            param_value, api_params = self.__extract_parameter_value(api_params, LOG_STRUCT_START, LOG_STRUCT_END)
        elif api_params.startswith(LOG_VEC_START):
            param_value, api_params = self.__extract_parameter_value(api_params, LOG_VEC_START, LOG_VEC_END)
        else:
            value_info = api_params.split(param_separator, 1)
            param_value = value_info[0]
            if (len(value_info) > 1):
                api_params = value_info[1]
            else:
                api_params = None

        if self.verbosity > 2:
            print('parse_and_create_parameter(): param_name: %s, data_type: %s, param_value: %s, api_params: %s' %
                  (param_name, data_type, param_value, api_params))

        param_object = self.__create_parameter_object(data_type, param_name, param_value)

        return api_params, param_object

    def __create_parameter_object(self, field_type, field, value):
        # <field> and <value> describe the type of object.
        # value optionally encodes data_type of the field. Expected value format;
        #     LOG_DATA_TYPE_START<data_type>LOG_DATA_TYPE_END<value>
        #
        #  <value>   : Could be enum, const, object pointer, structured parameter, vector.
        #  Encoding is as follows;
        #  <data_type>_e : Parameter is enum.
        #  <data_type>*  : Parameter is a pointer to an object.
        #  LOG_STRUCT_START<value>LOG_STRUCT_END : Structured data type.
        #  LOG_VEC_START<value>LOG_VEC_END : Vector data type.
        param_object = ''

        if self.verbosity > 1:
            print("create_parameter_object(): field_type: %s field: %s  value: %s device_id: %s" %
                  (field_type, field, value, self.device_id))

        param_name, data_type, value = field, field_type, value

        if data_type and data_type.endswith('_e'):  # Enum parameter.
            if data_type.find('la_event_e') != -1:                      # FIXME avoid special processing.
                objects_creation_string = param_name + '=' + 'sdk.' + value + '\n'
            else:
                data_type = data_type.replace('silicon_one::', '').replace('::', '.')
                objects_creation_string = param_name + '=' + 'sdk.' + data_type + '_' + value + '\n'

        elif data_type and data_type.endswith('*'):   # Pointer to object parameter.
            if value == 'nullptr':
                objects_creation_string = param_name.rstrip("*") + '=' + value + '\n'
            else:
                oid = self.__get_oid_from_string(value)
                oid = self.__adjust_object_id(oid)
                objects_creation_string = param_name.strip('*') + '=' + 'device.get_object(' + oid + ')' + '\n'

        elif data_type == 'silicon_one::la_ipv4_addr_t':
            objects_creation_string = param_name + '=' + 'sdk.la_ipv4_addr_t()' + '\n'
            b_addr3, b_addr2, b_addr1, b_addr0 = self.__extract_ipv4_b_addr(value)
            objects_creation_string += 'sdk.set_ipv4_addr(' + param_name + ',' + \
                b_addr0 + ',' + b_addr1 + ',' + b_addr2 + ',' + b_addr3 + ')' + '\n'

        elif data_type == 'silicon_one::la_ipv6_addr_t':
            objects_creation_string = param_name + '=' + 'sdk.la_ipv6_addr_t()' + '\n'
            w_addr7, w_addr6, w_addr5, w_addr4, w_addr3, w_addr2, w_addr1, w_addr0 = self.__extract_ipv6_w_addr(value)
            objects_creation_string += 'sdk.set_ipv6_w_addr(' + param_name + ',' + w_addr0 + ',' + w_addr1 + ',' + \
                w_addr2 + ',' + w_addr3 + ',' + w_addr4 + ',' + w_addr5 + ',' + w_addr6 + ',' + w_addr7 + ')' + '\n'

        elif (value.startswith(LOG_VEC_START)):   # Vector or array parameter.
            objects_creation_string = ''
            # Only need to define list for top level vector/array parameter.
            if param_name.find('.') == -1:
                objects_creation_string += param_name + '=' + '[]' + '\n'

            if data_type is not None:
                data_type = data_type.replace('silicon_one::', '').replace('::', '.')
            objects_creation_string += self.__create_vector_parameter(data_type, param_name, value)

        elif (value.startswith(LOG_STRUCT_START)):   # Structured parameter.
            data_type = data_type.split('::')
            data_type = data_type[len(data_type) - 1]
            objects_creation_string = param_name + ' = ' + 'sdk.' + data_type + '()' + '\n'
            objects_creation_string += self.__create_struct_parameter(data_type, param_name, value)
        else:
            if data_type:
                print(
                    'Warning: create_parameter_object(): Failed to parse parameter param_name: %s, data_type: %s, value: %s' %
                    (param_name, data_type, value))
                print('Ignore and try creating object as native data_type....')
            objects_creation_string = param_name + '=' + value + '\n'

        return objects_creation_string

    def __create_vector_parameter(self, vector_elem_type, param_name, value):
        # Vector parameter argument format;
        # value: string representing vectors elements separated  by ';'
        #        LOG_VEC_STARTelem1;elem2;...elemNLOG_VEC_END
        if not value.startswith(LOG_VEC_START) and not value.endswith(LOG_VEC_END):
            print('Error: create_vector_parameter(): Invalid vector parameter value format. Missing %s in value: %s' %
                  (LOG_VEC_START + LOG_VEC_END, value), file=sys.stderr)
            return None

        if self.verbosity > 1:
            print("create_vector_parameter(): data_type: %s,  param_name %s, value: %s, device_id: %s" %
                  (vector_elem_type, param_name, value, self.device_id))

        vec_elem_object = ''
        param_vec_object = ''

        vec_elements = []
        for e in value.strip(LOG_VEC_START + LOG_VEC_END).split(';'):
            if e != '':
                vec_elements.append(e)

        vec_elem_type = None
        if vector_elem_type is not None:
            if vector_elem_type.startswith('std.vector'):   # Vector parameter
                vec_elem_type = re.search('std.vector<(.+),.*>', vector_elem_type).group(1)
            else:   # Array parameter
                vec_elem_type, val = self.__extract_parameter_value(vector_elem_type, LOG_DATA_TYPE_START, LOG_DATA_TYPE_END)
        if vec_elem_type and vec_elem_type in ignore_data_types:  # Ignore native data types
            vec_elem_type = None
        element_index = 0
        for element in vec_elements:
            vec_elem_name = 'vec_element' + str(element_index)
            if self.verbosity > 2:
                print('create_vector_parameter(): Vector element name: %s, type: %s, value: %s' %
                      (vec_elem_name, vec_elem_type, element))
            if vec_elem_type is not None and not vec_elem_type.endswith('*'):
                vec_elem_type = vec_elem_type.split('.')
                vec_elem_type = vec_elem_type[len(vec_elem_type) - 1]
                param_vec_object += vec_elem_name + '=' + 'sdk.' + vec_elem_type + '()' + '\n'
                # if vec_elem_type.endswith('sms_age_quantization_thresholds'):   # Fixme remove special processing.
                #    param_vec_object += vec_elem_name + '=' + 'sdk.' + vec_elem_type.split('.')[1] + '()' + '\n'
                # else:
                #    param_vec_object += vec_elem_name + '=' + 'sdk.' + vec_elem_type + '()' + '\n'
            vec_elem_object = self.__create_parameter_object(vec_elem_type, vec_elem_name, element)
            param_vec_object += vec_elem_object
            param_vec_object += param_name + '.append(' + vec_elem_name + ')' + '\n'
            element_index += 1

        if self.verbosity > 2:
            print('create_vector_parameter(): param_vec_object: ', param_vec_object)

        return param_vec_object

    def __create_struct_parameter(self, struct_type, param_name, value):
        # Strucutred parameter argument format;
        # key: SDK structure name.
        # value: string representing structure's fields and corresponding values. Expected format:
        #        (f=v,f=v,f=(f=v,f=v,...),...)
        #
        # Strip off () from parameter value.
        if not value.startswith(LOG_STRUCT_START) or not value.endswith(LOG_STRUCT_END):
            print("Error: Invalid Structure parameter format. Missing %s in value:" %
                  (LOG_STRUCT_START + LOG_STRUCT_END), value, file=sys.stderr)
            return None

        struct_fields = value[1:-1]

        if self.verbosity > 1:
            print('create_struct_parameter(): struct_type: %s, field_name: %s, struct_fields: %s' %
                  (struct_type, param_name, struct_fields))

        param_struct_object = ''
        while struct_fields is not None and len(struct_fields) != 0:
            # Parameter encoding is param=<data_type>value where data_type is optional.
            field_name, struct_fields = struct_fields.split('=', 1)
            field_name = param_name + '.' + field_name.strip()
            struct_fields, param_object = self.__parse_and_create_parameter(
                field_name, struct_fields, LOG_STRUCT_SEPARATOR)
            param_struct_object += param_object
            if self.verbosity > 1:
                print('struct_param_object: %s' % (param_object))
                print('struct_fields: %s' % (struct_fields))

        return param_struct_object

    def __extract_ipv4_b_addr(self, value):
        ipv4_b_addr = value.split('.')
        if self.verbosity > 2:
            print('Extracted ipv4 addr: ', ipv4_b_addr)
        return ipv4_b_addr

    def __extract_ipv6_w_addr(self, value):
        ipv6_w_addr = value.split(':')
        if self.verbosity > 2:
            print('Extracted ipv6 addr: ', ipv6_w_addr)
        return ipv6_w_addr

    def __extract_parameter_value(self, api_params, start_str, end_str):
        separators = 0
        extracted_string = ''
        for index, char in enumerate(api_params):
            extracted_string += char
            if char == start_str:
                separators += 1
            elif char == end_str:
                separators -= 1
                if separators == 0:
                    break

        if self.verbosity > 1:
            print('extract_parameter_value(): extracted_string: %s, api_params: %s' %
                  (extracted_string, api_params[index + 1:]))

        return extracted_string, api_params[index + 1:].lstrip(';;').lstrip(',').lstrip(')').lstrip(' ')

    def __remove_info_from_log(self, api_message):
        if api_message.find('#') == -1:
            return api_message

        c = api_message.split('#')

        if len(c) % 2 == 0:
            print('Error: remove_info_from_log(): Malformed informational logs. Must be encapusulated in #. e.g. #<info_log>#', file=sys.stderr)
            print(api_message)
            return None

        api_message_clean = ''
        for i, e in enumerate(c):
            if not i % 2:
                api_message_clean += c[i]

        if self.verbosity > 2:
            print('remove_info_from_log(): API params clean: ', api_message_clean)

        return api_message_clean

    def __get_oid_from_string(self, string):
        oid_info = re.search('\(oid=([0-9]+?)\)', string)
        oid = oid_info.group(1)
        return oid

    def __adjust_object_id(self, object_oid):
        if self.bad_oid:
            oid = int(object_oid)
            if oid > self.bad_oid:
                oid -= 1
            object_oid = str(oid)

        return object_oid
