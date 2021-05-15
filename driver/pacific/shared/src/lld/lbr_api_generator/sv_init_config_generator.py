#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# Generate HW init configuration system-verilog for RTL

import ast
import re
import logging
import datetime
from lbr_parsing_common import *

#######################################################
# Global variables
#######################################################
NUM_OF_SLICES = 6

# @brief Writes System Verilog config files with the collected init values
#
# @param[in] verilog_block_to_lbr       {verilog_blockname : lbr parsed block (dict)}
# @param[in] verilog_block_to_sw_path   {verilog_blockname : sw path}
# @param[in] verilog_to_sv_instance     {verilog_blockname : sv instance name}
# @param[in] sv_config_filename         the output config file name


def create_sv_config_files(sw_paths_with_uid,
                           lbr_parsed,
                           verilog_to_sv_instance,
                           sv_config_out_path,
                           create_init_after_soft_reset=False):

    init_mode_slice_map = {
        'init_mode_sa': ['InitValueSa'] * NUM_OF_SLICES,
        'init_mode_lc': ['InitValueLcNwk'] * int(NUM_OF_SLICES / 2) + ['InitValueLcFab'] * int(NUM_OF_SLICES / 2),
        'init_mode_fe': ['InitValueFe'] * NUM_OF_SLICES}

    verilog_block_to_lbr, verilog_block_to_sw_path = build_verilog_block_to_data(sw_paths_with_uid, lbr_parsed)

    init_after_soft_reset_suffix = '' if create_init_after_soft_reset == False else '_after_soft_reset'
    out_filename = re.sub('device', '', sv_config_out_path) + '_init_config' + init_after_soft_reset_suffix + '.sv'
    with open(out_filename, 'w') as sv_file:
        logging.debug("writing to %s", out_filename)
        writer = indented_writer(sv_file)
        writer.depth = 0
        writer.write(
            "// This file has been automatically generated using lbr_api_generator.py on {:%Y-%m-%d %H:%M:%S}. Do not edit it manually.\n\n".format(
                datetime.datetime.now()))
        writer.write(
            'task init_regs_mems' +
            init_after_soft_reset_suffix +
            '(input string init_mode, input int frequency, input int device_id, input bit is_hbm, input bit is_100g_fabric, input int numnwk, input int numfab, input bit is_MAT_6_4T, input bit is_MAT_3_2T_A, input bit is_MAT_3_2T_B, input int credit_in_bytes);\n')
        writer.depth = 1
        writer.write('uvm_status_e status;\n')
        writer.write(
            'bit[`UVM_REG_DATA_WIDTH-1:0] temp_bit_array;   // used for lines / items field writes, set to max possible line size\n\n')

        # Iterate blocks:
        for verilog_blockname, block_lbr in verilog_block_to_lbr.items():
            if verilog_blockname in verilog_to_sv_instance:
                sv_instance = verilog_to_sv_instance[verilog_blockname]
            else:
                continue

            lbr_block_name = block_lbr['Name']
            block_sw_path = verilog_block_to_sw_path[verilog_blockname]
            sw_path_slice_pair_index, sw_path_slice_index, sw_path_ifg_index, block_index = parse_sw_path(block_sw_path)

            if ((sw_path_slice_pair_index is not None) and ((sw_path_slice_index is not None) or (sw_path_ifg_index is not None))):
                exception_massage = '\'slice\' or \'ifg\' cannot co-exist with \'slice_pair\' in the same sw-path (\'{0}\')'.format(
                    block_sw_path)
                raise Exception(exception_massage)
            else:
                # Calculate other indices:
                if sw_path_ifg_index is not None:
                    sw_path_slice_index = sw_path_slice_index if sw_path_slice_index is not None else int(sw_path_ifg_index / 2)
                    sw_path_slice_pair_index = sw_path_slice_pair_index if sw_path_slice_pair_index is not None else int(
                        sw_path_ifg_index / 4)
                elif sw_path_slice_index is not None:
                    sw_path_slice_pair_index = sw_path_slice_pair_index if sw_path_slice_pair_index is not None else int(
                        sw_path_slice_index / 2)

            # Iterate registers in block:
            for parsed_register in block_lbr['Registers']:
                # theoretically, it might be possible that the design will create an array of size 1
                is_single_register = parsed_register['IsSingle']
                register_array_suffix = ''
                register_instance_allocation = parsed_register['InstanceAllocation']
                array_length = parsed_register['ArrayLength']

                # Iterate registers in (possibly) register array:
                for register_index in range(array_length):
                    slice_index, slice_pair_index, ifg_index = update_indices_by_instance_allocation(sw_path_slice_index,
                                                                                                     sw_path_slice_pair_index,
                                                                                                     sw_path_ifg_index,
                                                                                                     register_instance_allocation,
                                                                                                     register_index)
                    if (slice_index is not None) and (slice_index > (NUM_OF_SLICES - 1)):
                        print(
                            "WARNING! instance '{0}' of register '{1}' is allocated with an invalid slice index ('{2}'). register's instance initialization is skipped.".format(
                                register_index,
                                parsed_register['Name'],
                                slice_index))
                        continue

                    if not is_single_register:
                        register_array_suffix = '[' + str(register_index) + ']'

                    register_base_print = 'model.' + sv_instance + '.' + lbr_block_name + \
                        '_regs_i.' + parsed_register['Name'] + '_reg_i' + register_array_suffix + '.'

                    register_has_init_value = write_reg_or_line(writer,
                                                                create_init_after_soft_reset,
                                                                init_mode_slice_map,
                                                                block_sw_path,
                                                                parsed_register,
                                                                'reg',
                                                                sw_path_slice_index,
                                                                sw_path_slice_pair_index,
                                                                sw_path_ifg_index,
                                                                slice_index,
                                                                slice_pair_index,
                                                                ifg_index,
                                                                block_index,
                                                                register_index,
                                                                array_length,
                                                                None,    # line
                                                                None,    # num_lines
                                                                lbr_block_name,
                                                                register_base_print,
                                                                None)

                    if register_has_init_value:
                        writer.depth = 1
                        writer.write(
                            'model.' +
                            sv_instance +
                            '.' +
                            lbr_block_name +
                            '_regs_i.' +
                            parsed_register['Name'] +
                            '_reg_i' +
                            register_array_suffix +
                            '.' +
                            'update(status, UVM_BACKDOOR);\n\n')

            # Iterate memories in block:
            for parsed_memory in block_lbr['Memories']:
                # theoretically, it might be possible that the design will create an array of size 1
                is_single_memory = parsed_memory['IsSingle']
                memory_array_suffix = ''
                memory_instance_allocation = parsed_memory['InstanceAllocation']
                array_length = parsed_memory['ArrayLength']

                # build line's bit range define:
                line_range_define = (lbr_block_name + '_CIF_' + parsed_memory['Name'] + '_WIDTH').upper()

                # Iterate memories in (possibly) memory array:
                for memory_index in range(array_length):
                    slice_index, slice_pair_index, ifg_index = update_indices_by_instance_allocation(sw_path_slice_index,
                                                                                                     sw_path_slice_pair_index,
                                                                                                     sw_path_ifg_index,
                                                                                                     memory_instance_allocation,
                                                                                                     memory_index)
                    if (slice_index is not None) and (slice_index > (NUM_OF_SLICES - 1)):
                        print(
                            "WARNING! instance '{0}' of memory '{1}' is allocated with an invalid slice index ('{2}'). memory's instance initialization is skipped.".format(
                                memory_index,
                                parsed_memory['Name'],
                                slice_index))
                        continue

                    if not is_single_memory:
                        memory_array_suffix = '[' + str(memory_index) + ']'

                    # Iterate memory entries (lines):
                    num_of_entries = parsed_memory['MemEntries']
                    for entry_index in range(num_of_entries):
                        mem_read = 'model.' + sv_instance + '.' + lbr_block_name + '_mems_i.' + \
                            parsed_memory['Name'] + '_mem_i' + memory_array_suffix + '.read(status, ' + str(entry_index) + ', temp_bit_array[`' + line_range_define + '-1:0], UVM_BACKDOOR);\n'
                        line_has_init_value = write_reg_or_line(writer,
                                                                create_init_after_soft_reset,
                                                                init_mode_slice_map,
                                                                block_sw_path,
                                                                parsed_memory,
                                                                'mem',
                                                                sw_path_slice_index,
                                                                sw_path_slice_pair_index,
                                                                sw_path_ifg_index,
                                                                slice_index,
                                                                slice_pair_index,
                                                                ifg_index,
                                                                block_index,
                                                                memory_index,
                                                                array_length,
                                                                entry_index,     # line
                                                                num_of_entries,  # num_lines
                                                                lbr_block_name,
                                                                '',
                                                                mem_read)

                        if line_has_init_value:
                            writer.depth = 1
                            mem_write = 'model.' + sv_instance + '.' + lbr_block_name + '_mems_i.' + \
                                parsed_memory['Name'] + '_mem_i' + memory_array_suffix + '.write(status, ' + str(entry_index) + ', temp_bit_array[`' + line_range_define + '-1:0], UVM_BACKDOOR);\n\n'
                            writer.write(mem_write)
        writer.depth = 0
        writer.write('endtask\n')
        del writer


# @brief Substitutes the indices' evaluation in the init macro and returns it
def substitute_macro(init_macro, slice, slice_pair, ifg, block, instance, num_instances, line, num_lines, item, num_items):
    sub_macro = init_macro

    # replace 0x with 'h:
    sub_macro = re.sub('0x', '\'h', sub_macro)
    sub_macro = re.sub('INIT_AFTER_SOFT_RESET ', '', sub_macro)

    sub_macro = safe_token_substitude(sub_macro, 'slice_pair', slice_pair)
    sub_macro = safe_token_substitude(sub_macro, 'slice', slice)
    sub_macro = safe_token_substitude(sub_macro, 'ifg', ifg)
    sub_macro = safe_token_substitude(sub_macro, 'block', block)
    sub_macro = safe_token_substitude(sub_macro, 'num_instances', num_instances)
    sub_macro = safe_token_substitude(sub_macro, 'instance', instance)
    sub_macro = safe_token_substitude(sub_macro, 'num_lines', num_lines)
    sub_macro = safe_token_substitude(sub_macro, 'line', line)
    sub_macro = safe_token_substitude(sub_macro, 'num_items', num_items)
    sub_macro = safe_token_substitude(sub_macro, 'item', item)

    return sub_macro


# @brief substitutes token's evaluation only if its evaluation exists, otherwise, if the token appears in the init_macro but has no evaluation - raises exception
#
# @param[in] init_macro     the raw init_macro
# @param[in] token          the token to be evaluated, one of: ['slice_pair', 'slice', 'ifg', 'block', 'num_instances', 'instance', 'num_lines', 'line', 'num_items', 'item']
# @param[in] token_replace  the token evaluation to replace the token
#
# @return the init_macro with the token evaluation
def safe_token_substitude(init_macro, token, token_replace):
    token_match = re.search(token, init_macro)
    if (token_match is not None) and (token_replace is None):
        exception_massage = '\'{0}\' token cannot be evaluated in \'init_macro\': \'{1}\''.format(token, init_macro)
        raise Exception(exception_massage)

    sub_macro = re.sub(token, str(token_replace), init_macro)

    return sub_macro


# @brief write register's / line's fields
def write_reg_or_line(writer,
                      create_init_after_soft_reset,
                      init_mode_slice_map,
                      block_sw_path,
                      parsed_reg_mem,
                      reg_or_mem,        # one of: ['reg, 'mem']
                      sw_path_slice_index,
                      sw_path_slice_pair_index,
                      sw_path_ifg_index,
                      slice_index,
                      slice_pair_index,
                      ifg_index,
                      block_index,
                      reg_mem_index,
                      reg_mem_array_length,
                      line,
                      num_lines,
                      lbr_block_name,
                      register_base_print,
                      mem_read):

    force_post_reset = False
    field_position_define_base = lbr_block_name + '_CIF_'

    if reg_or_mem == 'mem':
        force_post_reset = True if parsed_reg_mem['Type'] == 'DYNAMIC' else False
        # build line's bit range define:
        line_width_define = (lbr_block_name + '_CIF_' + parsed_reg_mem['Name'] + '_WIDTH').upper()
        field_position_define_base += parsed_reg_mem['Name'] + '_'

    found_field_with_init_value = False

    # Iterate fields in the register/memory:
    for parsed_field in parsed_reg_mem['Fields']:
        was_first_field_init_made = False

        field_offset = parsed_field['PositionLow']
        item_width = None if parsed_field['ArrayItemWidth'] is None else parsed_field['ArrayItemWidth']
        field_width = None if parsed_field['Width'] is None else int(parsed_field['Width'])
        if (field_width is not None) and (item_width is not None):
            num_items = int(field_width / item_width)
        else:
            num_items = None

        # build field bit range define:
        field_position_define = (field_position_define_base + parsed_field['Name'] + '_POSITION').upper()

        field_instance_allocation = parsed_field['InstanceAllocation']

        register_base_print_field = register_base_print + parsed_field['Name'] + '.set'

        field_has_InitAllModes = False
        # first, set default init for the field if exists:

        # str_all = parsed_field['InitValueAllModes']
        # if str_all != None:
        #     print(str_all)

        init_all_modes_macro = fetch_macro(parsed_field['InitValueAllModes'], create_init_after_soft_reset, force_post_reset)
        if init_all_modes_macro is not None:

            field_has_InitAllModes = True   # indicates to spare the set of default value later

            writer.depth = 1

            if (reg_or_mem == 'mem') and found_field_with_init_value == False:
                if (create_init_after_soft_reset or force_post_reset):
                    # read current mem value (specified fields will be overwritten)
                    writer.write(mem_read)
                else:
                    # init line to 0 before assigning it values:
                    writer.write('temp_bit_array[`' + line_width_define + '-1:0] = 0;\n')

            write_field_mode(writer,
                             item_width,
                             num_items,
                             init_all_modes_macro,
                             field_offset,
                             field_instance_allocation,
                             sw_path_slice_index,
                             sw_path_slice_pair_index,
                             sw_path_ifg_index,
                             slice_index,
                             slice_pair_index,
                             ifg_index,
                             block_index,
                             reg_mem_index,
                             reg_mem_array_length,
                             line,
                             num_lines,
                             register_base_print_field,
                             field_position_define,
                             reg_or_mem)

            found_field_with_init_value = True

        field_has_Lc_init_macro = (parsed_field['InitValueLcNwk'] is not None) or \
                                  (parsed_field['InitValueLcFab'] is not None)

        if (slice_index is None) and (field_has_Lc_init_macro):
            # print warning:
            print('WARNING! cannot resolve \'slice_index\' for register: \'' + parsed_reg_mem['Name'] + '\', field: \'' + parsed_field['Name'] + '\'.  The index either cannot be fetched from \'sw_path\': \'' +
                  block_sw_path + '\' or not specified \'per_slice\' in \'InstanceAllocation: ' + str(parsed_field['InstanceAllocation']) + '\'). \'init_mode\' is taken as if \'slice_index\'=0.')

        # generate init line for each mode (per field)
        for init_mode in ['init_mode_sa', 'init_mode_lc', 'init_mode_fe']:
            lbr_init_mode = init_mode_slice_map[init_mode][0] if slice_index is None else init_mode_slice_map[init_mode][slice_index]
            init_macro = fetch_macro(parsed_field[lbr_init_mode], create_init_after_soft_reset, force_post_reset)

            if init_macro is None:
                continue

            writer.depth = 1
            if not was_first_field_init_made:
                was_first_field_init_made = True

                # print default val for reg's field (if needed) or init line to 0 (again, if needed)
                if not field_has_InitAllModes:
                    # init reg to default value or memory line to 0:
                    if (reg_or_mem == 'reg'):
                        if not (create_init_after_soft_reset or force_post_reset):
                            # for regs - prepare 'field_default_value' which is needed for 'eval(field_default_value_line)'
                            field_default_value = parsed_field['BinaryDefault']
                            # save the default value as str of hex number:
                            field_default_value = (get_n_byte_hex_list(field_default_value))[0]
                            # replace 0x with 'h:
                            field_default_value = re.sub('0x', '\'h', field_default_value)
                            # print (field_default_value):
                            writer.write(register_base_print_field + '(' + str(field_default_value) + ');\n')
                    else:   # Mem:
                        if found_field_with_init_value == False:      # First Mem's line init
                            if (create_init_after_soft_reset or force_post_reset):
                                # read current mem value (specified fields will be overwritten)
                                writer.write(mem_read)
                            else:
                                # init line to 0 before assigning it values:
                                writer.write('temp_bit_array[`' + line_width_define + '-1:0] = 0;\n')

                # print the condition:
                condition_line = 'if (init_mode == "' + init_mode + '") begin\n'
            else:
                condition_line = 'end else if (init_mode == "' + init_mode + '") begin\n'
            writer.write(condition_line)

            writer.depth = 2
            write_field_mode(writer,
                             item_width,
                             num_items,
                             init_macro,
                             field_offset,
                             field_instance_allocation,
                             sw_path_slice_index,
                             sw_path_slice_pair_index,
                             sw_path_ifg_index,
                             slice_index,
                             slice_pair_index,
                             ifg_index,
                             block_index,
                             reg_mem_index,
                             reg_mem_array_length,
                             line,
                             num_lines,
                             register_base_print_field,
                             field_position_define,
                             reg_or_mem)

            found_field_with_init_value = True

        if was_first_field_init_made:
            writer.depth = 1
            writer.write('end\n')

    return found_field_with_init_value


# @brief fetches init_macro with correspondence to its stage (init after soft reset)
#
# @param[in] init_macro                     the raw init_macro
# @param[in] create_init_after_soft_reset   boolean, indicates whether we build init config for before/after soft reset
#
# @return the init_macro with the token evaluation
def fetch_macro(init_macro, create_init_after_soft_reset, force_post_reset=False):
    if (init_macro is not None):
        match = "^INIT_AFTER_SOFT_RESET\s+"
        is_init_after_soft_reset_macro = (re.search(match, init_macro) is not None) or force_post_reset

        if (create_init_after_soft_reset):
            if (is_init_after_soft_reset_macro):
                init_macro = re.sub(match, '', init_macro)
            else:
                init_macro = None
        elif (is_init_after_soft_reset_macro):
            init_macro = None

    return init_macro


# @brief writes specific field mode within a register's/line's field.
def write_field_mode(writer,
                     item_width,
                     num_items,
                     init_macro,
                     field_offset,
                     field_instance_allocation,
                     sw_path_slice_index,
                     sw_path_slice_pair_index,
                     sw_path_ifg_index,
                     slice_index,
                     slice_pair_index,
                     ifg_index,
                     block_index,
                     reg_mem_index,
                     reg_mem_array_length,
                     line,
                     num_lines,
                     register_base_print_field,
                     field_position_define,
                     reg_or_mem):

    offset = 0 if reg_or_mem == 'reg' else field_offset

    if item_width is not None:
        # the field is items array:
        for item_index in range(num_items):
            # update indices with item_index as 'instance' interpretation:
            slice_index, slice_pair_index, ifg_index = update_indices_by_instance_allocation(sw_path_slice_index,
                                                                                             sw_path_slice_pair_index,
                                                                                             sw_path_ifg_index,
                                                                                             field_instance_allocation,
                                                                                             item_index)

            if (slice_index is not None) and (slice_index > (NUM_OF_SLICES - 1)):
                print(
                    "WARNING! item '{0}' of field '{1}' is allocated with an invalid slice index ('{2}'). field's item initialization is set to 0.".format(
                        item_index,
                        register_base_print_field,
                        slice_index))
                continue

            item_sub_macro = substitute_macro(init_macro,
                                              slice_index,
                                              slice_pair_index,
                                              ifg_index,
                                              block_index,
                                              reg_mem_index,
                                              reg_mem_array_length,
                                              line,
                                              num_lines,
                                              item_index,
                                              num_items)

            writer.write('temp_bit_array[' + str(((item_index + 1) * item_width) + offset - 1) +
                         ':' + str((item_index * item_width) + offset) + '] = ' + item_sub_macro + ';\n')

        if reg_or_mem == 'reg':
            writer.write(register_base_print_field + '(temp_bit_array[`' + field_position_define + ']);\n')

    else:
        sub_macro = substitute_macro(init_macro,
                                     slice_index,
                                     slice_pair_index,
                                     ifg_index,
                                     block_index,
                                     reg_mem_index,
                                     reg_mem_array_length,
                                     line,
                                     num_lines,
                                     None,  # item
                                     None)  # num_items
        if reg_or_mem == 'reg':
            writer.write(register_base_print_field + '(' + sub_macro + ');\n')
        else:        # Mem:
            writer.write('temp_bit_array[`' + field_position_define + '] = ' + sub_macro + ';\n')


# @brief Generates dict of <Verilog block name, sv instance name> from the given file
#
# @param[in] verilog_to_sv_instance_filename      The path to a file with dict <Verilog block name, sv instance name>
#
# @return A dict of <Verilog block name, sv instance name>
def load_verilog_to_sv_instance_dict(verilog_to_sv_instance_filename):
    with open(verilog_to_sv_instance_filename, 'r') as verilog_to_sv_instance_file:
        verilog_to_sv_instance_str = verilog_to_sv_instance_file.read()
        verilog_to_sv_instance = ast.literal_eval(verilog_to_sv_instance_str)
    return verilog_to_sv_instance


# @brief Build {verilog_blockname : lbr parsed block} dict
#
# @param[in] sw_paths_with_uid  Dict of: {'project_tree' (i.e 'pacific_tree') : List of SW-paths to all LBR-blocks, and their block_ids}
# @param[in] lbr_parsed         The parsed LBR data
# @return   verilog_block_to_lbr        {verilog_blockname : lbr parsed block (dict)}
# @return   verilog_block_to_sw_path    {verilog_blockname : sw path}
def build_verilog_block_to_data(sw_paths_with_uid, lbr_parsed):
    verilog_block_to_lbr = {}
    verilog_block_to_sw_path = {}
    for block_list in sw_paths_with_uid.values():
        for block in block_list:
            # skip 'dummy_entry' (they do not hold 'block_to_sw_path_config')
            if 'block_to_sw_path_config' not in block:
                continue

            verilog_blockname = block['block_uid_data']['verilog_blockname']
            lbr_name = block['block_to_sw_path_config']['lbr_block_name']
            sw_path = block['sw_path']

            verilog_block_to_sw_path[verilog_blockname] = sw_path

            # retrieve the corresponding 'parsed lbr block' of the verilog_blockname
            lbr_parsed_block = next(
                (lbr_parsed[block_name] for block_name in lbr_parsed if block_name == lbr_name), None)
            if lbr_parsed_block is None:
                exception_message = 'verilog block \'{0}\' has no matching lbr'.format(verilog_blockname)
                raise Exception(exception_message)

            verilog_block_to_lbr[verilog_blockname] = lbr_parsed_block
    return verilog_block_to_lbr, verilog_block_to_sw_path
