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

# Generate HW init functions for SDK

import re
import logging
import datetime
from lbr_parsing_common import *

MAX_EVALUATION_LENGTH = 64

# @brief Creates init_functions.h file


def create_init_functions(lbr_parsed,
                          asic_name,
                          sv_defines_file_path,
                          sdk_init_functions_out_path):

    out_filename = sdk_init_functions_out_path + '/' + asic_name + '_init_functions.h'
    with open(out_filename, 'w') as init_functions_file:
        logging.debug("writing to %s", out_filename)
        writer = indented_writer(init_functions_file)
        writer.depth = 0
        writer.write(
            "// This file has been automatically generated using init_functions_generator.py on {:%Y-%m-%d %H:%M:%S}. Do not edit it manually.\n\n".format(
                datetime.datetime.now()))

        header_define = "__" + asic_name.upper() + "_INIT_FUNCTIONS_H__"
        writer.write("#ifndef {0}\n".format(header_define))
        writer.write("#define {0}\n\n".format(header_define))

        writer.write("#pragma GCC diagnostic push\n")
        writer.write("#pragma GCC diagnostic ignored \"-Wunused-parameter\"\n\n")

        write_namespace_begin(writer, 'silicon_one')
        write_sv_defines_enum(writer, sv_defines_file_path, asic_name)
        write_init_functions(writer, lbr_parsed, asic_name)
        write_namespace_end(writer, 'silicon_one')
        writer.write("#pragma GCC diagnostic pop\n\n")
        writer.write("#endif // {0}\n".format(header_define))


def write_sv_defines_enum(writer, sv_defines_file_path, asic_name):
    with open(sv_defines_file_path, 'r') as sv_defines_file:
        sv_defines_lines = sv_defines_file.readlines()
        if len(sv_defines_lines) == 0:
            return

        writer.depth += 1
        writer.write("// SystemVerilog defines:\n")
        writer.write("namespace {}_sv_defines_e {{\n".format(asic_name))
        writer.write("enum {\n")
        writer.depth += 1

        for line in sv_defines_lines:
            splitted_line = [elem.strip() for elem in line.split('=')]
            if len(splitted_line) != 2:
                raise Exception(
                    "illegal num of tokens in the line. line = '{0}', splitted_line = '{1}'".format(
                        line, splitted_line))
            writer.write("{0} = {1},\n".format(splitted_line[0], splitted_line[1]))

        writer.depth -= 1
        writer.write("};\n")
        writer.write("}} // namespace {}_sv_defines_e\n\n\n".format(asic_name))
        writer.depth -= 1


def write_init_functions(writer, lbr_parsed, asic_name):
    writer.depth += 1
    writer.write("// ***************\n")
    writer.write("// INIT FUNCTIONS:\n")
    writer.write("// ***************\n\n")

    for block_name, parsed_block in lbr_parsed.items():
        for storage_type in ('Registers', 'Memories'):
            for regs_mems in parsed_block[storage_type]:
                all_regs_mems_revisions = [regs_mems] + [rev['regmem_dict'] for rev in regs_mems['OtherRevisions']]
                for reg_mem in all_regs_mems_revisions:
                    force_post_reset = True if ((storage_type == 'Memories') and (reg_mem['Type'] == 'DYNAMIC')) else False
                    init_function_prototype_name_base = "init_function__" + asic_name + "__" + block_name + "__" + reg_mem['Name']
                    for field in reg_mem['Fields']:
                        field_init_functions_data = get_field_init_functions_data(field, force_post_reset, asic_name)
                        if field_init_functions_data is None:
                            continue

                        verify_max_evaluation = (
                            field['Width'] > MAX_EVALUATION_LENGTH) if (
                            field['ArrayItemWidth'] is None) else (
                            field['ArrayItemWidth'] > MAX_EVALUATION_LENGTH)

                        for (init_stage, c_lbr_init_mode), (c_init_expression,
                                                            raw_lbr_init_expression) in field_init_functions_data.items():
                            init_function_name = init_function_prototype_name_base + "__" + \
                                field["Name"] + "__" + init_stage + "__" + c_lbr_init_mode

                            if verify_max_evaluation:
                                # For the rare scenario of 'non-itemized field bigger than 64b' or 'itemized field with item bigger than 64b',
                                # perform naive python evaluation of the expression to assure the 'max 64b evaluation limitiation' is not violated
                                # (if the init expression is not naive enough for python eval to handle with - it will fail and cannot be initialized by the device configuration mechanism.
                                # The initialization of this storage needs to be coded manually in the SDK.)
                                try:
                                    init_expression_eval = eval(raw_lbr_init_expression)
                                except BaseException:
                                    raise Exception(
                                        'Failed to evaluate an init expression of more than {0} bits. The initialization of this storage needs to be coded manually in the SDK. Block: \'{1}\', Storage: \'{2}\', Field: \'{3}\', Init expression: \'{4}\''.format(
                                            MAX_EVALUATION_LENGTH,
                                            block_name,
                                            reg_mem['Name'],
                                            field['Name'],
                                            raw_lbr_init_expression))
                                if init_expression_eval >= (1 << MAX_EVALUATION_LENGTH):
                                    raise Exception(
                                        'Init expression evaluated to be larger than {0} bits, which is not supported by the device configuration mechanism. The initialization of this storage needs to be coded manually in the SDK. Block: \'{1}\', Storage: \'{2}\', Field: \'{3}\', Init expression: \'{4}\''.format(
                                            MAX_EVALUATION_LENGTH,
                                            block_name,
                                            reg_mem['Name'],
                                            field['Name'],
                                            raw_lbr_init_expression))

                            writer.write("uint64_t {0}(double frequency, la_device_id_t device_id, bool is_hbm, bool is_100g_fabric, size_t numnwk, size_t numfab, bool is_MAT_6_4T, bool is_MAT_3_2T_A, bool is_MAT_3_2T_B, size_t credit_in_bytes, lld_block::block_instance_t block, la_slice_pair_id_t slice_pair, la_slice_id_t slice, la_ifg_id_t ifg, size_t instance, size_t num_instances, size_t line, size_t num_lines, size_t num_items, size_t item) {{\n".format(init_function_name))
                            writer.depth += 1
                            writer.write("return {0};\n".format(c_init_expression))
                            writer.depth -= 1
                            writer.write("}\n\n\n")
    writer.depth -= 1


def get_field_init_functions_data(field, force_post_reset, asic_name):
    lbr_mode_to_init_function_suffix = {'InitValueSa': 'sa',
                                        'InitValueLcNwk': 'lc_nwk',
                                        'InitValueLcFab': 'lc_fab',
                                        'InitValueFe': 'fe'}

    # {(init_stage, c_lbr_init_mode) : (c_init_expression, raw_lbr_init_expression)}
    init_functions_data = {}

    init_stage, raw_lbr_init_expression = fetch_stage_and_raw_expression(field["InitValueAllModes"], force_post_reset)

    if init_stage is not None:
        c_init_expression = convert_raw_expression_to_c(raw_lbr_init_expression, asic_name)
        for c_lbr_init_mode in lbr_mode_to_init_function_suffix.values():
            init_functions_data[(init_stage, c_lbr_init_mode)] = (c_init_expression, raw_lbr_init_expression)

    for lbr_init_mode, c_lbr_init_mode in lbr_mode_to_init_function_suffix.items():
        init_stage, raw_lbr_init_expression = fetch_stage_and_raw_expression(field[lbr_init_mode], force_post_reset)
        if init_stage is not None:
            c_init_expression = convert_raw_expression_to_c(raw_lbr_init_expression, asic_name)
            init_functions_data[(init_stage, c_lbr_init_mode)] = (c_init_expression, raw_lbr_init_expression)

    return init_functions_data if bool(init_functions_data) else None


def fetch_stage_and_raw_expression(raw_lbr_init_expression, force_post_reset):
    stage = None
    if (raw_lbr_init_expression is not None):
        match = "^INIT_AFTER_SOFT_RESET\s+"
        is_init_after_soft_reset_expression = (re.search(match, raw_lbr_init_expression) is not None)

        if (is_init_after_soft_reset_expression or force_post_reset):
            raw_lbr_init_expression = re.sub(match, '', raw_lbr_init_expression)
            stage = 'post_soft_reset'
        else:
            stage = 'pre_soft_reset'

    return stage, raw_lbr_init_expression


def convert_raw_expression_to_c(raw_lbr_init_expression, asic_name):
    # Remove underscore from hex numbers:
    # Example: 0xF_FFFF -> 0xFFFFF
    c_init_expression = re.sub('(^|[^_])\d*\'?h([a-fA-F0-9_]+)', hex_underscore_repl, raw_lbr_init_expression)

    # Convert bin to hex:
    # Example: 0b1001 -> 0x9
    c_init_expression = re.sub('(?:^| )\d*b([01]+)', bin_to_hex, c_init_expression)

    # Remove 'd' verilog decimal specifier:
    # Example d127 -> 127
    c_init_expression = re.sub('(?:^| )d(\d*)(?:$| )', '\\1', c_init_expression)

    # bit extraction:
    # 13[2:1] = 0b1101[2:1] = 0b10 = 2
    match = "\[(\d+):(\d+)\]"
    ranges = re.findall(match, c_init_expression)
    for range in ranges:
        high_range = int(range[0])
        if high_range >= MAX_EVALUATION_LENGTH:
            raise Exception(
                "Init expression contains invalid bit extraction (range exceeds {} bits). init expression: {1}".format(
                    MAX_EVALUATION_LENGTH, raw_lbr_init_expression))

    # shift right <#lsb> bits, mask with (<#msb> - <#lsb> + 1) ones:
    # 13[2:1] = 0b1101[2:1] = (0b1101 >> 1) & (0b11) = 0b10 = 2
    c_init_expression = re.sub(match, '>>\\2 & ((1<<(\\1-\\2+1))-1)', c_init_expression)

    # Sign hex numbers as 'long':
    # Example: 0x9F -> 0x9Fl
    c_init_expression = re.sub('(0[xX][0-9a-fgA-F]+)', '\\1l', c_init_expression)

    # Sign dec numbers as 'long':
    # Example: 30 -> 30l
    c_init_expression = re.sub('(?<!\w)(\d+)+(?![.xX])', '\\1l', c_init_expression)

    # sv defines:
    # Example: `RLB_UCL_CONTEXT -> <asic_name>_sv_defines_e::RLB_UCL_CONTEXT
    c_init_expression = re.sub('`(\w*)', '{}_sv_defines_e::\\1'.format(asic_name), c_init_expression)

    # division:
    div_match = "(?<!\/)\/(?!\/)"
    # perform divisions as 'double' calculation
    c_init_expression = re.sub(div_match, '/(double)', c_init_expression)
    # round down by casting
    c_init_expression = re.sub('round_down', 'static_cast<uint64_t>', c_init_expression)

    return c_init_expression


def hex_underscore_repl(match_obj):
    return match_obj.group(1) + '0x' + match_obj.group(2).replace('_', '')


def bin_to_hex(match_obj):
    return hex(int(match_obj.group(1), 2))
