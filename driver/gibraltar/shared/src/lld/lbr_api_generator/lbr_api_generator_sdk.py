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

import logging
import os
import datetime
import ntpath
import json
from lbr_parsing_common import *
from enum import Enum
import importlib


# @brief Writes C++ files based on the collected data
#
# Writes a .cpp and an .h file based on the collected data from the input file
#
# @param[in] out_filename                   The output C++ path+basename to use
# @param[in] lbr_parsed                     The parsed LBR data (blocks and their regs/mems/reg_fields)
# @param[in] blockname_uid_list             A list of blockname and its ID
# @param[in] flat_classes                   A list of classes with their members
# @param[in] sw_paths_with_uid              A list of SW-paths for each block with the block ID
# @param[in] sbif_overrides                 Overrides specific to SBIF


def create_c_files(
        out_filename,
        lbr_parsed,
        blockname_uid_list,
        flat_classes,
        sw_paths_with_uid,
        sbif_overrides):
    logging.debug("writing to c++ files")

    tree_filename = out_filename + '_tree'
    global asic_name
    asic_name = os.path.basename(out_filename).lower()

    asic_path = 'lbr_params_{}'.format(asic_name)
    asic_module = asic_path.replace('/', '.')

    global asic_params
    asic_params = importlib.import_module(asic_module)

    # C++ namespace for global types that are declared outside of device_class
    device_namespace = get_device_namespace(asic_name)

    with open(tree_filename + '.h', 'w') as h_file:
        device_class = asic_name.upper() + '_TREE'

        logging.debug("writing to %s", out_filename + '_tree.h')

        writer = indented_writer(h_file)

        write_api_header_h_file(writer, device_class)
        write_classes_h_file(writer, flat_classes, lbr_parsed, blockname_uid_list)
        write_api_footer_h_file(writer, device_class)

        del writer

    with open(tree_filename + '.cpp', 'w') as cpp_file:
        logging.debug("writing to %s", tree_filename + '.cpp')

        writer = indented_writer(cpp_file)

        write_api_header_cpp_file(writer, tree_filename)
        write_device_top_func_cpp_file(writer, sw_paths_with_uid, flat_classes, lbr_parsed, sbif_overrides)
        write_api_footer_cpp_file(writer)

        del writer

    with open(out_filename + '_reg_structs.h', 'w') as struct_h_file:
        logging.debug("writing to %s", out_filename + '_reg_structs' + '.h')
        device_class = asic_name.upper() + '_REG_STRUCTS'

        writer = indented_writer(struct_h_file)

        lst_includes = ['common/bit_utils.h', 'common/bit_vector.h']
        write_api_header_h_file(writer, device_class, lst_includes)
        write_namespace_begin(writer, device_namespace)
        write_reg_structs_h_file(writer, lbr_parsed)
        write_namespace_end(writer, device_namespace)
        write_api_footer_h_file(writer, device_class)

        del writer

    with open(out_filename + '_mem_structs.h', 'w') as mem_struct_h_file:
        logging.debug("writing to %s", out_filename + '_mem_structs' + '.h')
        device_class = asic_name.upper() + '_MEM_STRUCTS'

        writer = indented_writer(mem_struct_h_file)

        lst_includes = ['common/bit_utils.h', 'common/bit_vector.h']
        write_api_header_h_file(writer, device_class, lst_includes)
        write_namespace_begin(writer, device_namespace)
        write_mem_structs_h_file(writer, lbr_parsed)
        write_namespace_end(writer, device_namespace)
        write_api_footer_h_file(writer, device_class)

        del writer


def create_json_file(out_filename, lbr_parsed):
    json_file = out_filename + '_tree.json'
    logging.debug("writing to %s", json_file)
    write_json_file(json_file, lbr_parsed)


# @brief Writes SWIG file based on the collected data
#
# Writes a .i file based on the collected data from the input file.
# The swig file contains template instantiations
#
# @param[in] out_filename               The output SWIG path+basename to use
# @param[in] flat_classes               A list of classes with their members
def create_swig_file(out_filename, flat_classes):
    logging.debug("writing to SWIG file")

    asic_name = os.path.basename(out_filename).lower()
    with open(out_filename + '_tree.i', 'w') as i_file:
        device_class = asic_name.upper() + '_TREE'

        logging.debug("writing to %s", out_filename + '_tree.i')

        writer = indented_writer(i_file)

        write_header_i_file(writer, device_class)
        write_block_templates_i_file(writer, flat_classes)

        del writer


def get_device_namespace(asic_name):
    if asic_name == PACIFIC_ASIC_NAME:
        return None
    return asic_name


def write_namespace_using(writer, namespace):
    if namespace:
        writer.write("using namespace {};\n\n".format(namespace))


# @brief Writes the header of the .h file
#
# @param[in] writer         The file writer that supports indenting
# @param[in] device_class   A string represeting the current device.
def write_api_header_h_file(writer, device_class, additional_includes=[]):
    header_define = "__" + device_class + "_H__"

    writer.depth = 0
    logging.debug("writing header in .h")
    writer.write(
        "// This file has been automatically generated using lbr_api_generator.py on {:%Y-%m-%d %H:%M:%S}. Do not edit it manually.\n".format(
            datetime.datetime.now()))
    writer.write("// \n\n")
    writer.write('#include <array>\n')
    writer.write("\n")
    writer.write('#include "common/logger.h"\n')
    writer.write('#include "lld/lld_register.h"\n')
    writer.write('#include "lld/lld_storage.h"\n')
    writer.write('#include "lld/lld_memory.h"\n')
    writer.write('#include "lld/lld_block.h"\n')
    for include in additional_includes:
        writer.write('#include \"{0}\"\n'.format(include))

    writer.write("\n")
    writer.write("#ifndef {0}\n".format(header_define))
    writer.write("#define {0}\n\n".format(header_define))
    write_sbus_block_defines(writer)
    write_namespace_begin(writer, 'silicon_one')


# @brief Writes the C++ #define directives used to identify and translate SBUS block IDs
#
# @param[in] writer         The file writer that supports indenting
def write_sbus_block_defines(writer):
    # TODO - remove
    writer.write("#define LLD_GET_SBUS_BLOCK_ID_FOR_CIF(n) ((n << 16) | LLD_BLOCK_ID_SBUS_BASE )\n")
    writer.write("\n")


# @brief Writes the enums of block_id, registers and memories
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] lbr_parsed             The parsed LBR data (blocks and their regs/mems/reg_fields)
# @param[in] blockname_uid_list     A list of blockname and its ID
def write_enums_h_file(writer, lbr_parsed, blockname_uid_list):
    # write the block_id enum
    logging.debug("writing block_id enum")
    write_block_id_enum_h_file(writer, blockname_uid_list)

    # write the registers enum
    logging.debug("writing registers enum")
    write_storage_type_enum_h_file(writer, lbr_parsed, 'register', 'Registers')

    # write the memories enum
    logging.debug("writing memories enum")
    write_storage_type_enum_h_file(writer, lbr_parsed, 'memory', 'Memories')

    # write the Register Fields enum
    logging.debug("writing register fields enum")
    write_register_field_enum_h_file(writer, lbr_parsed)


# @brief Writes the block_ids enum
#
# Writes the block_ids enum, with the ID as the value of each member of the enum.
# The value of SBUS blocks is based on the block_id of their CIF hosting block.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] blockname_uid_list     A list of blockname and its ID


def write_block_id_enum_h_file(writer, blockname_uid_list):
    writer.write("/// @brief Block_id definitions\n")

    # build and write the enum declaration
    prefixed_enum_base_name = "{0}_block_id".format(lld_prefix)
    enum_declaration_str = "enum {0}_e".format(prefixed_enum_base_name)
    enum_declaration_str += " {\n"
    writer.write(enum_declaration_str)
    writer.depth += 1

    prev_source_of_entry = None  # this is used to print comment lines

    c_block_uid_enum_name = ''  # this is needed out the loop to write the LAST enum
    for block_uid_data in blockname_uid_list:
        if prev_source_of_entry != block_uid_data['source']:
            comment_str = "// blocks from {0} file\n".format(block_uid_data['source'])
            writer.write(comment_str)
            prev_source_of_entry = block_uid_data['source']

        if block_uid_data['entry_type'] == 'dummy_entry':   # dummy entries represent custom enum entries. in the UID field
            custom_entry_name = block_uid_data['blockname']
            c_custom_entry_enum_name = (prefixed_enum_base_name + "_" + custom_entry_name).upper()
            c_custom_entry_enum_val = block_uid_data['uid']
            c_custom_entry_enum_comment = block_uid_data['description']

            block_uid_data['c_enum_name'] = c_custom_entry_enum_name

            writer.write("{0} = {1}, ///< {2}\n".format(c_custom_entry_enum_name,
                                                        c_custom_entry_enum_val, c_custom_entry_enum_comment))

        else:
            verilog_blockname = block_uid_data['verilog_blockname']
            # if the blockname ends with _UID then remove it
            verilog_blockname = re.sub(r'_UID$', '', verilog_blockname)

            c_block_uid_enum_name = (prefixed_enum_base_name + "_" + verilog_blockname).upper()
            block_uid_data['c_enum_name'] = c_block_uid_enum_name

            if block_uid_data['entry_type'] == 'LBR_block_sbus':
                parent_block_uid_data = block_uid_data['parent_block_uid_data']
                parent_block_enum_name = parent_block_uid_data['c_enum_name']
                parent_block_verilog_name = parent_block_uid_data['verilog_blockname']

                c_block_uid_formula = "LLD_GET_SBUS_BLOCK_ID_FOR_CIF({0})".format(parent_block_enum_name)
                c_block_uid_enum_comment = "SBUS master on {0}".format(parent_block_verilog_name)
            else:  # block_uid_data['entry_type'] == 'LBR_block'
                math_formula = block_uid_data['math_formula']
                c_block_uid_formula = ''
                for formula_element in math_formula:
                    uid_element_value, shift_left = formula_element
                    if c_block_uid_formula != '':  # if the formula is not empty, then need to add the prev value to the new
                        c_block_uid_formula += " + "
                    if shift_left != 0:
                        new_element_str = "({0}<<{1})".format(uid_element_value, shift_left)
                    else:
                        # if shiftleft = 0, then there is nothing to do. this is for the last element of the formula (the LSB value)
                        new_element_str = "{0}".format(uid_element_value)
                    c_block_uid_formula = "({0}{1})".format(c_block_uid_formula, new_element_str)

                c_block_uid_enum_comment = "=" + str(block_uid_data['uid_value'])

                if 'description' in block_uid_data:
                    c_block_uid_enum_comment = block_uid_data['description']

            writer.write("{0} = {1}, ///< {2}\n".format(c_block_uid_enum_name, c_block_uid_formula, c_block_uid_enum_comment))

    writer.depth -= 1
    writer.write("};\n\n")  # close the enum

# @brief JSON "Description" field to CPP Doxygen format.
#
# @param[in] json_desc     JSON description
#
# @return Description in CPP Doxygen format.


def translate_json_desc_to_cpp_doxygen(json_desc_str):
    # Translate "<XXX>" to "(XXX)" since "<XXX>" should be a valid xml/html tag.
    cpp_desc_str = re.sub(r'<(\w+)>', r'(\1)', json_desc_str)

    return cpp_desc_str

# @brief JSON "Description" field to CPP format.
#
# @param[in] json_desc     JSON description
#
# @return Description in CPP format.


def translate_json_desc_to_cpp(json_desc_str):
    # Translate "\#" to "#"
    cpp_desc_str = re.sub(r'\\#', r'#', json_desc_str)

    return cpp_desc_str

# @brief Writes an enum for a storage type of a block. Used to write register/memory enums
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] lbr_parsed             The parsed LBR data (blocks and their regs/mems/reg_fields)
# @param[in] enum_base_name         The base name of an enum. For a base_name = 'register' the enum 'register_e' will be created.
# @param[in] storage_type_name      The name of the storage type, as it appears in the parsed LBR ('Registers' or 'Memories')


def write_storage_type_enum_h_file(writer, lbr_parsed, enum_base_name, storage_type_name):
    enum_comment_str = "/// @brief {0} definitions\n".format(storage_type_name)
    writer.write(enum_comment_str)

    # build and write the enum declaration
    prefixed_enum_base_name = "{0}_{1}".format(lld_prefix, enum_base_name)
    enum_declaration_str = "enum {0}_e".format(prefixed_enum_base_name)
    enum_declaration_str += " {\n"
    writer.write(enum_declaration_str)

    writer.depth += 1
    c_storage_enum_name = ""
    for lbr_name in lbr_parsed:
        block_name = lbr_name.upper()
        logging.debug("writing %s of block %s ", storage_type_name, block_name)
        writer.write("// Start of {0} block\n".format(block_name))

        # Generate enum entries for rev1 and rev2
        for storage in lbr_parsed[lbr_name][storage_type_name]:
            revisions = [storage] + [r['regmem_dict'] for r in storage['OtherRevisions']]
            for storage_dict in revisions:
                # On Pacific, add revision prefix if there are two revisions of the same thing.
                if asic_name == PACIFIC_ASIC_NAME and len(revisions) > 1:
                    revision_prefix = asic_params.REVISION_PREFIX[storage_dict['RevisionName']]
                else:
                    revision_prefix = ''

                c_storage_enum_name = (prefixed_enum_base_name + "_" + block_name + "_" +
                                       revision_prefix + storage_dict['Name']).upper()
                c_storage_enum_comment = storage_dict['Description']
                c_storage_enum_comment = translate_json_desc_to_cpp_doxygen(c_storage_enum_comment)
                writer.write("{0}, ///< {1}: {2}\n".format(c_storage_enum_name, block_name, c_storage_enum_comment))
                storage_dict['c_enum_name'] = c_storage_enum_name

        writer.write_noindent("\n")
    last_member_str = "{0}_{1}_LAST = {2}\n".format(lld_prefix, enum_base_name, c_storage_enum_name)
    writer.write(last_member_str.upper())
    writer.depth -= 1
    writer.write("};\n\n")  # close the enum


# @brief Writes enum of register fields
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] lbr_parsed             The parsed LBR data (blocks and their regs/mems/reg_fields)
def write_register_field_enum_h_file(writer, lbr_parsed):
    writer.write("/// @brief Register Fields definitions\n")

    # build and write the enum declaration
    prefixed_enum_base_name = "{0}_register_field".format(lld_prefix)
    enum_declaration_str = "enum {0}_e".format(prefixed_enum_base_name)
    enum_declaration_str += " {\n"
    writer.write(enum_declaration_str)
    writer.depth += 1

    c_field_enum_name = ''
    for lbr_name in lbr_parsed:
        block_name = lbr_name.upper()
        logging.debug("writing register fields of block %s ", block_name)
        writer.write("// Start of {0} block\n".format(block_name))
        block_registers = lbr_parsed[lbr_name]['Registers']
        for reg_dict in block_registers:
            reg_name = reg_dict['Name']
            writer.write("// Start of {0} register\n".format(reg_name))
            register_fields = reg_dict['Fields']
            for field_data in register_fields:
                field_name = field_data['Name']
                c_field_enum_name = (prefixed_enum_base_name + "_" + block_name + "_" + reg_name + "_" + field_name).upper()
                c_field_enum_comment = field_data['Description']
                c_field_enum_comment = translate_json_desc_to_cpp_doxygen(c_field_enum_comment)
                writer.write("{0}, ///< {1}: {2}\n".format(c_field_enum_name, block_name, c_field_enum_comment))
        writer.write_noindent("\n")
    writer.write("{0}_REGISTER_FIELD_LAST = {1}\n".format(lld_prefix.upper(), c_field_enum_name))
    writer.depth -= 1
    writer.write("};\n\n")  # close the enum


# @brief Writing a register/memory field setter for arrayed field.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] buf_width              Type length to use 8/32/64.
# @param[in] field_offset           Field offset in the register.
# @param[in] field_dict             Dictionary with all field's attributes.
def write_register_memory_field_array_setter(writer, buf_width, field_offset, field_dict, element_width):
    logging.debug("Writing array setter function to '%s'", field_dict['Name'])
    num_bytes = (element_width // buf_width) + 1
    writer.write("void set_{0} (uint64_t index, uint64_t val)\n".format(field_dict['Name']))
    writer.write("{\n")
    writer.depth += 1
    writer.write("if (index >= ({0} / {1}) || val > ((1ull << {1}) - 1))\n".format(field_dict['Width'], element_width))
    writer.depth += 1
    writer.write("return;\n")
    writer.depth -= 1
    writer.write(
        "bit_utils::set_bits((uint{0}_t*) this, {1} + ((index + 1) * {2}) - 1, {1} + (index * {2}), (const uint{0}_t*) &val);\n".format(
            buf_width,
            field_offset,
            element_width))
    writer.depth -= 1
    writer.write("}\n")


# @brief Getting register field for arrayed field.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] buf_width              Type length to use 8/32/64.
# @param[in] field_offset           Field offset in the register.
# @param[in] field_dict             Dictionary with all field's attributes.
def write_register_memory_field_array_getter(writer, buf_width, field_offset, field_dict, element_width):
    logging.debug("Writing array setter function to '%s'", field_dict['Name'])
    num_bytes = (element_width // buf_width) + 1
    writer.write("uint{0}_t get_{1} (size_t index)\n".format(buf_width, field_dict['Name']))
    writer.write("{\n")
    writer.depth += 1
    writer.write("if (index >= ({0} / {1}))\n".format(field_dict['Width'], element_width))
    writer.depth += 1
    writer.write("return 0;\n")
    writer.depth -= 1
    writer.write("uint{0}_t val = 0;\n".format(buf_width))
    writer.write(
        "bit_utils::get_bits((const uint{0}_t*) this, {1} + ((index + 1) * {2} - 1), {1} + (index * {2}), &val);\n".format(
            buf_width,
            field_offset,
            element_width))
    writer.write("return val;\n")
    writer.depth -= 1
    writer.write("}\n")

# @brief Getting register field length for arrayed field.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] field_dict             Dictionary with all field's attributes.


def write_register_memory_field_array_size(writer, field_dict, element_width):
    logging.debug("Writing array length function to '%s'", field_dict['Name'])
    writer.write("static size_t get_{0}_array_size()\n".format(field_dict['Name']))
    writer.write("{\n")
    writer.depth += 1
    writer.write("return ({0} / {1});\n".format(field_dict['Width'], element_width))
    writer.depth -= 1
    writer.write("}\n")

# @brief Writing a register/memory field setter for large field.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] buf_width              Type length to use 8/32/64.
# @param[in] field_offset           Field offset in the register.
# @param[in] field_dict             Dictionary with all field's attributes.
# @param[in] field_width            Total width of the entire field.


def write_long_register_memory_field_setter(writer, buf_width, field_offset, field_dict, field_width):
    logging.debug("Writing long-field setter function to '%s'", field_dict['Name'])
    writer.write("void set_{0} (const uint{1}_t* val)\n".format(field_dict['Name'], buf_width))
    writer.write("{\n")
    writer.depth += 1
    writer.write("bit_utils::set_bits((uint{0}_t*) this, {2}, {1}, val);\n".format(buf_width,
                                                                                   field_offset, field_offset + field_width - 1))
    writer.depth -= 1
    writer.write("}\n")


# @brief Writing a register/memory field getter for large field.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] buf_width              Type length to use 8/32/64.
# @param[in] field_offset           Field offset in the register.
# @param[in] field_dict             Dictionary with all field's attributes.
# @param[in] field_width            Total width of the entire field.
def write_long_register_memory_field_getter(writer, buf_width, field_offset, field_dict, field_width):
    logging.debug("Writing long-field setter function to '%s'", field_dict['Name'])
    writer.write("void get_{0} (uint{1}_t* val)\n".format(field_dict['Name'], buf_width))
    writer.write("{\n")
    writer.depth += 1
    writer.write("bit_utils::get_bits((uint{0}_t*) this, {2}, {1}, val);\n".format(buf_width,
                                                                                   field_offset, field_offset + field_width - 1))
    writer.depth -= 1
    writer.write("}\n")


# @brief Get a register/memory field width enum.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] field_dict             Dictionary with all field's attributes.
# @param[in] element_width          Element width.
def get_register_memory_field_width_enum_str(writer, field_dict, element_width):
    logging.debug("Writing enum for '%s' width", field_dict['Name'])
    width_name = "{0}_WIDTH".format(field_dict['Name'].upper())
    # SIZE_WIDTH gets clobbered by standard C macro
    if (width_name == "SIZE_WIDTH"):
        width_name = "_SIZE_WIDTH"
    return "{0} = {1}".format(width_name, element_width)


# @brief Writing a register/memory field line(s) in the structs.h file.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] max_width              Max width of the field.
# @param[in] buf_width              Type length to use 8/32/64.
# @param[in] field_dict             Dictionary describing the field.


def write_register_memory_field_structs_h_file(writer, max_width, buf_width, field_dict):
    logging.debug("Writing register/memory field '%s'", field_dict['Name'])
    field_name = field_dict['Name']
    field_width = field_dict['Width']
    description = field_dict['Description']
    num_parts = ((field_width - 1) // max_width) + 1

    if (field_width > max_width):
        i = 0
        field_name = field_name + "_p"
        while (field_width > 0):
            field_name_p = field_name + str(i)
            field_width_p = min(field_width, max_width)
            c_field_enum_comment = description + " (part " + str(i) + " of " + str(num_parts) + ")"
            c_field_enum_comment = translate_json_desc_to_cpp_doxygen(c_field_enum_comment)
            writer.write("uint{0}_t {1} : {2}; ///< {3}\n".format(max_width,
                                                                  field_name_p, field_width_p, c_field_enum_comment))
            i += 1
            field_width -= max_width

    else:
        c_field_enum_comment = description
        c_field_enum_comment = translate_json_desc_to_cpp_doxygen(c_field_enum_comment)
        writer.write("uint{0}_t {1} : {2}; ///< {3}\n".format(max_width, field_name, field_width, c_field_enum_comment))

    return field_dict['Width']


# @brief Writing a register line(s) in the structs.h file.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] max_width              Max width of each field.
# @param[in] buf_width              Type length to use 8/32/64.
# @param[in] block_name             Block owns the register.
# @param[in] reg_dict               Reg data.
# @param[in] add_revision_prefix    Whether to add revision prefix to the union name
# @param[in] write_common_typedef   Whether to write a common revision-less typedef.
def write_register_structs_h_file(
        writer,
        max_width,
        buf_width,
        block_name,
        reg_dict,
        add_revision_prefix=False,
        write_common_typedef=False):

    prefix = asic_params.REVISION_PREFIX[reg_dict['RevisionName']]
    if not add_revision_prefix:
        prefix = ''

    reg_name = reg_dict['Name'].lower()
    reg_dict['block_member_name'] = '{}_{}{}'.format(block_name, prefix, reg_name)
    type_name = reg_dict['block_member_name'] + '_register'

    if write_common_typedef:
        if len(prefix) > 0:
            writer.write("// Common type for multiple revisions but identical bit fields.\n")
            common_type_name = "{0}_{1}_register".format(block_name, reg_name)
            writer.write("using {} = {};\n\n".format(common_type_name, type_name))
        return

    register_fields = reg_dict['Fields']
    offset = 0
    c_reg_width_in_bits = int(reg_dict['Width'])
    c_reg_width_in_bytes = width_in_bytes(c_reg_width_in_bits)
    writer.write("union {} {{\n".format(type_name))
    writer.depth += 1
    writer.write("enum {{ SIZE = {0}, SIZE_IN_BITS = {1} }};\n\n".format(c_reg_width_in_bytes, c_reg_width_in_bits))
    writer.write("struct fields {\n")
    writer.depth += 1
    lst_offsets = []
    current_offset = 0
    for field_dict in register_fields:
        lst_offsets.append(current_offset)
        current_offset += write_register_memory_field_structs_h_file(writer, max_width, buf_width, field_dict)

    padding_width = max_width - (current_offset % max_width)
    if padding_width < max_width:
        writer.write("uint{0}_t dummy_padding : {1}; ///< Padding\n".format(max_width, padding_width))

    i = 0
    enum_strs = []
    for field_dict in register_fields:
        array_item_width = field_dict['ArrayItemWidth']
        array_element_width = None if ('ArrayElementWidth' not in field_dict) else field_dict['ArrayElementWidth']
        is_itemized_field = (array_item_width is not None) or (array_element_width is not None)
        if is_itemized_field:
            if (array_item_width is not None) and (array_element_width is not None) and (array_item_width is not array_element_width):
                raise Exception(
                    "Itemized field refers to contradicting item width info. block = {}, register = {}, field = {}, array_item_width (from lbr) = {}, array_element_width (from 'lbr_overrides.json') = {}".format(
                        block_name,
                        reg_dict['Name'],
                        field_dict['Name'],
                        array_item_width,
                        array_element_width))

            element_width = array_item_width if (array_item_width is not None) else array_element_width

            if element_width < max_width:
                write_register_memory_field_array_setter(writer, buf_width, lst_offsets[i], field_dict, element_width)
                write_register_memory_field_array_getter(writer, buf_width, lst_offsets[i], field_dict, element_width)
                write_register_memory_field_array_size(writer, field_dict, element_width)
            else:
                write_long_register_memory_field_setter(writer, buf_width, lst_offsets[i], field_dict, element_width)
                write_long_register_memory_field_getter(writer, buf_width, lst_offsets[i], field_dict, element_width)
        else:
            element_width = field_dict['Width']
            if element_width > max_width:
                write_long_register_memory_field_setter(writer, buf_width, lst_offsets[i], field_dict, element_width)
                write_long_register_memory_field_getter(writer, buf_width, lst_offsets[i], field_dict, element_width)

        enum_strs.append(get_register_memory_field_width_enum_str(writer, field_dict, element_width))
        i += 1

    writer.write_noindent("\n")
    writer.write("enum {\n")
    writer.depth += 1
    for s in enum_strs:
        writer.write("{0},\n".format(s))
    writer.depth -= 1
    writer.write("};\n")

    writer.depth -= 1
    writer.write("} fields;\n")
    writer.write_noindent("\n")
    writer.write("uint8_t u8[SIZE];\n".format(c_reg_width_in_bytes))
    writer.write_noindent("\n")
    writer.write(
        "inline operator bit_vector() { uint64_t* storage = (uint64_t*)this; return bit_vector(storage, SIZE_IN_BITS); }\n")
    writer.depth -= 1
    writer.write("};\n\n")


# @brief Writes structs of register fields
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] lbr_parsed             The parsed LBR data (blocks and their regs/mems/reg_fields)
def write_reg_structs_h_file(writer, lbr_parsed):
    field_max_width = 64
    buffer_width = 64
    writer.write("\n")
    writer.write("/// @brief Register Fields definitions\n")
    writer.write("#pragma pack(push, 1)\n")
    # build and write the struct declaration
    for lbr_name in lbr_parsed:
        block_name = lbr_name.lower()
        logging.debug("writing register struct fields of block %s ", block_name)
        writer.write("// Start of {0} block\n".format(block_name))
        block_registers = lbr_parsed[lbr_name]['Registers']
        for reg in block_registers:
            revisions = [reg] + [r['regmem_dict'] for r in reg['OtherRevisions']]

            if len(revisions) == 1:
                # Single revision
                write_register_structs_h_file(writer, field_max_width, buffer_width, block_name, reg, add_revision_prefix=False)
            else:
                # Multiple revisions
                for r in revisions:
                    write_register_structs_h_file(writer, field_max_width, buffer_width, block_name, r, add_revision_prefix=True)
                revisions_have_field_diffs = len([r['regmem_dict'] for r in reg['OtherRevisions'] if r['fields_diff']])
                if not revisions_have_field_diffs:
                    # Write a common typedef if multiple revisions have identical bit fields.
                    write_register_structs_h_file(writer, field_max_width, buffer_width, block_name,
                                                  reg, add_revision_prefix=True, write_common_typedef=True)

    writer.write("#pragma pack(pop)\n")


# @brief Writing a memory line(s) in the structs.h file.
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] max_width              Max width of each field.
# @param[in] buf_width              Type length to use 8/32/64.
# @param[in] block_name             Block owns the memory.
# @param[in] mem_dict               Memory data.
# @param[in] add_revision_prefix    Whether to add revision prefix to the union name
# @param[in] write_common_typedef   Whether to write a common revision-less typedef.
def write_memory_structs_h_file(
        writer,
        max_width,
        buf_width,
        block_name,
        mem_dict,
        add_revision_prefix=False,
        write_common_typedef=False):

    prefix = asic_params.REVISION_PREFIX[mem_dict['RevisionName']]
    if not add_revision_prefix:
        prefix = ''

    mem_name = mem_dict['Name'].lower()
    mem_dict['block_member_name'] = '{}_{}{}'.format(block_name, prefix, mem_name)
    type_name = mem_dict['block_member_name'] + '_memory'

    if write_common_typedef:
        if len(prefix) > 0:
            writer.write("// Common type for multiple revisions but identical bit fields.\n")
            common_type_name = "{0}_{1}_memory".format(block_name, mem_name)
            writer.write("using {} = {};\n\n".format(common_type_name, type_name))
        else:
            pass  # empty prefix, nothing to do because typedef would be identical to the actual struct
        return

    memory_fields = mem_dict['Fields']
    offset = 0
    c_mem_width_in_bits = int(mem_dict['MemTotalWidth'])
    c_mem_width_in_bytes = width_in_bytes(c_mem_width_in_bits)
    c_logical_mem_width_in_bits = int(mem_dict['MemLogicalWidth'])
    writer.write("// Start of {0} memory\n".format(mem_name))
    writer.write("union {} {{\n".format(type_name))
    writer.depth += 1
    writer.write("enum {{ SIZE = {0}, SIZE_IN_BITS = {1}, SIZE_IN_BITS_WO_ECC = {2} }};\n\n".format(
        c_mem_width_in_bytes, c_mem_width_in_bits, c_logical_mem_width_in_bits))
    writer.write("struct fields {\n")
    writer.depth += 1
    lst_offsets = []
    current_offset = 0
    memory_fields_with_ecc = memory_fields.copy()
    if c_logical_mem_width_in_bits != c_mem_width_in_bits:
        c_mem_ecc_width_in_bits = c_mem_width_in_bits - c_logical_mem_width_in_bits
        ecc_dict = {}
        ecc_dict['Name'] = 'hw_ecc'
        ecc_dict['Width'] = c_mem_ecc_width_in_bits
        ecc_dict['Description'] = 'HW-implemented ECC'
        memory_fields_with_ecc.append(ecc_dict)

    for field_dict in memory_fields_with_ecc:
        lst_offsets.append(current_offset)
        current_offset += write_register_memory_field_structs_h_file(writer, max_width, buf_width, field_dict)

    padding_width = max_width - (current_offset % max_width)
    if padding_width < max_width:
        writer.write("uint{0}_t dummy_padding : {1}; ///< Padding\n".format(max_width, padding_width))

    i = 0
    enum_strs = []
    for field_dict in memory_fields_with_ecc:
        array_item_width = None if ('ArrayItemWidth' not in field_dict) else field_dict['ArrayItemWidth']
        array_element_width = None if ('ArrayElementWidth' not in field_dict) else field_dict['ArrayElementWidth']
        is_itemized_field = (array_item_width is not None) or (array_element_width is not None)
        if is_itemized_field:
            if (array_item_width is not None) and (array_element_width is not None) and (array_item_width is not array_element_width):
                raise Exception(
                    "Itemized field refers to contradicting item width info. block = {}, memory = {}, field = {}, array_item_width (from lbr) = {}, array_element_width (from 'lbr_overrides.json') = {}".format(
                        block_name,
                        mem_dict['Name'],
                        field_dict['Name'],
                        array_item_width,
                        array_element_width))

            element_width = array_item_width if (array_item_width is not None) else array_element_width

            if element_width < max_width:
                write_register_memory_field_array_setter(writer, buf_width, lst_offsets[i], field_dict, element_width)
                write_register_memory_field_array_getter(writer, buf_width, lst_offsets[i], field_dict, element_width)
                write_register_memory_field_array_size(writer, field_dict, element_width)
            else:
                write_long_register_memory_field_setter(writer, buf_width, lst_offsets[i], field_dict, element_width)
                write_long_register_memory_field_getter(writer, buf_width, lst_offsets[i], field_dict, element_width)
        else:
            element_width = field_dict['Width']
            if element_width > max_width:
                write_long_register_memory_field_setter(writer, buf_width, lst_offsets[i], field_dict, element_width)
                write_long_register_memory_field_getter(writer, buf_width, lst_offsets[i], field_dict, element_width)

        enum_strs.append(get_register_memory_field_width_enum_str(writer, field_dict, element_width))
        i += 1

    writer.write_noindent("\n")
    writer.write("enum {\n")
    writer.depth += 1
    for s in enum_strs:
        writer.write("{0},\n".format(s))
    writer.depth -= 1
    writer.write("};\n")

    writer.depth -= 1
    writer.write("} fields;\n")
    writer.write_noindent("\n")
    writer.write("uint8_t u8[SIZE];\n".format(c_mem_width_in_bytes))
    writer.write_noindent("\n")
    writer.write(
        "inline operator bit_vector() { uint64_t* storage = (uint64_t*)this; return bit_vector(storage, SIZE_IN_BITS_WO_ECC); }\n")
    writer.depth -= 1
    writer.write("};\n\n")

# @brief Writes structs of memory fields
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] lbr_parsed             The parsed LBR data (blocks and their regs/mems/reg_fields)


def write_mem_structs_h_file(writer, lbr_parsed):
    field_max_width = 64
    buffer_width = 64
    writer.write("\n")
    writer.write("/// @brief Memory Fields definitions\n")
    writer.write("#pragma pack(push, 1)\n")
    # build and write the struct declaration
    for lbr_name in lbr_parsed:
        block_name = lbr_name.lower()
        logging.debug("writing memory struct fields of block %s ", block_name)
        writer.write("// Start of {0} block\n".format(block_name))
        block_memories = lbr_parsed[lbr_name]['Memories']
        for mem in block_memories:
            revisions = [mem] + [m['regmem_dict'] for m in mem['OtherRevisions']]

            if len(revisions) == 1:
                # Single revision
                write_memory_structs_h_file(writer, field_max_width, buffer_width, block_name, mem, add_revision_prefix=False)
            else:
                # Multiple revisions
                for m in revisions:
                    write_memory_structs_h_file(writer, field_max_width, buffer_width, block_name, m, add_revision_prefix=True)

                revisions_have_field_diffs = len([m['regmem_dict'] for m in mem['OtherRevisions'] if m['fields_diff']])
                if not revisions_have_field_diffs:
                    # Write a common typedef if multiple revisions have identical bit fields.
                    write_memory_structs_h_file(writer, field_max_width, buffer_width, block_name, mem,
                                                add_revision_prefix=True, write_common_typedef=True)

    writer.write("#pragma pack(pop)\n")


# @brief Writes JSON describing the HW
#
# @param[in] writer                 The file writer that supports indenting
# @param[in] lbr_parsed             The parsed LBR data (blocks and their regs/mems/reg_fields)
def write_json_file(file_name, lbr_parsed):
    members = {}
    for lbr_name in lbr_parsed:
        block_name = lbr_name.lower()

        # Write registers
        block_registers = lbr_parsed[lbr_name]['Registers']
        for reg_dict in block_registers:
            revisions = [reg_dict] + [r['regmem_dict'] for r in reg_dict['OtherRevisions']]
            for r in revisions:
                block_member_name = r['block_member_name']
                member_dict = {}
                member_dict['type'] = 'register'
                member_dict['block'] = block_name
                member_dict['width'] = int(r['Width'])
                member_dict['desc'] = r['Description']
                fields = []
                offset = 0
                member_fields = r['Fields']
                for field_dict in member_fields:
                    field_name = field_dict['Name']
                    field_width = field_dict['Width']
                    fields.append([field_name, offset, field_width])
                    offset += field_width

                member_dict['fields'] = fields
                members[block_member_name] = member_dict

        # Write memories
        block_memories = lbr_parsed[lbr_name]['Memories']
        for mem_dict in block_memories:
            revisions = [mem_dict] + [m['regmem_dict'] for m in mem_dict['OtherRevisions']]
            for m in revisions:
                block_member_name = m['block_member_name']
                member_dict = {}
                member_dict['type'] = 'memory'
                member_dict['block'] = block_name
                member_dict['width'] = int(m['MemLogicalWidth'])
                member_dict['desc'] = m['Description']
                fields = []
                offset = 0
                member_fields = m['Fields']
                for field_dict in member_fields:
                    field_name = field_dict['Name']
                    field_width = field_dict['Width']
                    fields.append([field_name, offset, field_width])
                    offset += field_width

                member_dict['fields'] = fields
                members[block_member_name] = member_dict

    with open(file_name, 'w') as outfile:
        json.dump(members, outfile, indent=2)


# @brief Writes the declaration of classes, and their member fields and functions
#
# The flat_classes is a list of classes that should be created. There are classes for each node in the path tree.
# Each class can have (one or more) the following properites: a tree-root, a middle-node of the path tree, a LBR-block node.
# Each class defines its member fields and methods.
# A tree-root class has a special initialize_valid_blocks() method that initializes the block_ids of all LBR blocks in the tree.
# The middle-node class has the next tree steps as its members
# The LBR-block class has the block's regs/mems as members
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] flat_classes               A list of classes with their members
# @param[in] lbr_parsed                 The parsed LBR data (blocks and their regs/mems/reg_fields)
def write_classes_h_file(writer, flat_classes, lbr_parsed, blockname_uid_list):
    writer.depth = 0
    writer.write("\n")

    # write the classes of the register path
    logging.debug("writing path classes and members")

    # the class appearance is ordered by the path depth, and then alphabetically
    def classes_sorter(entry): return (entry['depth'], entry['class_name'])
    flat_classes_list = sorted(flat_classes.values(), key=classes_sorter)

    # traverse the list in reverse, becase the leaf blocks/classes need to be declared before the classes that use them
    for class_data in reversed(flat_classes_list):
        class_name = class_data['class_name']
        class_declaration_str = "class {0} : public lld_block\n".format(class_name)
        logging.debug("writing path class_name=%s", class_name)

        writer.write(class_declaration_str)
        writer.write("{\n")
        writer.write("\nCEREAL_SUPPORT_PRIVATE_MEMBERS\n")
        writer.write("public:\n")
        writer.depth += 1

        # write the members of the class that are used as a path for inner leafs
        write_class_path_members(writer, class_data)

        # write the members of the class that represent registers and memories
        write_class_reg_mem_members(writer, class_data, lbr_parsed)

        # Declare constructor function.
        # device_tree should be created using the static device_tree::create function,
        # and so its constructor is private.
        if class_data['depth'] != 0:
            writer.write("// C'tors\n")
            writer.write("{}(la_device_revision_e revision);\n".format(class_name))
            writer.write("{}() = default; // used by serialization\n\n".format(class_name))

        # the top-level path (e.g. pacific) triggers the initialization of all blocks with their uids
        if class_data['depth'] == 0:
            write_enums_h_file(writer, lbr_parsed, blockname_uid_list)

            writer.write("static std::shared_ptr<%s> create(la_device_revision_e revision);\n" % class_name)
            writer.write("lld_block_scptr get_block(la_block_id_t block_id) const;\n")
            writer.write("static lld_register_desc_t get_register_desc(uint32_t register_num);\n")
            writer.write("static lld_memory_desc_t get_memory_desc(uint32_t memory_num);\n")

            # declare get reg/mem functions
            writer.write("\n")
            function_str = "lld_register_scptr get_register(la_block_id_t block_id, la_entry_addr_t addr) const;\n"
            writer.write(function_str)
            function_str = "lld_register_scptr get_register(la_block_id_t block_id, lld_register_e reg_id, size_t arr_idx) const;\n"
            writer.write(function_str)
            function_str = "lld_register_scptr get_register(la_block_id_t block_id, lld_register_e reg_id) const;\n"
            writer.write(function_str)

            writer.write("\n")

            function_str = "lld_memory_scptr get_memory(la_block_id_t block_id, la_entry_addr_t addr) const;\n"
            writer.write(function_str)
            function_str = "lld_memory_scptr get_memory(la_block_id_t block_id, lld_memory_e mem_id, size_t arr_idx) const;\n"
            writer.write(function_str)
            function_str = "lld_memory_scptr get_memory(la_block_id_t block_id, lld_memory_e mem_id) const;\n"
            writer.write(function_str)

            writer.write("\n")

            # declare private
            writer.write("\n")
            writer.depth -= 1
            writer.write("private:\n")
            writer.depth += 1
            # declare private members
            writer.write("std::map< la_block_id_t, lld_block_scptr > m_leaf_blocks;\n")

            # declare private functions
            writer.write("// C'tor\n")
            writer.write("{}(la_device_revision_e revision);\n".format(class_name))
            writer.write("{}() = default; // used by serialization\n\n".format(class_name))

            writer.write("void initialize();\n")
            writer.write("void initialize_valid_blocks();\n")

        writer.depth -= 1
        writer.write("};\n\n")


# @brief Writes class members that represent next steps in the path tree
#
# A middle-node class has the next tree steps as its members. This function writes them.
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] class_data                 The class data struct that holds the members
def write_class_path_members(writer, class_data):
    if (len(class_data['members']) > 0):
        class_name = class_data['class_name']
        logging.debug("writing path members for class_name=%s", class_name)

        def members_sorter(entry): return (entry['instance_name'])
        members_list = sorted(class_data['members'].values(), key=members_sorter)
        writer.write("// path members declaration\n")
        for member_entry in members_list:
            member_class_name = member_entry['member_class_name']
            instance_name = member_entry['instance_name']
            multiplicity = member_entry['multiplicity']

            if multiplicity == 0:  # not an array
                member_declaration_str = "std::shared_ptr<{0}> {1};\n".format(member_class_name, instance_name)
            else:
                member_declaration_str = "std::shared_ptr<{0}> {2}[{1}];\n".format(member_class_name, multiplicity, instance_name)

            writer.write(member_declaration_str)


# @brief Writes class members that represent registers and memories
#
# A LBR-block class has registers and memories as its members. This function writes them.
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] class_data                 The class data struct that holds the members
# @param[in] lbr_parsed                 A dictionary of the parsed LBR, with lbr_blocknames as keys
def write_class_reg_mem_members(writer, class_data, lbr_parsed):
    if is_class_an_lbr_block(
            class_data):  # if this class doesnt represent an sbus (for which there are no reg/mem so for now) and its an LBR then it has reg/mem
        class_name = class_data['class_name']
        logging.debug("writing regs/mems for class_name=%s", class_name)

        lbr_block_name = class_data['lbr_block_name']
        if lbr_block_name not in lbr_parsed:   # this class is a block, but the blockname is not found in the LBR files, so dont know what regs/mems to write
            exception_message = "class_name '{0}' represents LBR block '{1}', but cannot find LBR file that defines that block.\nknown LBR blocks are:{2}"\
                                .format(class_name, lbr_block_name, lbr_parsed.keys())
            raise Exception(exception_message)

        writer.write("// block members declaration\n")
        # write register members
        registers = lbr_parsed[lbr_block_name]['Registers']
        write_class_storage_members(writer, lbr_block_name, registers, "lld_register_sptr", "lld_register_array_sptr")

        # write memory members
        memories = lbr_parsed[lbr_block_name]['Memories']
        write_class_storage_members(writer, lbr_block_name, memories, "lld_memory_sptr", "lld_memory_array_sptr")

        # write functions
        writer.write("\n")

    if class_data['depth'] > 0:
        writer.write("// block functions declaration\n")

        if class_data['lbr_block_name'] is not None:
            # initialize 'leaf block'
            writer.write(
                "void initialize(la_block_id_t block_id, const char* lbr_name, const std::string& name, lld_block::block_indices_struct block_indices);\n")
        else:
            # initialize 'intermediate block'
            writer.write("void initialize(la_block_id_t block_id, const char* lbr_name, const std::string& name);\n")

# @brief Helper function that writes block class storage members
#
# Iterates over the members and writes their declaration.
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] lbr_block_name             The name of the LBR block for which the members are written
# @param[in] member_entries             A list of member entries
# @param[in] single_member_type_str     A member can have a single instance, or an array. This string represents the classname of a single instance.


def write_class_storage_members(writer, lbr_block_name, member_entries, single_member_type_str, array_member_type_str):
    for entry in member_entries:
        entry_name = entry['Name']
        entry_description = entry['Description']
        if entry_description.strip() == '':
            entry_description = "(no description)"
        else:
            entry_description = translate_json_desc_to_cpp_doxygen(entry_description)

        if entry['IsSingle']:  # not an array
            member_type_str = single_member_type_str
        else:
            array_length = entry['ArrayLength']
            member_type_str = array_member_type_str

        member_declaration_str = "{0} {1}; \t///< {2}: {3}\n".format(
            member_type_str, entry_name, lbr_block_name.upper(), entry_description)
        writer.write(member_declaration_str)


# @brief Writes the footer of the .h file
#
# @param[in] writer             The file writer that supports indenting
# @param[in] device_class       A string represeting the current device.
def write_api_footer_h_file(writer, device_class):
    header_define = "__" + device_class + "_H__"

    write_namespace_end(writer, 'silicon_one')
    writer.write("#endif // {0}\n".format(header_define))


# @brief Writes the header of the .cpp file
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] out_filename               The output C++ path+basename
def write_api_header_cpp_file(writer, out_filename):
    logging.debug("writing header in .cpp")
    writer.write("// Automatically generated file - don't change\n")
    writer.write("// \n\n")
    writer.write('''

// Disable optimizations as clang, GCC choke on this file in -O3 mode.
# ifdef __GNUC__
    # ifdef __clang__
        # pragma clang optimize off
    # else
        # pragma GCC optimize ("O0")
    # endif
# endif

# include <vector>

''')

    # the out_filename may be a full path. in the include i want just the basename of the file
    c_basename = ntpath.basename(out_filename)
    writer.write("#include <memory>\n\n")
    writer.write("#include \"lld/lld_init_expression.h\"\n")
    writer.write("#include \"{0}.h\"\n".format(c_basename))
    writer.write("#include \"{0}_init_functions.h\"\n\n".format(asic_name))
    write_namespace_begin(writer, 'silicon_one')


def get_init_expresion_entry_name(asic, block, reg_or_mem, reg_men_name, field_name):
    return '''{}_{}_{}_{}_{}_ied'''.format(asic, block, reg_or_mem, reg_men_name, field_name)

# @brief Writes fields data for register/memory field descriptors.
#
# @param[in] writer                         The file writer that supports indenting
# @param[in] lbr_parsed                     The parsed LBR data (blocks and their regs/mems/reg_fields)
# @param[in] write_regs                     If True, write register fields; otherwise, write memory fields


def write_fields_init_expressions_array(writer, lbr_parsed, write_regs):
    if write_regs:
        reg_or_mem = 'reg'
        objs = 'Registers'
    else:
        reg_or_mem = 'mem'
        objs = 'Memories'

    writer.depth += 1

    writer.write("// Start of function initializers")

    init_expresions_structs = []

    for lbr_name in lbr_parsed:
        block_name = lbr_name.upper()
        logging.debug("writing field initializators of block %s ", block_name)
        block_objs = lbr_parsed[lbr_name][objs]
        for obj in block_objs:
            revisions = [obj] + [o['regmem_dict'] for o in obj['OtherRevisions']]
            for obj_dict in revisions:
                # 'force_post_reset = True' represents the fact that dynamic memories shall apply their init expressions, whether exist, in the 'post_soft_reset' stage even if the init expression wasn't specified with the 'INIT_AFTER_SOFT_RESET' flag.
                force_post_reset = True if (not write_regs and obj_dict['Type'] == 'DYNAMIC') else False
                init_function_prefix = asic_name + "__" + block_name + "__" + obj_dict['Name']

                for f in obj_dict['Fields']:
                    init_expression_data = get_lld_field_init_expression_data(init_function_prefix, f, force_post_reset)
                    if init_expression_data != '':
                        #entry_name = '''{}_init_expession_data_{}'''.format(reg_or_mem, f['Name'])
                        entry_name = get_init_expresion_entry_name(asic_name, block_name, reg_or_mem, obj_dict['Name'], f['Name'])
                        if entry_name not in init_expresions_structs:
                            writer.write(
                                '''\rstatic constexpr struct lld_field_init_expression_data {} = {};\n\n'''.format(
                                    entry_name, init_expression_data))
                            init_expresions_structs.append(entry_name)

    writer.depth -= 1

    return init_expresions_structs
# @brief Writes fields data for register/memory field descriptors.
#
# @param[in] writer                         The file writer that supports indenting
# @param[in] lbr_parsed                     The parsed LBR data (blocks and their regs/mems/reg_fields)
# @param[in] write_regs                     If True, write register fields; otherwise, write memory fields


def write_fields_array(writer, lbr_parsed, write_regs):

    init_entries_list = write_fields_init_expressions_array(writer, lbr_parsed, write_regs)

    if write_regs:
        reg_or_mem = 'reg'
        objs = 'Registers'
    else:
        reg_or_mem = 'mem'
        objs = 'Memories'

    writer.write('''
static constexpr struct {
    const char* name;
    uint32_t lsb;
    uint32_t width_in_bits;
    lld_storage_field_type_e type;
    const lld_field_init_expression_data *init_expression_data;
} %s_desc_fields[] = {
''' % reg_or_mem)

    writer.depth += 1

    for lbr_name in lbr_parsed:
        block_name = lbr_name.upper()
        logging.debug("writing field descriptors of block %s ", block_name)
        writer.write("// Start of {0} block\n".format(block_name))
        block_objs = lbr_parsed[lbr_name][objs]
        for obj in block_objs:
            revisions = [obj] + [o['regmem_dict'] for o in obj['OtherRevisions']]
            for obj_dict in revisions:
                lsb = 0

                writer.write('''// {}\n'''.format(obj_dict['c_enum_name']))

                # 'force_post_reset = True' represents the fact that dynamic memories shall apply their init expressions, whether exist, in the 'post_soft_reset' stage even if the init expression wasn't specified with the 'INIT_AFTER_SOFT_RESET' flag.
                force_post_reset = True if (not write_regs and obj_dict['Type'] == 'DYNAMIC') else False
                init_function_prefix = asic_name + "__" + block_name + "__" + obj_dict['Name']

                for f in obj_dict['Fields']:
                    if write_regs:
                        field_type = get_reg_fields_type_enum_name(f['Type'])
                    else:
                        field_type = 'MIXED'

                    #entry_name = '''{}_init_expession_data_{}'''.format(reg_or_mem, f['Name'])
                    entry_name = get_init_expresion_entry_name(asic_name, block_name, reg_or_mem, obj_dict['Name'], f['Name'])
                    if entry_name in init_entries_list:
                        init_expression_data = '&' + entry_name
                    else:
                        init_expression_data = 'nullptr'

                    writer.write('''{{
     .name = "{}",
     .lsb = {},
     .width_in_bits = {},
     .type = {},
     .init_expression_data = {}
    }},
'''.format(f['Name'],
                        lsb,
                        f['Width'],
                        "lld_storage_field_type_e::" + field_type,
                        init_expression_data))

                    lsb += f['Width']

    writer.depth -= 1

    writer.write('};\n\n')


class instance_allocation_class:
    instance_allocation_str_to_enum = {'per_slice': 'instance_allocation_e::PER_SLICE',
                                       'per_slice_pair': 'instance_allocation_e::PER_SLICE_PAIR',
                                       'per_ifg': 'instance_allocation_e::PER_IFG',
                                       None: 'instance_allocation_e::NONE'}


# @brief Writes the get_register_desc function
#
# Defines a static function that returns a register description based on register number.
# The function has a static array of register description structs.
# The content of the array is geneated from the parsed LBR data.
# The register number passed to the generated function matches the register enum value.
#
# @param[in] writer                         The file writer that supports indenting
# @param[in] lbr_parsed                     The parsed LBR data (blocks and their regs/mems/reg_fields)
# @param[in] sbif_overrides                 Overrides specific to SBIF
def write_register_get_desc_cpp_file(writer, lbr_parsed, sbif_overrides, classname):
    writer.depth = 0
    writer.write("\n")

    # write the register descriptors function
    logging.debug("writing lld_get_register_desc function")

    # static array signature
    writer.write('''
static constexpr struct {
    la_entry_addr_t addr;                               ///< Address of an instance
    la_entry_width_t width;                             ///< Width in bytes of single entry
    uint16_t instances;                                 ///< Number of instances of same register
    const char* name;                                   ///< Name of the register
    const char* desc;                                   ///< Description of the register
    lld_register_type_e type;                           ///< The type of register
    bool writable;                                      ///< Whether this register can be written to
    bool include_counter;                               ///< At least one counter field in the register
    bool include_status;                                ///< At least one status field in the register
    const uint8_t* default_value;                       ///< The default value in hexadecimal representation
    uint32_t width_in_bits;                             ///< Width of a single entry i
    size_t first_field;                                 ///< First field index
    size_t num_fields;                                  ///< Number of fields
    instance_allocation_e instance_allocation;          ///< Register instance allocation
} reg_desc_params[] = {
''')

    # array members definition
    fields_used = 0
    writer.depth += 1

    for lbr_name in lbr_parsed:
        block_name = lbr_name.upper()
        logging.debug("writing register_desc of block %s ", block_name)
        writer.write("// Start of {0} block\n".format(block_name))
        block_registers = lbr_parsed[lbr_name]['Registers']
        for reg in block_registers:
            revisions = [reg] + [r['regmem_dict'] for r in reg['OtherRevisions']]
            for reg_dict in revisions:
                c_reg_enum_name = reg_dict['c_enum_name']
                c_reg_address = get_c_address(block_name, reg_dict, sbif_overrides)
                c_reg_width_in_bits = int(reg_dict['Width'])
                c_reg_width_in_bytes = width_in_bytes(c_reg_width_in_bits)
                c_reg_instances = reg_dict['ArrayLength']
                entry_description = reg_dict['Description']
                entry_description = translate_json_desc_to_cpp(entry_description)
                if entry_description.strip() == '':
                    entry_description = "(no description)"
                c_reg_description = "{0}: {1}".format(block_name, entry_description)
                c_reg_type = "lld_register_type_e::" + reg_dict['Type']
                c_reg_writable = get_c_register_writable(block_name, reg_dict, sbif_overrides)
                c_reg_has_counter = get_c_register_has_counter_field(reg_dict['FieldsTypes'])
                c_reg_has_status = get_c_register_has_status_field(reg_dict['FieldsTypes'])
                reg_default_value_hex_list = reg_dict['DefaultValue']
                c_reg_default_value_array = "nullptr"  # by default, there is no default value to a register. pun intended. :)
                if reg_default_value_hex_list[0]:
                    c_reg_default_value_array = f"(const uint8_t []){{{', '.join(','.join(reg_default_value) for reg_default_value in reg_default_value_hex_list)}}}"
                c_reg_instance_allocation = instance_allocation_class.instance_allocation_str_to_enum[reg_dict['InstanceAllocation']]

                writer.write('''
    {{
     .addr = {},
     .width = {},
     .instances = {},
     .name = "{}",
     .desc = "{}",
     .type = {},
     .writable = {},
     .include_counter = {},
     .include_status = {},
     .default_value = {},
     .width_in_bits = {},
     .first_field = {},
     .num_fields = {},
     .instance_allocation = {}
    }},
'''.format(c_reg_address,
                    c_reg_width_in_bytes,
                    c_reg_instances,
                    c_reg_enum_name,
                    c_reg_description,
                    c_reg_type,
                    c_reg_writable,
                    c_reg_has_counter,
                    c_reg_has_status,
                    c_reg_default_value_array,
                    c_reg_width_in_bits,
                    fields_used,
                    len(reg_dict['Fields']),
                    c_reg_instance_allocation))

                fields_used += len(reg_dict['Fields'])

        writer.write_noindent("\n")
    writer.depth -= 1
    writer.write("};\n")   # close the array
    writer.write_noindent("\n")

    # Array fields
    write_fields_array(writer, lbr_parsed, write_regs=True)

    # function signature
    writer.write('''
lld_register_desc_t
{}::get_register_desc(uint32_t register_num)
{{
    dassert_crit(register_num <= {}_REGISTER_LAST);

    auto& p(reg_desc_params[register_num]);
    std::vector<lld_field_desc> fields_vec;
    for (size_t i = p.first_field; i < p.first_field + p.num_fields; i++) {{
        auto& f(reg_desc_fields[i]);
        fields_vec.push_back(lld_field_desc{{.name = f.name, .lsb = f.lsb, .width_in_bits = f.width_in_bits, .type = f.type, .init_expression_data = f.init_expression_data}});
    }}

    std::vector<uint8_t> default_value(p.default_value, p.default_value + (p.default_value ? p.instances * p.width : 0));
    return lld_register_desc_t{{.addr = p.addr, .width = p.width, .instances = p.instances, .name = p.name, .desc = p.desc, .type = p.type, .writable = p.writable, .include_counter = p.include_counter, .include_status = p.include_status, .default_value = default_value, .width_in_bits = p.width_in_bits, .instance_allocation = p.instance_allocation, .fields = fields_vec}};
}}

'''.format(classname, lld_prefix.upper()))


# @brief Writes the get_memory_desc function
#
# Defines a static function that returns a memory description based on memort number.
# The function has a static array of memory description structs. The contents of the array are geneated from the parsed LBR data, and the block address offset config.
# The memory number passed to the generated function matches the memory enum value.
#
# @param[in] writer                         The file writer that supports indenting
# @param[in] lbr_parsed                     The parsed LBR data (blocks and their regs/mems/reg_fields)
# @param[in] sbif_overrides                 Overrides specific to SBIF
def write_memory_get_desc_cpp_file(writer, lbr_parsed, sbif_overrides, classname):
    writer.depth = 0
    writer.write("\n")

    # write the memory descriptors function
    logging.debug("writing lld_get_memory_desc function")

    writer.write('''
static constexpr struct {
    la_entry_addr_t addr;                      ///< Address of an instance
    la_entry_width_t width_bits;               ///< Logical width in bits of single entry
    la_entry_width_t width_total;              ///< Total width in bytes of single entry (with ECC bits)
    la_entry_width_t width_total_bits;         ///< Total width in bits of single entry (with ECC bits)
    uint32_t entries;                          ///< Number of entries
    uint16_t instances;                        ///< Number of instances of same memory
    const char* wrapper;                       ///< Memory wrapper name
    const char* name;                          ///< Name of the memory
    const char* desc;                          ///< Description of the memory
    lld_memory_type_e type;                    ///< The type of memory
    lld_memory_subtype_e subtype;              ///< The subtype of memory
    lld_memory_protection_e protection;        ///< Memory protection of this memory
    bool readable;                             ///< Whether this memory can be read from
    bool writable;                             ///< Whether this memory can be written to
    size_t first_field;                        ///< First field index
    size_t num_fields;                         ///< Number of fields
    instance_allocation_e instance_allocation; ///< Memory instance allocation
} mem_desc_params[] = {
''')

    fields_used = 0

    writer.depth += 1

    for lbr_name in lbr_parsed:
        block_name = lbr_name.upper()
        logging.debug("writing memory_desc of block %s ", block_name)
        writer.write("// Start of {0} block\n".format(block_name))
        block_memories = lbr_parsed[lbr_name]['Memories']
        for mem in block_memories:
            revisions = [mem] + [r['regmem_dict'] for r in mem['OtherRevisions']]
            for mem_dict in revisions:
                c_mem_enum_name = mem_dict['c_enum_name']
                c_mem_address = get_c_address(block_name, mem_dict, sbif_overrides)
                c_mem_logical_width_in_bits, c_mem_total_width_in_bits, c_mem_total_width_in_bytes = \
                    get_c_mem_width(block_name, mem_dict, sbif_overrides)
                c_mem_entries = get_c_mem_entries(block_name, mem_dict, sbif_overrides)
                c_mem_instances = mem_dict['ArrayLength']
                c_mem_wrapper = mem_dict['MemWrapper']
                c_mem_total_width = mem_dict['MemTotalWidth']

                entry_description = mem_dict['Description']
                entry_description = translate_json_desc_to_cpp(entry_description)
                if entry_description.strip() == '':
                    entry_description = "(no description)"
                c_mem_description = "{0}: {1}".format(block_name, entry_description)
                c_mem_type = "lld_memory_type_e::" + mem_dict['Type']
                c_mem_subtype = "lld_memory_subtype_e::" + mem_dict['SubType']
                c_mem_protect = "lld_memory_protection_e::" + mem_dict['MemProtect']

                c_mem_cpu_read_access = mem_dict['CpuReadAccess']
                c_mem_cpu_write_access = mem_dict['CpuWriteAccess']
                c_mem_instance_allocation = instance_allocation_class.instance_allocation_str_to_enum[mem_dict['InstanceAllocation']]

                writer.write('''
    {{
     .addr = {},
     .width_bits = {},
     .width_total = {},
     .width_total_bits = {},
     .entries = {},
     .instances = {},
     .wrapper = "{}",
     .name = "{}",
     .desc = "{}",
     .type = {},
     .subtype = {},
     .protection = {},
     .readable = {},
     .writable = {},
     .first_field ={},
     .num_fields ={},
     .instance_allocation = {}
    }},
'''.format(c_mem_address,
                    c_mem_logical_width_in_bits,
                    c_mem_total_width_in_bytes,
                    c_mem_total_width_in_bits,
                    c_mem_entries,
                    c_mem_instances,
                    c_mem_wrapper,
                    c_mem_enum_name,
                    c_mem_description,
                    c_mem_type,
                    c_mem_subtype,
                    c_mem_protect,
                    c_mem_cpu_read_access,
                    c_mem_cpu_write_access,
                    fields_used,
                    len(mem_dict['Fields']),
                    c_mem_instance_allocation))

                fields_used += len(mem_dict['Fields'])

    writer.depth -= 1
    writer.write('};\n\n')   # close the array

    # Array fields
    write_fields_array(writer, lbr_parsed, write_regs=False)

    # function signature
    writer.write('''
lld_memory_desc_t
{}::get_memory_desc(uint32_t memory_num)
{{
    dassert_crit(memory_num <= {}_MEMORY_LAST);

    auto& p(mem_desc_params[memory_num]);
    std::vector<lld_field_desc> fields_vec;
    for (size_t i = p.first_field; i < p.first_field + p.num_fields; i++) {{
        auto& f(mem_desc_fields[i]);
        fields_vec.push_back(lld_field_desc{{.name = f.name, .lsb = f.lsb, .width_in_bits = f.width_in_bits, .type = f.type, .init_expression_data = f.init_expression_data}});
    }}

    return lld_memory_desc_t{{.addr = p.addr, .width_bits = p.width_bits, .width_total = p.width_total, .width_total_bits = p.width_total_bits, .entries = p.entries, .instances = p.instances, .wrapper = p.wrapper, .name = p.name, .desc = p.desc, .type = p.type, .subtype = p.subtype, .protection = p.protection, .readable = p.readable, .writable = p.writable, .instance_allocation = p.instance_allocation, .fields = fields_vec}};
}}

'''.format(classname, lld_prefix.upper()))


# @brief Writes the header of the .i file
#
# @param[in] writer         The file writer that supports indenting
# @param[in] device_class   A string represeting the current device.
def write_header_i_file(writer, device_class):
    writer.depth = 0
    logging.debug("writing header in .i")
    writer.write("// Automatically generated file - don't change\n")
    writer.write("// \n\n")
    writer.write("// SWIG interface file for Leaba {0}.\n".format(device_class))
    writer.write("// \n\n")


# @brief Writes the template instantiations of the class member
#
# The flat_classes is a list of classes that should be created. There are classes for each node in the path tree.
# Each class can have (one or more) the following properites: a tree-root, a middle-node of the path tree, a LBR-block node.
# Each class defines its member fields and methods.
# A tree-root or a middle-node has more leafs (blocks). An array of blocks, in the C++ code, is implemented as an std::array.
# SWIG needs a SWIG-template instantiation for each c-template.
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] flat_classes               A list of classes with their members
def write_block_templates_i_file(writer, flat_classes):
    writer.depth = 0

    # write the classes of the register path
    logging.debug("writing SWIG template instantiations")

    # the class appearance is ordered by the path depth, and then alphabetically
    def classes_sorter(entry): return (entry['depth'], entry['class_name'])
    flat_classes_list = sorted(flat_classes.values(), key=classes_sorter)

    # traverse the list in reverse, to match the order in the .h file, just for convenience.
    for class_data in reversed(flat_classes_list):
        # write the members of the class that are used as a path for inner leafs
        write_class_member_template_instantiation(writer, class_data)


# @brief Writes class members that represent next steps in the path tree
#
# A middle-node class has the next tree steps as its members. This function writes them.
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] class_data                 The class data struct that holds the members
def write_class_member_template_instantiation(writer, class_data):
    class_name = class_data['class_name']
    logging.debug("writing swig helpers for class_name=%s", class_name)

    writer.write('''%shared_ptr(silicon_one::{0})\n'''.format(class_name))

    if (len(class_data['members']) > 0):
        def members_sorter(entry): return (entry['instance_name'])
        members_list = sorted(class_data['members'].values(), key=members_sorter)
        writer.write("// member template instantiations for class_name={0}\n".format(class_name))
        for member_entry in members_list:
            member_class_name = member_entry['member_class_name']
            multiplicity = member_entry['multiplicity']

            if multiplicity > 0:  # is an array
                member_declaration_str = "CARRAY_SPTR_TYPEMAPS(std::shared_ptr<silicon_one::{0}>)\n".format(
                    member_class_name, multiplicity)
                writer.write(member_declaration_str)
        writer.write("\n")


# @brief Generate C addresses, optionally add offset.
#
# @param[in] block_name                     Name of a block that owns this memory
# @param[in] regmem_dict                    Register or Memory dict
# @param[in] sbif_overrides                 Overrides specific to SBIF


def get_c_address(block_name, regmem_dict, sbif_overrides):
    addr = regmem_dict['Address']
    name = regmem_dict['Name']

    # create a zero-padded hexadecimal string from the address field
    c_address = "0x{0:{pad_with}{align_direction}{pad_to_length}}".format(
        addr, pad_with='0', align_direction='>', pad_to_length=4)

    # add offset
    if (block_name == 'SBIF') and not (name in sbif_overrides['base_address_skip_names']):
        c_address = "( " + c_address + " + " + sbif_overrides['base_address'] + " )"

    return c_address


# @brief Generate C value for "writable" field of a register descriptor.
#
# @param[in] block_name                     Name of a block that owns this memory
# @param[in] regmem_dict                    Register or Memory dict
# @param[in] sbif_overrides                 Overrides specific to SBIF

def get_c_register_writable(block_name, reg_dict, sbif_overrides):
    if block_name == 'SBIF' or block_name == 'ACM' or reg_dict['Writable']:
        return 'true'

    return 'false'

# @brief Generate C value for "include_counter" field of a register descriptor.
#
# @param[in] fields                     Type of all the fields in the register


def get_c_register_has_counter_field(fields):
    if 'COUNTER' in fields:
        return 'true'

    return 'false'

# @brief Generate C value for "include_status" field of a register descriptor.
#
# @param[in] fields                     Type of all the fields in the register


def get_c_register_has_status_field(fields):
    if 'STATUS' in fields:
        return 'true'

    return 'false'

# @brief Generate C memory logical width bits and total width bits / bytes.
#
# @param[in] block_name                     Name of a block that owns this memory
# @param[in] regmem_dict                    Register or Memory dict
# @param[in] sbif_overrides                 Overrides specific to SBIF


def get_c_mem_width(block_name, mem_dict, sbif_overrides):
    if block_name == 'SBIF':
        c_mem_logical_width_in_bits = sbif_overrides['MemLogicalWidth']
        c_mem_total_width_in_bits = sbif_overrides['MemTotalWidth']
    else:
        c_mem_logical_width_in_bits = mem_dict['MemLogicalWidth']
        c_mem_total_width_in_bits = mem_dict['MemTotalWidth']

    c_mem_total_width_in_bytes = width_in_bytes(int(c_mem_total_width_in_bits))

    return c_mem_logical_width_in_bits, c_mem_total_width_in_bits, c_mem_total_width_in_bytes


# @brief Get a string for number of memory entries
#
# Optionally, multiply by a factor and fixup XY TCAM.
#
# @param[in] block_name                     Name of a block that owns this memory
# @param[in] mem_dict                       Memory dict
# @param[in] sbif_overrides                 Overrides specific to SBIF
def get_c_mem_entries(block_name, mem_dict, sbif_overrides):
    c_mem_entries = str(mem_dict['MemEntries'])
    if block_name == 'SBIF':
        c_mem_entries = "( " + c_mem_entries + " * " + sbif_overrides['phys_per_logical'] + " )"

    # in XY tcams, each entry takes two lines
    if mem_dict['SubType'] == "X_Y_TCAM" or mem_dict['SubType'] == "KEY_MASK_TCAM":
        c_mem_entries += " * 2"

    return c_mem_entries


def get_lld_field_init_expression_data(init_function_prefix, field, force_post_reset):
    array_item_width = 'LLD_ARRAY_ITEM_WIDTH_INVALID' if field['ArrayItemWidth'] is None else str(field['ArrayItemWidth'])
    instance_allocation = instance_allocation_class.instance_allocation_str_to_enum[field['InstanceAllocation']]
    all_items_are_false_and_null, init_functions_data = get_init_functions_data(init_function_prefix, field, force_post_reset)

    if all_items_are_false_and_null and array_item_width == 'LLD_ARRAY_ITEM_WIDTH_INVALID' and instance_allocation == 'instance_allocation_e::NONE':
        return ''

    lld_field_init_expression_data_initializer = '{ .array_item_width = %s, .instance_allocation = %s, .init_functions_data = %s }' % (
        array_item_width, instance_allocation, init_functions_data)

    return lld_field_init_expression_data_initializer


def get_init_functions_data(init_function_prefix, field, force_post_reset):
    lbr_mode_to_init_function_suffix = {'InitValueSa': 'sa',
                                        'InitValueLcNwk': 'lc_nwk',
                                        'InitValueLcFab': 'lc_fab',
                                        'InitValueFe': 'fe'}

    init_stage_and_c_lbr_init_mode_order_in_array = (('pre_soft_reset', 'sa'),
                                                     ('pre_soft_reset', 'lc_nwk'),
                                                     ('pre_soft_reset', 'lc_fab'),
                                                     ('pre_soft_reset', 'fe'),
                                                     ('post_soft_reset', 'sa'),
                                                     ('post_soft_reset', 'lc_nwk'),
                                                     ('post_soft_reset', 'lc_fab'),
                                                     ('post_soft_reset', 'fe'))

    # {(init_stage, init_function_suffix) : (is_instance_dependent, is_line_dependent)}
    existing_init_functions_data = {}

    all_items_are_false_and_null = True

    init_stage = fetch_stage(field["InitValueAllModes"], force_post_reset)
    if init_stage is not None:
        is_instance_dependent = check_dependence(field["InitValueAllModes"], 'instance')
        is_line_dependent = check_dependence(field["InitValueAllModes"], 'line')
        for init_function_suffix in lbr_mode_to_init_function_suffix.values():
            existing_init_functions_data[(init_stage, init_function_suffix)] = (is_instance_dependent, is_line_dependent)

    for lbr_init_mode, init_function_suffix in lbr_mode_to_init_function_suffix.items():
        init_stage = fetch_stage(field[lbr_init_mode], force_post_reset)
        if init_stage is not None:
            is_instance_dependent = check_dependence(field[lbr_init_mode], 'instance')
            is_line_dependent = check_dependence(field[lbr_init_mode], 'line')
            existing_init_functions_data[(init_stage, init_function_suffix)] = (is_instance_dependent, is_line_dependent)

    init_functions_data_initializer = "{ "
    for array_index in range(len(init_stage_and_c_lbr_init_mode_order_in_array)):
        (init_stage, init_function_suffix) = init_stage_and_c_lbr_init_mode_order_in_array[array_index]
        if (init_stage, init_function_suffix) not in existing_init_functions_data:
            init_functions_data_initializer += "\n[{}] = {{ .is_instance_dependent = false, .is_line_dependent = false, .init_function = nullptr }},".format(
                array_index)
            continue

        all_items_are_false_and_null = False

        (is_instance_dependent, is_line_dependent) = existing_init_functions_data[(init_stage, init_function_suffix)]
        init_function_name = "init_function__" + init_function_prefix.lower() + "__" + \
            field["Name"] + "__" + init_stage + "__" + init_function_suffix
        init_functions_data_initializer += "\n[{}] = {{ .is_instance_dependent = {}, .is_line_dependent = {}, .init_function = {} }},".format(
            array_index, str(is_instance_dependent).lower(), str(is_line_dependent).lower(), init_function_name)
    init_functions_data_initializer += " }"

    return all_items_are_false_and_null, init_functions_data_initializer


def fetch_stage(init_expression, force_post_reset):
    stage = None
    if (init_expression is not None):
        match = "^INIT_AFTER_SOFT_RESET\s+"
        is_init_after_soft_reset_macro = (re.search(match, init_expression) is not None)
        stage = 'post_soft_reset' if (is_init_after_soft_reset_macro or force_post_reset) else 'pre_soft_reset'
    return stage

# @brief Writes the functions of device-top class (the root of the path tree)
#
# Defines the constructor function of the device-top, and the function that initialized the block_ids of all the LBR blocks in the path tree.
# The constructor is written by write_non_leaf_block_initializer.
# The block_id initialization uses the block_id enum.
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] sw_paths_with_uid          A list of SW-paths for each block with the block ID


def write_device_top_func_cpp_file(writer, sw_paths_with_uid, flat_classes, lbr_parsed, sbif_overrides):
    writer.depth = 0
    writer.write("\n")

    # write the calling of all blocks to initialize
    logging.debug("writing device top constructor and initialize function")

    assert len(sw_paths_with_uid) == 1

    for top_level_class_name, sw_paths_for_top_level in sw_paths_with_uid.items():
        # write the get_register_desc() and get_memory_desc() functions
        write_register_get_desc_cpp_file(writer, lbr_parsed, sbif_overrides, top_level_class_name)
        write_memory_get_desc_cpp_file(writer, lbr_parsed, sbif_overrides, top_level_class_name)

        # write the block_id initialization function
        writer.write("void\n")
        init_function_declaration_str = "{0}::initialize_valid_blocks()\n".format(top_level_class_name)
        writer.write(init_function_declaration_str)
        writer.write("{\n")
        writer.depth += 1

        for lbr_block_name_and_sw_path_for_block in sw_paths_for_top_level:
            c_sw_path = lbr_block_name_and_sw_path_for_block['sw_path']

            # the sw_path is the full path used (pacific.slice[1]). since this
            # function is inside the 'pacific' class, it should use 'slice[1]'. so
            # remove the 'pacific' from the sw_path
            py_sw_path = re.sub(top_level_class_name + "\.", '', c_sw_path)
            c_sw_path = py_sw_path.replace('.', '->')

            block_uid_data = lbr_block_name_and_sw_path_for_block['block_uid_data']
            c_block_uid_enum_name = block_uid_data['c_enum_name']
            lbr_block_name = lbr_block_name_and_sw_path_for_block['lbr_block_name']

            sw_path_slice_pair_index, sw_path_slice_index, sw_path_ifg_index, block_index = parse_sw_path(c_sw_path)
            sw_path_slice_pair_index = str(sw_path_slice_pair_index) if (
                sw_path_slice_pair_index is not None) else 'LA_SLICE_PAIR_ID_INVALID'
            sw_path_slice_index = str(sw_path_slice_index) if (sw_path_slice_index is not None) else 'LA_SLICE_ID_INVALID'
            sw_path_ifg_index = str(sw_path_ifg_index) if (sw_path_ifg_index is not None) else 'LA_IFG_ID_INVALID'
            block_index = str(block_index) if (block_index is not None) else 'lld_block::BLOCK_INSTANCE_INVALID'

            writer.write(
                '{0}->initialize({1}, "{2}", "{3}", lld_block::block_indices_struct{{{4}, {5}, {6}, {7}}});\n'.format(
                    c_sw_path,
                    c_block_uid_enum_name,
                    lbr_block_name,
                    py_sw_path,
                    sw_path_slice_pair_index,
                    sw_path_slice_index,
                    sw_path_ifg_index,
                    block_index))
            writer.write('m_leaf_blocks[{1}] = {0};\n'.format(c_sw_path, c_block_uid_enum_name))

        writer.depth -= 1
        writer.write("}\n")  # close function

        writer.write('''
std::shared_ptr<%(class)s>
%(class)s::create(la_device_revision_e revision)
{
    std::shared_ptr<%(class)s> tree = std::shared_ptr<%(class)s>(new %(class)s(revision));
    tree->initialize();

    return tree;
}

lld_block_scptr
%(class)s::get_block(la_block_id_t block_id) const
{
    auto it = m_leaf_blocks.find(block_id);
    if (it != m_leaf_blocks.end()) {
        return it->second;
    }

    log_err(LLD, "block_id=%%d not found, device revision=%%d", block_id, (int)m_revision);
    return nullptr;
}

lld_register_scptr
%(class)s::get_register(la_block_id_t block_id, la_entry_addr_t addr) const
{
    lld_block_scptr block = get_block(block_id);

    return block ? block->get_register(addr) : nullptr;
}
''' % {'class': top_level_class_name})

        writer.write('''
lld_register_scptr
{}::get_register(la_block_id_t block_id, {}::lld_register_e reg_id, size_t arr_idx) const
{{
    const lld_register_desc_t desc = get_register_desc(reg_id);

    return get_register(block_id, desc.addr + arr_idx);
}}
'''.format(top_level_class_name, top_level_class_name))

        writer.write('''
lld_register_scptr
{}::get_register(la_block_id_t block_id, {}::lld_register_e reg_id) const
{{
    return get_register(block_id, reg_id, 0 /*arr_idx*/);
}}
'''.format(top_level_class_name, top_level_class_name))

        writer.write('''
lld_memory_scptr
%s::get_memory(la_block_id_t block_id, la_entry_addr_t addr) const
{
    lld_block_scptr block = get_block(block_id);

    return block ? block->get_memory(addr) : nullptr;
}
''' % top_level_class_name)

        writer.write('''
lld_memory_scptr
{}::get_memory(la_block_id_t block_id, {}::lld_memory_e mem_id, size_t arr_idx) const
{{
    const lld_memory_desc_t desc = get_memory_desc(mem_id);

    return get_memory(block_id, desc.addr + arr_idx * lld_memory_desc_t::ARRAY_INSTANCE_OFFSET);
}}
'''.format(top_level_class_name, top_level_class_name))

        writer.write('''
lld_memory_scptr
{}::get_memory(la_block_id_t block_id, {}::lld_memory_e mem_id) const
{{
    return get_memory(block_id, mem_id, 0 /*arr_idx*/);
}}
'''.format(top_level_class_name, top_level_class_name))

    write_block_init_cpp_file(writer, flat_classes, lbr_parsed, sbif_overrides, top_level_class_name)


# @brief Writes the implementation of LBR block classes initializaion list
#
# LBR block classes have registers/memories as their members. The configuration of the these members is done in the initializaion list of their parent block.
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] flat_classes               A list of classes with their members
# @param[in] lbr_parsed                 The parsed LBR data (blocks and their regs/mems/reg_fields)
# @param[in] sbif_overrides             Overrides specific to SBIF
def write_block_init_cpp_file(writer, flat_classes, lbr_parsed, sbif_overrides, top_level_class_name):
    writer.depth = 0
    writer.write("\n")

    # write the block initialization of the register path
    logging.debug("writing block classes initialize functions")

    writer.write("// block classes c'tors and initialization functions\n")
    # the class appearance is ordered by the path depth, and then alphabetically

    def classes_sorter(entry): return (entry['depth'], entry['class_name'])
    flat_classes_list = sorted(flat_classes.values(), key=classes_sorter)

    for class_data in flat_classes_list:
        class_name = class_data['class_name']
        writer.depth = 0

        # if this class is an LBR block, then it has reg/mems that need to be initialized, otherwise skip.
        lbr_block_name = class_data['lbr_block_name']

        # Get the registers and memories of the block
        try:
            registers = lbr_parsed[lbr_block_name]['Registers']
        except KeyError:
            registers = None

        try:
            memories = lbr_parsed[lbr_block_name]['Memories']
        except KeyError:
            memories = None

        if lbr_block_name and lbr_block_name.upper() == 'SBIF':
            register_step = sbif_overrides['register_step']
            need_memory_padding = sbif_overrides['need_memory_padding']
        else:
            register_step = 1
            need_memory_padding = 'true'

        # write block constructor signature
        revision_param_name = 'revision'
        logging.debug("writing block constructor function of class_name=%s", class_name)
        writer.write("""
{0}::{0}(la_device_revision_e {1}):
    lld_block({2}/*register_step*/, {3}/*need_memory_padding*/, {1})
""".format(class_name, revision_param_name, register_step, need_memory_padding))

        write_member_block_initialize_invoke(writer, class_data)

        writer.write('\n{}\n')

        # write initialization function
        if class_data['depth'] == 0:
            writer.write("""
void
%s::initialize()
{
""" % class_name)
        elif lbr_block_name is not None:
            # initialize 'leaf block'
            writer.write("""
void
%s::initialize(la_block_id_t block_id, const char* lbr_name, const std::string& name, lld_block::block_indices_struct block_indices)
{
    lld_block::initialize(block_id, lbr_name, name, block_indices);

""" % class_name)
        else:
            # initialize 'intermediate block'
            writer.write("""
void
%s::initialize(la_block_id_t block_id, const char* lbr_name, const std::string& name)
{
    lld_block::initialize(block_id, lbr_name, name);

""" % class_name)

        writer.depth += 1

        if registers:
            writer.write("// registers initialization\n")
            write_member_regmem_constructor_invoke(writer, True, registers, lbr_block_name, top_level_class_name)
        if memories:
            writer.write("// memories initialization\n")
            write_member_regmem_constructor_invoke(writer, False, memories, lbr_block_name, top_level_class_name)

        writer.depth -= 1

        if lbr_block_name is None:
            write_non_leaf_block_initializer(writer, class_data, flat_classes_list)
        else:
            writer.depth += 1
            if registers:
                write_add_members_to_member_map(writer, registers, "m_registers")

            if memories:
                write_add_members_to_member_map(writer, memories, "m_memories")

            writer.depth -= 1

        writer.depth -= 1
        writer.write("}\n\n")  # close function


# @brief Indicates whether a class is an LBR block
#
# A class that is an LBR block has an LBR name, and is not an SBUS block
#
# @param[in] class_data     The class under query
# @return TRUE if this class represents an LBR, i.e. should have mem/reg
def is_class_an_lbr_block(class_data):
    return class_data['lbr_block_name'] is not None and 'has_sbus' not in class_data


def write_member_block_initialize_invoke(writer, class_data):

    def members_sorter(entry): return (entry['instance_name'])
    members_list = sorted(class_data['members'].values(), key=members_sorter)

    for member_entry in members_list:
        instance_name = member_entry['instance_name']
        multiplicity = member_entry['multiplicity']
        member_class_name = member_entry['member_class_name']

        s = ", "
        if multiplicity == 0:  # not an array
            s += "{}(std::make_shared<{}>(revision))".format(instance_name, member_class_name)
        else:
            s += "{}{{".format(instance_name)
            preceding_comma = ""
            for i in range(multiplicity):
                s += "{}std::make_shared<{}>(revision)".format(preceding_comma, member_class_name)
                preceding_comma = ", "
            s += "}"
        s += "\n"
        writer.write(s)


# @brief Writes the constructor invocation for list of members in a class.
#
# Calls the constructor of each member in a list, in the initialiaion list format: reg1(...), reg2(...), ...
# For example, single register member contructor call is: reg1(this, REG1_ENUM_NUM)
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] is_reg                     Whether entries are registers or memories
# @param[in] entries                    A list of entries that represent the members.
# @param[in] lbr_block_name             The name of the LBR block for which the members are written.
# @param[in] top_level_class_name       Name of the top level class.
def write_member_regmem_constructor_invoke(writer, is_reg, entries, lbr_block_name, top_level_class_name):
    get_desc_func = 'get_register_desc' if is_reg else 'get_memory_desc'
    for num, entry in enumerate(entries):
        entry_name = entry['Name']
        if entry['OtherRevisions']:
            assert len(entry['OtherRevisions']) == 1, "rev1 is currently the only 'other' revision"
            rev1 = entry['OtherRevisions'][0]['regmem_dict']
            if asic_name == PACIFIC_ASIC_NAME:
                condition = 'm_revision == la_device_revision_e::PACIFIC_A0'
            else:
                assert False
            entry_enum_name = '{0} ? {1}::{2} : {1}::{3}'.format(condition,
                                                                 top_level_class_name, rev1['c_enum_name'], entry['c_enum_name'])
        else:
            entry_enum_name = top_level_class_name + '::' + entry['c_enum_name']

        # Currently, we support only two revisions of LBRs.
        # rev1 - a few non-default LBRs
        # rev2 - all LBRs
        if entry['ValidInRevisions'] == ['rev1', 'rev2']:
            entry_is_valid = 'true'  # Entry is valid in all currently supported revisions
        elif entry['ValidInRevisions'] == ['rev1']:
            if asic_name == PACIFIC_ASIC_NAME:
                entry_is_valid = 'm_revision == la_device_revision_e::PACIFIC_A0'
            else:
                assert False
        elif entry['ValidInRevisions'] == ['rev2']:
            entry_is_valid = asic_params.entry_is_valid
        else:
            assert False, "Unexpected ValidInRevisions=" + str(entry['ValidInRevisions'])

        ctor_args = 'shared_from_this(), "{}", {}::{}({})'.format(entry_name, top_level_class_name, get_desc_func, entry_enum_name)
        if not entry['IsSingle']:  # if the member is an array, then need to also set its size
            c_array_len = entry['ArrayLength']
            ctor_args += ", {}".format(c_array_len)
        ctor_args += ', {}'.format(entry_is_valid)

        storage_type = 'lld_register' if is_reg else 'lld_memory'
        if not entry['IsSingle']:
            storage_type = 'lld_register_array_container' if is_reg else 'lld_memory_array_container'

        entry_initialization_str = '{} = std::make_shared<{}>({});\n'.format(entry_name, storage_type, ctor_args)
        writer.write(entry_initialization_str)


# @brief Writes code that adds entries to a map.
#
# A block has two maps of its members: map of registers and map of memories. This function writes the code that adds each member (in a list of entries) to a map.
# In case the member is an array, then its elements are added to the map.
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] entries                    A list of entries that represent the members.
# @param[in] entries_map_name           The name of the map to add to.


def write_add_members_to_member_map(writer, entries, entries_map_name):
    writer.write("// populate {}\n".format(entries_map_name))
    for entry in entries:
        entry_name = entry['Name']
        writer.write("if ({}->is_valid()) {{\n".format(entry_name))
        writer.depth += 1
        if entry['IsSingle']:
            writer.write("{0}[{1}->get_desc()->addr] = {1};\n".format(entries_map_name, entry_name))
        else:  # if the member is an array, then need to add each of its elements
            c_array_len = entry['ArrayLength']
            writer.write("for (uint32_t i = 0; i < {}; i++) {{\n".format(c_array_len))
            writer.depth += 1
            writer.write("{0}[(*{1})[i]->get_desc()->addr] = (*{1})[i];\n".format(entries_map_name, entry_name))
            writer.depth -= 1
            writer.write("}\n")
        writer.depth -= 1
        writer.write("}\n")


def is_leaf_block(class_name, classes_list):
    for c in classes_list:
        if c['class_name'] == class_name:
            return c['lbr_block_name'] is not None

    # Should never get here
    return None

# @brief Writes initializer for non leaf lld_blocks.
#
# Initialize all block's sub-blocks to vector of lld_blocks*
#
# @param[in] writer                     The file writer that supports indenting
# @param[in] class_data                 The class data struct that holds the members
# @param[in] classes_list               List of all classes


def write_non_leaf_block_initializer(writer, class_data, classes_list):
    writer.depth += 1

    if class_data['depth'] == 0:
        writer.write("initialize_valid_blocks();\n")
        block_name = class_data['class_name']
        full_name_prefix = ''
    else:
        block_name = class_data['base_name']
        full_name_prefix = 'm_name + "." + '

    writer.write("m_lbr_name = \"{0}\";\n".format(block_name))

    members_dict = class_data['members']
    for member_class, member_entry in members_dict.items():
        if is_leaf_block(member_entry['member_class_name'], classes_list):
            continue

        instance_name = member_entry['instance_name']
        multiplicity = member_entry['multiplicity']

        if multiplicity == 0:  # not an array
            writer.write('{0}->initialize(LA_BLOCK_ID_INVALID, "", {1}"{0}");\n'.format(instance_name, full_name_prefix))
        else:
            for i in range(multiplicity):
                writer.write('{0}[{1}]->initialize(LA_BLOCK_ID_INVALID, "", {2}"{0}[{1}]");\n'.format(instance_name, i, full_name_prefix))

    writer.write('\n')

    m_blocks_str = "m_blocks = lld_block_vec_t {"
    for member_class, member_entry in members_dict.items():
        instance_name = member_entry['instance_name']
        multiplicity = member_entry['multiplicity']

        if multiplicity == 0:  # not an array
            m_blocks_str += "\n\t\t\t{0},".format(instance_name)
        else:
            for i in range(multiplicity):
                m_blocks_str += "\n\t\t\t{0}[{1}],".format(instance_name, i)
    m_blocks_str = m_blocks_str[:-1] + "};\n"
    writer.write(m_blocks_str)

# @brief Writes the footer of the .cpp file
#
# @param[in] writer                     The file writer that supports indenting


def write_api_footer_cpp_file(writer):
    write_namespace_end(writer, 'silicon_one')
