// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#include "device_configurator_base.h"
#include "common/common_strings.h"
#include "common/dassert.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lld/ll_device.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"
#include "lld/lld_strings.h"
#include "lld/lld_utils.h"
#include <string>

using namespace std;

namespace silicon_one
{

device_configurator_base::device_configurator_base(ll_device_sptr ll_device)
    : m_ll_device(ll_device), m_device_mode(device_mode_e::INVALID), m_num_of_slices(0)
{
    dassert_crit(m_ll_device != nullptr);
}

la_status
device_configurator_base::initialize(device_mode_e device_mode,
                                     system_init_vars system_vars,
                                     std::vector<lbr_slice_mode_e>&& slices_type,
                                     const std::vector<la_slice_id_t>& used_slices)
{
    for (auto iter = used_slices.begin(); iter != used_slices.end(); iter++) {
        m_used_slices.push_back(*iter);
    }

    m_device_mode = device_mode;
    m_system_vars = system_vars;
    m_slices_type = slices_type;
    m_num_of_slices = m_slices_type.size();

    return LA_STATUS_SUCCESS;
}

la_status
device_configurator_base::configure_device(const init_stage_e init_stage)
{
    la_status status = LA_STATUS_SUCCESS;
    log_debug(HLD, "Start initializing init_stage %s", to_string(init_stage).c_str());

    // Configure blocks:
    lld_block::lld_block_vec_t leaf_blocks = m_ll_device->get_device_tree()->get_leaf_blocks();
    for (const lld_block_scptr& block : leaf_blocks) {
        // If block is not in allowed blocks list skip it early
        if (!m_ll_device->is_block_allowed(block)) {
            continue;
        }
        status = configure_block(block, init_stage);
        return_on_error(status);
    }

    log_debug(HLD, "Finish initializing init_stage %s", to_string(init_stage).c_str());
    return status;
}

la_status
device_configurator_base::configure_block(const lld_block_scptr& block, const init_stage_e init_stage)
{
    dassert_crit(block);
    la_status status = LA_STATUS_SUCCESS;

    log_debug(HLD, "Start initializing block %s", block->get_name().c_str());

    const lld_block::block_indices_struct& block_indices = block->get_block_indices();

    lld_block::lld_register_vec_t registers = block->get_registers();
    status = configure_registers(registers, init_stage, block_indices, block->get_name().c_str());
    return_on_error(status);

    lld_block::lld_memory_vec_t memories = block->get_memories();
    status = configure_memories(memories, init_stage, block_indices, block->get_name().c_str());
    return_on_error(status);

    return status;
}

la_status
device_configurator_base::configure_registers(lld_block::lld_register_vec_t& registers,
                                              const init_stage_e init_stage,
                                              const lld_block::block_indices_struct& block_indices,
                                              const char* block_name)
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    bool is_reg_instance_dependent = true;
    bool is_init_expression_exist = false;

    // Sort the registers vector by its addresses (ascending order), necessary for dependencies opts:
    std::sort(registers.begin(), registers.end(), [](const lld_register_scptr& a, const lld_register_scptr& b) -> bool {
        return a->get_desc()->addr < b->get_desc()->addr;
    });
    for (const auto& reg : registers) {
        dassert_crit(reg);
        const lld_register_desc_t* reg_desc = reg->get_desc();

        reg_mem_init_vars reg_vars;
        reg_vars.instance = reg->get_index();
        reg_vars.num_instances = reg_desc->instances;

        // Update indices by register instance allocation:
        lld_block::block_indices_struct reg_block_indices(block_indices);
        update_indices_by_instance_allocation(reg_block_indices, reg_desc->instance_allocation, reg_vars.instance);

        if (m_device_mode == device_mode_e::LINECARD) {
            // line card device mode is related with 2 different 'lbr slice init modes' (line card network/fabric), hence, instance
            // optimization is not applied.
            is_init_expression_exist = false;
            is_reg_instance_dependent = true;

        } else if (reg->get_index() == 0) {
            is_init_expression_exist = false;

            if (reg_desc->instances > 1) {
                // The register is the first instance in an array, check for instance dependence:
                // instance dependence can be caused by either instance allocation (only in the reg hierarchy, field's instance
                // allocation doesn't refer to the 'instance' token but rather to the 'item' token) or by the init expressions
                // themselves which might contain the 'instance' token.
                is_reg_instance_dependent = (reg_desc->instance_allocation != instance_allocation_e::NONE);
                if (!is_reg_instance_dependent) {
                    is_reg_instance_dependent
                        = check_dependence(reg_desc->fields, reg_block_indices, init_stage, expression_dependence_type_e::INSTANCE);
                }
            }

        } else if (!is_reg_instance_dependent) {
            // We'll reach this point if instance>0 and the register is not instance dependent
            if (is_init_expression_exist) {
                // If there was found in the first reg iteration a related init expression - take the register's value from the last
                // one inserted:
                bit_vector last_reg_val = reg_val_list.back().second;
                reg_val_list.push_back({reg, move(last_reg_val)});
            }
            continue;
        }

        // We'll reach this point if either instance=0
        // Or instance>0 and the reg is instance dependent
        // Or device mode is 'line card'
        bit_vector reg_value(0, reg_desc->width_in_bits);
        status = calc_reg_value(reg_value, reg_desc, reg_block_indices, reg_vars, init_stage, is_init_expression_exist);
        return_on_error(status);

        if (is_init_expression_exist) {
            reg_val_list.push_back({reg, move(reg_value)});
        }
    }

    // Write block's registers:
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status, HLD, ERROR, "Failed to write registers for block %s.", block_name);

    return status;
}

la_status
device_configurator_base::configure_memories(lld_block::lld_memory_vec_t& memories,
                                             const init_stage_e init_stage,
                                             const lld_block::block_indices_struct& block_indices,
                                             const char* block_name)
{
    la_status status = LA_STATUS_SUCCESS;
    lld_memory_line_value_list_t mem_line_value_list;
    lld_memory_value_list_t mem_value_list;
    vector<bit_vector> instance_independent_mem_values;
    bool is_mem_instance_dependent = true;
    bool is_mem_line_dependent = true;
    bool is_init_expression_exist = false;

    // Sort the mem vector by its addresses (ascending order), necessary for dependencies opts:
    std::sort(memories.begin(), memories.end(), [](const lld_memory_scptr& a, const lld_memory_scptr& b) -> bool {
        return a->get_desc()->addr < b->get_desc()->addr;
    });

    for (const auto& mem : memories) {
        dassert_crit(mem);
        const lld_memory_desc_t* mem_desc = mem->get_desc();

        reg_mem_init_vars mem_vars;
        mem_vars.instance = mem->get_index();

        mem_vars.num_instances = mem_desc->instances;
        mem_vars.num_lines = mem_desc->entries;

        // Update block indices by memory instance allocation:
        lld_block::block_indices_struct mem_block_indices(block_indices);
        update_indices_by_instance_allocation(mem_block_indices, mem_desc->instance_allocation, mem_vars.instance);

        if (m_device_mode == device_mode_e::LINECARD) {
            // line card device mode is related with 2 different 'lbr slice init modes' (line card network/fabric), hence, instance
            // optimization is not applied.
            is_init_expression_exist = false;
            is_mem_instance_dependent = true;
            is_mem_line_dependent
                = check_dependence(mem_desc->fields, mem_block_indices, init_stage, expression_dependence_type_e::LINE);

        } else if (mem->get_index() == 0) {
            is_init_expression_exist = false;

            if (mem_desc->instances > 1) {
                // The memory is the first instance in an array, check for instance dependence:
                // instance dependence can be caused by either instance allocation (only in the mem hierarchy, field's instance
                // allocation doesn't refer to the 'instance' token but rather to the 'item' token) or by the init expressions
                // themselves which might contain the 'instance' token.
                instance_independent_mem_values.clear();
                is_mem_instance_dependent = (mem_desc->instance_allocation != instance_allocation_e::NONE);
                if (!is_mem_instance_dependent) {
                    is_mem_instance_dependent
                        = check_dependence(mem_desc->fields, mem_block_indices, init_stage, expression_dependence_type_e::INSTANCE);
                }
            } else {
                is_mem_instance_dependent = false;
            }

            // line dependence can be caused by the init expressions themselves which might contain the 'line' token.
            is_mem_line_dependent
                = check_dependence(mem_desc->fields, mem_block_indices, init_stage, expression_dependence_type_e::LINE);

        } else if (!is_mem_instance_dependent) {
            // We'll reach this point if instance>0 and the memory is not instance dependent
            if (is_init_expression_exist) {
                // If there was found in the first mem iteration a related init expression - take the memory lines' values that were
                // already calculated:
                if (is_mem_line_dependent) {
                    // {instance dependent, line dependent} = {X, V}
                    // Take lines values from the already calculated auxiliary vector:
                    for (la_entry_addr_t line = 0; line < mem_desc->entries; ++line) {
                        mem_line_value_list.push_back({{mem, line}, instance_independent_mem_values[line]});
                    }

                } else {
                    // {instance dependent, line dependent} = {X, X}
                    // Take memory value from the last one inserted:
                    bit_vector last_mem_val = mem_value_list.back().second;
                    mem_value_list.push_back({mem, move(last_mem_val)});
                }
            }
            continue;
        }

        // We'll reach this point if either instance=0
        // Or instance>0 and the mem is instance dependent
        // Or device mode is 'line card'
        if (is_mem_line_dependent) {
            // Either instance=0 and {instance dependent, line dependent} = {?, V}
            // Or instance>0 and {instance dependent, line dependent} = {V, V}

            //  if the slice is disabled - do not try to init the memory.
            //  GILAD_ADD .. This is not the best practice!!

            if (skip_this_block_matilda(mem_block_indices, m_used_slices)) {
                continue;
            }

            for (la_entry_addr_t line = 0; line < mem_vars.num_lines; ++line) {
                mem_vars.line = line;

                bit_vector mem_value(0, mem_desc->width_bits);
                status
                    = calc_mem_entry_value(mem_value, mem_desc, mem_block_indices, mem_vars, init_stage, is_init_expression_exist);
                return_on_error(status);

                // Init expression of instance which refers to out-of-range slice should be ignored, hence, it may occur that
                // 'is_init_expression_exist = false' and 'is_mem_line_dependent = true' for a such mem:
                if (is_init_expression_exist) {
                    if ((mem_vars.instance == 0) && !is_mem_instance_dependent) {
                        // Build the auxiliary vector for the non instance dependence opt:
                        instance_independent_mem_values.push_back(mem_value);
                    }
                    mem_line_value_list.push_back({{mem, line}, move(mem_value)});
                }
            }
        } else {
            // Either instance=0 and {instance dependent, line dependent} = {?, X}
            // Or instance>0 and {instance dependent, line dependent} = {V, X}
            bit_vector mem_value(0, mem_desc->width_bits);
            status = calc_mem_entry_value(mem_value, mem_desc, mem_block_indices, mem_vars, init_stage, is_init_expression_exist);
            return_on_error(status);

            if (is_init_expression_exist) {
                mem_value_list.push_back({mem, move(mem_value)});
            }
        }
    }

    // Write block's memories:
    status = lld_write_memory_list(m_ll_device, mem_value_list);
    return_on_error(status, HLD, ERROR, "Failed to write memories' const values for block %s.", block_name);

    status = lld_write_memory_line_list(m_ll_device, mem_line_value_list);
    return_on_error(status, HLD, ERROR, "Failed to write memories for block %s.", block_name);

    return status;
}

la_status
device_configurator_base::calc_reg_value(bit_vector& out_reg_value,
                                         const lld_register_desc_t* reg_desc,
                                         const lld_block::block_indices_struct& reg_block_indices,
                                         const reg_mem_init_vars& reg_vars,
                                         const init_stage_e init_stage,
                                         bool& out_is_init_expression_exist)
{
    la_status status = LA_STATUS_SUCCESS;

    if (init_stage == init_stage_e::POST_SOFT_RESET) {
        // Calculate the 'pre soft reset' value first as the 'post soft reset' calculation starting point:
        status = calc_reg_value(
            out_reg_value, reg_desc, reg_block_indices, reg_vars, init_stage_e::PRE_SOFT_RESET, out_is_init_expression_exist);
        return_on_error(status);
    } else if (reg_desc->default_value.size()) {
        // For 'pre soft reset' - take the default value (if exists) as starting point:
        out_reg_value = bit_vector(
            reg_desc->width, &reg_desc->default_value.data()[reg_vars.instance * reg_desc->width], reg_desc->width_in_bits);
    }

    status = apply_fields_init_funcs(
        out_reg_value, reg_desc->fields, reg_block_indices, reg_vars, init_stage, out_is_init_expression_exist);
    return_on_error(status);

    return status;
}

la_status
device_configurator_base::calc_mem_entry_value(bit_vector& out_mem_entry_value,
                                               const lld_memory_desc_t* mem_desc,
                                               const lld_block::block_indices_struct& mem_block_indices,
                                               const reg_mem_init_vars& mem_vars,
                                               const init_stage_e init_stage,
                                               bool& out_is_init_expression_exist)
{
    la_status status = LA_STATUS_SUCCESS;

    if (init_stage == init_stage_e::POST_SOFT_RESET) {
        // Calculate the 'pre soft reset' value first as the 'post soft reset' calculation starting point:
        status = calc_mem_entry_value(
            out_mem_entry_value, mem_desc, mem_block_indices, mem_vars, init_stage_e::PRE_SOFT_RESET, out_is_init_expression_exist);
        return_on_error(status);
    }

    status = apply_fields_init_funcs(
        out_mem_entry_value, mem_desc->fields, mem_block_indices, mem_vars, init_stage, out_is_init_expression_exist);
    return_on_error(status);

    return status;
}

la_status
device_configurator_base::apply_fields_init_funcs(bit_vector& out_reg_mem_value,
                                                  const std::vector<lld_field_desc>& fields_vec,
                                                  const lld_block::block_indices_struct& reg_mem_block_indices,
                                                  const reg_mem_init_vars& reg_mem_vars,
                                                  const init_stage_e init_stage,
                                                  bool& out_is_init_expression_exist)
{
    la_status status = LA_STATUS_SUCCESS;

    // Update fields' value up to theirs init expressions:
    out_is_init_expression_exist = false;
    for (const lld_field_desc& field_desc : fields_vec) {
        bool out_is_field_init_expression_exist;
        status = apply_field_value(
            out_reg_mem_value, field_desc, reg_mem_block_indices, reg_mem_vars, init_stage, out_is_field_init_expression_exist);
        return_on_error(status);

        out_is_init_expression_exist |= out_is_field_init_expression_exist;
    }

    return status;
}

la_status
device_configurator_base::apply_field_value(bit_vector& out_reg_mem_value,
                                            const lld_field_desc& field_desc,
                                            const lld_block::block_indices_struct& reg_mem_block_indices,
                                            const reg_mem_init_vars& reg_mem_vars,
                                            const init_stage_e init_stage,
                                            bool& out_is_field_init_expression_exist)
{
    out_is_field_init_expression_exist = false;
    uint32_t field_lsb = field_desc.lsb;
    uint32_t field_width = field_desc.width_in_bits;
    const lld_field_init_expression_data* field_init_expression_data = field_desc.init_expression_data;

    if (field_init_expression_data == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    instance_allocation_e field_instance_allocation = field_init_expression_data->instance_allocation;

    lld_array_item_width_t item_width = field_init_expression_data->array_item_width;

    if (item_width != LLD_ARRAY_ITEM_WIDTH_INVALID) {
        // Itemized:

        lld_block::block_indices_struct field_block_indices(reg_mem_block_indices);

        size_t num_items = field_width / item_width;

        // Check for correct lbr parameters
        if (field_width != num_items * item_width) {
            log_err(HLD,
                    "Itemized field configuration does not match: field_width (%u) != num_items (%lu) * item_width (%u).",
                    field_width,
                    num_items,
                    item_width);
        }

        for (size_t item = 0; item < num_items; ++item) {
            // Update indices by field instance allocation:
            update_indices_by_instance_allocation(field_block_indices, field_instance_allocation, item);

            init_expression_slice_mode_e init_mode = get_init_mode(field_block_indices);

            if (init_mode == init_expression_slice_mode_e::SLICE_OUT_OF_RANGE) {
                // Out of range slices are skipped
                continue;
            }

            size_t init_function_data_idx = get_init_function_data_index(init_stage, init_mode);
            const init_function_data& init_function_data = field_init_expression_data->init_functions_data[init_function_data_idx];
            if (init_function_data.init_function == nullptr) {
                continue;
            }
            out_is_field_init_expression_exist = true;
            uint64_t item_value = init_function_data.init_function(m_system_vars.frequency,
                                                                   m_system_vars.device_id,
                                                                   m_system_vars.is_hbm,
                                                                   m_system_vars.is_100g_fabric,
                                                                   m_system_vars.numnwk,
                                                                   m_system_vars.numfab,
                                                                   m_system_vars.is_MAT_6_4T,
                                                                   m_system_vars.is_MAT_3_2T_A,
                                                                   m_system_vars.is_MAT_3_2T_B,
                                                                   m_system_vars.credit_in_bytes,
                                                                   field_block_indices.block_index,
                                                                   field_block_indices.slice_pair_index,
                                                                   field_block_indices.slice_index,
                                                                   field_block_indices.ifg_index,
                                                                   reg_mem_vars.instance,
                                                                   reg_mem_vars.num_instances,
                                                                   reg_mem_vars.line,
                                                                   reg_mem_vars.num_lines,
                                                                   num_items,
                                                                   item);

            size_t item_offset = item_width * item;
            size_t item_lsb = field_lsb + item_offset;
            size_t item_msb = item_lsb + item_width - 1;
            out_reg_mem_value.set_bits(item_msb, item_lsb, item_value);
        }
    } else {
        // Non-itemized:

        if (field_instance_allocation != instance_allocation_e::NONE) {
            log_err(HLD, "Non-itemized field should not have 'instance_allocation' attribute.");
        }

        init_expression_slice_mode_e init_mode = get_init_mode(reg_mem_block_indices);

        if (init_mode == init_expression_slice_mode_e::SLICE_OUT_OF_RANGE) {
            // Out of range slices are skipped
            return LA_STATUS_SUCCESS;
        }

        size_t init_function_data_idx = get_init_function_data_index(init_stage, init_mode);
        const init_function_data& init_function_data = field_init_expression_data->init_functions_data[init_function_data_idx];
        if (init_function_data.init_function == nullptr) {
            // nothing to update:
            return LA_STATUS_SUCCESS;
        }

        out_is_field_init_expression_exist = true;
        uint64_t field_value = init_function_data.init_function(m_system_vars.frequency,
                                                                m_system_vars.device_id,
                                                                m_system_vars.is_hbm,
                                                                m_system_vars.is_100g_fabric,
                                                                m_system_vars.numnwk,
                                                                m_system_vars.numfab,
                                                                m_system_vars.is_MAT_6_4T,
                                                                m_system_vars.is_MAT_3_2T_A,
                                                                m_system_vars.is_MAT_3_2T_B,
                                                                m_system_vars.credit_in_bytes,
                                                                reg_mem_block_indices.block_index,
                                                                reg_mem_block_indices.slice_pair_index,
                                                                reg_mem_block_indices.slice_index,
                                                                reg_mem_block_indices.ifg_index,
                                                                reg_mem_vars.instance,
                                                                reg_mem_vars.num_instances,
                                                                reg_mem_vars.line,
                                                                reg_mem_vars.num_lines,
                                                                size_t(-1) /* num_items */,
                                                                size_t(-1) /* item */);

        size_t field_msb = field_lsb + field_width - 1;
        out_reg_mem_value.set_bits(field_msb, field_lsb, field_value);
    }

    return LA_STATUS_SUCCESS;
}

void
device_configurator_base::update_indices_by_instance_allocation(lld_block::block_indices_struct& block_indices_to_update,
                                                                const instance_allocation_e instance_allocation,
                                                                const size_t item_or_instance_index) const
{
    switch (instance_allocation) {
    case instance_allocation_e::NONE:
        return;
    case instance_allocation_e::PER_IFG:
        block_indices_to_update.ifg_index = item_or_instance_index;
        return;
    case instance_allocation_e::PER_SLICE:
        block_indices_to_update.slice_index = item_or_instance_index;
        return;
    case instance_allocation_e::PER_SLICE_PAIR:
        block_indices_to_update.slice_pair_index = item_or_instance_index;
        return;
    }
}

la_slice_id_t
device_configurator_base::calc_flat_slice_index(const lld_block::block_indices_struct& block_indices)
{
    // Flat slice index can be resolved from the following 4 combinations of {slice_pair, slice, ifg}, 'X' means invalid, each
    // combination has its valid indices' range within the context they appear.
    // Note that there might be use cases where indices get out of range (for example - device with 6 slices, global register with 7
    // instances and instance_allocation='per_slice' -> the last instance will be related to out of range slice).
    // 1. {slice_pair, slice, X} - slice_pair is relative to the device with range[0..(m_num_of_slices/2)-1], slice is relative to
    // slice_pair with range[0..1]
    // 2. {X, slice, X} 		 - slice is relative to the device with range[0..m_num_of_slices-1]
    // 3. {slice_pair, X, ifg} 	 - slice_pair is relative to the device with range[0..(m_num_of_slices/2)-1], ifg is relative to
    // slice_pair with range[0..3]
    // 4. {X, X, ifg}			 - ifg is relative to the device with range[0..(m_num_of_slices*2)-1]

    if (block_indices.slice_index != LA_SLICE_ID_INVALID) {
        if (block_indices.slice_pair_index != LA_SLICE_PAIR_ID_INVALID) {
            dassert_crit(block_indices.slice_index < 2);
            return (block_indices.slice_pair_index * 2) + block_indices.slice_index;
        }

        return block_indices.slice_index;
    }

    if (block_indices.ifg_index != LA_IFG_ID_INVALID) {
        if (block_indices.slice_pair_index != LA_SLICE_PAIR_ID_INVALID) {
            dassert_crit(block_indices.ifg_index < 4);
            return (block_indices.slice_pair_index * 2) + (block_indices.ifg_index / 2);
        }

        return (block_indices.ifg_index / 2);
    }

    return LA_SLICE_ID_INVALID;
}

bool
device_configurator_base::skip_this_block_matilda(const lld_block::block_indices_struct& block_indices,
                                                  const std::vector<la_slice_id_t>& used_slices)
{
    lld_block::block_indices_struct field_block_indices(block_indices);
    la_slice_id_t slice_flat_index = device_configurator_base::calc_flat_slice_index(field_block_indices);
    if (slice_flat_index != LA_SLICE_ID_INVALID) {
        bool is_active_slice = contains(used_slices, slice_flat_index);
        if (!is_active_slice) {
            log_debug(HLD,
                      "device_configurator_base::configure_memories  should skip block belonging to disabled slice No.%d",
                      slice_flat_index);
            return true;
        }
    }
    return false;
}

// Checks whether any of the relevant expressions related with the fields of a storage (reg/mem) has a mention of dependence_type -
// i.e., whether it depends on the 'line' or 'instance' tokens.
// Relevant expressions are those that are actually going to be used, based on the slice (which can be impacted from
// 'instance_allocation's) and device mode.
bool
device_configurator_base::check_dependence(const std::vector<lld_field_desc>& fields_desc_vec,
                                           const lld_block::block_indices_struct& reg_mem_block_indices,
                                           const init_stage_e init_stage,
                                           const expression_dependence_type_e dependence_type) const
{
    // Note - when checking for instance dependence, it is assumed that by getting here the reg/mem has no instance_allocation

    for (const auto& field_desc : fields_desc_vec) {
        const lld_field_init_expression_data* field_init_expression_data = field_desc.init_expression_data;

        if (field_init_expression_data == nullptr) {
            continue;
        }

        lld_array_item_width_t item_width = field_init_expression_data->array_item_width;
        if (item_width != LLD_ARRAY_ITEM_WIDTH_INVALID) {
            // Itemized:
            lld_block::block_indices_struct field_block_indices(reg_mem_block_indices);
            instance_allocation_e field_instance_allocation = field_init_expression_data->instance_allocation;

            uint32_t field_width = field_desc.width_in_bits;
            uint32_t num_items = field_width / item_width;

            for (size_t item_index = 0; item_index < num_items; ++item_index) {
                // Update indices by field instance allocation:
                update_indices_by_instance_allocation(field_block_indices, field_instance_allocation, item_index);

                init_expression_slice_mode_e init_mode = get_init_mode(field_block_indices);
                if (init_mode == init_expression_slice_mode_e::SLICE_OUT_OF_RANGE) {
                    // Out of range slices are skipped
                    continue;
                }

                bool res = check_init_func_dependence(field_init_expression_data, init_stage, init_mode, dependence_type);
                if (res) {
                    return true;
                }
            }
        } else {
            // Non-itemized:
            init_expression_slice_mode_e init_mode = get_init_mode(reg_mem_block_indices);
            if (init_mode == init_expression_slice_mode_e::SLICE_OUT_OF_RANGE) {
                // Out of range slices are skipped
                continue;
            }

            bool res = check_init_func_dependence(field_init_expression_data, init_stage, init_mode, dependence_type);
            if (res) {
                return true;
            }
        }
    }

    return false;
}

inline size_t
device_configurator_base::get_init_function_data_index(const init_stage_e init_stage,
                                                       const init_expression_slice_mode_e init_mode) const
{
    static constexpr size_t num_of_lbr_slice_modes = to_utype(init_expression_slice_mode_e::LAST_LBR_SLICE_MODE) + 1;
    return (size_t)init_stage * num_of_lbr_slice_modes + (size_t)init_mode;
}

bool
device_configurator_base::check_init_func_dependence(const lld_field_init_expression_data* field_init_expression_data,
                                                     const init_stage_e init_stage,
                                                     const init_expression_slice_mode_e init_mode,
                                                     const expression_dependence_type_e dependence_type) const
{
    size_t init_function_data_idx = get_init_function_data_index(init_stage, init_mode);
    const init_function_data& init_function_data = field_init_expression_data->init_functions_data[init_function_data_idx];
    if (init_function_data.init_function == nullptr) {
        return false;
    }

    if (((dependence_type == expression_dependence_type_e::INSTANCE) && (init_function_data.is_instance_dependent))
        || ((dependence_type == expression_dependence_type_e::LINE) && (init_function_data.is_line_dependent))) {
        return true;
    }

    return false;
}

init_expression_slice_mode_e
device_configurator_base::get_init_mode(const lld_block::block_indices_struct& block_indices) const
{
    la_slice_id_t slice_flat_index = calc_flat_slice_index(block_indices);

    if (skip_this_block_matilda(block_indices, m_used_slices)) {
        // slice is 'out of range' or 'Disabled', meaning, it refers to irrelevant storage.
        // For example: there might be a global storage (reg/mem) array, with num_of_instances > num_of_slices and
        // instance_allocation=per_slice,
        // for which, as guided by the design, the instances >= num_of_slices are meaningless leftovers and should be ignored.
        return init_expression_slice_mode_e::SLICE_OUT_OF_RANGE;
    }

    switch (m_device_mode) {
    case device_mode_e::STANDALONE:
        return init_expression_slice_mode_e::INIT_VALUE_SA;

    case device_mode_e::LINECARD:
        if (slice_flat_index == LA_SLICE_ID_INVALID) {
            // 'slice_flat_index == LA_SLICE_ID_INVALID' means that the slice ID cannot be evaluated (there is missing
            // info to do so, i.e, block path doesn't specify the slice index and instance allocation isn't specified).
            // TODO: Add a check that for unresolved slice index in 'lc mode', only 'lc_nwk lbr init expression' exists. Since in
            // the
            // current implementation 'InitValueAllModes' masks whether an init mode was specified with an init expression and
            // changing it will result in quite a lot of work - the same behavior is kept as before and this task is deferred.
            // Take lc_nwk init expression as fallback:
            return init_expression_slice_mode_e::INIT_VALUE_LC_NWK;
        }

        if (m_slices_type[slice_flat_index] == lbr_slice_mode_e::NETWORK) {
            return init_expression_slice_mode_e::INIT_VALUE_LC_NWK;
        }

        return init_expression_slice_mode_e::INIT_VALUE_LC_FAB;

    case device_mode_e::FABRIC_ELEMENT:
        return init_expression_slice_mode_e::INIT_VALUE_FE;

    default:
        dassert_crit(false);
        return init_expression_slice_mode_e::SLICE_OUT_OF_RANGE;
    }
}

} // namespace silicon_one
