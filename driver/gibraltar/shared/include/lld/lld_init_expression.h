// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_LLD_INIT_EXPRESSION_H__
#define __LEABA_LLD_INIT_EXPRESSION_H__

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"
#include "common/gen_utils.h"
#include "lld/lld_block.h"

namespace silicon_one
{

/// @brief  Reg/Mem/Field instance allocation
///
///			'instance_allocation' is an lbr attribute which appears at the reg/mem / field hierarchies.
/// 		It can refer to either reg/mem instance number (for an array of regs/mems) or to item number in an itemized fields.
/// 		Its purpose is to set the instance allocation type with the instance/item value.
/// 		Example: given an array of registers with instance_allocation='PER_SLICE', init expression='slice/2',
/// 		for instance=4 ==> init expression evaluation = 4/2
enum class instance_allocation_e { NONE, PER_SLICE, PER_SLICE_PAIR, PER_IFG };

/// @brief Initialization stage
///
/// init stage refers to when an init expression should be applied.
enum class init_stage_e { PRE_SOFT_RESET, POST_SOFT_RESET, LAST = POST_SOFT_RESET };

/// @brief  lbr slice mode for init expressions
///
/// describes the possible lbr init modes
enum class init_expression_slice_mode_e {
    INIT_VALUE_SA,
    INIT_VALUE_LC_NWK,
    INIT_VALUE_LC_FAB,
    INIT_VALUE_FE,
    LAST_LBR_SLICE_MODE = INIT_VALUE_FE,
    SLICE_OUT_OF_RANGE
};

constexpr size_t max_num_of_init_expressions_per_field
    = (to_utype(init_stage_e::LAST) + 1) * (to_utype(init_expression_slice_mode_e::LAST_LBR_SLICE_MODE) + 1);

/// @brief  Field array item width
///
/// 'array_item_width' is an lbr attribute which appears at the field hierarchy.
/// Field might possibly be treated as an array of items, the size of one item is the 'array_item_width'
/// Example: field_width=20, array_item_width=4 ==> the field should be treated as an array of 5 items, each 4 bit long.
using lld_array_item_width_t = uint32_t;
constexpr lld_array_item_width_t LLD_ARRAY_ITEM_WIDTH_INVALID = (lld_array_item_width_t)(-1);

/// @brief  Init function pointer
///
/// 'init_func_ptr' is a pointer to an auto-generated function which represents an 'InitValue[Sa/Lc/Fe/AllModes]' lbr init
/// expression.
/// The functions might be called for initialization/resetting purposes.
/// These expressions are supported only in the field hierarchy.
using init_function_ptr = uint64_t (*)(double frequency,
                                       la_device_id_t device_id,
                                       bool is_hbm,
                                       bool is_100g_fabric,
                                       size_t numnwk,
                                       size_t numfab,
                                       bool is_MAT_6_4T,
                                       bool is_MAT_3_2T_A,
                                       bool is_MAT_3_2T_B,
                                       size_t credit_in_bytes,
                                       lld_block::block_instance_t block,
                                       la_slice_pair_id_t slice_pair,
                                       la_slice_id_t slice,
                                       la_ifg_id_t ifg,
                                       size_t instance,
                                       size_t num_instances,
                                       size_t line,
                                       size_t num_lines,
                                       size_t num_items,
                                       size_t item);

/// @brief  All related data with an init function
///
/// This struct keep the relevant needed data to evaluate single init expression.
/// Note that field might have many related init expressions (for example: 2 stages (pre/post soft reset), 4 lbr init modes (s/lc
/// nwk/lc fab/fe) can result in 8 different init expressions which related to the same field), each represented by its own
/// instance.
struct init_function_data {
    // 'is_instance/line_dependent' keeps a hint whether the init expression includes the tokens instance/line. It is used for
    // evaluation optimizations.
    bool is_instance_dependent;
    bool is_line_dependent;
    init_function_ptr init_function;
};

/// @brief  All field's init expressions related data
///
/// Keeps all the field's related init data
struct lld_field_init_expression_data {
    lld_array_item_width_t array_item_width;
    instance_allocation_e instance_allocation;
    init_function_data init_functions_data[max_num_of_init_expressions_per_field];
};

} // namespace silicon_one

#endif /* __LEABA_LLD_INIT_EXPRESSION_H__ */
