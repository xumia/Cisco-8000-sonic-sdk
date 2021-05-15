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

#ifndef __LEABA_DEVICE_CONFIGURATOR_H__
#define __LEABA_DEVICE_CONFIGURATOR_H__

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"
#include "common/bit_vector.h"
#include "hld_types.h"
#include "lld/lld_block.h"
#include "lld/lld_init_expression.h"

namespace silicon_one
{

class ll_device;
struct lld_register_desc_t;
struct lld_memory_desc_t;
struct lld_field_desc;
struct lld_field_init_expression_data;

class device_configurator_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // Used for device modes (i.e line card) that has different init values for each slice mode:
    enum class lbr_slice_mode_e { NETWORK, FABRIC };

    // Used for checking init expression specific tokens dependence:
    enum class expression_dependence_type_e { INSTANCE, LINE };

    struct system_init_vars {
        double frequency; // [mhz]
        la_device_id_t device_id;
        bool is_hbm;
        bool is_100g_fabric;
        size_t numnwk;
        size_t numfab;
        bool is_MAT_6_4T;
        bool is_MAT_3_2T_A;
        bool is_MAT_3_2T_B;
        size_t credit_in_bytes;
    };

    // C'tor
    device_configurator_base(ll_device_sptr ll_device);

    /// @brief Initialize object with its system init variables
    la_status initialize(device_mode_e device_mode,
                         system_init_vars system_vars,
                         std::vector<lbr_slice_mode_e>&& slices_type,
                         const std::vector<la_slice_id_t>& used_slices);

    /// @brief Configure device at provided step.
    la_status configure_device(const init_stage_e init_stage);

    static la_slice_id_t calc_flat_slice_index(const lld_block::block_indices_struct& block_indices);
    static bool skip_this_block_matilda(const lld_block::block_indices_struct& block_indices,
                                        const std::vector<la_slice_id_t>& used_slices);

private:
    device_configurator_base() = default;
    struct reg_mem_init_vars {
        size_t instance;
        size_t num_instances;
        size_t line;
        size_t num_lines;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(reg_mem_init_vars);

    la_status configure_block(const lld_block_scptr& block, const init_stage_e init_stage);

    la_status configure_registers(lld_block::lld_register_vec_t& registers,
                                  const init_stage_e init_stage,
                                  const lld_block::block_indices_struct& block_indices,
                                  const char* block_name);

    la_status configure_memories(lld_block::lld_memory_vec_t& memories,
                                 const init_stage_e init_stage,
                                 const lld_block::block_indices_struct& block_indices,
                                 const char* block_name);

    init_expression_slice_mode_e get_init_mode(const lld_block::block_indices_struct& block_indices) const;

    bool check_dependence(const std::vector<lld_field_desc>& fields_desc_vec,
                          const lld_block::block_indices_struct& reg_mem_block_indices,
                          const init_stage_e init_stage,
                          const expression_dependence_type_e dependence_type) const;

    bool check_init_func_dependence(const lld_field_init_expression_data* field_init_expression_data,
                                    const init_stage_e init_stage,
                                    const init_expression_slice_mode_e init_mode,
                                    const expression_dependence_type_e dependence_type) const;

    void update_indices_by_instance_allocation(lld_block::block_indices_struct& block_indices_to_update,
                                               const instance_allocation_e instance_allocation,
                                               const size_t item_or_instance_index) const;

    la_status calc_reg_value(bit_vector& out_reg_value,
                             const lld_register_desc_t* reg_desc,
                             const lld_block::block_indices_struct& reg_block_indices,
                             const reg_mem_init_vars& reg_vars,
                             const init_stage_e init_stage,
                             bool& out_is_init_expression_exist);

    la_status calc_mem_entry_value(bit_vector& out_mem_entry_value,
                                   const lld_memory_desc_t* mem_desc,
                                   const lld_block::block_indices_struct& mem_block_indices,
                                   const reg_mem_init_vars& mem_vars,
                                   const init_stage_e init_stage,
                                   bool& out_is_init_expression_exist);

    la_status apply_fields_init_funcs(bit_vector& out_reg_mem_value,
                                      const std::vector<lld_field_desc>& fields_vec,
                                      const lld_block::block_indices_struct& reg_mem_block_indices,
                                      const reg_mem_init_vars& reg_vars,
                                      const init_stage_e init_stage,
                                      bool& out_is_init_expression_exist);

    la_status apply_field_value(bit_vector& out_reg_mem_value,
                                const lld_field_desc& field_desc,
                                const lld_block::block_indices_struct& reg_mem_block_indices,
                                const reg_mem_init_vars& reg_mem_vars,
                                const init_stage_e init_stage,
                                bool& out_is_field_init_expression_exist);

    size_t get_init_function_data_index(const init_stage_e init_stage, const init_expression_slice_mode_e init_mode) const;

    ll_device_sptr m_ll_device;
    device_mode_e m_device_mode;
    std::vector<lbr_slice_mode_e> m_slices_type;
    std::vector<la_slice_id_t> m_used_slices;

    size_t m_num_of_slices;
    system_init_vars m_system_vars;
};

} // namespace silicon_one

#endif // __LEABA_DEVICE_CONFIGURATOR_H__
