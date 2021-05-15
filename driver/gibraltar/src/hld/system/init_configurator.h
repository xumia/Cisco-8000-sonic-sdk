// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __INIT_CONFIGURATOR_H__
#define __INIT_CONFIGURATOR_H__

#include "api/types/la_common_types.h"
#include "hld_types.h"
#include "lld/lld_utils.h"

namespace silicon_one
{

class gibraltar_tree;
class la_device_impl;

class init_configurator
{
public:
    enum class init_step_e {
        PRE_SOFT_RESET,
        POST_SOFT_RESET,
    };

    // C'tor
    init_configurator(la_device_impl* device);

    /// @brief Initialize object.
    ///
    /// @retval status.
    la_status initialize();

    ///@brief Destroy object.
    ///
    /// @retval status.
    la_status destroy();

    /// @brief Configure device at provided step.
    ///
    /// @retval status.
    la_status configure_device(init_step_e init_step);

    la_device_impl* get_device() const;

private:
    // Reads single json object from metadata file.
    json_t* read_object(json_t* data, const char* tag);

    la_status configure_device_in_init_step(const std::string init_step_string);

    la_status configure_device_mode(json_t* device_modes_config);

    la_status configure_block(const char* block_name, json_t* block_data);

    la_status configure_block_registers(lld_block_scptr block, json_t* block_data);

    void configure_register(lld_block_scptr block, json_t* register_data, lld_register_value_list_t& reg_val_list);

    la_status configure_block_memories(lld_block_scptr block, json_t* block_data);

    la_status configure_memory(lld_block_scptr block, const char* memory_name, json_t* memory_line_arr);

    la_status configure_memory_const(lld_block_scptr block, json_t* memory_const_data);

    la_status configure_memory_line(lld_block_scptr block,
                                    lld_memory_scptr& memory,
                                    json_t* memory_line_data,
                                    lld_memory_line_value_list_t& mem_line_value_list);

    std::string to_tag_string(init_step_e init_step);
    std::string to_tag_string(device_mode_e device_mode);

private:
    la_device_impl* m_device;

    const gibraltar_tree* m_gibraltar_tree;

    json_t* m_root;
};

} // namespace silicon_one

#endif // __INIT_CONFIGURATOR_H__
