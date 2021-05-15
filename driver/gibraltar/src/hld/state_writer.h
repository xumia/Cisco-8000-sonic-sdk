// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __STATE_WRITER_H__
#define __STATE_WRITER_H__

#include <jansson.h>
#include <map>
#include <vector>
#include <zlib.h>

#include "api/system/la_device.h"
#include "common/bit_vector.h"
#include "common/la_status.h"

#include "lld/lld_block.h"
#include "lld/lld_fwd.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"

/// @file
/// @brief Leaba state writer utility to dump registers/memories

namespace silicon_one
{

using storage_to_json = std::map<lld_storage_scptr, json_t*, handle_ops<lld_storage_scptr> >;

class ll_device;
class lld_block;

class state_writer
{
public:
    state_writer(ll_device_sptr m_ll_device, la_device::save_state_options options);
    ~state_writer();

    la_status fill();
    la_status write(std::string file_name);
    json_t* acquire_json_tree();

    // Append a JSON structure to the state writer JSON root.
    la_status fill(json_t*& in_root, std::string in_str);

private:
    json_t* get_register_subfields_json(const lld_register_desc_t* desc, const bit_vector& value);
    la_status get_register_value(lld_register_scptr reg, bit_vector& out_value) const;
    la_status fill_json_with_real_storage_values();
    void build_tree_json();
    void lld_block_to_json(lld_block_scptr block, json_t* json);
    void leaf_lld_block_to_json(lld_block_scptr block, json_t* json);
    void complex_lld_block_to_json(lld_block_scptr block, json_t* json);
    bool should_include(lld_register_scptr reg) const;
    bool should_include(lld_memory_scptr mem) const;

    json_t* m_root_json;
    ll_device_sptr m_ll_device;
    la_device::save_state_options m_options;
    lld_block_scptr m_lld_block;
    storage_to_json m_map;
};

} // namespace silicon_one

#endif /* __STATE_WRITER_H__ */
