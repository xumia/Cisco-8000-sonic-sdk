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

#include "system/la_erspan_mirror_command_plgr.h"
#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "npu/mc_copy_id_manager.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_erspan_mirror_command_plgr::la_erspan_mirror_command_plgr(const la_device_impl_wptr& device)
    : la_erspan_mirror_command_akpg(device)
{
}

la_erspan_mirror_command_plgr::~la_erspan_mirror_command_plgr()
{
}

la_status
la_erspan_mirror_command_plgr::configure_ibm_command_table(la_uint_t sampling_rate)
{
    auto sp_impl = m_dsp.weak_ptr_static_cast<const la_system_port_base>();

    const auto& table(m_device->m_tables.ibm_cmd_table);
    npl_ibm_cmd_table_key_t key;
    npl_ibm_cmd_table_value_t value;
    npl_ibm_cmd_table_entry_t* entry = nullptr;

    key.rxpp_to_txpp_local_vars_mirror_command = m_mirror_gid;
    value.payloads.ibm_cmd_table_result.sampling_probability = sampling_rate;
    value.payloads.ibm_cmd_table_result.is_mc = 0;
    value.payloads.ibm_cmd_table_result.tc_map_profile = la_device_impl::IBM_TC_PROFILE;

    la_voq_set* voq_set = sp_impl->get_voq_set();

    // For ERSPAN rate-limiting support, add the TC to the base voq to get the
    // final voq. The TC profile mapping values should always be 0.
    value.payloads.ibm_cmd_table_result.voq_or_bitmap.base_voq = voq_set->get_base_voq_id() + m_voq_offset;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
