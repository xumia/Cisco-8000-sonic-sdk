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

#include "resolution_configurator.h"
#include "api/types/la_object.h"
#include "common/gen_utils.h"
#include "resolution_configurator_impl.h"

namespace silicon_one
{

resolution_configurator::resolution_configurator()
{
}

resolution_configurator::~resolution_configurator()
{
}

la_status
resolution_configurator::initialize(int stage, const la_device_impl_wptr& device)
{
    m_stage = stage;

    switch (stage) {
    case 0:
        m_stage0_impl = make_unique<resolution_configurator_impl<resolution_stage0_trait_t> >(device);
        if (!m_stage0_impl) {
            return LA_STATUS_EOUTOFMEMORY;
        }
        break;
    case 1:
        m_stage1_impl = make_unique<resolution_configurator_impl<resolution_stage1_trait_t> >(device);
        if (!m_stage1_impl) {
            return LA_STATUS_EOUTOFMEMORY;
        }
        break;
    case 2:
        m_stage2_impl = make_unique<resolution_configurator_impl<resolution_stage2_trait_t> >(device);
        if (!m_stage2_impl) {
            return LA_STATUS_EOUTOFMEMORY;
        }
        break;
    case 3:
        m_stage3_impl = make_unique<resolution_configurator_impl<resolution_stage3_trait_t> >(device);
        if (!m_stage3_impl) {
            return LA_STATUS_EOUTOFMEMORY;
        }
        break;

    default:
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

template <typename table_value_type>
la_status
resolution_configurator::configure_dest_map_entry(const destination_id& dest,
                                                  const table_value_type& value,
                                                  resolution_cfg_handle_t& cfg_handle,
                                                  const npl_em_common_data_t& common_data)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->configure_dest_map_entry(dest, value, cfg_handle, common_data);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->configure_dest_map_entry(dest, value, cfg_handle, common_data);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->configure_dest_map_entry(dest, value, cfg_handle, common_data);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->configure_dest_map_entry(dest, value, cfg_handle, common_data);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

template <typename table_value_type>
la_status
resolution_configurator::configure_lb_entry(const la_uint32_t group_id,
                                            const la_uint32_t member_id,
                                            const table_value_type& value,
                                            resolution_cfg_handle_t& cfg_handle,
                                            const npl_em_common_data_t& common_data)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->configure_lb_entry(group_id, member_id, value, cfg_handle, common_data);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->configure_lb_entry(group_id, member_id, value, cfg_handle, common_data);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->configure_lb_entry(group_id, member_id, value, cfg_handle, common_data);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->configure_lb_entry(group_id, member_id, value, cfg_handle, common_data);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resolution_configurator::configure_in_stage_lb_entry(const la_uint32_t group_id,
                                                     const la_uint32_t member_id,
                                                     const la_object_wcptr& in_stage_dest,
                                                     resolution_cfg_handle_t& cfg_handle)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->configure_in_stage_lb_entry(group_id, member_id, in_stage_dest, cfg_handle, true);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->configure_in_stage_lb_entry(group_id, member_id, in_stage_dest, cfg_handle, true);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->configure_in_stage_lb_entry(group_id, member_id, in_stage_dest, cfg_handle, true);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->configure_in_stage_lb_entry(group_id, member_id, in_stage_dest, cfg_handle, true);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resolution_configurator::configure_in_stage_lb_entry(const la_uint32_t group_id,
                                                     const la_uint32_t member_id,
                                                     const la_object_wcptr& in_stage_dest,
                                                     resolution_cfg_handle_t& cfg_handle,
                                                     const npl_em_common_data_t& common_data)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->configure_in_stage_lb_entry(group_id, member_id, in_stage_dest, cfg_handle, false, common_data);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->configure_in_stage_lb_entry(group_id, member_id, in_stage_dest, cfg_handle, false, common_data);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->configure_in_stage_lb_entry(group_id, member_id, in_stage_dest, cfg_handle, false, common_data);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->configure_in_stage_lb_entry(group_id, member_id, in_stage_dest, cfg_handle, false, common_data);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resolution_configurator::unconfigure_entry(resolution_cfg_handle_t& cfg_handle)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->unconfigure_entry(cfg_handle);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->unconfigure_entry(cfg_handle);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->unconfigure_entry(cfg_handle);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->unconfigure_entry(cfg_handle);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resolution_configurator::set_group_size(const la_uint32_t group_id,
                                        const la_uint32_t group_size,
                                        npl_lb_consistency_mode_e consistency_mode)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->set_group_size(group_id, group_size, consistency_mode);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->set_group_size(group_id, group_size, consistency_mode);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->set_group_size(group_id, group_size, consistency_mode);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->set_group_size(group_id, group_size, consistency_mode);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resolution_configurator::get_group_size(const la_uint32_t group_id,
                                        la_uint32_t& out_group_size,
                                        npl_lb_consistency_mode_e& out_consistency_mode)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->get_group_size(group_id, out_group_size, out_consistency_mode);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->get_group_size(group_id, out_group_size, out_consistency_mode);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->get_group_size(group_id, out_group_size, out_consistency_mode);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->get_group_size(group_id, out_group_size, out_consistency_mode);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resolution_configurator::erase_group_size(const la_uint32_t group_id)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->erase_group_size(group_id);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->erase_group_size(group_id);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->erase_group_size(group_id);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->erase_group_size(group_id);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resolution_configurator::configure_protection_monitor(const la_protection_monitor_gid_t& monitor_id,
                                                      npl_resolution_protection_selector_e selector)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->configure_protection_monitor(monitor_id, selector);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->configure_protection_monitor(monitor_id, selector);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->configure_protection_monitor(monitor_id, selector);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->configure_protection_monitor(monitor_id, selector);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resolution_configurator::unconfigure_protection_monitor(const la_protection_monitor_gid_t& monitor_id)
{
    switch (m_stage) {
    case 0:
        dassert_crit(m_stage0_impl);
        return m_stage0_impl->unconfigure_protection_monitor(monitor_id);
    case 1:
        dassert_crit(m_stage1_impl);
        return m_stage1_impl->unconfigure_protection_monitor(monitor_id);
    case 2:
        dassert_crit(m_stage2_impl);
        return m_stage2_impl->unconfigure_protection_monitor(monitor_id);
    case 3:
        dassert_crit(m_stage3_impl);
        return m_stage3_impl->unconfigure_protection_monitor(monitor_id);
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

// Manually instantiate relevant templates
template la_status resolution_configurator::configure_lb_entry<npl_resolution_stage_assoc_data_narrow_entry_t>(
    const uint32_t,
    const uint32_t,
    const npl_resolution_stage_assoc_data_narrow_entry_t&,
    resolution_cfg_handle_t&,
    const npl_em_common_data_t&);
template la_status resolution_configurator::configure_lb_entry<npl_resolution_stage_assoc_data_wide_entry_t>(
    const uint32_t,
    const uint32_t,
    const npl_resolution_stage_assoc_data_wide_entry_t&,
    resolution_cfg_handle_t&,
    const npl_em_common_data_t&);
template la_status resolution_configurator::configure_lb_entry<npl_resolution_stage_assoc_data_wide_protection_record_t>(
    const uint32_t,
    const uint32_t,
    const npl_resolution_stage_assoc_data_wide_protection_record_t&,
    resolution_cfg_handle_t&,
    const npl_em_common_data_t&);

template la_status resolution_configurator::configure_dest_map_entry<npl_resolution_stage_assoc_data_narrow_entry_t>(
    const destination_id&,
    const npl_resolution_stage_assoc_data_narrow_entry_t&,
    resolution_cfg_handle_t&,
    const npl_em_common_data_t&);
template la_status resolution_configurator::configure_dest_map_entry<npl_resolution_stage_assoc_data_wide_entry_t>(
    const destination_id&,
    const npl_resolution_stage_assoc_data_wide_entry_t&,
    resolution_cfg_handle_t&,
    const npl_em_common_data_t&);
template la_status resolution_configurator::configure_dest_map_entry<npl_resolution_stage_assoc_data_wide_protection_record_t>(
    const destination_id&,
    const npl_resolution_stage_assoc_data_wide_protection_record_t&,
    resolution_cfg_handle_t&,
    const npl_em_common_data_t&);

} // namespace silicon_one
