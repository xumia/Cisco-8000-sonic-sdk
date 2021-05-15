// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_voq_cgm_evicted_profile_impl.h"
#include "common/gen_utils.h"
#include "hld_utils.h"

#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"
#include "voq_cgm_handler.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <cmath>

namespace silicon_one
{

la_voq_cgm_evicted_profile_impl::la_voq_cgm_evicted_profile_impl(const la_device_impl_wptr& device) : m_device(device)
{
}

la_voq_cgm_evicted_profile_impl::~la_voq_cgm_evicted_profile_impl()
{
}

la_status
la_voq_cgm_evicted_profile_impl::initialize(la_object_id_t oid, uint64_t voq_cgm_evicted_profile_index)
{
    m_oid = oid;
    m_index = voq_cgm_evicted_profile_index;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_evicted_profile_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_voq_cgm_evicted_profile_impl::type() const
{
    return object_type_e::VOQ_CGM_EVICTED_PROFILE;
}

std::string
la_voq_cgm_evicted_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_voq_cgm_evicted_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_voq_cgm_evicted_profile_impl::oid() const
{
    return m_oid;
}

const la_device*
la_voq_cgm_evicted_profile_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_voq_cgm_evicted_profile_impl::get_id() const
{
    return m_index;
}

la_status
la_voq_cgm_evicted_profile_impl::ensure_sms_evicted_buffers_key_valid(const la_voq_sms_evicted_buffers_key& key) const
{
    la_uint64_t num_evicted_buffers_regions;
    la_status status
        = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS, num_evicted_buffers_regions);
    return_on_error(status);
    if (key.evicted_buffers_region >= num_evicted_buffers_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_total_bytes_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    return_on_error(status);
    if (key.sms_voqs_total_bytes_region >= num_sms_total_bytes_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_voq_bytes_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    return_on_error(status);
    if (key.sms_bytes_region >= num_sms_voq_bytes_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_evicted_profile_impl::do_set_sms_evicted_buffers_drop_behavior(la_quantization_region_t evicted_buffers_region,
                                                                          la_quantization_region_t sms_voqs_total_bytes_region,
                                                                          la_quantization_region_t sms_bytes_region,
                                                                          la_qos_color_e drop_color_level)
{
    // Choose table.
    const auto& tables(m_device->m_tables.voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table);

    // Prepare arguments.
    npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_t::value_type v;

    k.evicted_profile_id = m_index;
    k.all_evicted_voq_buff_consump_level = evicted_buffers_region;
    k.buffer_pool_available_level = sms_voqs_total_bytes_region;
    k.buffer_voq_size_level = sms_bytes_region;

    v.payloads.voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_results.drop_green
        = (drop_color_level <= la_qos_color_e::GREEN);
    v.payloads.voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_results.drop_yellow
        = (drop_color_level <= la_qos_color_e::YELLOW);

    v.action = NPL_VOQ_CGM_SLICE_EVICTED_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return write_status;
}

la_status
la_voq_cgm_evicted_profile_impl::set_sms_evicted_buffers_drop_behavior(const la_voq_sms_evicted_buffers_key& key,
                                                                       const la_voq_sms_evicted_buffers_drop_val& val)
{
    start_api_call("key=", key, "val=", val);

    // Don't allow configuration for default profile VOQ_CGM_DEFAULT_EVICTED_PROFILE.
    if (m_index == la_device_impl::VOQ_CGM_DEFAULT_EVICTED_PROFILE) {
        return LA_STATUS_EINVAL;
    }

    // Validate key.
    la_status status = ensure_sms_evicted_buffers_key_valid(key);
    return_on_error(status);

    return do_set_sms_evicted_buffers_drop_behavior(
        key.evicted_buffers_region, key.sms_voqs_total_bytes_region, key.sms_bytes_region, val.drop_color_level);
}

la_status
la_voq_cgm_evicted_profile_impl::get_sms_evicted_buffers_drop_behavior(const la_voq_sms_evicted_buffers_key& key,
                                                                       la_voq_sms_evicted_buffers_drop_val& out_val) const
{
    start_api_getter_call();

    // Validate key.
    la_status status = ensure_sms_evicted_buffers_key_valid(key);
    return_on_error(status);

    // Choose table.
    const auto& tables(m_device->m_tables.voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table);

    // Prepare arguments.
    npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_t::value_type v;
    npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.evicted_profile_id = m_index;
    k.all_evicted_voq_buff_consump_level = key.evicted_buffers_region;
    k.buffer_pool_available_level = key.sms_voqs_total_bytes_region;
    k.buffer_voq_size_level = key.sms_bytes_region;

    // Read current value
    size_t first_inst = m_device->first_active_slice_id();
    status = tables[first_inst]->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();
    if (v.payloads.voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_results.drop_green) {
        out_val.drop_color_level = la_qos_color_e::GREEN;
    } else if (v.payloads.voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_results.drop_yellow) {
        out_val.drop_color_level = la_qos_color_e::YELLOW;
    } else {
        out_val.drop_color_level = la_qos_color_e::NONE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_evicted_profile_impl::do_set_default_behavior()
{
    la_uint64_t num_evicted_buffers_regions;
    la_status status
        = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS, num_evicted_buffers_regions);
    return_on_error(status);

    la_uint64_t num_sms_total_bytes_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    return_on_error(status);

    la_uint64_t num_sms_voq_bytes_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);

    for (la_quantization_region_t evicted_buffers_region = 0; evicted_buffers_region < num_evicted_buffers_regions;
         evicted_buffers_region++) {
        for (la_quantization_region_t sms_total_bytes_region = 0; sms_total_bytes_region < num_sms_total_bytes_regions;
             sms_total_bytes_region++) {
            for (la_quantization_region_t sms_voq_bytes_region = 0; sms_voq_bytes_region < num_sms_voq_bytes_regions;
                 sms_voq_bytes_region++) {
                // Read from default config.
                la_qos_color_e drop_color_level;
                status = m_device->m_voq_cgm_handler->get_voq_cgm_evicted_buffers_default_behavior(
                    evicted_buffers_region, sms_total_bytes_region, sms_voq_bytes_region, drop_color_level);
                return_on_error(status);

                status = do_set_sms_evicted_buffers_drop_behavior(
                    evicted_buffers_region, sms_total_bytes_region, sms_voq_bytes_region, drop_color_level);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_evicted_profile_impl::set_default_behavior()
{
    start_api_call("");

    return do_set_default_behavior();
}

} // namespace silicon_one
