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

#include "la_unicast_tc_profile_impl.h"
#include "hld_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_tc_profile_impl::la_tc_profile_impl(const la_device_impl_wptr& device) : m_device(device)
{
}

la_tc_profile_impl::~la_tc_profile_impl()
{
}

la_status
la_tc_profile_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    bool is_success = m_device->m_index_generators.tc_profiles.allocate(m_id);
    if (!is_success) {
        return LA_STATUS_ERESOURCE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_tc_profile_impl::destroy()
{
    // Clean tables
    const auto& dsp_table(m_device->m_tables.rxpdr_dsp_tc_map);
    npl_rxpdr_dsp_tc_map_key_t dsp_key;
    const auto& oq_table(m_device->m_tables.txpdr_tc_map_table);
    npl_txpdr_tc_map_table_key_t oq_key;

    dsp_key.rxpdr_dsp_lookup_table_result_tc_map_profile = m_id;
    oq_key.txpdr_local_vars_tc_map_profile = m_id;

    for (la_traffic_class_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
        dsp_key.rxpp_pd_tc = tc;

        // Not sure there's an entry for all possible TCs. ENOTFOUND is a legitimate return value.
        la_status status = dsp_table->erase(dsp_key);
        if ((status != LA_STATUS_SUCCESS) && (status != LA_STATUS_ENOTFOUND)) {
            return status;
        }

        status = oq_table->erase(oq_key);
        if ((status != LA_STATUS_SUCCESS) && (status != LA_STATUS_ENOTFOUND)) {
            return status;
        }
    }

    m_device->m_index_generators.tc_profiles.release(m_id);

    return LA_STATUS_SUCCESS;
}

uint64_t
la_tc_profile_impl::get_id() const
{
    return m_id;
}

la_status
la_tc_profile_impl::set_mapping(la_traffic_class_t tc, la_uint8_t offset)
{
    start_api_call("tc=", tc, "offset=", offset);

    if (tc >= NUM_TC_CLASSES) {
        return LA_STATUS_EINVAL;
    }

    if (offset >= NUM_OQ_PER_PIF) {
        return LA_STATUS_EINVAL;
    }

    // DSP table
    const auto& dsp_table(m_device->m_tables.rxpdr_dsp_tc_map);
    npl_rxpdr_dsp_tc_map_key_t dsp_key;
    npl_rxpdr_dsp_tc_map_value_t dsp_value;
    npl_rxpdr_dsp_tc_map_entry_t* dsp_entry = nullptr;

    dsp_key.rxpdr_dsp_lookup_table_result_tc_map_profile = m_id;
    dsp_key.rxpp_pd_tc = tc;
    dsp_value.payloads.rxpdr_dsp_tc_map_result.tc_offset = offset;

    la_status status = dsp_table->set(dsp_key, dsp_value, dsp_entry);
    return_on_error(status);

    // OQ TC mapping table (MC egress replication)
    const auto& oq_table(m_device->m_tables.txpdr_tc_map_table);
    npl_txpdr_tc_map_table_key_t oq_key;
    npl_txpdr_tc_map_table_value_t oq_value;
    npl_txpdr_tc_map_table_entry_t* oq_entry = nullptr;

    oq_key.txpdr_local_vars_tc_map_profile = m_id;
    oq_key.rxpp_pd_tc = tc;
    oq_value.payloads.txpdr_local_vars_tc_offset = offset;

    status = oq_table->set(oq_key, oq_value, oq_entry);

    // OQ TC mapping table for LP Queuing
    const auto& bvn_table(m_device->m_tables.bvn_tc_map_table);
    npl_bvn_tc_map_table_key_t bvn_key;
    npl_bvn_tc_map_table_value_t bvn_value;
    npl_bvn_tc_map_table_entry_t* bvn_entry = nullptr;

    bvn_key.tc_map_profile = m_id;
    bvn_key.tc = tc;
    bvn_value.payloads.bvn_offset = offset;

    status = bvn_table->set(bvn_key, bvn_value, bvn_entry);

    return status;
}

la_status
la_tc_profile_impl::get_mapping(la_traffic_class_t tc, la_uint8_t& out_offset) const
{
    if (tc >= NUM_TC_CLASSES) {
        return LA_STATUS_EINVAL;
    }

    // DSP table
    const auto& dsp_table(m_device->m_tables.rxpdr_dsp_tc_map);
    npl_rxpdr_dsp_tc_map_key_t dsp_key;
    npl_rxpdr_dsp_tc_map_entry_t* dsp_entry = nullptr;

    dsp_key.rxpdr_dsp_lookup_table_result_tc_map_profile = m_id;
    dsp_key.rxpp_pd_tc = tc;

    la_status status = dsp_table->lookup(dsp_key, dsp_entry);
    return_on_error(status);

    out_offset = dsp_entry->value().payloads.rxpdr_dsp_tc_map_result.tc_offset;

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_tc_profile_impl::type() const
{
    return object_type_e::TC_PROFILE;
}

std::string
la_tc_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_tc_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_tc_profile_impl::oid() const
{
    return m_oid;
}

const la_device*
la_tc_profile_impl::get_device() const
{
    return m_device.get();
}

} // namespace silicon_one
