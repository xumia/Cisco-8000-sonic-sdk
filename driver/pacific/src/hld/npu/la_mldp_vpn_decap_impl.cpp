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

#include "la_mldp_vpn_decap_impl.h"
#include "api/npu/la_vrf.h"
#include "hld_utils.h"
#include "npu/counter_utils.h"
#include "npu/la_counter_set_impl.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_mldp_vpn_decap_impl::la_mldp_vpn_decap_impl(const la_device_impl_wptr& device) : m_device(device), m_vrf(nullptr)
{
}

la_mldp_vpn_decap_impl::~la_mldp_vpn_decap_impl()
{
}

la_object::object_type_e
la_mldp_vpn_decap_impl::type() const
{
    return la_object::object_type_e::MLDP_VPN_DECAP;
}

std::string
la_mldp_vpn_decap_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_mldp_vpn_decap_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_mldp_vpn_decap_impl::oid() const
{
    return m_oid;
}

const la_device*
la_mldp_vpn_decap_impl::get_device() const
{
    return m_device.get();
}

la_mpls_label
la_mldp_vpn_decap_impl::get_label() const
{
    start_api_getter_call();
    return m_label;
}

const la_vrf*
la_mldp_vpn_decap_impl::get_vrf() const
{
    start_api_getter_call();
    return m_vrf.get();
}

la_uint_t
la_mldp_vpn_decap_impl::get_rpfid()
{
    return m_rpfid;
}

bool
la_mldp_vpn_decap_impl::get_node_type()
{
    return m_bud_node;
}

la_status
la_mldp_vpn_decap_impl::check_rpf_range()
{
    la_uint64_t min_rpf_id;
    la_uint64_t max_rpf_id;
    m_device->get_limit(limit_type_e::MLDP_MIN_RPF_ID, min_rpf_id);
    m_device->get_limit(limit_type_e::MLDP_MAX_RPF_ID, max_rpf_id);

    if (m_rpfid == la_device_impl::INVALID_RPF_ID) {
        log_err(HLD, "%s: RPF ID must be min %lld and max %lld ", __func__, min_rpf_id, max_rpf_id);
        return LA_STATUS_EINVAL;
    }

    if (m_rpfid < min_rpf_id) {
        log_err(HLD, "%s: RPF ID must be larger than %lld ", __func__, min_rpf_id);
        return LA_STATUS_EINVAL;
    }

    if (m_rpfid > max_rpf_id) {
        log_err(HLD, "%s: RPF ID must be smaller than %lld ", __func__, max_rpf_id);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mldp_vpn_decap_impl::add_to_mldp_termination_table(const la_counter_set_wcptr& counter)
{
    la_status retval = check_rpf_range();
    return_on_error(retval);

    for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
        const auto& table(m_device->m_tables.mpls_termination_em1_table[slice]);
        npl_mpls_termination_em1_table_value_t value;
        npl_mpls_termination_em1_table_key_t key;

        la_vrf_gid_t vrf_gid = m_vrf->get_gid();

        key.termination_label = m_label.label;

        npl_mpls_termination_result_t& result(value.payloads.mpls_termination_result.result);
        result.service = m_bud_node ? NPL_MPLS_SERVICE_L3_MLDP_BUD : NPL_MPLS_SERVICE_L3_MLDP_TAIL;
        result.pwe_vpn_mldp_info.l3vpn_info.l3_relay_id.id = vrf_gid;
        result.pwe_vpn_mldp_info.l3vpn_info.vpn_p_counter = populate_counter_ptr_slice(counter, slice, COUNTER_DIRECTION_INGRESS);
        result.pwe_vpn_mldp_info.l3vpn_info.vpn_mldp_info.mldp_info.rpf_id = m_rpfid;

        la_status status = table->set(key, value, m_slice_data[slice].m_mldp_termination_entry);

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mldp_vpn_decap_impl::update_mldp_termination_table(la_mpls_label label, const la_vrf_wcptr& vrf, la_uint_t rpfid, bool bud_node)
{
    npl_mpls_termination_em1_table_value_t value;
    npl_mpls_termination_em1_table_key_t key;
    npl_mpls_termination_em1_table_t::entry_wptr_type entry_ptr;
    la_status retval;

    m_label = label;

    for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {

        const auto& table(m_device->m_tables.mpls_termination_em1_table[slice]);

        key.termination_label = m_label.label;
        la_status status = table->lookup(key, entry_ptr);
        return_on_error(status);

        if (!entry_ptr) {
            return LA_STATUS_ENOTFOUND;
        }
    }

    m_vrf = vrf;
    m_counter = nullptr;
    m_rpfid = rpfid;
    m_bud_node = bud_node;
    la_vrf_gid_t vrf_gid = m_vrf->get_gid();

    retval = check_rpf_range();
    return_on_error(retval);

    for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
        const auto& table(m_device->m_tables.mpls_termination_em1_table[slice]);
        npl_mpls_termination_result_t& result(value.payloads.mpls_termination_result.result);

        result.service = m_bud_node ? NPL_MPLS_SERVICE_L3_MLDP_BUD : NPL_MPLS_SERVICE_L3_MLDP_TAIL;
        result.pwe_vpn_mldp_info.l3vpn_info.l3_relay_id.id = vrf_gid;
        result.pwe_vpn_mldp_info.l3vpn_info.vpn_p_counter = populate_counter_ptr_slice(m_counter, slice, COUNTER_DIRECTION_INGRESS);
        result.pwe_vpn_mldp_info.l3vpn_info.vpn_mldp_info.mldp_info.rpf_id = m_rpfid;

        la_status status = table->set(key, value, m_slice_data[slice].m_mldp_termination_entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mldp_vpn_decap_impl::remove_from_mldp_termination_table()
{
    for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
        const auto& table(m_device->m_tables.mpls_termination_em1_table[slice]);
        npl_mpls_termination_em1_table_key_t key = m_slice_data[slice].m_mldp_termination_entry->key();

        la_status status = table->erase(key);
        return_on_error(status);

        m_slice_data[slice].m_mldp_termination_entry = nullptr;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_mldp_vpn_decap_impl::initialize(la_object_id_t oid, la_mpls_label label, const la_vrf_wcptr& vrf, la_uint_t rpfid, bool bud_node)
{
    m_oid = oid;
    if (!of_same_device(vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    m_label = label;
    m_vrf = vrf;
    m_counter = nullptr;
    m_rpfid = rpfid;
    m_bud_node = bud_node;

    la_status status = add_to_mldp_termination_table(m_counter);
    return_on_error(status);

    m_device->add_object_dependency(vrf, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_mldp_vpn_decap_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = remove_from_mldp_termination_table();
    return_on_error(status);

    status = remove_counter();
    return_on_error(status);

    m_device->remove_object_dependency(m_vrf, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_mldp_vpn_decap_impl::set_counter(la_counter_set* counter)
{
    start_api_call("counter=", counter);
    la_status status;

    const la_counter_set_impl_wptr& counter_sp = m_device->get_sptr<la_counter_set_impl>(counter);

    if (counter_sp == nullptr) {
        // Remove the previous counter
        status = remove_counter();
        return_on_error(status);
        return LA_STATUS_SUCCESS;
    }

    if (!of_same_device(counter_sp, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    size_t counter_set_size = counter_sp->get_set_size();
    if (counter_set_size != 2) {
        return LA_STATUS_EINVAL;
    }

    const auto& prev_counter = m_counter;
    if (counter_sp == prev_counter) {
        return LA_STATUS_SUCCESS;
    }

    status = counter_sp->add_mpls_decap_counter();
    return_on_error(status);

    m_device->add_object_dependency(counter_sp, this);

    status = add_to_mldp_termination_table(counter_sp);
    return_on_error(status);

    // Remove the previous counter
    status = remove_counter();
    return_on_error(status);

    m_counter = counter_sp;

    return LA_STATUS_SUCCESS;
}

la_status
la_mldp_vpn_decap_impl::remove_counter()
{
    const auto& counter_impl = m_counter;

    if (counter_impl == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    m_device->remove_object_dependency(counter_impl, this);

    la_status status = counter_impl->remove_mpls_decap_counter();
    return_on_error(status);

    m_counter = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_mldp_vpn_decap_impl::get_counter(la_counter_set*& out_counter) const
{
    start_api_getter_call();

    out_counter = m_counter.get();

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
