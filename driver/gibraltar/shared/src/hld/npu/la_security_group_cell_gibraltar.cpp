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

#include "la_security_group_cell_gibraltar.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "nplapi/npl_constants.h"
#include "npu/counter_utils.h"
#include "npu/la_acl_security_group.h"
#include "system/la_device_impl.h"

#include <sstream>

namespace silicon_one
{

la_security_group_cell_gibraltar::la_security_group_cell_gibraltar(const la_device_impl_wptr& device)
    : la_security_group_cell_base(device)
{
}

la_security_group_cell_gibraltar::~la_security_group_cell_gibraltar()
{
}

la_status
la_security_group_cell_gibraltar::initialize(la_object_id_t oid,
                                             la_sgt_t sgt,
                                             la_dgt_t dgt,
                                             la_ip_version_e ip_version,
                                             const la_counter_set_wptr& counter)
{
    m_sgt = sgt;
    m_dgt = dgt;
    m_ip_version = ip_version;

    npl_sgt_matrix_table_t::key_type key;
    npl_sgt_matrix_table_t::value_type value;
    npl_sgt_matrix_table_t::entry_pointer_type entry = nullptr;

    key.src_sgt = m_sgt;
    key.dst_sgt = m_dgt;
    key.ip_version = (m_ip_version == la_ip_version_e::IPV6) ? true : false;

    la_status status = m_device->m_tables.sgt_matrix_table->lookup(key, entry);

    if (status == LA_STATUS_SUCCESS) {
        return LA_STATUS_EEXIST;
    }

    value.payloads.sgt_matrix_em_result.group_policy_allow_drop = m_allow_drop;
    value.payloads.sgt_matrix_em_result.group_policy_acl_id = ((m_sgacl_id & 0xff) << 24) | (m_sgacl_bincode & 0x00ffffff);

    status = m_device->m_tables.sgt_matrix_table->set(key, value, entry);
    return_on_error(status);

    m_oid = oid;
    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::update_attributes()
{
    npl_sgt_matrix_table_t::key_type key;
    npl_sgt_matrix_table_t::value_type value;
    npl_sgt_matrix_table_t::entry_pointer_type entry = nullptr;

    key.src_sgt = m_sgt;
    key.dst_sgt = m_dgt;
    key.ip_version = (m_ip_version == la_ip_version_e::IPV6) ? true : false;

    la_status status = m_device->m_tables.sgt_matrix_table->lookup(key, entry);
    return_on_error(status);

    value = entry->value();

    value.payloads.sgt_matrix_em_result.group_policy_allow_drop = m_allow_drop;
    value.payloads.sgt_matrix_em_result.group_policy_acl_id = ((m_sgacl_id & 0xff) << 24) | (m_sgacl_bincode & 0x00ffffff);

    status = entry->update(value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::configure_cell_counter_attribute_tables(la_counter_set* counter)
{
    npl_sgt_matrix_table_t::key_type key;
    npl_sgt_matrix_table_t::value_type value;
    npl_sgt_matrix_table_t::entry_pointer_type entry = nullptr;
    npl_counter_ptr_t counter_ptr;

    npl_sgacl_counter_bank_table_key_t key_sgacl_cb;
    npl_sgacl_counter_bank_table_value_t value_sgacl_cb;
    npl_sgacl_counter_bank_table_entry_t* entry_sgacl_cb;

    key.src_sgt = m_sgt;
    key.dst_sgt = m_dgt;
    key.ip_version = (m_ip_version == la_ip_version_e::IPV6) ? true : false;

    la_status status = m_device->m_tables.sgt_matrix_table->lookup(key, entry);
    return_on_error(status);

    value = entry->value();

    // Populate cell counter.
    if (counter != nullptr) {
        for (la_slice_id_t slice : m_device->get_used_slices()) {
            counter_ptr = populate_counter_ptr_slice(m_device->get_sptr(counter), slice, COUNTER_DIRECTION_INGRESS);
            value.payloads.sgt_matrix_em_result.group_policy_counter_metadata.sgacl_counter_lsb = counter_ptr.cb_set_base;
            value.payloads.sgt_matrix_em_result.group_policy_counter_metadata.sgacl_bank_idx = 0;
            // Reset the cb index and then copy in the slice DB.
            counter_ptr.cb_set_base = 0;
            value_sgacl_cb.payloads.counter_bank_msb = counter_ptr;
            la_status status
                = m_device->m_tables.sgacl_counter_bank_table[slice]->set(key_sgacl_cb, value_sgacl_cb, entry_sgacl_cb);
            return_on_error(status);
        }
    }

    status = entry->update(value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::do_set_counter(la_counter_set* counter)
{
    if (counter && counter->get_device() != m_device.get()) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (counter && counter->get_set_size() != 2) {
        return LA_STATUS_EINVAL;
    }

    auto prev_counter = m_counter.get();
    if (counter == prev_counter) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    if (counter == nullptr) {
        // Remove the previous counter
        status = remove_counter();
        return_on_error(status);

        return LA_STATUS_SUCCESS;
    }

    la_counter_set_impl* counter_impl = static_cast<la_counter_set_impl*>(counter);
    status = counter_impl->add_security_group_cell_counter();
    return_on_error(status);

    m_device->add_object_dependency(counter_impl, this);

    // Remove the previous counter
    if (prev_counter) {
        la_status status = remove_counter();
        return_on_error(status);
    }

    m_counter = m_device->get_sptr(counter);

    status = configure_cell_counter_attribute_tables(counter);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::set_counter(la_counter_set* counter)
{
    start_api_call("counter=", counter);

    la_status status = do_set_counter(counter);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::get_counter(la_counter_set*& out_counter) const
{
    start_api_call("");

    out_counter = m_counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::set_monitor_mode(bool allow_drop)
{
    start_api_call("allow_drop=", allow_drop);

    if (m_allow_drop == allow_drop) {
        return LA_STATUS_SUCCESS;
    }

    transaction txn;
    bool old_allow_drop = m_allow_drop;
    m_allow_drop = allow_drop;

    txn.on_fail([&]() { m_allow_drop = old_allow_drop; });

    txn.status = update_attributes();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::get_monitor_mode(bool& out_allow_drop) const
{
    start_api_getter_call();

    out_allow_drop = m_allow_drop;

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::set_acl(la_acl* sgacl)
{
    start_api_call("sgacl=", sgacl);

    if (sgacl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (sgacl->get_device() != m_device) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    transaction txn;

    auto sgacl_sptr = m_device->get_sptr(sgacl);
    auto sgacl_delegate = get_delegate(sgacl_sptr);
    if (sgacl_delegate == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    if (m_sgt == 0 && m_dgt == 0) {
        sgacl_delegate->set_unknown_sgacl_id();
    } else if (m_sgt == 0xFFFF && m_dgt == 0xFFFF) {
        sgacl_delegate->set_default_sgacl_id();
    }

    // Make-before-break. Add IFGs to new acl, swap, then remove from old acl
    txn.status = add_current_ifgs(this, sgacl_delegate);
    return_on_error(txn.status);

    auto old_sgacl = m_sgacl;
    auto old_sgacl_id = m_sgacl_id;

    m_sgacl = sgacl_delegate;

    // For cell, m_sgacl_id will have with (acl_id + bincode)
    m_sgacl_id = m_sgacl->get_sgacl_id();
    txn.on_fail([&]() {
        m_sgacl = old_sgacl;
        m_sgacl_id = old_sgacl_id;
    });

    txn.status = update_attributes();
    return_on_error(txn.status);
    txn.on_fail([&]() { txn.status = remove_current_ifgs(this, sgacl_delegate); });

    m_device->add_ifg_dependency(this, sgacl_delegate);
    m_device->add_object_dependency(sgacl_sptr, this);

    if (old_sgacl) {
        m_device->remove_ifg_dependency(this, old_sgacl);
        m_device->remove_object_dependency(old_sgacl->get_acl_parent(), this);

        txn.status = remove_current_ifgs(this, old_sgacl);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::clear_acl()
{
    transaction txn;

    auto sgacl_delegate = m_sgacl;

    if (sgacl_delegate == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    m_sgacl = nullptr;

    m_device->remove_ifg_dependency(this, sgacl_delegate);
    m_device->remove_object_dependency(sgacl_delegate->get_acl_parent(), this);

    txn.on_fail([&]() { m_sgacl = sgacl_delegate; });
    txn.status = remove_current_ifgs(this, sgacl_delegate);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::get_acl(la_acl*& out_sgacl) const
{
    if (m_sgacl != nullptr) {
        out_sgacl = m_sgacl->get_acl_parent().get();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::remove_counter()
{
    la_counter_set* counter = m_counter.get();

    if (counter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_counter_set_impl* counter_impl = static_cast<la_counter_set_impl*>(counter);
    m_device->remove_object_dependency(counter_impl, this);

    la_status status = counter_impl->remove_security_group_cell_counter();
    return_on_error(status);

    m_counter = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    if (m_counter != nullptr) {
        // Remove counter
        la_status status = remove_counter();
        return_on_error(status);
    }

    npl_sgt_matrix_table_t::key_type key;
    npl_sgt_matrix_table_t::value_type value;
    npl_sgt_matrix_table_t::entry_pointer_type entry = nullptr;

    key.src_sgt = m_sgt;
    key.dst_sgt = m_dgt;
    key.ip_version = (m_ip_version == la_ip_version_e::IPV6) ? true : false;

    la_status status = m_device->m_tables.sgt_matrix_table->lookup(key, entry);

    if (status != LA_STATUS_SUCCESS) {
        return LA_STATUS_ENOTFOUND;
    }

    status = m_device->m_tables.sgt_matrix_table->erase(key);
    return_on_error(status);

    la_device_impl::security_group_cell_t cell = {.sgt = m_sgt, .dgt = m_dgt, .ip_version = m_ip_version};
    m_device->m_security_group_cell_map.erase(cell);

    return LA_STATUS_SUCCESS;
}

slice_ifg_vec_t
la_security_group_cell_gibraltar::get_ifgs() const
{
    return get_all_network_ifgs(m_device);
}

la_status
la_security_group_cell_gibraltar::set_bincode(la_uint32_t bincode)
{
    start_api_call("bincode=", bincode);

    if (m_sgt == 0 && m_dgt == 0) {
        return LA_STATUS_SUCCESS;
    }

    if (m_sgacl_bincode == bincode) {
        return LA_STATUS_SUCCESS;
    }

    transaction txn;
    la_uint32_t old_sgacl_bincode = m_sgacl_bincode;
    m_sgacl_bincode = bincode;

    txn.on_fail([&]() { m_sgacl_bincode = old_sgacl_bincode; });

    txn.status = update_attributes();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_security_group_cell_gibraltar::get_bincode(la_uint32_t& out_bincode) const
{
    start_api_getter_call();

    out_bincode = m_sgacl_bincode;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
