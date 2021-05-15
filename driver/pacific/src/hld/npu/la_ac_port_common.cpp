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

#include "la_ac_port_common.h"
#include "api/npu/la_switch.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_ac_profile_impl.h"
#include "la_l3_ac_port_impl.h"
#include "la_strings.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_ac_port_common::la_ac_port_common(const la_device_impl_wptr& device)
    : m_gid(-1),
      m_device(device),
      m_vid1(0),
      m_vid2(0),
      m_attached_p2p_pwe(false),
      m_slice_data(ASIC_MAX_SLICES_PER_DEVICE_NUM, slice_data()),
      m_port_state(object_state_e::ACTIVE)
{
}

la_ac_port_common::~la_ac_port_common()
{
}

uint64_t
la_ac_port_common::get_local_slp_id(la_slice_id_t slice_idx) const
{
    return m_slice_data[slice_idx].local_slp_id;
}

la_status
la_ac_port_common::get_service_mapping_vids(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const
{
    // Return empty vids when port is DISABLED
    if (m_port_state == object_state_e::DISABLED) {
        return LA_STATUS_SUCCESS;
    }

    out_vid1 = m_vid1;
    out_vid2 = m_vid2;
    return LA_STATUS_SUCCESS;
}

const la_device_impl*
la_ac_port_common::get_device() const
{
    return m_device.get();
}

la_status
la_ac_port_common::initialize(la_object_wcptr parent,
                              la_uint64_t gid,
                              la_ethernet_port_base_wptr ethernet_port_impl,
                              la_vlan_id_t vid1,
                              la_vlan_id_t vid2)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_parent = parent;
    const la_object* ac_port = nullptr;
    la_status status = ethernet_port_impl->get_ac_port(vid1, vid2, ac_port);
    return_on_error(status);

    if (ac_port != nullptr) {
        return LA_STATUS_EBUSY;
    }

    m_gid = gid;
    m_eth_port = ethernet_port_impl;
    m_vid1 = vid1;
    m_vid2 = vid2;
    m_port_state = object_state_e::ACTIVE;

    m_eth_port->set_ac_port(vid1, vid2, parent);

    m_mapped_vids.clear();

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::add_ifg(la_slice_ifg ifg)
{
    transaction txn;

    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (slice_added) {
        txn.status = allocate_local_slp_id(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([&]() { deallocate_local_slp_id(ifg.slice); });

        txn.status = configure_slice_ac_attributes(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([&]() { erase_slice_ac_attributes(ifg.slice); });

        txn.status = configure_slice_service_mapping_vid(ifg.slice);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::remove_ifg(la_slice_ifg ifg)
{
    transaction txn;

    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->add_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (slice_removed) {
        txn.status = erase_slice_ac_attributes(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([&]() { configure_slice_ac_attributes(ifg.slice); });

        txn.status = erase_slice_service_mapping_vid(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([&]() { configure_slice_service_mapping_vid(ifg.slice); });

        txn.status = deallocate_local_slp_id(ifg.slice);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::allocate_local_slp_id(la_slice_id_t slice_idx)
{
    bool allocated
        = m_device->m_index_generators.slice_pair[slice_idx / 2].service_port_slps.allocate(m_slice_data[slice_idx].local_slp_id);

    if (!allocated) {
        return LA_STATUS_ERESOURCE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::deallocate_local_slp_id(la_slice_id_t slice_idx)
{
    if (m_slice_data[slice_idx].local_slp_id != LOCAL_SLP_ID_INVALID) {
        m_device->m_index_generators.slice_pair[slice_idx / 2].service_port_slps.release(m_slice_data[slice_idx].local_slp_id);
        m_slice_data[slice_idx].local_slp_id = LOCAL_SLP_ID_INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::configure_slice_ac_attributes(la_slice_id_t slice_idx)
{
    // skip programming when port is DISABLED
    if (m_port_state == object_state_e::DISABLED) {
        return LA_STATUS_SUCCESS;
    }

    if ((m_vid1 == LA_VLAN_ID_INVALID) && (m_vid2 != LA_VLAN_ID_INVALID)) {
        return LA_STATUS_EINVAL;
    }

    if (m_vid1 == LA_VLAN_ID_INVALID && m_vid2 == LA_VLAN_ID_INVALID) {
        return configure_slice_ac_port_table(slice_idx);
    }

    if (m_vid1 != LA_VLAN_ID_INVALID) {
        if (m_vid2 == LA_VLAN_ID_INVALID) {
            return configure_slice_ac_port_tag_table(slice_idx);
        } else {
            return configure_slice_ac_port_tag_tag_table(slice_idx, m_vid1, m_vid2, true);
        }
    }

    log_err(HLD, "la_ac_port_common::configure_slice_ac_attributes: vid1 is invalid but vid2 is valid");
    return LA_STATUS_EUNKNOWN;
}

la_uint_t
la_ac_port_common::get_slice_relay_id(la_slice_id_t slice_idx)
{
    if (m_attached_p2p_pwe) {
        return m_attached_p2p_pwe_gid;
    }

    return ((m_attached_switch) ? m_attached_switch->get_gid() : m_slice_data[slice_idx].relay_id);
}

la_status
la_ac_port_common::configure_slice_ac_port_table(la_slice_id_t slice_idx)
{
    npl_service_mapping_em0_ac_port_table_t::key_type k;
    npl_service_mapping_em0_ac_port_table_t::value_type v;

    k.local_slp_id.id = m_eth_port->get_id();
    v.action = NPL_SERVICE_MAPPING_EM0_AC_PORT_TABLE_ACTION_SM;
    v.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
    v.payloads.sm.relay_id.id = get_slice_relay_id(slice_idx);

    la_status status
        = m_device->m_tables.service_mapping_em0_ac_port_table[slice_idx]->insert(k, v, m_slice_data[slice_idx].em0_ac_entry);
    return_on_error(status,
                    HLD,
                    ERROR,
                    "la_ac_port_common::configure_slice_ac_port_table: ac_port_table[%d].insert failed, status = %s",
                    slice_idx,
                    la_status2str(status).c_str());

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::configure_slice_ac_port_tag_table(la_slice_id_t slice_idx)
{
    npl_service_mapping_em0_ac_port_tag_table_t::key_type k;
    npl_service_mapping_em0_ac_port_tag_table_t::value_type v;

    k.local_slp_id.id = m_eth_port->get_id();
    k.vid1.id = m_vid1;

    v.action = NPL_SERVICE_MAPPING_EM0_AC_PORT_TAG_TABLE_ACTION_SM;
    v.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
    v.payloads.sm.relay_id.id = get_slice_relay_id(slice_idx);

    la_status status = m_device->m_tables.service_mapping_em0_ac_port_tag_table[slice_idx]->insert(
        k, v, m_slice_data[slice_idx].em0_ac_tag_entry);
    return_on_error(status);

    status = configure_slice_ac_port_tag_fallback_table(slice_idx, m_vid1, true);

    return status;
}

la_status
la_ac_port_common::configure_slice_ac_port_tag_tag_table(la_slice_id_t slice_idx,
                                                         la_vlan_id_t vid1,
                                                         la_vlan_id_t vid2,
                                                         bool update_entry)
{
    npl_service_mapping_em0_ac_port_tag_tag_table_entry_wptr_t em0_ac_tag_tag_entry;
    npl_service_mapping_em0_ac_port_tag_tag_table_t::key_type k;
    npl_service_mapping_em0_ac_port_tag_tag_table_t::value_type v;

    k.local_slp_id.id = m_eth_port->get_id();
    k.vid1.id = vid1;
    k.vid2.id = vid2;

    v.action = NPL_SERVICE_MAPPING_EM0_AC_PORT_TAG_TAG_TABLE_ACTION_SM;
    v.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
    v.payloads.sm.relay_id.id = get_slice_relay_id(slice_idx);

    la_status status = m_device->m_tables.service_mapping_em0_ac_port_tag_tag_table[slice_idx]->insert(k, v, em0_ac_tag_tag_entry);
    return_on_error(status);

    if (update_entry) {
        m_slice_data[slice_idx].em0_ac_tag_tag_entry = em0_ac_tag_tag_entry;
    }

    return status;
}

la_status
la_ac_port_common::configure_slice_ac_port_tag_fallback_table(la_slice_id_t slice_idx, la_vlan_id_t vid, bool update_entry)
{
    npl_service_mapping_em1_ac_port_tag_table_entry_wptr_t em1_ac_tag_entry;
    la_ac_profile* ac_profile;
    la_status status = m_eth_port->get_ac_profile(ac_profile);
    return_on_error(status);

    la_ac_profile_impl* ac_profile_impl = static_cast<la_ac_profile_impl*>(ac_profile);
    bool need_fallback = ac_profile_impl->need_fallback();

    if (need_fallback) {
        const auto& table(m_device->m_tables.service_mapping_em1_ac_port_tag_table[slice_idx]);
        npl_service_mapping_em1_ac_port_tag_table_key_t key;
        npl_service_mapping_em1_ac_port_tag_table_value_t value;

        key.local_slp_id.id = m_eth_port->get_id();
        key.vid1.id = vid;

        value.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
        value.payloads.sm.relay_id.id = get_slice_relay_id(slice_idx);
        status = table->insert(key, value, em1_ac_tag_entry);
        return_on_error(status);
        if (update_entry) {
            m_slice_data[slice_idx].em1_ac_tag_entry = em1_ac_tag_entry;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::configure_slice_ac_tcam_attributes(la_slice_id_t slice_idx,
                                                      const npl_mac_lp_attributes_payload_t& payload,
                                                      const uint32_t relay_id)
{
    // skip programming when port is DISABLED
    if (m_port_state == object_state_e::DISABLED) {
        return LA_STATUS_SUCCESS;
    }

    if (m_vid1 == LA_VLAN_ID_INVALID) {
        if (m_vid2 == LA_VLAN_ID_INVALID) {
            return configure_slice_ac_port_tcam_table(slice_idx, payload, relay_id);
        } else {
            return LA_STATUS_EINVAL;
        }
    } else {
        if (m_vid2 == LA_VLAN_ID_INVALID) {
            return configure_slice_ac_port_tcam_tag_table(slice_idx, payload, relay_id);
        } else {
            return configure_slice_ac_port_tcam_tag_tag_table(slice_idx, payload, relay_id);
        }
    }
}

la_status
la_ac_port_common::configure_slice_ac_port_tcam_table(la_slice_id_t slice_idx,
                                                      const npl_mac_lp_attributes_payload_t& payload,
                                                      const uint32_t relay_id)

{
    if (m_slice_data[slice_idx].tcam_ac_entry == nullptr) {
        // if it is the 1st time, sert the entry
        npl_service_mapping_tcam_ac_port_table_t::key_type k;
        npl_service_mapping_tcam_ac_port_table_t::key_type m;
        npl_service_mapping_tcam_ac_port_table_t::value_type v;

        k.local_slp_id.id = m_eth_port->get_id();

        m.local_slp_id.id = 0xffff;

        v.action = NPL_SERVICE_MAPPING_TCAM_AC_PORT_TABLE_ACTION_SM;
        v.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
        v.payloads.sm.relay_id = relay_id;
        v.payloads.sm.lp_attr.lp_attr = payload;

        size_t entry_loc = -1; // without the initialization, Werror yell for no apparent reason
        la_status status = m_device->m_tables.service_mapping_tcam_ac_port_table[slice_idx]->locate_first_free_entry(entry_loc);
        return_on_error(status, HLD, ERROR, "failed to get free entry in service_mapping_tcam_ac_port_table slice %d", slice_idx);

        status = m_device->m_tables.service_mapping_tcam_ac_port_table[slice_idx]->insert(
            entry_loc, k, m, v, m_slice_data[slice_idx].tcam_ac_entry);
        return_on_error(status, HLD, ERROR, "failed to insert entry to service_mapping_tcam_ac_port_table slice %d", slice_idx);

    } else {
        // entry already exist, just modify it
        npl_service_mapping_tcam_ac_port_table_t::value_type v;

        v.action = NPL_SERVICE_MAPPING_TCAM_AC_PORT_TABLE_ACTION_SM;
        v.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
        v.payloads.sm.relay_id = relay_id;
        v.payloads.sm.lp_attr.lp_attr = payload;

        la_status status = m_device->m_tables.service_mapping_tcam_ac_port_table[slice_idx]->set_entry_value(
            m_slice_data[slice_idx].tcam_ac_entry, v);
        return_on_error(status, HLD, ERROR, "failed to update entry in service_mapping_tcam_ac_port_table slice %d", slice_idx);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::configure_slice_ac_port_tcam_tag_table(la_slice_id_t slice_idx,
                                                          const npl_mac_lp_attributes_payload_t& payload,
                                                          const uint32_t relay_id)
{
    if (m_slice_data[slice_idx].tcam_ac_tag_entry == nullptr) {
        // if it is the 1st time, sert the entry
        npl_service_mapping_tcam_ac_port_tag_table_t::key_type k;
        npl_service_mapping_tcam_ac_port_tag_table_t::key_type m;
        npl_service_mapping_tcam_ac_port_tag_table_t::value_type v;

        k.local_slp_id.id = m_eth_port->get_id();
        k.vid1.id = m_vid1;

        m.local_slp_id.id = 0xffff;
        m.vid1.id = 0xfff;

        v.action = NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TABLE_ACTION_SM;
        v.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
        v.payloads.sm.relay_id = relay_id;
        v.payloads.sm.lp_attr.lp_attr = payload;

        size_t entry_loc = -1; // without the initialization, Werror yell for no apparent reason
        la_status status = m_device->m_tables.service_mapping_tcam_ac_port_tag_table[slice_idx]->locate_first_free_entry(entry_loc);
        return_on_error(
            status, HLD, ERROR, "failed to get free entry in service_mapping_tcam_ac_port_tag_table slice %d", slice_idx);

        status = m_device->m_tables.service_mapping_tcam_ac_port_tag_table[slice_idx]->insert(
            entry_loc, k, m, v, m_slice_data[slice_idx].tcam_ac_tag_entry);
        return_on_error(
            status, HLD, ERROR, "failed to insert entry to service_mapping_tcam_ac_port_tag_table slice %d)", slice_idx);

    } else {
        // entry already exist, just modify it
        npl_service_mapping_tcam_ac_port_tag_table_t::value_type v;

        v.action = NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TABLE_ACTION_SM;
        v.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
        v.payloads.sm.relay_id = relay_id;
        v.payloads.sm.lp_attr.lp_attr = payload;

        la_status status = m_device->m_tables.service_mapping_tcam_ac_port_tag_table[slice_idx]->set_entry_value(
            m_slice_data[slice_idx].tcam_ac_tag_entry, v);
        return_on_error(status, HLD, ERROR, "failed to update entry in service_mapping_tcam_ac_port_tag_table slice %d", slice_idx);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::configure_slice_ac_port_tcam_tag_tag_table(la_slice_id_t slice_idx,
                                                              const npl_mac_lp_attributes_payload_t& payload,
                                                              const uint32_t relay_id)
{
    if (m_slice_data[slice_idx].tcam_ac_tag_tag_entry == nullptr) {
        // if it is the 1st time, sert the entry
        npl_service_mapping_tcam_ac_port_tag_tag_table_t::key_type k;
        npl_service_mapping_tcam_ac_port_tag_tag_table_t::key_type m;
        npl_service_mapping_tcam_ac_port_tag_tag_table_t::value_type v;

        k.local_slp_id.id = m_eth_port->get_id();
        k.vid1.id = m_vid1;
        k.vid2.id = m_vid2;

        m.local_slp_id.id = 0xffff;
        m.vid1.id = 0xfff;
        m.vid2.id = 0xfff;

        v.action = NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TAG_TABLE_ACTION_SM;
        v.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
        v.payloads.sm.relay_id = relay_id;
        v.payloads.sm.lp_attr.lp_attr = payload;

        size_t entry_loc = -1; // without the initialization, Werror yell for no apparent reason
        la_status status
            = m_device->m_tables.service_mapping_tcam_ac_port_tag_tag_table[slice_idx]->locate_first_free_entry(entry_loc);
        return_on_error(
            status, HLD, ERROR, "failed to get free entry in service_mapping_tcam_ac_port_tag_tag_table slice %d", slice_idx);

        status = m_device->m_tables.service_mapping_tcam_ac_port_tag_tag_table[slice_idx]->insert(
            entry_loc, k, m, v, m_slice_data[slice_idx].tcam_ac_tag_tag_entry);
        return_on_error(
            status, HLD, ERROR, "failed to insert entry to service_mapping_tcam_ac_port_tag_tag_table slice %d", slice_idx);

    } else {
        // entry already exist, just modify it
        npl_service_mapping_tcam_ac_port_tag_tag_table_t::value_type v;

        v.action = NPL_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TAG_TABLE_ACTION_SM;
        v.payloads.sm.lp_id.id = m_slice_data[slice_idx].local_slp_id;
        v.payloads.sm.relay_id = relay_id;
        v.payloads.sm.lp_attr.lp_attr = payload;

        la_status status = m_device->m_tables.service_mapping_tcam_ac_port_tag_tag_table[slice_idx]->set_entry_value(
            m_slice_data[slice_idx].tcam_ac_tag_tag_entry, v);
        return_on_error(
            status, HLD, ERROR, "failed to update entry in service_mapping_tcam_ac_port_tag_tag_table slice %d", slice_idx);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::set_switch(const la_switch_wcptr& sw)
{
    la_switch_gid_t sw_gid = (sw) ? sw->get_gid() : 0;
    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice_idx : slices) {
        la_status status = set_switch_per_slice(sw_gid, slice_idx);

        if (status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    m_attached_switch = sw;

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::set_switch_per_slice(la_switch_gid_t sw_gid, la_slice_id_t slice_idx)
{
    // skip programming when port is DISABLED
    if (m_port_state == object_state_e::DISABLED) {
        return LA_STATUS_SUCCESS;
    }

    slice_data& data(m_slice_data[slice_idx]);

    if (data.em0_ac_entry) {
        return set_switch_per_slice_ac_port(sw_gid, slice_idx);
    } else if (data.em0_ac_tag_entry) {
        return set_switch_per_slice_ac_port_tag(sw_gid, slice_idx);
    } else if (data.em0_ac_tag_tag_entry) {
        return set_switch_per_slice_ac_port_tag_tag(sw_gid, slice_idx);
    }

    return LA_STATUS_EUNKNOWN;
}

la_status
la_ac_port_common::set_switch_per_slice_ac_port(la_switch_gid_t sw_gid, la_slice_id_t slice_idx)
{
    slice_data& data(m_slice_data[slice_idx]);
    npl_service_mapping_em0_ac_port_table_t::value_type cv(data.em0_ac_entry->value());
    cv.payloads.sm.relay_id.id = sw_gid;

    la_status status = data.em0_ac_entry->update(cv);

    return status;
}

la_status
la_ac_port_common::set_switch_per_slice_ac_port_tag(la_switch_gid_t sw_gid, la_slice_id_t slice_idx)
{
    slice_data& data(m_slice_data[slice_idx]);
    npl_service_mapping_em0_ac_port_tag_table_t::value_type cv(data.em0_ac_tag_entry->value());
    cv.payloads.sm.relay_id.id = sw_gid;

    la_status status = data.em0_ac_tag_entry->update(cv);
    return_on_error(status);

    if (data.em1_ac_tag_entry != nullptr) {
        npl_service_mapping_em1_ac_port_tag_table_t::value_type cv(data.em1_ac_tag_entry->value());
        cv.payloads.sm.relay_id.id = sw_gid;

        status = data.em1_ac_tag_entry->update(cv);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::set_switch_per_slice_ac_port_tag_tag(la_switch_gid_t sw_gid, la_slice_id_t slice_idx)
{
    slice_data& data(m_slice_data[slice_idx]);
    npl_service_mapping_em0_ac_port_tag_tag_table_t::value_type cv(data.em0_ac_tag_tag_entry->value());
    cv.payloads.sm.relay_id.id = sw_gid;

    la_status status = data.em0_ac_tag_tag_entry->update(cv);

    return status;
}

la_status
la_ac_port_common::set_destination_p2p_pwe(la_pwe_gid_t pwe_gid, bool is_attached)
{
    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice_idx : slices) {
        la_status status = set_destination_p2p_pwe_per_slice(pwe_gid, slice_idx);

        if (status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    if (is_attached) {
        m_attached_p2p_pwe = true;
        m_attached_p2p_pwe_gid = pwe_gid;
    } else {
        m_attached_p2p_pwe = false;
        m_attached_p2p_pwe_gid = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::set_destination_p2p_pwe_per_slice(la_pwe_gid_t pwe_gid, la_slice_id_t slice_idx)
{
    // skip programming when port is DISABLED
    if (m_port_state == object_state_e::DISABLED) {
        return LA_STATUS_SUCCESS;
    }

    slice_data& data(m_slice_data[slice_idx]);

    if (data.em0_ac_entry) {
        return set_destination_p2p_pwe_per_slice_ac_port(pwe_gid, slice_idx);
    } else if (data.em0_ac_tag_entry) {
        return set_destination_p2p_pwe_per_slice_ac_port_tag(pwe_gid, slice_idx);
    } else if (data.em0_ac_tag_tag_entry) {
        return set_destination_p2p_pwe_per_slice_ac_port_tag_tag(pwe_gid, slice_idx);
    }

    return LA_STATUS_EUNKNOWN;
}

la_status
la_ac_port_common::set_destination_p2p_pwe_per_slice_ac_port(la_pwe_gid_t pwe_gid, la_slice_id_t slice_idx)
{
    slice_data& data(m_slice_data[slice_idx]);
    npl_service_mapping_em0_ac_port_table_t::value_type cv(data.em0_ac_entry->value());
    cv.payloads.sm.relay_id.id = pwe_gid;

    la_status status = data.em0_ac_entry->update(cv);

    return status;
}

la_status
la_ac_port_common::set_destination_p2p_pwe_per_slice_ac_port_tag(la_pwe_gid_t pwe_gid, la_slice_id_t slice_idx)
{
    slice_data& data(m_slice_data[slice_idx]);
    npl_service_mapping_em0_ac_port_tag_table_t::value_type cv(data.em0_ac_tag_entry->value());
    cv.payloads.sm.relay_id.id = pwe_gid;

    la_status status = data.em0_ac_tag_entry->update(cv);
    return_on_error(status);

    if (data.em1_ac_tag_entry != nullptr) {
        npl_service_mapping_em1_ac_port_tag_table_t::value_type cv(data.em1_ac_tag_entry->value());
        cv.payloads.sm.relay_id.id = pwe_gid;

        status = data.em1_ac_tag_entry->update(cv);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::set_destination_p2p_pwe_per_slice_ac_port_tag_tag(la_pwe_gid_t pwe_gid, la_slice_id_t slice_idx)
{
    slice_data& data(m_slice_data[slice_idx]);
    npl_service_mapping_em0_ac_port_tag_tag_table_t::value_type cv(data.em0_ac_tag_tag_entry->value());
    cv.payloads.sm.relay_id.id = pwe_gid;

    la_status status = data.em0_ac_tag_tag_entry->update(cv);

    return status;
}

la_status
la_ac_port_common::erase_slice_ac_attributes(la_slice_id_t slice_idx)
{
    // skip programming when port is DISABLED
    if (m_port_state == object_state_e::DISABLED) {
        return LA_STATUS_SUCCESS;
    }

    slice_data& data(m_slice_data[slice_idx]);
    la_status status;

    if (data.em0_ac_entry != nullptr) {
        const auto& table(m_device->m_tables.service_mapping_em0_ac_port_table[slice_idx]);
        npl_service_mapping_em0_ac_port_table_key_t key = data.em0_ac_entry->key();

        status = table->erase(key);
        return_on_error(status,
                        HLD,
                        ERROR,
                        "la_ac_port_common::erase_slice_ac_attributes: ac_port_table[%d].erase failed, status = %s",
                        slice_idx,
                        la_status2str(status).c_str());

        data.em0_ac_entry = nullptr;
    }

    if (data.em0_ac_tag_entry != nullptr) {
        const auto& table(m_device->m_tables.service_mapping_em0_ac_port_tag_table[slice_idx]);
        npl_service_mapping_em0_ac_port_tag_table_key_t key = data.em0_ac_tag_entry->key();

        status = table->erase(key);
        return_on_error(status,
                        HLD,
                        ERROR,
                        "la_ac_port_common::erase_slice_ac_attributes: em0_ac_port_tag_table[%d].erase failed, status = %s",
                        slice_idx,
                        la_status2str(status).c_str());

        data.em0_ac_tag_entry = nullptr;
    }

    if (data.em1_ac_tag_entry != nullptr) {
        const auto& table(m_device->m_tables.service_mapping_em1_ac_port_tag_table[slice_idx]);
        npl_service_mapping_em1_ac_port_tag_table_key_t key = data.em1_ac_tag_entry->key();

        status = table->erase(key);
        return_on_error(status,
                        HLD,
                        ERROR,
                        "la_ac_port_common::erase_slice_ac_attributes: em1_ac_port_tag_table[%d].erase failed, status = %s",
                        slice_idx,
                        la_status2str(status).c_str());

        data.em1_ac_tag_entry = nullptr;
    }

    if (data.em0_ac_tag_tag_entry != nullptr) {
        const auto& table(m_device->m_tables.service_mapping_em0_ac_port_tag_tag_table[slice_idx]);
        npl_service_mapping_em0_ac_port_tag_tag_table_key_t key = data.em0_ac_tag_tag_entry->key();

        status = table->erase(key);
        return_on_error(status,
                        HLD,
                        ERROR,
                        "la_ac_port_common::erase_slice_ac_attributes: em0_ac_port_tag_tag_table[%d].erase failed, status = %s",
                        slice_idx,
                        la_status2str(status).c_str());

        data.em0_ac_tag_tag_entry = nullptr;
    }

    if (data.tcam_ac_entry != nullptr) {
        const auto& table(m_device->m_tables.service_mapping_tcam_ac_port_table[slice_idx]);
        status = table->erase(data.tcam_ac_entry->line());
        return_on_error(
            status, HLD, ERROR, "la_ac_port_common::erase_slice_ac_attributes: tcam_ac_port_table[%d].erase failed", slice_idx);
    }

    if (data.tcam_ac_tag_entry != nullptr) {
        const auto& table(m_device->m_tables.service_mapping_tcam_ac_port_tag_table[slice_idx]);
        status = table->erase(data.tcam_ac_tag_entry->line());
        return_on_error(
            status, HLD, ERROR, "la_ac_port_common::erase_slice_ac_attributes: tcam_ac_port_tag_table[%d].erase failed", slice_idx);
    }

    if (data.tcam_ac_tag_tag_entry != nullptr) {
        const auto& table(m_device->m_tables.service_mapping_tcam_ac_port_tag_tag_table[slice_idx]);
        status = table->erase(data.tcam_ac_tag_tag_entry->line());
        return_on_error(status,
                        HLD,
                        ERROR,
                        "la_ac_port_common::erase_slice_ac_attributes: tcam_ac_port_tag_tag_table[%d].erase failed",
                        slice_idx);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::get_service_mapping_vid_list(la_vid_vec_t& out_mapped_vids) const
{
    out_mapped_vids = m_mapped_vids;

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::erase_slice_service_mapping_vid(la_slice_id_t slice)
{
    la_status status;

    for (auto vid : m_mapped_vids) {
        status = remove_service_mapping_vid_per_slice(slice, vid);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::remove_service_mapping_vid_per_slice(la_slice_id_t slice, la_vlan_id_t vid)
{

    la_vlan_id_t port_vid;
    la_status status;

    status = m_eth_port->get_port_vid(port_vid);
    return_on_error(status);

    if (vid != LA_VLAN_ID_INVALID) {
        const auto& table(m_device->m_tables.service_mapping_em0_ac_port_tag_tag_table[slice]);
        npl_service_mapping_em0_ac_port_tag_tag_table_t::key_type k;

        k.local_slp_id.id = m_eth_port->get_id();
        k.vid1.id = port_vid;
        k.vid2.id = vid;

        status = table->erase(k);
        return_on_error(status,
                        HLD,
                        ERROR,
                        "la_ac_port_common::erase_slice_ac_attributes: em0_ac_port_tag_tag_table[%d].erase failed, status = %s",
                        slice,
                        la_status2str(status).c_str());
    } else {
        const auto& table(m_device->m_tables.service_mapping_em1_ac_port_tag_table[slice]);
        npl_service_mapping_em1_ac_port_tag_table_key_t k;

        k.local_slp_id.id = m_eth_port->get_id();
        k.vid1.id = port_vid;

        status = table->erase(k);
        return_on_error(status,
                        HLD,
                        ERROR,
                        "la_ac_port_common::erase_slice_ac_attributes: em1_ac_port_tag_table[%d].erase failed, status = %s",
                        slice,
                        la_status2str(status).c_str());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::remove_service_mapping_vid(la_vlan_id_t vid)
{
    la_ac_profile* ac_profile;
    la_status status = m_eth_port->get_ac_profile(ac_profile);
    return_on_error(status);

    la_ac_profile_impl* ac_profile_impl = static_cast<la_ac_profile_impl*>(ac_profile);
    bool need_fallback = ac_profile_impl->need_fallback();

    if (!need_fallback) {
        return LA_STATUS_EINVAL;
    }

    const auto& compare_vid = [&vid](const la_vlan_id_t& vlan) { return vid == vlan; };
    auto vlan_entry_it = std::find_if(m_mapped_vids.cbegin(), m_mapped_vids.cend(), compare_vid);

    if (vlan_entry_it == m_mapped_vids.cend()) {
        return LA_STATUS_EINVAL;
    }

    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice : slices) {
        status = remove_service_mapping_vid_per_slice(slice, vid);
        return_on_error(status);
    }

    m_mapped_vids.erase(vlan_entry_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::configure_slice_service_mapping_vid(la_slice_id_t slice)
{
    la_status status;
    for (auto vid : m_mapped_vids) {
        status = add_service_mapping_vid_per_slice(slice, vid);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::add_service_mapping_vid_per_slice(la_slice_id_t slice, la_vlan_id_t vid)
{
    la_status status;
    la_vlan_id_t port_vid;

    status = m_eth_port->get_port_vid(port_vid);
    return_on_error(status);

    if (vid != LA_VLAN_ID_INVALID) {
        status = configure_slice_ac_port_tag_tag_table(slice, port_vid, vid, false);
    } else {
        status = configure_slice_ac_port_tag_fallback_table(slice, port_vid, false);
    }

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::add_service_mapping_vid(la_vlan_id_t vid)
{
    la_ac_profile* ac_profile;
    la_status status = m_eth_port->get_ac_profile(ac_profile);
    return_on_error(status);

    la_ac_profile_impl* ac_profile_impl = static_cast<la_ac_profile_impl*>(ac_profile);
    bool need_fallback = ac_profile_impl->need_fallback();

    if (!need_fallback) {
        return LA_STATUS_EINVAL;
    }

    const auto& compare_vid = [&vid](const la_vlan_id_t& vlan) { return vid == vlan; };

    if (std::any_of(m_mapped_vids.cbegin(), m_mapped_vids.cend(), compare_vid)) {
        return LA_STATUS_SUCCESS;
    }

    m_mapped_vids.push_back(vid);

    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice : slices) {
        status = add_service_mapping_vid_per_slice(slice, vid);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ac_port_common::set_service_mapping_vids(la_vlan_id_t vid1, la_vlan_id_t vid2)
{
    const la_object* ac_port = nullptr;
    la_status status = m_eth_port->get_ac_port(vid1, vid2, ac_port);
    return_on_error(status);

    if (ac_port != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if ((vid1 == LA_VLAN_ID_INVALID) && (vid2 != LA_VLAN_ID_INVALID)) {
        return LA_STATUS_EINVAL;
    }

    if (vid1 == LA_VLAN_ID_INVALID) {
        // PORT
        if (m_vid1 != LA_VLAN_ID_INVALID) {
            return LA_STATUS_EINVAL;
        }
    }

    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice : slices) {
        la_status status = erase_slice_ac_attributes(slice);
        return_on_error(status);
    }

    m_eth_port->clear_ac_port(m_vid1, m_vid2);

    m_vid1 = vid1;
    m_vid2 = vid2;

    for (la_slice_id_t slice : slices) {
        la_status status = configure_slice_ac_attributes(slice);
        return_on_error(status);
    }

    m_eth_port->set_ac_port(m_vid1, m_vid2, m_parent);

    return LA_STATUS_SUCCESS;
}

// In L3 case, this is used for storing some additional l3 attributes
la_status
la_ac_port_common::set_relay_id(la_slice_id_t slice_idx, uint32_t relay_id)
{
    m_slice_data[slice_idx].relay_id = relay_id;

    return set_switch_per_slice(relay_id, slice_idx);
}

void
la_ac_port_common::destroy()
{
    if (m_port_state != object_state_e::DISABLED) {
        m_eth_port->clear_ac_port(m_vid1, m_vid2);
    }
}

la_status
la_ac_port_common::disable()
{
    la_status status;
    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice : slices) {
        status = erase_slice_ac_attributes(slice);
        return_on_error(status);
    }

    m_eth_port->clear_ac_port(m_vid1, m_vid2);
    m_port_state = object_state_e::DISABLED;
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
