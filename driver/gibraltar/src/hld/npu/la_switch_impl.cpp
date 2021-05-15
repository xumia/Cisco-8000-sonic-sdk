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

#include "api/npu/la_l2_destination.h"
#include "api/types/la_event_types.h"

#include "hw_tables/arc_cpu_common.h"
#include "hw_tables/cem.h"
#include "nplapi/nplapi_tables.h"

#include "counter_utils.h"
#include "hld_utils.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_switch_impl.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include "ra/resource_manager.h"
#include <sstream>

namespace silicon_one
{

la_switch_impl::la_switch_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_relay_attributes_entry(nullptr),
      m_max_switch_mac_addresses(MAX_MAC_PER_SWITCH_NO_LIMIT_VALUE),
      m_encap_vni(0),
      m_encap_vni_use_count(0),
      m_decap_vni(0),
      m_vxlan_encap_counter(nullptr),
      m_vxlan_decap_counter(nullptr),
      m_vni_profile_data({}),
      m_slice_data(ASIC_MAX_SLICES_PER_DEVICE_NUM, slice_data()),
      m_slice_pair_data(NUM_SLICE_PAIRS_PER_DEVICE, slice_pair_data())
{
}

la_status
la_switch_impl::initialize(la_object_id_t oid, la_switch_gid_t switch_gid)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    if (m_relay_attributes_entry != nullptr) {
        return LA_STATUS_EBUSY;
    }

    /* WA Temporary protection to disallow SWTICH_GIDs >= 12k until configuring extended table is implemented */
    if (switch_gid >= SERVICE_RELAY_ATTRIBUTES_TABLE_ENTRIES) {
        log_err(HLD, "%s: Switch GIDs >= 12k are not supported yet - switch_gid (%ud)", __FUNCTION__, switch_gid);
        return LA_STATUS_EINVAL;
    }

    npl_service_relay_attributes_table_key_t key;
    npl_service_relay_attributes_table_value_t value;
    npl_mac_l2_relay_attributes_t& payload(value.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes);

    key.relay_id.id = switch_gid;

    value.action = NPL_SERVICE_RELAY_ATTRIBUTES_TABLE_ACTION_RELAY;
    payload.drop_unknown_bc = 0;
    payload.drop_unknown_mc = 0;
    payload.drop_unknown_uc = 0;
    payload.is_svi = 0;
    payload.bd_attributes.l2_lpts_attributes = 0;
    payload.bd_attributes.sgacl_enforcement = 0;
    destination_id actual_destination_id = m_device->get_actual_destination_id(m_device->RX_DROP_DSP);
    payload.flood_destination.val = actual_destination_id.val;
    payload.igmp_snooping = 0;
    payload.mld_snooping = 0;

    la_status status = m_device->m_tables.service_relay_attributes_table->insert(key, value, m_relay_attributes_entry);
    return_on_error(status);

    status = set_max_switch_mac_addresses(m_max_switch_mac_addresses);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    if (m_encap_vni_use_count != 0) {
        return LA_STATUS_EBUSY;
    }

    la_status status;

    if (m_decap_vni != 0) {
        status = clear_decap_vni();
    }

    status = remove_vxlan_encap_counter();
    return_on_error(status);

    status = remove_vxlan_decap_counter();
    return_on_error(status);

    la_l2_destination* flood_destination = nullptr;
    status = get_flood_destination(flood_destination);
    return_on_error(status);

    if (flood_destination != nullptr) {
        m_device->remove_object_dependency(flood_destination, this);
    }

    la_mac_entry_vec out_mac_entries;
    status = flush_mac_entries(false, out_mac_entries);
    return_on_error(status);
    out_mac_entries.clear();

    npl_service_relay_attributes_table_t::key_type key(m_relay_attributes_entry->key());
    status = m_device->m_tables.service_relay_attributes_table->erase(key);
    return_on_error(status);

    m_relay_attributes_entry = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_mac_aging_time(la_mac_aging_time_t& out_aging_time)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::set_mac_aging_time(la_mac_aging_time_t aging_time)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::get_max_switch_mac_addresses(la_uint64_t& out_max_addresses)
{
    out_max_addresses = m_max_switch_mac_addresses;

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_max_switch_mac_addresses(la_uint64_t max_addresses)
{
    start_api_call("max_addresses=", max_addresses);

    cem em(m_device->m_ll_device);
    la_switch_gid_t gid = get_gid();

    la_status status = em.set_switch_mac_limit(gid, m_max_switch_mac_addresses, max_addresses);
    return_on_error(status);

    m_max_switch_mac_addresses = max_addresses;

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_max_port_mac_addresses(const la_l2_port* lport, la_uint64_t* out_max_addresses)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::set_max_port_mac_addresses(const la_l2_port* lport, la_uint64_t max_addresses)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::set_flood_destination(la_l2_destination* destination)
{
    start_api_call("destination=", destination);

    destination_id actual_dest_id = m_device->get_actual_destination_id(m_device->RX_DROP_DSP);
    npl_destination_t fd = {.val = actual_dest_id.val};

    la_l2_destination* previous_destination = nullptr;
    la_status status = get_flood_destination(previous_destination);
    return_on_error(status);

    if (destination) {
        fd.val = m_device->get_l2_destination_gid(m_device->get_sptr(destination));
    }

    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.flood_destination = fd;

    status = m_relay_attributes_entry->update(v);
    return_on_error(status);

    if (previous_destination != nullptr) {
        m_device->remove_object_dependency(previous_destination, this);
    }

    if (destination != nullptr) {
        m_device->add_object_dependency(destination, this);
    }

    return status;
}

la_status
la_switch_impl::get_flood_destination(la_l2_destination*& out_destination) const
{
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());

    la_l2_destination_wptr out_destination_wptr = m_device->get_l2_destination_by_gid(
        v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.flood_destination.val);
    out_destination = out_destination_wptr.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_ipv4_local_multicast_destination(la_ipv4_addr_t gaddr, la_l2_destination*& out_dest)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::set_ipv4_local_multicast_destination(la_ipv4_addr_t gaddr, la_l2_destination* destination)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::delete_ipv4_local_multicast_destination(la_ipv4_addr_t gaddr)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::clear_all_ipv4_local_multicast_destination()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::get_ipv6_local_multicast_destination(la_ipv6_addr_t gaddr, la_l2_destination*& out_dest)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::set_ipv6_local_multicast_destination(la_ipv6_addr_t gaddr, la_l2_destination* destination)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::delete_ipv6_local_multicast_destination(la_ipv6_addr_t gaddr)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::clear_all_ipv6_local_multicast_destination()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::set_event_enabled(la_event_e event, bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::get_event_enabled(la_event_e event, bool& out_enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_switch_impl::set_mac_entry(la_mac_addr_t mac_addr, la_l2_destination* l2_destination, la_mac_aging_time_t mac_aging_time)
{
    return (set_mac_entry(mac_addr, l2_destination, mac_aging_time, true));
}

la_status
la_switch_impl::set_mac_entry(la_mac_addr_t mac_addr,
                              la_l2_destination* l2_destination,
                              la_mac_aging_time_t mac_aging_time,
                              la_class_id_t class_id)
{
    la_status status = set_mac_entry(mac_addr, l2_destination, mac_aging_time, true);
    return_on_error(status);

    // Prepare key and value for insertion
    npl_mac_forwarding_w_metadata_table_t::key_type k;
    npl_mac_forwarding_w_metadata_table_value_t v;
    npl_mac_forwarding_w_metadata_table_t::entry_pointer_type e = nullptr;

    npl_service_relay_attributes_table_t::key_type relay_key(m_relay_attributes_entry->key());

    k.mac_forwarding_key.relay_id.id = relay_key.relay_id.id;
    k.mac_forwarding_key.mac_address.mac_address = mac_addr.flat;

    v.action = NPL_MAC_FORWARDING_W_METADATA_TABLE_ACTION_FOUND;
    v.payloads.found.dest.val = m_device->get_l2_destination_gid(m_device->get_sptr(l2_destination));
    v.payloads.found.dest_metadata.class_id.id = class_id;

    // Insert
    status = m_device->m_tables.mac_forwarding_w_metadata_table->set(k, v, e);

    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "la_switch_impl::set_mac_entry failed (%s)", silicon_one::to_string(status).c_str());
        la_status s = remove_mac_entry(mac_addr);
        return_on_error(s);
    }
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_mac_entry(la_mac_addr_t mac_addr,
                              la_l2_destination* l2_destination,
                              la_mac_aging_time_t mac_aging_time,
                              bool owner)
{
    start_api_call("mac_addr=", mac_addr, "l2_destination=", l2_destination, "mac_aging_time=", mac_aging_time, "owner=", owner);
    if (l2_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    // Prepare key and value for insertion
    npl_mac_forwarding_table_t::key_type k;
    npl_mac_forwarding_table_value_t v;
    npl_mac_forwarding_table_t::entry_pointer_type e = nullptr;

    npl_service_relay_attributes_table_t::key_type relay_key(m_relay_attributes_entry->key());

    k.mac_forwarding_key.relay_id.id = relay_key.relay_id.id;
    k.mac_forwarding_key.mac_address.mac_address = mac_addr.flat;

    arc_cpu_application_specific_fields config_aging_params;
    memset(&config_aging_params, 0, sizeof(arc_cpu_application_specific_fields));

    config_aging_params.fields.age_owner = owner;

    if (mac_aging_time == LA_MAC_AGING_TIME_NEVER) {
        config_aging_params.fields.age_value = cem::EM_NO_AGING_AGE;
    } else {
        la_mac_aging_time_t age_interval;
        la_status status = m_device->get_mac_aging_interval(age_interval);
        return_on_error(status, HLD, NOTICE, "failed to get configured MAC age interval");

        uint32_t age_bucket{};
        if ((age_interval == LA_MAC_AGING_TIME_NEVER || age_interval == 0) && mac_aging_time != 0) {
            // MAC aging is disabled, configure dynamic entry still
            age_bucket = (uint32_t)cem::EM_REFRESH_AGE;
        } else {
            // MAC aging is enabled, need to calculate proper age_bucket
            age_bucket = (uint32_t)div_round_up(mac_aging_time, age_interval);
            // Adjust age_bucket into proper range
            age_bucket = clamp(age_bucket, 1, (uint32_t)cem::EM_REFRESH_AGE);
        }

        config_aging_params.fields.age_value = age_bucket;
    }

    v.action = NPL_MAC_FORWARDING_TABLE_ACTION_WRITE;
    v.payloads.mact_result.destination.val = m_device->get_l2_destination_gid(m_device->get_sptr(l2_destination));
    v.payloads.mact_result.application_specific_fields = config_aging_params.flat;

    // Insert
    la_status status = m_device->m_tables.mac_forwarding_table->set(k, v, e);

    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "la_switch_impl::set_mac_entry failed (%s)", silicon_one::to_string(status).c_str());
    }
    return_on_error(status);

    status = notify_mac_move(mac_addr);
    return status;
}

la_status
la_switch_impl::notify_mac_move(la_mac_addr_t mac_addr) const
{
    attribute_management_details amd;
    amd.op = attribute_management_op::MAC_MOVED;
    amd.mac_addr = mac_addr;
    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };
    la_status status = m_device->notify_attribute_changed(this, amd, undo);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "mac move notification failed(status = %s)", la_status2str(status).c_str());
    }
    return status;
}

la_status
la_switch_impl::get_mac_entry(la_mac_addr_t mac_addr,
                              la_l2_destination*& out_l2_destination,
                              la_mac_age_info_t& out_mac_entry_info) const
{
    start_api_getter_call("mac_addr=", mac_addr);

    // Prepare key for lookup
    npl_mac_forwarding_table_t::key_type k;
    npl_mac_forwarding_table_t::entry_pointer_type e = nullptr;

    npl_service_relay_attributes_table_t::key_type relay_key(m_relay_attributes_entry->key());
    k.mac_forwarding_key.relay_id.id = relay_key.relay_id.id;
    k.mac_forwarding_key.mac_address.mac_address = mac_addr.flat;

    // Lookup in SW
    la_status status = m_device->m_tables.mac_forwarding_table->lookup(k, e);
    return_on_error(status);

    // Lookup in HW
    // NOTE:
    // For consistency we expect both lookups in SW and HW should pass
    // However, if MAC aging is enabled, it is possible HW has already aged out
    // the entry. Applications can use the HW lookup result to verify if
    // entry is still alive.
    cem_location loc{};
    bit_vector cem_payload(0, 64);
    bit_vector cem_key(0, 78);
    cem_key.set_bits(3, 0, 1);                                             // 4b mact_ldb, set to 1 for SA device
    cem_key.set_bits(51, 4, k.mac_forwarding_key.mac_address.mac_address); // MAC SA sits here
    cem_key.set_bits(65, 52, k.mac_forwarding_key.relay_id.id);            // Relay ID sits here

    std::shared_ptr<cem> em = m_device->m_resource_manager->get_cem();
    if (em == nullptr) {
        em = std::make_shared<cem>(m_device->m_ll_device);
    }

    status = em->lookup(cem_key, cem_payload, loc);
    return_on_error(status, HLD, NOTICE, "failed to find MAC entry on HW");

    // Update return values
    npl_mac_forwarding_table_t::value_type v(e->value());
    la_l2_destination_wptr out_l2_destination_wptr = m_device->get_l2_destination_by_gid(v.payloads.mact_result.destination.val);
    out_l2_destination = out_l2_destination_wptr.get();
    if (out_l2_destination == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    // Retrieve age info
    la_mac_aging_time_t age_time = LA_MAC_AGING_TIME_NEVER;
    la_mac_aging_time_t age_remaining = LA_MAC_AGING_TIME_NEVER;

    cem::cem_age_info age_info{};
    status = em->read_age(cem_key, cem_payload, age_info);
    return_on_error(status, HLD, NOTICE, "failed to get MAC entry's age info");

    la_mac_aging_time_t age_interval;
    status = m_device->get_mac_aging_interval(age_interval);
    return_on_error(status, HLD, NOTICE, "failed to get configured MAC age interval");

    // Calculate elapsed time
    switch (age_info.age_value) {
    case cem::EM_REFRESH_AGE:
    case cem::EM_NEW_MAX_AGE:
        age_time = 0;
        age_remaining = cem::EM_REFRESH_AGE * age_interval;
        break;
    case cem::EM_NO_AGING_AGE:
        // default is set to LA_MAC_AGING_TIME_NEVER
        // no need to change for static entries
        break;
    default:
        age_time = (cem::EM_REFRESH_AGE - age_info.age_value) * age_interval;
        age_remaining = age_info.age_value * age_interval;
        break;
    }

    out_mac_entry_info.owner = age_info.age_owner;
    out_mac_entry_info.age_value = age_time;
    out_mac_entry_info.age_remaining = age_remaining;
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_mac_entry(la_mac_addr_t mac_addr,
                              la_l2_destination*& out_l2_destination,
                              la_mac_age_info_t& out_mac_entry_info,
                              la_class_id_t& out_class_id) const
{
    la_status status = get_mac_entry(mac_addr, out_l2_destination, out_mac_entry_info);
    return_on_error(status);

    // Prepare key for lookup
    npl_mac_forwarding_w_metadata_table_t::key_type k;
    npl_mac_forwarding_w_metadata_table_t::entry_pointer_type e = nullptr;

    npl_service_relay_attributes_table_t::key_type relay_key(m_relay_attributes_entry->key());
    k.mac_forwarding_key.relay_id.id = relay_key.relay_id.id;
    k.mac_forwarding_key.mac_address.mac_address = mac_addr.flat;

    // Lookup in SW
    status = m_device->m_tables.mac_forwarding_w_metadata_table->lookup(k, e);
    return_on_error(status);

    // Update return values
    npl_mac_forwarding_w_metadata_table_t::value_type v(e->value());
    out_class_id = v.payloads.found.dest_metadata.class_id.id;

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::remove_mac_entry(la_mac_addr_t mac_addr)
{
    start_api_call("la_mac_addr_t=", mac_addr);
    // Prepare key for lookup
    npl_mac_forwarding_table_t::key_type k;

    npl_service_relay_attributes_table_t::key_type relay_key(m_relay_attributes_entry->key());

    // Prepare key for lookup
    npl_mac_forwarding_w_metadata_table_t::key_type k_meta;
    npl_mac_forwarding_w_metadata_table_t::entry_pointer_type e_meta = nullptr;

    k_meta.mac_forwarding_key.relay_id.id = relay_key.relay_id.id;
    k_meta.mac_forwarding_key.mac_address.mac_address = mac_addr.flat;

    // Check for an entry in the metadata table
    la_status status = m_device->m_tables.mac_forwarding_w_metadata_table->lookup(k_meta, e_meta);
    if (status == LA_STATUS_SUCCESS) {
        la_status s = m_device->m_tables.mac_forwarding_w_metadata_table->erase(k_meta);
        return_on_error(s);
    }

    k.mac_forwarding_key.relay_id.id = relay_key.relay_id.id;
    k.mac_forwarding_key.mac_address.mac_address = mac_addr.flat;

    status = m_device->m_tables.mac_forwarding_table->erase(k);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }
    return_on_error(status);

    status = notify_mac_move(mac_addr); // piggy back on mac move notification
    return status;
}

la_status
la_switch_impl::get_encap_vni(la_vni_t& vni) const
{
    if (m_encap_vni_use_count == 0) {
        return LA_STATUS_ENOTFOUND;
    }

    vni = m_encap_vni;

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::update_all_ifgs(bool add)
{
    la_status status;

    for (la_slice_ifg ifg : get_all_network_ifgs(m_device)) {
        if (add) {
            status = add_ifg(ifg);
            return_on_error(status);
        } else {
            status = remove_ifg(ifg);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::do_set_encap_vni(la_vni_t vni)
{
    // program mac_relay_to_vni_table
    npl_mac_relay_to_vni_table_key_t k;
    npl_mac_relay_to_vni_table_value_t v;

    // get the relay_id
    npl_service_relay_attributes_table_t::key_type relay_key(m_relay_attributes_entry->key());

    k.l2_relay_id.id = relay_key.relay_id.id;

    v.action = NPL_MAC_RELAY_TO_VNI_TABLE_ACTION_WRITE;
    v.payloads.vxlan_relay_encap_data.vni = vni;

    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        v.payloads.vxlan_relay_encap_data.vni_counter
            = populate_counter_ptr_slice_pair(m_vxlan_encap_counter, slice_pair, COUNTER_DIRECTION_EGRESS);
        la_status status = m_device->m_tables.mac_relay_to_vni_table[slice_pair]->set(
            k, v, m_slice_pair_data[slice_pair].mac_relay_to_vni_table_entry);
        return_on_error(
            status, HLD, ERROR, "set switch %lu to mac_relay_to_vni_table slice pair %d failed", relay_key.relay_id.id, slice_pair);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_encap_vni(la_vni_t vni)
{
    if (m_encap_vni_use_count != 0) {
        if (m_encap_vni == vni) {
            m_encap_vni_use_count++;
            return LA_STATUS_SUCCESS;
        } else {
            log_err(HLD, "%s: vni not match. new vni=%u, current vni=%u", __FUNCTION__, vni, m_encap_vni);
            return LA_STATUS_EBUSY;
        }
    }

    la_status status = do_set_encap_vni(vni);
    return_on_error(status);

    m_encap_vni_use_count = 1;
    m_encap_vni = vni;

    std::vector<la_object*> deps = m_device->get_dependent_objects(this);
    for (auto objp : deps) {
        if (objp->type() == object_type_e::L2_SERVICE_PORT) {
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::clear_encap_vni()
{
    if (m_encap_vni_use_count > 0) {
        m_encap_vni_use_count--;
        if (m_encap_vni_use_count > 0) {
            return LA_STATUS_SUCCESS;
        }
    } else {
        return LA_STATUS_EINVAL;
    }

    // delete entry in mac_relay_to_vni_table
    npl_mac_relay_to_vni_table_key_t k;

    // get the relay_id
    npl_service_relay_attributes_table_t::key_type relay_key(m_relay_attributes_entry->key());

    k.l2_relay_id.id = relay_key.relay_id.id;

    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        la_status status = m_device->m_tables.mac_relay_to_vni_table[slice_pair]->erase(k);
        return_on_error(status,
                        HLD,
                        ERROR,
                        "deleting switch %lu in mac_relay_to_vni_table slice pair %d failed",
                        relay_key.relay_id.id,
                        slice_pair);
        m_slice_pair_data[slice_pair].mac_relay_to_vni_table_entry = nullptr;
    }

    m_encap_vni_use_count = 0;
    m_encap_vni = 0;

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_decap_vni(la_vni_t& vni) const
{
    start_api_getter_call();

    vni = m_decap_vni;

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::do_set_decap_vni(la_vni_t vni)
{
    // get the relay_id
    npl_service_relay_attributes_table_t::key_type relay_key(m_relay_attributes_entry->key());

    // program vni_table
    npl_vni_table_key_t vni_k;
    npl_vni_table_value_t vni_v;

    vni_k.vni = vni;
    vni_v.action = NPL_VNI_TABLE_ACTION_WRITE;
    vni_v.payloads.vni_table_result.l2_relay_attributes_id.id = relay_key.relay_id.id;
    vni_v.payloads.vni_table_result.vlan_profile = m_vni_profile_data.vni_profile_index;

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        vni_v.payloads.vni_table_result.vni_counter
            = populate_counter_ptr_slice_pair(m_vxlan_decap_counter, slice / 2, COUNTER_DIRECTION_INGRESS);
        la_status status = m_device->m_tables.vni_table[slice]->set(vni_k, vni_v, m_slice_data[slice].vni_table_entry);
        return_on_error(status, HLD, ERROR, "set vni %u to vni_table slice %d insertion failed", vni, slice);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::allocate_vni_profile(vxlan_termination_mode_e vni_profile)
{
    la_status status;
    uint64_t vni_profile_index;

    if (m_vni_profile_data.vni_profile_allocated && (m_vni_profile_data.vni_profile != vni_profile)) {
        status = release_vni_profile();
        return_on_error(status);
    }

    status = m_device->allocate_vni_profile(vni_profile, vni_profile_index);
    return_on_error(status);

    m_vni_profile_data.vni_profile_allocated = true;
    m_vni_profile_data.vni_profile = vni_profile;
    m_vni_profile_data.vni_profile_index = vni_profile_index;

    status = update_all_ifgs(true);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::release_vni_profile()
{
    if (!m_vni_profile_data.vni_profile_allocated) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = m_device->release_vni_profile(m_vni_profile_data.vni_profile);
    return_on_error(status);

    status = update_all_ifgs(false);
    return_on_error(status);

    m_vni_profile_data.vni_profile_allocated = false;

    return LA_STATUS_SUCCESS;
}

la_switch::vxlan_termination_mode_e
la_switch_impl::get_decap_vni_profile() const
{
    start_api_getter_call();
    return m_vni_profile_data.vni_profile;
}

la_status
la_switch_impl::set_decap_vni_profile(vxlan_termination_mode_e vni_profile)
{
    start_api_call("vni_profile=", vni_profile);

    if (vni_profile == m_vni_profile_data.vni_profile) {
        return LA_STATUS_SUCCESS;
    }

    la_svi_port_base* svi_port;
    la_status status = get_svi_port(svi_port);

    if (status == LA_STATUS_SUCCESS) {
        if (m_vni_profile_data.vni_profile == la_switch::vxlan_termination_mode_e::IGNORE_DMAC) {
            status = svi_port->remove_no_da_termination_table_entry();
            return_on_error(status);
        }
        if (vni_profile == la_switch::vxlan_termination_mode_e::IGNORE_DMAC) {
            status = svi_port->update_no_da_termination_table_entry();
            return_on_error(status);
        }
    }

    m_vni_profile_data.vni_profile = vni_profile;

    status = allocate_vni_profile(vni_profile);
    return_on_error(status);

    if (m_decap_vni != 0) {
        return do_set_decap_vni(m_decap_vni);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_decap_vni(la_vni_t vni)
{
    start_api_call("vni=", vni);

    if (vni >= LA_VXVLAN_MAX_VNI) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_decap_vni == vni) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    if (!m_vni_profile_data.vni_profile_allocated) {
        status = allocate_vni_profile(m_vni_profile_data.vni_profile);
        return_on_error(status);
    }

    status = do_set_decap_vni(vni);
    return_on_error(status);

    m_decap_vni = vni;

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::clear_decap_vni()
{
    start_api_call("");

    la_status status;

    // delete entry in vni_table
    npl_vni_table_key_t vni_k;

    vni_k.vni = m_decap_vni;

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        status = m_device->m_tables.vni_table[slice]->erase(vni_k);
        return_on_error(status, HLD, ERROR, "deleting vni %u in vni_table slice %d failed", m_decap_vni, slice);
        m_slice_data[slice].vni_table_entry = nullptr;
    }

    if (m_vni_profile_data.vni_profile_allocated) {
        status = release_vni_profile();
        return_on_error(status);
    }

    m_decap_vni = 0;

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_vxlan_encap_counter(la_counter_set*& counter) const
{
    counter = m_vxlan_encap_counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_vxlan_encap_counter(la_counter_set* counter)
{
    m_vxlan_encap_counter = m_device->get_sptr<la_counter_set_impl>(counter);
    ;

    if (m_vxlan_encap_counter != nullptr) {
        la_status status = m_vxlan_encap_counter->add_vni_encap_counter();
        return_on_error(status);

        m_device->add_object_dependency(m_vxlan_encap_counter, this);
    }

    return do_set_encap_vni(m_encap_vni);
}

la_status
la_switch_impl::remove_vxlan_encap_counter()
{
    if (m_vxlan_encap_counter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = m_vxlan_encap_counter->remove_vni_encap_counter();
    return_on_error(status);

    m_device->remove_object_dependency(m_vxlan_encap_counter, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_vxlan_decap_counter(la_counter_set*& counter) const
{
    counter = m_vxlan_decap_counter.get();
    ;
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_vxlan_decap_counter(la_counter_set* counter)
{
    m_vxlan_decap_counter = m_device->get_sptr<la_counter_set_impl>(counter);

    if (m_vxlan_decap_counter != nullptr) {
        la_status status = m_vxlan_decap_counter->add_vni_decap_counter();
        return_on_error(status);

        m_device->add_object_dependency(m_vxlan_decap_counter, this);
    }
    return do_set_decap_vni(m_decap_vni);
}

la_status
la_switch_impl::remove_vxlan_decap_counter()
{
    if (m_vxlan_decap_counter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = m_vxlan_decap_counter->remove_vni_decap_counter();
    return_on_error(status);

    m_device->remove_object_dependency(m_vxlan_decap_counter, this);

    return LA_STATUS_SUCCESS;
}

la_switch_gid_t
la_switch_impl::get_gid() const
{
    npl_service_relay_attributes_table_t::key_type key(m_relay_attributes_entry->key());
    return key.relay_id.id;
}

la_object::object_type_e
la_switch_impl::type() const
{
    return object_type_e::SWITCH;
}

std::string
la_switch_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_switch_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_switch_impl::oid() const
{
    return m_oid;
}
const la_device*
la_switch_impl::get_device() const
{
    return m_device.get();
}

la_switch_impl::~la_switch_impl()
{
}

la_status
la_switch_impl::handle_new_attachment(const la_object* obj)
{
    if (!of_same_device(obj, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    switch (obj->type()) {
    case object_type_e::L2_SERVICE_PORT: {
        const la_l2_service_port_base* port = static_cast<const la_l2_service_port_base*>(obj);
        auto ifgs = port->get_ifgs();

        for (la_slice_ifg ifg : ifgs) {
            la_status status = add_ifg(ifg);

            return_on_error(status);
        }
    } break;
    default:
        break;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::remove_attachment(const la_object* obj)
{
    if (!of_same_device(obj, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    switch (obj->type()) {
    case object_type_e::L2_SERVICE_PORT: {
        const la_l2_service_port_base* port = static_cast<const la_l2_service_port_base*>(obj);
        auto ifgs = port->get_ifgs();

        for (la_slice_ifg ifg : ifgs) {
            la_status status = remove_ifg(ifg);

            return_on_error(status);
        }
    } break;
    default:
        break;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }

    default:
        log_err(
            HLD, "la_switch_impl::notify_change received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

slice_ifg_vec_t
la_switch_impl::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_slice_id_vec_t
la_switch_impl::get_slices() const
{
    return m_ifg_use_count->get_slices();
}

la_status
la_switch_impl::remove_ifg(la_slice_ifg ifg)
{
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    if (slice_removed) {
        la_status status = m_device->notify_ifg_removed(this, ifg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::add_ifg(la_slice_ifg ifg)
{
    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);

    if (slice_added) {
        la_status status = m_device->notify_ifg_added(this, ifg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_is_svi_flag(bool is_svi)
{
    const auto& table(m_device->m_tables.service_relay_attributes_table);
    npl_service_relay_attributes_table_key_t key;
    npl_service_relay_attributes_table_entry_t* entry = nullptr;

    key.relay_id.id = get_gid();

    la_status status = table->lookup(key, entry);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "la_switch_impl::set_is_svi_flag: lookup failed %s", la_status2str(status).c_str());
        return status;
    }
    npl_service_relay_attributes_table_value_t value(entry->value());
    npl_mac_l2_relay_attributes_t& payload(value.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes);
    payload.is_svi = is_svi;
    status = entry->update(value);
    return status;
}

la_status
la_switch_impl::set_drop_unknown_uc_enabled(bool drop_unknown_uc_enabled)
{
    start_api_call("drop_unknown_uc_enabled=", drop_unknown_uc_enabled);
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.drop_unknown_uc = drop_unknown_uc_enabled;
    la_status status = m_relay_attributes_entry->update(v);
    return status;
}

la_status
la_switch_impl::get_drop_unknown_uc_enabled(bool& out_drop_unknown_uc_enabled) const
{
    start_api_getter_call();
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    out_drop_unknown_uc_enabled = v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.drop_unknown_uc;
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_drop_unknown_mc_enabled(bool drop_unknown_mc_enabled)
{
    start_api_call("drop_unknown_mc_enabled=", drop_unknown_mc_enabled);
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.drop_unknown_mc = drop_unknown_mc_enabled;
    la_status status = m_relay_attributes_entry->update(v);
    return status;
}

la_status
la_switch_impl::get_drop_unknown_mc_enabled(bool& out_drop_unknown_mc_enabled) const
{
    start_api_getter_call();
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    out_drop_unknown_mc_enabled = v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.drop_unknown_mc;
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_drop_unknown_bc_enabled(bool drop_unknown_bc_enabled)
{
    start_api_call("drop_unknown_bc_enabled=", drop_unknown_bc_enabled);
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.drop_unknown_bc = drop_unknown_bc_enabled;
    la_status status = m_relay_attributes_entry->update(v);
    return status;
}

la_status
la_switch_impl::get_drop_unknown_bc_enabled(bool& out_drop_unknown_bc_enabled) const
{
    start_api_getter_call();
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    out_drop_unknown_bc_enabled = v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.drop_unknown_bc;
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_svi_port(la_svi_port_base*& svi_port)
{
    std::vector<la_object*> deps = m_device->get_dependent_objects(this);
    for (auto objp : deps) {
        if (objp->type() == object_type_e::SVI_PORT) {
            svi_port = static_cast<la_svi_port_base*>(objp);
            return LA_STATUS_SUCCESS;
        }
    }
    return LA_STATUS_ENOTFOUND;
}

la_status
la_switch_impl::get_mac_entries_count(la_uint32_t& out_count)
{
    start_api_getter_call();

    size_t entries_total = m_device->m_tables.mac_forwarding_table->size();
    if (entries_total == 0) {
        out_count = 0;
        return LA_STATUS_SUCCESS;
    }

    vector_alloc<npl_mac_forwarding_table_t::entry_pointer_type> entries(entries_total, nullptr);
    size_t entries_num = m_device->m_tables.mac_forwarding_table->get_entries(&entries[0], entries_total);
    if (entries_total != entries_num) {
        return LA_STATUS_EINVAL;
    }

    uint16_t gid = (uint16_t)this->get_gid();
    out_count = std::count_if(entries.begin(), entries.end(), [this, gid](npl_mac_forwarding_table_t::entry_pointer_type entry) {
        return ((entry != nullptr) && ((uint16_t)entry->key().mac_forwarding_key.relay_id.id == gid));
    });
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_mac_entries(la_mac_entry_vec& out_mac_entries)
{
    start_api_getter_call();
    size_t entries_total = m_device->m_tables.mac_forwarding_table->size();
    if (entries_total == 0) {
        out_mac_entries.clear();
        return LA_STATUS_SUCCESS;
    }

    vector_alloc<npl_mac_forwarding_table_t::entry_pointer_type> entries(entries_total, nullptr);
    size_t entries_num = m_device->m_tables.mac_forwarding_table->get_entries(&entries[0], entries_total);
    dassert_ncrit(entries_num <= entries_total);

    auto gid = this->get_gid();
    for (size_t i = 0; i < entries_num; i++) {
        npl_mac_forwarding_table_t::key_type k(entries[i]->key());
        npl_mac_forwarding_table_t::value_type v(entries[i]->value());
        if (k.mac_forwarding_key.relay_id.id != gid) {
            continue;
        }
        la_mac_entry_t record{};
        record.slp_gid = v.payloads.mact_result.destination.val;
        record.relay_gid = k.mac_forwarding_key.relay_id.id;
        record.addr.flat = k.mac_forwarding_key.mac_address.mac_address;
        out_mac_entries.push_back(record);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_force_flood_mode(bool enabled)
{
    start_api_call("enabled=", enabled);
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.bd_attributes.flush_all_macs = enabled;
    la_status status = m_relay_attributes_entry->update(v);
    return status;
}

la_status
la_switch_impl::set_copc_profile(la_control_plane_classifier::switch_profile_id_t switch_profile_id)
{
    start_api_call("switch_profile_id=", switch_profile_id);

    if (switch_profile_id > la_device_impl::MAX_COPC_SWITCH_PROFILES) {
        return LA_STATUS_EOUTOFRANGE;
    }

    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.bd_attributes.l2_lpts_attributes
        = (uint64_t)switch_profile_id;
    la_status status = m_relay_attributes_entry->update(v);
    return status;
}

la_status
la_switch_impl::get_copc_profile(la_control_plane_classifier::switch_profile_id_t& out_switch_profile_id) const
{
    start_api_getter_call();
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    out_switch_profile_id
        = (uint8_t)v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.bd_attributes.l2_lpts_attributes;
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_ipv4_multicast_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.igmp_snooping = enabled;
    la_status status = m_relay_attributes_entry->update(v);
    return status;
}

la_status
la_switch_impl::get_ipv4_multicast_enabled(bool& out_enabled)
{
    start_api_getter_call();
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    out_enabled = v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.igmp_snooping;
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_ipv6_multicast_enabled(bool enabled)
{

    start_api_call("enabled=", enabled);
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.mld_snooping = enabled;
    la_status status = m_relay_attributes_entry->update(v);
    return status;
}

la_status
la_switch_impl::get_ipv6_multicast_enabled(bool& out_enabled)
{

    start_api_getter_call();
    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    out_enabled = v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.mld_snooping;
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::delete_ipv4_multicast_route(la_ipv4_addr_t gaddr)
{

    start_api_call("gaddr=", gaddr);

    auto it = m_ipv4_em_entries.find(gaddr);

    if (it == m_ipv4_em_entries.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    const auto mcg = it->second;

    const auto& table(m_device->m_tables.mac_relay_g_ipv4_table);
    npl_mac_relay_g_ipv4_table_key_t key;
    key.relay_id.id = get_gid();
    key.dip_27_0 = gaddr.s_addr & 0xfffffff;

    la_status status = table->erase(key);
    return_on_error(status);

    m_device->remove_object_dependency(mcg, this);

    m_ipv4_em_entries.erase(gaddr);

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_ipv4_multicast_route(la_ipv4_addr_t gaddr, la_l2_mc_route_info& out_l2_mc_route_info) const
{

    start_api_getter_call();

    auto it = m_ipv4_em_entries.find(gaddr);

    if (it == m_ipv4_em_entries.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    out_l2_mc_route_info.mcg = it->second.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::add_ipv4_multicast_route(la_ipv4_addr_t gaddr, la_l2_multicast_group* mcg)
{

    start_api_call("gaddr=", gaddr, "mcg=", mcg)

        if (mcg == nullptr)
    {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(mcg, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto it = m_ipv4_em_entries.find(gaddr);

    if (it != m_ipv4_em_entries.end()) {
        return LA_STATUS_EEXIST;
    }

    const auto& table(m_device->m_tables.mac_relay_g_ipv4_table);
    npl_mac_relay_g_ipv4_table_key_t key;
    npl_mac_relay_g_ipv4_table_value_t value;
    npl_mac_relay_g_ipv4_table_entry_wptr_t entry;
    npl_destination_t fd = {.val = m_device->get_l2_destination_gid(m_device->get_sptr(mcg))};

    key.relay_id.id = get_gid();
    key.dip_27_0 = gaddr.s_addr & 0xfffffff;

    value.action = NPL_MAC_RELAY_G_IPV4_TABLE_ACTION_WRITE;
    value.payloads.mac_relay_g_destination.destination = fd;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    m_device->add_object_dependency(mcg, this);

    m_ipv4_em_entries[gaddr] = m_device->get_sptr(mcg);

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::delete_ipv6_multicast_route(la_ipv6_addr_t gaddr)
{

    start_api_call("gaddr=", gaddr);

    auto it = m_ipv6_em_entries.find(gaddr);

    if (it == m_ipv6_em_entries.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    const auto mcg = it->second;

    const auto& table(m_device->m_tables.mac_relay_g_ipv6_table);
    npl_mac_relay_g_ipv6_table_key_t key;

    key.relay_id.id = get_gid();
    key.dip_119_0[1] = (gaddr.s_addr >> 64) & 0xffffffffffffffff;
    key.dip_119_0[0] = gaddr.s_addr & 0xffffffffffffffff;

    la_status status = table->erase(key);
    return_on_error(status);

    m_device->remove_object_dependency(mcg, this);

    m_ipv6_em_entries.erase(gaddr);

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_ipv6_multicast_route(la_ipv6_addr_t gaddr, la_l2_mc_route_info& out_l2_mc_route_info) const
{

    start_api_getter_call();

    auto it = m_ipv6_em_entries.find(gaddr);

    if (it == m_ipv6_em_entries.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    out_l2_mc_route_info.mcg = it->second.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::add_ipv6_multicast_route(la_ipv6_addr_t gaddr, la_l2_multicast_group* mcg)
{

    start_api_call("gaddr=", gaddr, "mcg=", mcg)

        if (mcg == nullptr)
    {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(mcg, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto it = m_ipv6_em_entries.find(gaddr);

    if (it != m_ipv6_em_entries.end()) {
        return LA_STATUS_EEXIST;
    }

    const auto& table(m_device->m_tables.mac_relay_g_ipv6_table);
    npl_mac_relay_g_ipv6_table_key_t key;
    npl_mac_relay_g_ipv6_table_value_t value;
    npl_mac_relay_g_ipv6_table_entry_wptr_t entry;
    npl_destination_t fd = {.val = m_device->get_l2_destination_gid(m_device->get_sptr(mcg))};

    key.relay_id.id = get_gid();
    key.dip_119_0[1] = (gaddr.s_addr >> 64) & 0xffffffffffffffff;
    key.dip_119_0[0] = gaddr.s_addr & 0xffffffffffffffff;

    value.action = NPL_MAC_RELAY_G_IPV6_TABLE_ACTION_WRITE;
    value.payloads.mac_relay_g_destination.destination = fd;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    m_device->add_object_dependency(mcg, this);

    m_ipv6_em_entries[gaddr] = m_device->get_sptr(mcg);

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::flush_mac_entries(bool dynamic_only, la_mac_entry_vec& out_mac_entries)
{
    start_api_call("dynamic_only=", dynamic_only);
    size_t entries_total = m_device->m_tables.mac_forwarding_table->size();
    if (entries_total == 0) {
        out_mac_entries.clear();
        return LA_STATUS_SUCCESS;
    }

    vector_alloc<npl_mac_forwarding_table_t::entry_pointer_type> entries(entries_total, nullptr);
    size_t entries_num = m_device->m_tables.mac_forwarding_table->get_entries(&entries[0], entries_total);
    dassert_ncrit(entries_num <= entries_total);

    auto gid = this->get_gid();
    for (size_t i = 0; i < entries_num; i++) {
        npl_mac_forwarding_table_t::key_type k(entries[i]->key());
        npl_mac_forwarding_table_t::value_type v(entries[i]->value());
        if (k.mac_forwarding_key.relay_id.id != gid) {
            continue;
        }
        arc_cpu_application_specific_fields config_aging_params{};
        config_aging_params.flat = v.payloads.mact_result.application_specific_fields;

        if (dynamic_only && (config_aging_params.fields.age_value == cem::EM_NO_AGING_AGE)) {
            // Skip static MAC entry
            continue;
        }

        // Remove metadata entry
        // Prepare metadata key for lookup
        npl_mac_forwarding_w_metadata_table_t::key_type k_meta;
        npl_mac_forwarding_w_metadata_table_t::entry_pointer_type e_meta = nullptr;

        k_meta.mac_forwarding_key.relay_id.id = k.mac_forwarding_key.relay_id.id;
        k_meta.mac_forwarding_key.mac_address.mac_address = k.mac_forwarding_key.mac_address.mac_address;

        // Check for an entry in the metadata table
        la_status status = m_device->m_tables.mac_forwarding_w_metadata_table->lookup(k_meta, e_meta);
        if (status == LA_STATUS_SUCCESS) {
            la_status s = m_device->m_tables.mac_forwarding_w_metadata_table->erase(k_meta);
            return_on_error(s);
        }

        // Remove MAC entry and push the record into vector for result
        la_mac_entry_t record{};
        record.slp_gid = v.payloads.mact_result.destination.val;
        record.relay_gid = k.mac_forwarding_key.relay_id.id;
        record.addr.flat = k.mac_forwarding_key.mac_address.mac_address;
        out_mac_entries.push_back(record);

        status = m_device->m_tables.mac_forwarding_table->erase(entries[i]->key());
        if (status == LA_STATUS_ENOTFOUND) {
            return LA_STATUS_SUCCESS;
        }
        return_on_error(status);

        status = notify_mac_move(record.addr); // piggy back on mac move notification
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::set_security_group_policy_enforcement(bool enforcement)
{
    start_api_call("enforcement=", enforcement);

    bool old_enforcement;
    la_status status = get_security_group_policy_enforcement(old_enforcement);
    return_on_error(status);

    if (old_enforcement == enforcement) {
        return LA_STATUS_SUCCESS;
    }

    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.bd_attributes.sgacl_enforcement = enforcement;

    status = m_relay_attributes_entry->update(v);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_switch_impl::get_security_group_policy_enforcement(bool& out_enforcement) const
{
    start_api_getter_call();

    npl_service_relay_attributes_table_value_t v(m_relay_attributes_entry->value());
    out_enforcement = v.payloads.relay.relay_table_payload.relay_attr.mac_l2_relay_attributes.bd_attributes.sgacl_enforcement;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
