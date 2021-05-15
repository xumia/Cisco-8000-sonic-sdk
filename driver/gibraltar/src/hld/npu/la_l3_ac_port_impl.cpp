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

#include "la_l3_ac_port_impl.h"

#include "la_acl_delegate.h"
#include "la_acl_impl.h"
#include "npu/la_ethernet_port_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "counter_utils.h"
#include "hld_types.h"
#include "la_strings.h"
#include "la_vrf_impl.h"
#include "npu/la_vrf_port_common_base.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "tm/la_unicast_tc_profile_impl.h"

#include <sstream>

namespace silicon_one
{

la_l3_ac_port_impl::la_l3_ac_port_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_slice_pair_data(NUM_SLICE_PAIRS_PER_DEVICE, slice_pair_data()),
      m_ac_port_common(device),
      m_service_mapping_type(la_ethernet_port::service_mapping_type_e::LARGE),
      m_stack_remote_lp_queueing(false)
{
    m_mac_addr.flat = 0;
}

la_l3_ac_port_impl::~la_l3_ac_port_impl()
{
}

la_status
la_l3_ac_port_impl::initialize(la_object_id_t oid,
                               la_l3_port_gid_t gid,
                               const la_ethernet_port* ethernet_port,
                               la_vlan_id_t vid1,
                               la_vlan_id_t vid2,
                               la_mac_addr_t mac_addr,
                               const la_vrf* vrf,
                               la_ingress_qos_profile_impl* ingress_qos_profile_impl,
                               la_egress_qos_profile_impl* egress_qos_profile_impl)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    if ((!of_same_device(ethernet_port, this)) || (!of_same_device(vrf, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    m_gid = gid;
    m_ethernet_port = m_device->get_sptr<la_ethernet_port_base>(const_cast<la_ethernet_port*>(ethernet_port));
    m_mac_addr = mac_addr;
    m_vrf = m_device->get_sptr<const la_vrf_impl>(vrf);
    auto status = m_ac_port_common.initialize(m_device->get_sptr(this), gid, m_ethernet_port, vid1, vid2);
    return_on_error(status);

    // get the service mapping type
    la_ethernet_port::service_mapping_type_e type;
    status = m_ethernet_port->get_service_mapping_type(type);
    return_on_error(status);
    m_service_mapping_type = type;

    status = m_device->create_vrf_port_common(m_device->get_sptr(this), m_vrf_port_common);
    return_on_error(status);

    status = m_vrf_port_common->initialize(gid,
                                           mac_addr,
                                           nullptr /* sw */,
                                           m_vrf,
                                           m_device->get_sptr(ingress_qos_profile_impl),
                                           m_device->get_sptr(egress_qos_profile_impl));
    return_on_error(status);

    // Add each of the ethernet port's slices to the AC port
    auto ifgs = m_ethernet_port->get_ifgs();
    for (la_slice_ifg ifg : ifgs) {
        status = add_ifg(ifg);
        return_on_error(status);
    }

    // Configure PFC MAC address
    status = configure_pfc_src_mac(mac_addr);
    return_on_error(status);

    m_device->add_object_dependency(m_ethernet_port, this);
    m_device->add_ifg_dependency(m_ethernet_port, this);
    // The dependencies of ingress_qos_profile_impl, egress_qos_profile_impl are managed by m_vrf_port_common

    register_vrf_dependency(m_vrf);
    register_service_mapping_dependency(m_ethernet_port);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::destroy()
{
    la_status status = LA_STATUS_SUCCESS;
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    deregister_vrf_dependency(m_vrf);
    deregister_service_mapping_dependency(m_ethernet_port);
    m_device->remove_ifg_dependency(m_ethernet_port, this);
    m_device->remove_object_dependency(m_ethernet_port, this);

    if (m_tc_profile) {
        // clear dependency on tc_profile
        m_device->remove_object_dependency(m_tc_profile, this);
    }

    if (m_filter_group != nullptr) {
        m_device->remove_object_dependency(m_filter_group, this);
    }

    bool is_agg = m_ethernet_port->is_aggregate();
    for (auto sp_voq_pair = m_voq_map.begin(); sp_voq_pair != m_voq_map.end(); ++sp_voq_pair) {
        auto sys_port = sp_voq_pair->first;
        auto voq_set = sp_voq_pair->second;
        m_device->remove_object_dependency(sys_port, this);
        m_device->remove_object_dependency(voq_set, this);

        auto sys_port_base = sys_port.weak_ptr_static_cast<const la_system_port_base>();
        status = sys_port_base->clear_voq_mapping(voq_set);
        return_on_error(status);
        if (is_agg) {
            // clear lp_over_lag_table
            status = clear_lp_over_lag_table(sys_port_base);
            return_on_error(status);
        }
    }

    m_voq_map.clear();
    auto ifgs = m_ifg_use_count->get_ifgs();

    for (la_slice_ifg ifg : ifgs) {
        status = remove_ifg(ifg);
        return_on_error(status);
    }

    status = m_vrf_port_common->destroy();
    return_on_error(status);

    m_ac_port_common.destroy();
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::disable()
{
    start_api_call("");
    la_status status;

    status = m_ac_port_common.disable();
    return_on_error(status);

    status = m_vrf_port_common->set_port_egress_mode(false);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_l3_ac_port_impl::type() const
{
    return la_object::object_type_e::L3_AC_PORT;
}

std::string
la_l3_ac_port_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_l3_ac_port_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_l3_ac_port_impl::oid() const
{
    return m_oid;
}

const la_device*
la_l3_ac_port_impl::get_device() const
{
    return m_device.get();
}

la_l3_port_gid_t
la_l3_ac_port_impl::get_gid() const
{
    return m_gid;
}

la_status
la_l3_ac_port_impl::get_mac(la_mac_addr_t& out_mac_addr) const
{
    out_mac_addr = m_mac_addr;
    return LA_STATUS_SUCCESS;
}

const la_vrf*
la_l3_ac_port_impl::get_vrf() const
{
    return m_vrf.get();
}

la_status
la_l3_ac_port_impl::set_vrf(const la_vrf* vrf)
{
    start_api_call("vrf=", vrf);

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_vrf_port_common->has_subnets()) {
        return LA_STATUS_EBUSY;
    }

    deregister_vrf_dependency(m_vrf);
    auto vrf_impl_sptr = m_device->get_sptr<const la_vrf_impl>(vrf);
    la_status status = m_vrf_port_common->set_vrf(vrf_impl_sptr);
    return_on_error(status);

    m_vrf = vrf_impl_sptr;
    register_vrf_dependency(m_vrf);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::set_ecn_remark_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status = m_vrf_port_common->set_ecn_remark_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::get_ecn_remark_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_ecn_remark_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::set_ecn_counting_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status = m_vrf_port_common->set_ecn_counting_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::get_ecn_counting_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_ecn_counting_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
la_l3_ac_port_impl::register_vrf_dependency(const la_vrf_impl_wcptr& vrf)
{
    m_device->add_object_dependency(vrf, this);
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::VRF_FALLBACK_CHANGED);
    m_device->add_attribute_dependency(vrf, this, registered_attributes);
}

void
la_l3_ac_port_impl::deregister_vrf_dependency(const la_vrf_impl_wcptr& vrf)
{
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::VRF_FALLBACK_CHANGED);
    m_device->remove_attribute_dependency(vrf, this, registered_attributes);
    m_device->remove_object_dependency(vrf, this);
}

void
la_l3_ac_port_impl::register_service_mapping_dependency(const la_ethernet_port_base_wptr& ethernet_port)
{
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::SERVICE_MAPPING_TYPE_CHANGED);
    m_device->add_attribute_dependency(ethernet_port, this, registered_attributes);
}

void
la_l3_ac_port_impl::deregister_service_mapping_dependency(const la_ethernet_port_base_wptr& ethernet_port)
{
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::SERVICE_MAPPING_TYPE_CHANGED);
    m_device->remove_attribute_dependency(ethernet_port, this, registered_attributes);
}

const la_ethernet_port*
la_l3_ac_port_impl::get_ethernet_port() const
{
    return m_ethernet_port.get();
}

la_status
la_l3_ac_port_impl::set_service_mapping_vids(la_vlan_id_t vid1, la_vlan_id_t vid2)
{
    start_api_call("vid1=", vid1, "vid2=", vid2);
    la_status status = m_ac_port_common.set_service_mapping_vids(vid1, vid2);
    return status;
}

la_status
la_l3_ac_port_impl::get_service_mapping_vids(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const
{
    la_status status = m_ac_port_common.get_service_mapping_vids(out_vid1, out_vid2);
    return status;
}

la_status
la_l3_ac_port_impl::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {

    case (attribute_management_op::VRF_FALLBACK_CHANGED):
        return update_fallback_vrf();

    case (attribute_management_op::SERVICE_MAPPING_TYPE_CHANGED):
        return set_service_mapping_type();

    default:
        return LA_STATUS_SUCCESS;
    }
}

la_status
la_l3_ac_port_impl::add_ifg(la_slice_ifg ifg)
{
    transaction txn;

    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (!ifg_added) {
        return LA_STATUS_SUCCESS;
    }

    // Notify users
    txn.status = m_device->notify_ifg_added(this, ifg);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_device->notify_ifg_removed(this, ifg); });

    txn.status = m_ac_port_common.add_ifg(ifg);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_ac_port_common.remove_ifg(ifg); });

    if (slice_pair_added) {
        txn.status = configure_lp_attributes_table(ifg.slice / 2);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_lp_attributes_table(ifg.slice / 2); });
    }

    txn.status = m_vrf_port_common->add_ifg(ifg);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::remove_ifg(la_slice_ifg ifg)
{
    transaction txn;

    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->add_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (!ifg_removed) {
        return LA_STATUS_SUCCESS;
    }

    txn.status = m_ac_port_common.remove_ifg(ifg);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_ac_port_common.add_ifg(ifg); });

    txn.status = m_vrf_port_common->remove_ifg(ifg);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_vrf_port_common->add_ifg(ifg); });

    if (slice_pair_removed) {
        txn.status = teardown_lp_attributes_table(ifg.slice / 2);
        return_on_error(txn.status);
        txn.on_fail([=]() { configure_lp_attributes_table(ifg.slice / 2); });
    }

    // Notify users
    txn.status = m_device->notify_ifg_removed(this, ifg);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::populate_mymac_fields(la_mac_addr_t mac_addr, npl_mac_lp_attributes_payload_t& out_payload)
{
    uint64_t prefix;
    uint64_t lsbits = m_device->m_mac_addr_manager->get_lsbits(mac_addr);
    la_status status = m_device->m_mac_addr_manager->get_prefix(mac_addr, prefix);
    return_on_error(status);

    out_payload.layer.three.l3_lp_mymac_da_lsb = lsbits;
    out_payload.layer.three.l3_lp_mymac_da_prefix = prefix;

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::populate_mldp_budnode_flag(bool enabled, npl_mac_lp_attributes_payload_t& out_payload)
{
    out_payload.layer.three.mldp_budnode_terminate = enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::configure_lp_attributes_table(la_slice_pair_id_t slice_pair_idx)
{
    // Configure key and value
    const auto& table(m_device->m_tables.service_lp_attributes_table[slice_pair_idx]);
    npl_service_lp_attributes_table_t::key_type k;
    npl_service_lp_attributes_table_value_t v;
    npl_mac_lp_attributes_payload_t& payload(v.payloads.write.mac_lp_attributes_payload.lp_attr);

    k.service_lp_attributes_table_key.id = m_ac_port_common.get_local_slp_id(slice_pair_idx);
    v.payloads.write.slp.id = k.service_lp_attributes_table_key.id;

    v.action = NPL_SERVICE_LP_ATTRIBUTES_TABLE_ACTION_WRITE;
    // payload.sec_acl_on_term = 0;
    payload.mac_lp_type = NPL_LP_TYPE_LAYER_3;

    la_status status = populate_mymac_fields(m_mac_addr, payload);
    return_on_error(status);

    status = populate_mldp_budnode_flag(m_mldp_budnode_terminate, payload);
    return_on_error(status);

    // Update table. base-L3-LP attributes will be updated by the VRF common port - use defaults for now
    status = table->insert(k, v, m_slice_pair_data[slice_pair_idx].lp_attributes_entry);

    return status;
}

la_status
la_l3_ac_port_impl::update_l3_lp_attributes_tcam(la_slice_pair_id_t slice_pair_id,
                                                 const npl_mac_lp_attributes_payload_t& payload,
                                                 const uint32_t relay_id)
{
    if (m_service_mapping_type != la_ethernet_port::service_mapping_type_e::SMALL) {
        return LA_STATUS_SUCCESS;
    }
    la_status status = m_ac_port_common.configure_slice_ac_tcam_attributes(slice_pair_id, payload, relay_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::get_l3_lp_qos_and_attributes(la_slice_pair_id_t pair_idx, npl_l3_dlp_qos_and_attributes_t& attrib) const
{
    la_status status = m_vrf_port_common->get_l3_lp_qos_and_attributes(pair_idx, attrib);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::update_l3_lp_attributes(la_slice_pair_id_t slice_pair_idx,
                                            const npl_base_l3_lp_attributes_t& attribs,
                                            const npl_l3_lp_additional_attributes_t& additional_attribs)
{
    // lp-attributes table is per slice-pair
    const auto& entry = m_slice_pair_data[slice_pair_idx].lp_attributes_entry;
    npl_service_lp_attributes_table_value_t value = entry->value();
    npl_mac_lp_attributes_payload_t& payload(value.payloads.write.mac_lp_attributes_payload.lp_attr);
    npl_base_l3_lp_attributes_t& lp_attributes(payload.layer.three.base);

    lp_attributes = attribs;

    la_status status = entry->update(value);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD,
                "la_l3_ac_port_impl::update_l3_lp_attributes: lp_attributes_table[%d].set_entry_value failed, status = %s",
                slice_pair_idx,
                la_status2str(status).c_str());
        return status;
    }

    // A serious contender for the "ugliest code ever" title!
    //
    // The MAC relay-id is used by the NPL for encoding the additional attributes for L3-AC, which
    // doesn't have a MAC relay:
    //
    // 1)  table service_mapping_em0_ac_port_tag_tag_table :
    //       actions :
    //          service_relay_attributes_table_key = relay_id;
    //
    // 2(  table service_relay_attributes_table :
    //       actions :
    //          mac_relay_and_l3_lp_attr.mac_relay_attributes.id = service_relay_attributes_table_key;
    //
    //       -- mac_relay_attributes is a union where one of the members is 'id' and another is
    //          'l3_lp_additional_attributes'. so the assignment above also assigns value to the
    //          additional-attributes, so the following line works
    //
    // 3)   control network_rx_mac_af_and_termination_macro :
    //          pd.layer_vars.fwd_ipv6_acl_id = mac_relay_and_l3_lp_attr.mac_relay_attributes.ipv6_acl_id
    bit_vector temp_bv = additional_attribs.pack();
    uint32_t relay_id = temp_bv.get_value();
    status = m_ac_port_common.set_relay_id(slice_pair_idx, relay_id);
    return_on_error(status);

    // in case of TCAM service mapping, update the l3 attributes in the TCAM
    // service mapping table
    status = update_l3_lp_attributes_tcam(slice_pair_idx, payload, relay_id);
    return_on_error(status,
                    HLD,
                    ERROR,
                    "la_l3_ac_port_impl::update_l3_lp_attributes: update l3 attribute in slice pair %d tcam failed",
                    slice_pair_idx);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::teardown_lp_attributes_table(la_slice_pair_id_t slice_pair_idx)
{
    const auto& table(m_device->m_tables.service_lp_attributes_table[slice_pair_idx]);
    npl_service_lp_attributes_table_key_t k = m_slice_pair_data[slice_pair_idx].lp_attributes_entry->key();

    la_status status = table->erase(k);
    return_on_error(status);

    m_slice_pair_data[slice_pair_idx].lp_attributes_entry = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }

    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        return update_dependent_attributes(op);

    default:
        log_err(HLD,
                "la_l3_ac_port_impl::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

slice_ifg_vec_t
la_l3_ac_port_impl::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_status
la_l3_ac_port_impl::set_active(bool active)
{
    start_api_call("active=", active);
    la_status status = m_vrf_port_common->set_active(active);

    return status;
}

la_status
la_l3_ac_port_impl::get_active(bool& out_active) const
{
    return m_vrf_port_common->get_active(out_active);
}

la_status
la_l3_ac_port_impl::get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const
{
    la_status status = m_vrf_port_common->get_protocol_enabled(protocol, out_enabled);

    return status;
}

la_status
la_l3_ac_port_impl::set_protocol_enabled(la_l3_protocol_e protocol, bool enabled)
{
    start_api_call("protocol=", protocol, " enabled=", enabled);
    la_status status = m_vrf_port_common->set_protocol_enabled(protocol, enabled);

    return status;
}

la_status
la_l3_ac_port_impl::get_event_enabled(la_event_e event, bool& out_enabled) const
{
    la_status status = m_vrf_port_common->get_event_enabled(event, out_enabled);

    return status;
}

la_status
la_l3_ac_port_impl::set_event_enabled(la_event_e event, bool enabled)
{
    start_api_call("event=", event, " enabled=", enabled);
    la_status status = m_vrf_port_common->set_event_enabled(event, enabled);

    return status;
}

la_status
la_l3_ac_port_impl::get_urpf_mode(la_l3_port::urpf_mode_e& out_urpf_mode) const
{
    la_status status = m_vrf_port_common->get_urpf_mode(out_urpf_mode);

    return status;
}

la_status
la_l3_ac_port_impl::set_urpf_mode(la_l3_port::urpf_mode_e urpf_mode)
{
    start_api_call("urpf_mode=", urpf_mode);
    la_status status = m_vrf_port_common->set_urpf_mode(urpf_mode);

    return status;
}

la_status
la_l3_ac_port_impl::set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile)
{
    start_api_call("ingress_qos_profile=", ingress_qos_profile);

    la_status status = m_vrf_port_common->set_ingress_qos_profile(ingress_qos_profile);

    return status;
}

la_status
la_l3_ac_port_impl::get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_ingress_qos_profile(out_ingress_qos_profile);

    return status;
}

la_status
la_l3_ac_port_impl::set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile)
{
    start_api_call("egress_qos_profile=", egress_qos_profile);

    la_status status = m_vrf_port_common->set_egress_qos_profile(egress_qos_profile);

    return status;
}

la_status
la_l3_ac_port_impl::get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_egress_qos_profile(out_egress_qos_profile);

    return status;
}

la_status
la_l3_ac_port_impl::set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2)
{
    start_api_call("tag1=", tag1, "tag2=", tag2);
    la_vlan_tag_t old_tag1, old_tag2;
    la_status status = m_vrf_port_common->get_egress_vlan_tag(old_tag1, old_tag2);
    return_on_error(status);

    status = m_vrf_port_common->set_egress_vlan_tag(tag1, tag2);
    return_on_error(status);

    attribute_management_details amd;
    amd.op = attribute_management_op::EGRESS_VLAN_TAG_CHANGED;
    la_amd_undo_callback_funct_t undo = [this, old_tag1, old_tag2](attribute_management_details amd) {
        la_status status = m_vrf_port_common->set_egress_vlan_tag(old_tag1, old_tag2);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "Error setting vlan tag. status: %s ", la_status2str(status).c_str());
        }
        return amd;
    };
    return m_device->notify_attribute_changed(this, amd, undo);
}

la_status
la_l3_ac_port_impl::add_ipv4_subnet(la_ipv4_prefix_t subnet)
{
    start_api_call("subnet=", subnet);
    la_status status = m_vrf_port_common->add_ipv4_subnet(subnet);

    return status;
}

la_status
la_l3_ac_port_impl::delete_ipv4_subnet(la_ipv4_prefix_t subnet)
{
    start_api_call("subnet=", subnet);
    la_status status = m_vrf_port_common->delete_ipv4_subnet(subnet);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv4_subnets(la_ipv4_prefix_vec_t& out_subnets) const
{
    la_status status = m_vrf_port_common->get_ipv4_subnets(out_subnets);

    return status;
}

la_status
la_l3_ac_port_impl::add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr);
    la_status status = m_vrf_port_common->add_ipv4_host(ip_addr, mac_addr);

    return status;
}

la_status
la_l3_ac_port_impl::modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr);
    la_status status = m_vrf_port_common->modify_ipv4_host(ip_addr, mac_addr);

    return status;
}

la_status
la_l3_ac_port_impl::add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr, "class_id=", class_id);
    la_status status = m_vrf_port_common->add_ipv4_host(ip_addr, mac_addr, class_id);

    return status;
}

la_status
la_l3_ac_port_impl::modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr, "class_id=", class_id);
    la_status status = m_vrf_port_common->modify_ipv4_host(ip_addr, mac_addr, class_id);

    return status;
}

la_status
la_l3_ac_port_impl::delete_ipv4_host(la_ipv4_addr_t ip_addr)
{
    start_api_call("ip_addr=", ip_addr);
    la_status status = m_vrf_port_common->delete_ipv4_host(ip_addr);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const
{
    la_status status = m_vrf_port_common->get_ipv4_host(ip_addr, out_mac_addr);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv4_host_and_class_id(la_ipv4_addr_t ip_addr,
                                               la_mac_addr_t& out_mac_addr,
                                               la_class_id_t& out_class_id) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_ipv4_host(ip_addr, out_mac_addr, out_class_id);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv4_hosts(la_mac_addr_vec& out_mac_addresses) const
{
    la_status status = m_vrf_port_common->get_ipv4_hosts(out_mac_addresses);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv4_hosts(la_ipv4_addr_vec& out_ip_addresses) const
{
    la_status status = m_vrf_port_common->get_ipv4_hosts(out_ip_addresses);

    return status;
}

la_status
la_l3_ac_port_impl::add_ipv6_subnet(la_ipv6_prefix_t subnet)
{
    start_api_call("subnet=", subnet);
    la_status status = m_vrf_port_common->add_ipv6_subnet(subnet);

    return status;
}

la_status
la_l3_ac_port_impl::delete_ipv6_subnet(la_ipv6_prefix_t subnet)
{
    start_api_call("subnet=", subnet);
    la_status status = m_vrf_port_common->delete_ipv6_subnet(subnet);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv6_subnets(la_ipv6_prefix_vec_t& out_subnets) const
{
    la_status status = m_vrf_port_common->get_ipv6_subnets(out_subnets);

    return status;
}

la_status
la_l3_ac_port_impl::add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr);
    la_status status = m_vrf_port_common->add_ipv6_host(ip_addr, mac_addr);

    return status;
}

la_status
la_l3_ac_port_impl::modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr);
    la_status status = m_vrf_port_common->modify_ipv6_host(ip_addr, mac_addr);

    return status;
}

la_status
la_l3_ac_port_impl::add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr, "class_id=", class_id);
    la_status status = m_vrf_port_common->add_ipv6_host(ip_addr, mac_addr, class_id);

    return status;
}

la_status
la_l3_ac_port_impl::modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr, "class_id=", class_id);
    la_status status = m_vrf_port_common->modify_ipv6_host(ip_addr, mac_addr, class_id);

    return status;
}

la_status
la_l3_ac_port_impl::delete_ipv6_host(la_ipv6_addr_t ip_addr)
{
    start_api_call("ip_addr=", ip_addr);
    la_status status = m_vrf_port_common->delete_ipv6_host(ip_addr);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_addres) const
{
    la_status status = m_vrf_port_common->get_ipv6_host(ip_addr, out_mac_addres);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv6_host_and_class_id(la_ipv6_addr_t ip_addr,
                                               la_mac_addr_t& out_mac_addres,
                                               la_class_id_t& out_class_id) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_ipv6_host(ip_addr, out_mac_addres, out_class_id);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv6_hosts(la_mac_addr_vec& out_mac_addresses) const
{
    la_status status = m_vrf_port_common->get_ipv6_hosts(out_mac_addresses);

    return status;
}

la_status
la_l3_ac_port_impl::get_ipv6_hosts(la_ipv6_addr_vec& out_ip_addresses) const
{
    la_status status = m_vrf_port_common->get_ipv6_hosts(out_ip_addresses);

    return status;
}

la_status
la_l3_ac_port_impl::set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group)
{
    start_api_call("dir=", dir, "acl_group=", acl_group);
    return m_vrf_port_common->set_acl_group(dir, acl_group);
}

la_status
la_l3_ac_port_impl::get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const
{
    start_api_getter_call("dir=", dir);
    return m_vrf_port_common->get_acl_group(dir, out_acl_group);
}

la_status
la_l3_ac_port_impl::clear_acl_group(la_acl_direction_e dir)
{
    start_api_call("dir=", dir);
    return m_vrf_port_common->clear_acl_group(dir);
}

la_status
la_l3_ac_port_impl::set_pbr_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    return m_vrf_port_common->set_pbr_enabled(enabled);
}

la_status
la_l3_ac_port_impl::get_pbr_enabled(bool& out_enabled) const
{
    start_api_getter_call("");
    return m_vrf_port_common->get_pbr_enabled(out_enabled);
}

la_status
la_l3_ac_port_impl::set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    start_api_call("mirror_cmd=", mirror_cmd, "is_acl_conditioned=", is_acl_conditioned);
    return m_vrf_port_common->set_ingress_mirror_command(mirror_cmd, is_acl_conditioned);
}

la_status
la_l3_ac_port_impl::get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    start_api_getter_call("");
    return m_vrf_port_common->get_ingress_mirror_command(out_mirror_cmd, out_is_acl_conditioned);
}

la_status
la_l3_ac_port_impl::set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    start_api_call("mirror_cmd=", mirror_cmd, "is_acl_conditioned=", is_acl_conditioned);
    return m_vrf_port_common->set_egress_mirror_command(mirror_cmd, is_acl_conditioned);
}

la_status
la_l3_ac_port_impl::get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    start_api_getter_call("");
    return m_vrf_port_common->get_egress_mirror_command(out_mirror_cmd, out_is_acl_conditioned);
}

la_status
la_l3_ac_port_impl::set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode)
{
    return m_vrf_port_common->set_ttl_inheritance_mode(mode);
}

la_mpls_ttl_inheritance_mode_e
la_l3_ac_port_impl::get_ttl_inheritance_mode() const
{
    return m_vrf_port_common->get_ttl_inheritance_mode();
}

la_status
la_l3_ac_port_impl::set_qos_inheritance_mode(la_mpls_qos_inheritance_mode_e mode)
{
    start_api_call("mode=", mode);
    return m_vrf_port_common->set_qos_inheritance_mode(mode);
}

la_mpls_qos_inheritance_mode_e
la_l3_ac_port_impl::get_qos_inheritance_mode() const
{
    return m_vrf_port_common->get_qos_inheritance_mode();
}

la_status
la_l3_ac_port_impl::update_fallback_vrf()
{
    return m_vrf_port_common->update_fallback_vrf();
}

la_status
la_l3_ac_port_impl::set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter)
{
    start_api_call("type=", type, " counter=", counter);
    return m_vrf_port_common->set_ingress_counter(type, counter);
}

la_status
la_l3_ac_port_impl::get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const
{
    return m_vrf_port_common->get_ingress_counter(type, out_counter);
}

la_status
la_l3_ac_port_impl::set_egress_counter(la_counter_set::type_e type, la_counter_set* counter)
{
    start_api_call("type=", type, " counter=", counter);
    return m_vrf_port_common->set_egress_counter(type, counter);
}

la_status
la_l3_ac_port_impl::get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const
{
    return m_vrf_port_common->get_egress_counter(type, out_counter);
}

la_status
la_l3_ac_port_impl::get_egress_vlan_tag(la_vlan_tag_t& out_tag1, la_vlan_tag_t& out_tag2) const
{
    return m_vrf_port_common->get_egress_vlan_tag(out_tag1, out_tag2);
}

la_status
la_l3_ac_port_impl::set_meter(const la_meter_set* meter)
{
    start_api_call("meter=", meter);

    la_status status = m_vrf_port_common->set_meter(const_cast<la_meter_set*>(meter));
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::get_meter(const la_meter_set*& out_meter) const
{
    start_api_getter_call();

    return m_vrf_port_common->get_meter(out_meter);
}

la_status
la_l3_ac_port_impl::get_bvn_profile(la_bvn_profile_t& out_bvn_profile) const
{
    if (m_tc_profile == nullptr) {
        log_err(HLD, "No bvn profile set");
        return LA_STATUS_ENOTINITIALIZED;
    }

    auto tc_profile_impl = m_tc_profile.weak_ptr_static_cast<const la_tc_profile_impl>();
    npl_bvn_profile_t bvn_profile;
    bvn_profile.tc_map_profile = tc_profile_impl->get_id();
    bvn_profile.lp_over_lag = m_ethernet_port->is_aggregate();
    out_bvn_profile = bvn_profile.pack().get_value();

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::configure_lp_over_lag_table(const la_system_port_base_wcptr& sp, const la_voq_set_wptr& voq_set)
{
    // program npl_lp_over_lag_table
    const auto& table(m_device->m_tables.lp_over_lag_table);
    npl_lp_over_lag_table_key_t k;
    npl_lp_over_lag_table_value_t v;
    npl_lp_over_lag_table_entry_t* entry;

    k.l3_dlp_lsbs = get_l3_lp_lsb(m_gid);
    k.l3_dlp_msbs = get_l3_lp_msb(m_gid);
    // DSP of member as destination
    k.destination = (silicon_one::get_destination_id(sp, RESOLUTION_STEP_STAGE2_NH)).val;
    // l3_dlp of self
    v.payloads.bvn_destination = (silicon_one::get_destination_id(voq_set, RESOLUTION_STEP_STAGE2_NH)).val;

    la_status status = table->insert(k, v, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_l3_ac_port_impl::l3_ac_voq_map_t::const_iterator
la_l3_ac_port_impl::find_in_voq_map(const la_system_port_wcptr& sys_port) const
{
    auto it = std::find_if(m_voq_map.begin(),
                           m_voq_map.end(),
                           [sys_port](const std::pair<la_system_port_wcptr, la_voq_set_wptr>& e) { return e.first == sys_port; });

    return it;
}

la_status
la_l3_ac_port_impl::set_stack_remote_logical_port_queueing_enabled(const la_system_port* system_port, bool enabled)
{
    start_api_call("system_port=", system_port, " enabled=", enabled);

    if (system_port == nullptr) {
        log_err(HLD, "invalid system_port");
        return LA_STATUS_EINVAL;
    }

    auto system_port_sptr = m_device->get_sptr(system_port);

    // check if system_port is part of l3_ac
    if (m_ethernet_port->is_member(system_port_sptr) == false) {
        log_err(HLD, "system_port doesn't belong to l3_ac");
        return LA_STATUS_EINVAL;
    }

    bool svl_mode = false;
    la_status status = m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (svl_mode && m_ethernet_port->is_aggregate()) {
        log_err(HLD, "aggregate port is not supported in SVL mode");
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto system_port_base = std::static_pointer_cast<const la_system_port_base>(system_port_sptr);

    if ((svl_mode != true) || (system_port_base->get_port_type() != la_system_port_base::port_type_e::REMOTE)) {
        log_err(HLD, svl_mode ? "not a remote system port" : "unsupported condition (non svl mode)");
        return LA_STATUS_EINVAL;
    }

    m_stack_remote_lp_queueing = enabled;

    // Inform all dependents to update hw tables
    attribute_management_details amd;
    amd.op = attribute_management_op::REMOTE_VOQ_CHANGED;
    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };
    return m_device->notify_attribute_changed(this, amd, undo);
}

la_status
la_l3_ac_port_impl::set_system_port_voq_set(const la_system_port* system_port, la_voq_set* voq_set)
{
    start_api_call("system_port=", system_port, " voq_set=", voq_set);
    bool clear = false;

    if (system_port == nullptr) {
        log_err(HLD, "invalid system_port");
        return LA_STATUS_EINVAL;
    }

    if (voq_set == nullptr) {
        log_err(HLD, "invalid voq set");
        return LA_STATUS_EINVAL;
    }

    bool svl_mode = false;
    la_status status = m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (svl_mode && m_ethernet_port->is_aggregate()) {
        log_err(HLD, "aggregate port is not supported in SVL mode");
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto system_port_sptr = m_device->get_sptr(system_port);
    auto voq_set_sptr = m_device->get_sptr(voq_set);

    weak_ptr_unsafe<la_voq_set> old_voq_set{};
    auto sp_voq_pair = find_in_voq_map(system_port_sptr);
    if (sp_voq_pair != m_voq_map.end()) {
        if (sp_voq_pair->second == voq_set_sptr) {
            return LA_STATUS_SUCCESS;
        } else {
            /* New voq_set on SP with existing mapping. Clear existing */
            clear = true;
            old_voq_set = sp_voq_pair->second;
        }
    }

    // check if system_port is part of l3_ac
    if (m_ethernet_port->is_member(system_port_sptr) == false) {
        log_err(HLD, "system_port doesn't belong to l3_ac");
        return LA_STATUS_EINVAL;
    }

    auto system_port_base = std::static_pointer_cast<const la_system_port_base>(system_port_sptr);
    // check voq and systemport are matching slice, ifg, device
    status = system_port_base->is_valid_voq_mapping(voq_set_sptr);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "invalid voq mapping for system_port");
        return status;
    }

    status = system_port_base->program_voq_mapping(voq_set_sptr, true /* is_lp */);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "set voq mapping failed");
        return status;
    }

    // add dependency on voq_set and system_port
    m_device->add_object_dependency(voq_set_sptr, this);

    // Store voq_set per SP
    m_voq_map[system_port_sptr] = voq_set_sptr;

    if (m_ethernet_port->is_aggregate()) {
        status = configure_lp_over_lag_table(system_port_base, voq_set_sptr);
        return_on_error(status);
    }

    // Inform all dependents to update hw tables
    attribute_management_details amd;
    amd.op = attribute_management_op::VOQ_CHANGED;
    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };
    status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(status);

    if (!clear) {
        /* Add SP dependncy only once */
        m_device->add_object_dependency(system_port_sptr, this);
    } else {
        status = system_port_base->clear_voq_mapping(old_voq_set);
        return_on_error(status);
        m_device->remove_object_dependency(old_voq_set, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::clear_lp_over_lag_table(const la_system_port_base_wcptr& sp)
{
    const auto& table(m_device->m_tables.lp_over_lag_table);
    npl_lp_over_lag_table_key_t k;

    k.l3_dlp_lsbs = get_l3_lp_lsb(m_gid);
    k.l3_dlp_msbs = get_l3_lp_msb(m_gid);
    k.destination = (silicon_one::get_destination_id(sp, RESOLUTION_STEP_STAGE2_NH)).val;

    la_status status = table->erase(k);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::clear_system_port_voq_set(const la_system_port* system_port)
{
    start_api_call("system_port=", system_port);
    if (system_port == nullptr) {
        log_err(HLD, "invalid system_port");
        return LA_STATUS_EINVAL;
    }

    auto system_port_sptr = m_device->get_sptr(system_port);
    auto sp_voq_pair = find_in_voq_map(system_port_sptr);
    if (sp_voq_pair == m_voq_map.end()) {
        log_err(HLD, "system_port qos not programmed");
        return LA_STATUS_ENOTFOUND;
    }

    auto system_port_base = std::static_pointer_cast<const la_system_port_base>(system_port_sptr);
    m_device->remove_object_dependency(sp_voq_pair->first, this);
    m_device->remove_object_dependency(sp_voq_pair->second, this);

    la_status status = system_port_base->clear_voq_mapping(sp_voq_pair->second);
    return_on_error(status);
    m_voq_map.erase(sp_voq_pair);

    if (m_ethernet_port->is_aggregate()) {
        // clear lp_over_lag_table
        la_status status = clear_lp_over_lag_table(system_port_base);
        return_on_error(status);
    }

    // Inform all dependents to update hw tables
    attribute_management_details amd;
    amd.op = attribute_management_op::VOQ_CHANGED;
    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };
    return m_device->notify_attribute_changed(this, amd, undo);
}

la_status
la_l3_ac_port_impl::get_system_port_voq_set(const la_system_port* system_port, la_voq_set*& out_voq_set) const
{
    start_api_call("system_port=", system_port);

    auto system_port_sptr = m_device->get_sptr(system_port);
    auto sp_voq_pair = find_in_voq_map(system_port_sptr);
    if (sp_voq_pair == m_voq_map.end()) {
        out_voq_set = nullptr;
        return LA_STATUS_ENOTFOUND;
    }
    out_voq_set = sp_voq_pair->second.get();
    return LA_STATUS_SUCCESS;
}

la_voq_set*
la_l3_ac_port_impl::get_voq_set() const
{
    if (m_voq_map.empty()) {
        return nullptr;
    }

    auto it = m_voq_map.begin();
    return (it->second.get());
}

la_status
la_l3_ac_port_impl::get_voq_sets(la_sysport_voq_vec_t& vec) const
{
    vec.clear();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l3_ac_port_impl::set_tc_profile(la_tc_profile* tc_profile)
{
    start_api_call("tc_profile=", tc_profile);
    if (tc_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto tc_profile_sptr = m_device->get_sptr<const la_tc_profile>(tc_profile);

    if (m_tc_profile == tc_profile_sptr) {
        return LA_STATUS_SUCCESS;
    }
    if (m_tc_profile) {
        // clear dependency on old tc_profile
        m_device->remove_object_dependency(m_tc_profile, this);
    }

    auto old_profile = m_tc_profile;
    m_tc_profile = tc_profile_sptr;
    // add dependency
    m_device->add_object_dependency(tc_profile, this);

    // Inform all dependents to update hw tables
    attribute_management_details amd;
    if (m_stack_remote_lp_queueing) {
        amd.op = attribute_management_op::REMOTE_VOQ_CHANGED;
    } else {
        amd.op = attribute_management_op::VOQ_CHANGED;
    }
    la_amd_undo_callback_funct_t undo = [&](attribute_management_details amd) {
        m_device->remove_object_dependency(m_tc_profile, this);
        m_tc_profile = old_profile;
        m_device->add_object_dependency(m_tc_profile, this);
        return amd;
    };
    return m_device->notify_attribute_changed(this, amd, undo);
}

la_status
la_l3_ac_port_impl::get_tc_profile(const la_tc_profile*& out_tc_profile) const
{
    out_tc_profile = m_tc_profile.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::set_csc_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status = m_vrf_port_common->set_csc_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::get_csc_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_csc_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::set_drop_counter_offset(la_stage_e stage, size_t offset)
{
    start_api_call("stage=", stage, "offset=", offset);

    return m_vrf_port_common->set_drop_counter_offset(stage, offset);
}

la_status
la_l3_ac_port_impl::get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const
{
    start_api_getter_call("stage=", stage, "offset=", offset);

    return m_vrf_port_common->get_drop_counter_offset(stage, out_offset);
}

la_status
la_l3_ac_port_impl::set_mac(const la_mac_addr_t& mac_addr)
{
    start_api_call("mac_addr=", mac_addr);

    // Configure DLP (adds the new address to the MAC address manager)
    la_status status = m_vrf_port_common->set_mac(mac_addr);
    return_on_error(status);

    // Configure LP
    for (auto& slice_pair_data : m_slice_pair_data) {
        const auto& entry = slice_pair_data.lp_attributes_entry;

        if (entry != nullptr) {
            auto value = entry->value();
            auto& payload(value.payloads.write.mac_lp_attributes_payload.lp_attr);

            status = populate_mymac_fields(mac_addr, payload);
            return_on_error(status);

            status = entry->update(value);
            return_on_error(status);
        }
    }

    la_mac_addr_t old_mac = m_mac_addr;
    m_mac_addr = mac_addr;

    attribute_management_details amd;
    amd.op = attribute_management_op::L3_AC_PORT_MAC_CHANGED;
    la_amd_undo_callback_funct_t undo = [&](attribute_management_details amd) {
        // reset with old mac.
        la_status status = m_vrf_port_common->set_mac(old_mac);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "Error setting mac. status: %s ", la_status2str(status).c_str());
            return amd;
        }
        for (auto& slice_pair_data : m_slice_pair_data) {
            auto& entry = slice_pair_data.lp_attributes_entry;
            if (entry != nullptr) {
                auto value = entry->value();
                auto& payload(value.payloads.write.mac_lp_attributes_payload.lp_attr);
                status = populate_mymac_fields(old_mac, payload);
                if (status != LA_STATUS_SUCCESS) {
                    log_err(HLD, "Error populating fields. status: %s ", la_status2str(status).c_str());
                    return amd;
                }
                status = entry->update(value);
                if (status != LA_STATUS_SUCCESS) {
                    log_err(HLD, "Error updating lp attributes. status: %s ", la_status2str(status).c_str());
                    return amd;
                }
            }
        }
        m_mac_addr = old_mac;
        return amd;
    };

    // Configure PFC MAC address
    status = configure_pfc_src_mac(mac_addr);
    return_on_error(status);

    status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::configure_pfc_src_mac(la_mac_addr_t mac_addr)
{
    la_vlan_id_t vlan1;
    la_vlan_id_t vlan2;
    la_status status = m_ac_port_common.get_service_mapping_vids(vlan1, vlan2);
    return_on_error(status);

    // Only configure for non-vlan ports
    if (vlan1 == 0 && vlan2 == 0) {
        const la_system_port* sys_port = m_ethernet_port->get_system_port();
        if (sys_port == nullptr) {
            const la_spa_port_base* spa_port = static_cast<const la_spa_port_base*>(m_ethernet_port->get_spa_port());
            system_port_vec_t sys_ports;
            status = spa_port->get_members(sys_ports);
            return_on_error(status);

            for (la_system_port* sys_port : sys_ports) {
                const la_object* obj = sys_port->get_underlying_port();
                if (obj->type() != la_object::object_type_e::MAC_PORT) {
                    continue;
                }
                la_mac_port_base* mac_port = const_cast<la_mac_port_base*>(static_cast<const la_mac_port_base*>(obj));

                status = mac_port->set_pfc_src_mac(mac_addr);
                return_on_error(status);
            }
        } else {
            const la_object* obj = sys_port->get_underlying_port();
            if (obj->type() != la_object::object_type_e::MAC_PORT) {
                return LA_STATUS_SUCCESS;
            }
            la_mac_port_base* mac_port = const_cast<la_mac_port_base*>(static_cast<const la_mac_port_base*>(obj));

            status = mac_port->set_pfc_src_mac(mac_addr);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::set_source_based_forwarding(const la_l3_destination* l3_destination, bool label_present, la_mpls_label label)
{
    start_api_call("l3_destination=", l3_destination, "label_present=", label_present, "label=", label);

    return m_vrf_port_common->set_source_based_forwarding(l3_destination, label_present, label);
}

la_status
la_l3_ac_port_impl::clear_source_based_forwarding()
{
    start_api_call("");

    return m_vrf_port_common->clear_source_based_forwarding();
}

la_status
la_l3_ac_port_impl::get_source_based_forwarding(const la_l3_destination*& out_l3_destination,
                                                bool& out_label_present,
                                                la_mpls_label& out_label) const
{
    start_api_getter_call();

    return m_vrf_port_common->get_source_based_forwarding(out_l3_destination, out_label_present, out_label);
}

la_status
la_l3_ac_port_impl::get_load_balancing_profile(la_l3_port::lb_profile_e& out_lb_profile) const
{
    start_api_getter_call();

    return m_vrf_port_common->get_load_balancing_profile(out_lb_profile);
}

la_status
la_l3_ac_port_impl::set_load_balancing_profile(la_l3_port::lb_profile_e lb_profile)
{
    start_api_call("lb_profile=", lb_profile);

    return m_vrf_port_common->set_load_balancing_profile(lb_profile);
}

bool
la_l3_ac_port_impl::is_lp_queueing_enabled() const
{
    return (!m_voq_map.empty() || m_stack_remote_lp_queueing);
}

bool
la_l3_ac_port_impl::is_stack_remote_lp_queueing_enabled() const
{
    return m_stack_remote_lp_queueing;
}

la_status
la_l3_ac_port_impl::set_service_mapping_type()
{
    la_ethernet_port::service_mapping_type_e type;

    la_status status = m_ethernet_port->get_service_mapping_type(type);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

    if (m_service_mapping_type == type) {
        return LA_STATUS_SUCCESS;
    }

    m_service_mapping_type = type;

    return LA_STATUS_SUCCESS;
}

bool
la_l3_ac_port_impl::is_aggregate() const
{
    return (m_ethernet_port->is_aggregate());
}

la_status
la_l3_ac_port_impl::add_virtual_mac(const la_mac_addr_t& mac_addr)
{
    start_api_call("mac_addr=", mac_addr);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l3_ac_port_impl::remove_virtual_mac(const la_mac_addr_t& mac_addr)
{
    start_api_call("mac_addr=", mac_addr);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l3_ac_port_impl::get_virtual_macs(la_mac_addr_vec& out_mac_addresses) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l3_ac_port_impl::set_ingress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    la_status status = m_vrf_port_common->set_ingress_sflow_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::get_ingress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_ingress_sflow_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::set_egress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    la_status status = m_vrf_port_common->set_egress_sflow_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::get_egress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();
    la_status status = m_vrf_port_common->get_egress_sflow_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::get_filter_group(const la_filter_group*& out_filter_group) const
{
    start_api_getter_call();
    out_filter_group = m_filter_group.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::set_filter_group(la_filter_group* filter_group)
{
    start_api_call("filter_group=", filter_group);

    if (filter_group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(filter_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    m_filter_group = m_device->get_sptr<const la_filter_group_impl>(filter_group);
    la_status status = m_vrf_port_common->set_filter_group(m_filter_group);
    return_on_error(status);

    m_device->add_object_dependency(m_filter_group, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::get_mldp_bud_terminate_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    out_enabled = m_mldp_budnode_terminate;
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_ac_port_impl::set_mldp_bud_terminate_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status = LA_STATUS_SUCCESS;

    // Configure LP
    for (auto& slice_pair_data : m_slice_pair_data) {
        const auto& entry = slice_pair_data.lp_attributes_entry;

        if (entry != nullptr) {
            auto value = entry->value();
            auto& payload(value.payloads.write.mac_lp_attributes_payload.lp_attr);

            status = populate_mldp_budnode_flag(enabled, payload);
            return_on_error(status);

            status = entry->update(value);
            return_on_error(status);
        }
    }

    m_mldp_budnode_terminate = enabled;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
