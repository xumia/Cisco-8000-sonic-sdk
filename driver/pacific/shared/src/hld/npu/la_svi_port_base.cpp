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

#include "la_svi_port_base.h"
#include "api/npu/la_vrf.h"
#include "npu/la_acl_delegate.h"
#include "npu/la_acl_impl.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_switch_impl.h"
#include "npu/la_vrf_impl.h"
#include "npu/la_vrf_port_common_base.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "npu/counter_utils.h"

#include <sstream>

namespace silicon_one
{

la_svi_port_base::la_svi_port_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_oid((la_object_id_t)-1),
      m_gid(0),
      m_vxlan_shared_overlay_nh_count(0),
      m_slice_data(ASIC_MAX_SLICES_PER_DEVICE_NUM, slice_data()),
      m_rcy_sm_vid1(LA_VLAN_ID_INVALID),
      m_rcy_sm_vid2(LA_VLAN_ID_INVALID)
{
}

la_svi_port_base::~la_svi_port_base()
{
}

la_status
la_svi_port_base::set_ecn_remark_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status = m_vrf_port_common->set_ecn_remark_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_ecn_remark_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_ecn_remark_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_ecn_counting_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status = m_vrf_port_common->set_ecn_counting_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_ecn_counting_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_ecn_counting_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::initialize(la_object_id_t oid,
                             la_l3_port_gid_t gid,
                             la_mac_addr_t mac_addr,
                             const la_switch* sw,
                             const la_vrf* vrf,
                             la_ingress_qos_profile_impl* ingress_qos_profile_impl,
                             la_egress_qos_profile_impl* egress_qos_profile_impl)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());

    m_oid = oid;
    if ((!of_same_device(sw, this)) || (!of_same_device(vrf, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Verify there's only one SVI port attached to this switch
    std::vector<la_object*> deps = m_device->get_dependent_objects(sw);
    for (auto objp : deps) {
        if (objp->type() == object_type_e::SVI_PORT) {
            log_err(HLD,
                    "la_svi_port_base::%s: %s has more than 1 SVI ports attached to it."
                    " This is currently not supported",
                    __func__,
                    sw->to_string().c_str());
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    m_sw = m_device->get_sptr<const la_switch_impl>(sw);
    m_vrf = m_device->get_sptr<const la_vrf_impl>(vrf);
    m_mac_addr = mac_addr;
    m_gid = gid;

    la_status status = m_device->create_vrf_port_common(m_device->get_sptr(this), m_vrf_port_common);
    return_on_error(status);

    status = m_vrf_port_common->initialize(
        gid, mac_addr, m_sw, m_vrf, m_device->get_sptr(ingress_qos_profile_impl), m_device->get_sptr(egress_qos_profile_impl));
    return_on_error(status);

    auto ifgs = m_sw->get_ifgs();

    for (la_slice_ifg ifg : ifgs) {
        status = add_ifg(ifg);
        if (status != LA_STATUS_SUCCESS) {

            la_status rollback_status = destroy();

            if (rollback_status != LA_STATUS_SUCCESS) {
                return LA_STATUS_EDOUBLE_FAULT;
            }

            return status;
        }
    }

    register_vrf_dependency(m_vrf);
    m_device->add_object_dependency(m_sw, this);
    m_device->add_ifg_dependency(m_sw, this);

    // The dependencies of ingress_qos_profile_impl, egress_qos_profile_impl are managed by m_vrf_port_common

    bit_vector mm_attributes((la_uint64_t)attribute_management_op::MAC_MOVED);
    m_device->add_attribute_dependency(m_sw, this, mm_attributes);
    status = m_sw.weak_ptr_const_cast<la_switch_impl>()->set_is_svi_flag(true);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }

    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        return update_dependent_attributes(op.action.attribute_management);

    default:
        log_err(HLD,
                "la_svi_port_base::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_svi_port_base::add_ifg(la_slice_ifg ifg)
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

    if (slice_added) {
        txn.status = init_mac_termination_table(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_mac_termination_table(ifg.slice); });
    }

    txn.status = m_vrf_port_common->add_ifg(ifg);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::remove_ifg(la_slice_ifg ifg)
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

    txn.status = m_vrf_port_common->remove_ifg(ifg);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_vrf_port_common->add_ifg(ifg); });

    if (slice_removed) {
        txn.status = teardown_mac_termination_table(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([=]() { init_mac_termination_table(ifg.slice); });
    }

    // Notify users
    txn.status = m_device->notify_ifg_removed(this, ifg);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::update_dependent_attributes(attribute_management_details attribute)
{
    switch (attribute.op) {
    case (attribute_management_op::VRF_FALLBACK_CHANGED):
        return update_fallback_vrf();
    case (attribute_management_op::MAC_MOVED):
        return process_mac_move_notification(attribute.mac_addr);
    default:
        return LA_STATUS_SUCCESS;
    }
}

la_status
la_svi_port_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }
    auto status = m_sw.weak_ptr_const_cast<la_switch_impl>()->set_is_svi_flag(false);
    return_on_error(status);
    m_inject_up_port = nullptr;
    deregister_vrf_dependency(m_vrf);
    bit_vector mm_attributes((la_uint64_t)attribute_management_op::MAC_MOVED);
    m_device->remove_attribute_dependency(m_sw, this, mm_attributes);
    m_device->remove_ifg_dependency(m_sw, this);
    m_device->remove_object_dependency(m_sw, this);

    if (m_filter_group != nullptr) {
        m_device->remove_object_dependency(m_filter_group, this);
    }

    auto ifgs = m_ifg_use_count->get_ifgs();
    for (la_slice_ifg ifg : ifgs) {
        la_status status = remove_ifg(ifg);
        return_on_error(status);
    }

    status = m_vrf_port_common->destroy();

    return status;
}

la_object::object_type_e
la_svi_port_base::type() const
{
    return object_type_e::SVI_PORT;
}

std::string
la_svi_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_svi_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_svi_port_base::oid() const
{
    return m_oid;
}

const la_device*
la_svi_port_base::get_device() const
{
    return m_device.get();
}

la_l3_port_gid_t
la_svi_port_base::get_gid() const
{
    return m_gid;
}

la_status
la_svi_port_base::set_active(bool active)
{
    start_api_call("active=", active);
    la_status status = m_vrf_port_common->set_active(active);

    return status;
}

la_status
la_svi_port_base::get_active(bool& out_active) const
{
    return m_vrf_port_common->get_active(out_active);
}

la_status
la_svi_port_base::get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const
{
    la_status status = m_vrf_port_common->get_protocol_enabled(protocol, out_enabled);

    return status;
}

la_status
la_svi_port_base::set_protocol_enabled(la_l3_protocol_e protocol, bool enabled)
{
    start_api_call("protocol=", protocol, "enabled=", enabled);
    la_status status = m_vrf_port_common->set_protocol_enabled(protocol, enabled);

    return status;
}

la_status
la_svi_port_base::get_event_enabled(la_event_e event, bool& out_enabled) const
{
    la_status status = m_vrf_port_common->get_event_enabled(event, out_enabled);

    return status;
}

la_status
la_svi_port_base::set_event_enabled(la_event_e event, bool enabled)
{
    start_api_call("event=", event, "enabled=", enabled);
    la_status status = m_vrf_port_common->set_event_enabled(event, enabled);

    return status;
}

la_status
la_svi_port_base::get_urpf_mode(la_l3_port::urpf_mode_e& out_urpf_mode) const
{
    la_status status = m_vrf_port_common->get_urpf_mode(out_urpf_mode);

    return status;
}

la_status
la_svi_port_base::set_urpf_mode(la_l3_port::urpf_mode_e urpf_mode)
{
    start_api_call("urpf_mode=", urpf_mode);
    la_status status = m_vrf_port_common->set_urpf_mode(urpf_mode);

    return status;
}

la_status
la_svi_port_base::set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile)
{
    start_api_call("ingress_qos_profile=", ingress_qos_profile);

    la_status status = m_vrf_port_common->set_ingress_qos_profile(ingress_qos_profile);

    return status;
}

la_status
la_svi_port_base::get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const
{
    start_api_call("");

    la_status status = m_vrf_port_common->get_ingress_qos_profile(out_ingress_qos_profile);

    return status;
}

la_status
la_svi_port_base::set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile)
{
    start_api_call("egress_qos_profile=", egress_qos_profile);

    la_status status = m_vrf_port_common->set_egress_qos_profile(egress_qos_profile);

    return status;
}

la_status
la_svi_port_base::get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const
{
    start_api_call("");

    la_status status = m_vrf_port_common->get_egress_qos_profile(out_egress_qos_profile);

    return status;
}

la_status
la_svi_port_base::set_mac(const la_mac_addr_t& mac_addr)
{
    la_status status;
    start_api_call("mac_addr=", mac_addr);

    la_switch_gid_t sw_gid = 0;
    sw_gid = m_sw->get_gid();

    npl_mac_termination_em_table_key_t old_uc_key;
    status = m_vrf_port_common->get_mac_termination_table_key(sw_gid, old_uc_key);
    return_on_error(status);

    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice : slices) {
        slice_data& data(m_slice_data[slice]);

        const auto& uc_table(m_device->m_tables.mac_termination_em_table[slice]);
        const auto& uc_entry = data.mac_termination_em_table_entry;
        npl_mac_termination_em_table_value_t uc_value = uc_entry->value();
        npl_mac_termination_em_table_key_t uc_key;

        status = uc_table->erase(old_uc_key);
        return_on_error(status);

        // Add the new address to the MAC address manager
        status = m_vrf_port_common->set_mac(mac_addr);
        return_on_error(status);

        status = m_vrf_port_common->get_mac_termination_table_key(sw_gid, uc_key);
        return_on_error(status);

        // Enter default values - they will be updated later by the VRF common port
        status = uc_table->insert(uc_key, uc_value, m_slice_data[slice].mac_termination_em_table_entry);
        return_on_error(status);
    }

    m_mac_addr = mac_addr;
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_mac(la_mac_addr_t& out_mac_addr) const
{
    out_mac_addr = m_mac_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::add_virtual_mac_termination_table(la_slice_id_t slice, const la_mac_addr_t& mac_addr)
{
    if (m_sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_switch_gid_t sw_gid = m_sw->get_gid();

    const auto& uc_table(m_device->m_tables.mac_termination_em_table[slice]);
    slice_data& data(m_slice_data[slice]);
    const auto& uc_entry = data.mac_termination_em_table_entry;
    npl_mac_termination_em_table_value_t uc_value = uc_entry->value();

    uint64_t prefix;
    la_status status = m_device->m_mac_addr_manager->get_prefix(mac_addr, prefix);
    return_on_error(status);

    npl_mac_termination_em_table_key_t uc_key;
    fill_npl_mac_termination_em_table_key(sw_gid, mac_addr, prefix, uc_key);

    // Enter default values - they will be updated later by the VRF common port
    npl_mac_termination_em_table_entry_t* uc_vmac_entry = nullptr;
    status = uc_table->insert(uc_key, uc_value, uc_vmac_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::add_virtual_mac(const la_mac_addr_t& mac_addr)
{
    start_api_call("mac_addr=", mac_addr);

    if (m_sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    const auto& compare_mac_addr = [&mac_addr](const la_mac_addr_t& vec_mac_addr) { return mac_addr.flat == vec_mac_addr.flat; };
    auto mac_addr_entry_it = std::find_if(m_virtual_mac_addr.cbegin(), m_virtual_mac_addr.cend(), compare_mac_addr);
    if (mac_addr_entry_it != m_virtual_mac_addr.cend()) {
        return LA_STATUS_EEXIST;
    }

    la_status status = m_device->m_mac_addr_manager->add(mac_addr, NPL_MAC_DA_TYPE_UC);
    return_on_error(status);

    auto slices = m_sw->get_slices();

    for (la_slice_id_t slice : slices) {
        status = add_virtual_mac_termination_table(slice, mac_addr);
        return_on_error(status);
    }

    m_virtual_mac_addr.push_back(mac_addr);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::remove_virtual_mac_termination_table(la_slice_id_t slice, const la_mac_addr_t& mac_addr)
{
    if (m_sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_switch_gid_t sw_gid = m_sw->get_gid();

    const auto& uc_table(m_device->m_tables.mac_termination_em_table[slice]);
    npl_mac_termination_em_table_key_t uc_key;

    uint64_t prefix;
    la_status status = m_device->m_mac_addr_manager->get_prefix(mac_addr, prefix);
    return_on_error(status);

    fill_npl_mac_termination_em_table_key(sw_gid, mac_addr, prefix, uc_key);

    status = uc_table->erase(uc_key);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::remove_virtual_mac(const la_mac_addr_t& mac_addr)
{
    start_api_call("mac_addr=", mac_addr);

    if (m_sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    const auto& compare_mac_addr = [&mac_addr](const la_mac_addr_t& vec_mac_addr) { return mac_addr.flat == vec_mac_addr.flat; };
    auto mac_addr_entry_it = std::find_if(m_virtual_mac_addr.cbegin(), m_virtual_mac_addr.cend(), compare_mac_addr);
    if (mac_addr_entry_it == m_virtual_mac_addr.cend()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto slices = m_sw->get_slices();

    for (la_slice_id_t slice : slices) {
        la_status status = remove_virtual_mac_termination_table(slice, mac_addr);
        return_on_error(status);
    }

    la_status status = m_device->m_mac_addr_manager->remove(mac_addr, NPL_MAC_DA_TYPE_UC);
    return_on_error(status);

    m_virtual_mac_addr.erase(mac_addr_entry_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_virtual_macs(la_mac_addr_vec& out_mac_addresses) const
{
    start_api_getter_call();

    out_mac_addresses = m_virtual_mac_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2)
{
    start_api_call("egress tag1=", tag1, "egress tag2=", tag2);

    /* due to current NPL data plane limitation below, double tag on SVI in
       L3 mode is not supported. It will be supported in future once
       NPL data plane limitation is removed.
       NPL data plane limitation: The 2nd tag is configured via
       reusing recycle vid2 in l3 dlp. However, recycle vid2 is also
       used for recycle purpose in SVI case.
    */
    if (!is_vlan_tag_eq(tag1, LA_VLAN_TAG_UNTAGGED) && !is_vlan_tag_eq(tag2, LA_VLAN_TAG_UNTAGGED)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

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
la_svi_port_base::get_switch(const la_switch*& out_sw) const
{
    out_sw = m_sw.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_vrf(const la_vrf*& out_vrf) const
{
    out_vrf = m_vrf.get();

    return LA_STATUS_SUCCESS;
}

slice_ifg_vec_t
la_svi_port_base::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_status
la_svi_port_base::add_ipv4_subnet(la_ipv4_prefix_t subnet)
{
    start_api_call("subnet=", subnet);
    la_status status = m_vrf_port_common->add_ipv4_subnet(subnet);

    return status;
}

la_status
la_svi_port_base::delete_ipv4_subnet(la_ipv4_prefix_t subnet)
{
    start_api_call("subnet=", subnet);
    la_status status = m_vrf_port_common->delete_ipv4_subnet(subnet);

    return status;
}

la_status
la_svi_port_base::get_ipv4_subnets(la_ipv4_prefix_vec_t& out_subnets) const
{
    la_status status = m_vrf_port_common->get_ipv4_subnets(out_subnets);

    return status;
}

la_status
la_svi_port_base::add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr);
    la_status status = m_vrf_port_common->add_ipv4_host(ip_addr, mac_addr);
    return_on_error(status);
    status = add_mac_move_ipv4_host(mac_addr, ip_addr, LA_CLASS_ID_DEFAULT);
    return status;
}

la_status
la_svi_port_base::modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr);
    la_status status = delete_mac_move_ipv4_host(ip_addr);
    return_on_error(status);
    status = m_vrf_port_common->modify_ipv4_host(ip_addr, mac_addr);
    return_on_error(status);
    status = add_mac_move_ipv4_host(mac_addr, ip_addr, LA_CLASS_ID_DEFAULT);
    return status;
}

la_status
la_svi_port_base::add_ipv4_host_with_class_id(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    la_status status = m_vrf_port_common->add_ipv4_host(ip_addr, mac_addr, class_id);
    return_on_error(status);
    status = add_mac_move_ipv4_host(mac_addr, ip_addr, class_id);
    return status;
}

la_status
la_svi_port_base::modify_ipv4_host_with_class_id(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    la_status status = delete_mac_move_ipv4_host(ip_addr);
    return_on_error(status);
    status = m_vrf_port_common->modify_ipv4_host(ip_addr, mac_addr, class_id);
    return_on_error(status);
    status = add_mac_move_ipv4_host(mac_addr, ip_addr, class_id);
    return status;
}

la_status
la_svi_port_base::delete_ipv4_host(la_ipv4_addr_t ip_addr)
{
    start_api_call("ip_addr=", ip_addr);
    la_status status = delete_mac_move_ipv4_host(ip_addr);
    return_on_error(status);
    status = m_vrf_port_common->delete_ipv4_host(ip_addr);

    return status;
}

la_status
la_svi_port_base::get_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const
{
    la_status status = m_vrf_port_common->get_ipv4_host(ip_addr, out_mac_addr);

    return status;
}

la_status
la_svi_port_base::get_ipv4_host_and_class_id(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr, la_class_id_t& out_class_id) const
{
    start_api_getter_call();
    la_status status = m_vrf_port_common->get_ipv4_host(ip_addr, out_mac_addr, out_class_id);

    return status;
}

la_status
la_svi_port_base::get_ipv4_hosts(la_mac_addr_vec& out_mac_addresses) const
{
    la_status status = m_vrf_port_common->get_ipv4_hosts(out_mac_addresses);

    return status;
}

la_status
la_svi_port_base::get_ipv4_hosts(la_ipv4_addr_vec& out_ip_addresses) const
{
    la_status status = m_vrf_port_common->get_ipv4_hosts(out_ip_addresses);

    return status;
}

la_status
la_svi_port_base::add_ipv6_subnet(la_ipv6_prefix_t subnet)
{
    start_api_call("subnet=", subnet);
    la_status status = m_vrf_port_common->add_ipv6_subnet(subnet);

    return status;
}

la_status
la_svi_port_base::get_ipv6_subnets(la_ipv6_prefix_vec_t& out_subnets) const
{
    la_status status = m_vrf_port_common->get_ipv6_subnets(out_subnets);

    return status;
}

la_status
la_svi_port_base::delete_ipv6_subnet(la_ipv6_prefix_t subnet)
{
    start_api_call("subnet=", subnet);
    la_status status = m_vrf_port_common->delete_ipv6_subnet(subnet);

    return status;
}

la_status
la_svi_port_base::add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr);
    la_status status = m_vrf_port_common->add_ipv6_host(ip_addr, mac_addr);
    return_on_error(status);
    status = add_mac_move_ipv6_host(mac_addr, ip_addr, LA_CLASS_ID_DEFAULT);
    return status;
}

la_status
la_svi_port_base::modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr);
    la_status status = delete_mac_move_ipv6_host(ip_addr);
    return_on_error(status);
    status = m_vrf_port_common->modify_ipv6_host(ip_addr, mac_addr);
    return_on_error(status);
    status = add_mac_move_ipv6_host(mac_addr, ip_addr, LA_CLASS_ID_DEFAULT);
    return status;
}

la_status
la_svi_port_base::add_ipv6_host_with_class_id(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    la_status status = m_vrf_port_common->add_ipv6_host(ip_addr, mac_addr, class_id);
    return_on_error(status);
    status = add_mac_move_ipv6_host(mac_addr, ip_addr, class_id);
    return status;
}

la_status
la_svi_port_base::modify_ipv6_host_with_class_id(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    la_status status = delete_mac_move_ipv6_host(ip_addr);
    return_on_error(status);
    status = m_vrf_port_common->modify_ipv6_host(ip_addr, mac_addr, class_id);
    return_on_error(status);
    status = add_mac_move_ipv6_host(mac_addr, ip_addr, class_id);
    return status;
}

la_status
la_svi_port_base::delete_ipv6_host(la_ipv6_addr_t ip_addr)
{
    start_api_call("ip_addr=", ip_addr);
    la_status status = delete_mac_move_ipv6_host(ip_addr);
    return_on_error(status);
    status = m_vrf_port_common->delete_ipv6_host(ip_addr);

    return status;
}

la_status
la_svi_port_base::get_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const
{
    la_status status = m_vrf_port_common->get_ipv6_host(ip_addr, out_mac_addr);

    return status;
}

la_status
la_svi_port_base::get_ipv6_host_and_class_id(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_addr, la_class_id_t& out_class_id) const
{
    start_api_getter_call();
    la_status status = m_vrf_port_common->get_ipv6_host(ip_addr, out_mac_addr, out_class_id);

    return status;
}

la_status
la_svi_port_base::get_ipv6_hosts(la_mac_addr_vec& out_mac_addresses) const
{
    la_status status = m_vrf_port_common->get_ipv6_hosts(out_mac_addresses);

    return status;
}

la_status
la_svi_port_base::get_ipv6_hosts(la_ipv6_addr_vec& out_ip_addresses) const
{
    la_status status = m_vrf_port_common->get_ipv6_hosts(out_ip_addresses);

    return status;
}

la_status
la_svi_port_base::set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group)
{
    start_api_call("dir=", dir, "acl_group=", acl_group);
    return m_vrf_port_common->set_acl_group(dir, acl_group);
}

la_status
la_svi_port_base::get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const
{
    start_api_getter_call("dir=", dir);
    return m_vrf_port_common->get_acl_group(dir, out_acl_group);
}

la_status
la_svi_port_base::clear_acl_group(la_acl_direction_e dir)
{
    start_api_call("dir=", dir);
    return m_vrf_port_common->clear_acl_group(dir);
}

la_status
la_svi_port_base::set_pbr_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    return m_vrf_port_common->set_pbr_enabled(enabled);
}

la_status
la_svi_port_base::get_pbr_enabled(bool& out_enabled) const
{
    start_api_getter_call("");
    return m_vrf_port_common->get_pbr_enabled(out_enabled);
}

la_status
la_svi_port_base::set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    start_api_call("mirror_cmd=", mirror_cmd, "is_acl_conditioned=", is_acl_conditioned);
    return m_vrf_port_common->set_ingress_mirror_command(mirror_cmd, is_acl_conditioned);
}

la_status
la_svi_port_base::get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    start_api_getter_call("");
    return m_vrf_port_common->get_ingress_mirror_command(out_mirror_cmd, out_is_acl_conditioned);
}

la_status
la_svi_port_base::set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    start_api_call("mirror_cmd=", mirror_cmd, "is_acl_conditioned=", is_acl_conditioned);
    return m_vrf_port_common->set_egress_mirror_command(mirror_cmd, is_acl_conditioned);
}

la_status
la_svi_port_base::get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    start_api_getter_call("");
    return m_vrf_port_common->get_egress_mirror_command(out_mirror_cmd, out_is_acl_conditioned);
}

la_status
la_svi_port_base::update_fallback_vrf()
{
    return m_vrf_port_common->update_fallback_vrf();
}

la_status
la_svi_port_base::update_no_da_termination_table_entry(la_slice_id_t slice, const npl_base_l3_lp_attributes_t& attribs)
{
    la_status status;
    const auto& table(m_device->m_tables.mac_termination_no_da_em_table[slice]);
    npl_mac_termination_no_da_em_table_key_t key;
    npl_mac_termination_no_da_em_table_entry_t* dummy_entry;
    npl_mac_termination_no_da_em_table_value_t value;
    npl_base_l3_lp_attributes_t& termination_attributes(value.payloads.termination_attributes.base);

    key.service_relay_attributes_table_key.id = m_sw->get_gid();
    termination_attributes = attribs;
    status = table->set(key, value, dummy_entry);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::remove_no_da_termination_table_entry(la_slice_id_t slice)
{
    la_status status;
    const auto& table(m_device->m_tables.mac_termination_no_da_em_table[slice]);
    npl_mac_termination_no_da_em_table_key_t key;

    key.service_relay_attributes_table_key.id = m_sw->get_gid();
    status = table->erase(key);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_l3_lp_qos_and_attributes(la_slice_pair_id_t pair_idx, npl_l3_dlp_qos_and_attributes_t& attrib) const
{
    la_status status = m_vrf_port_common->get_l3_lp_qos_and_attributes(pair_idx, attrib);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::update_virtual_mac_payload(la_slice_id_t slice, const npl_base_l3_lp_attributes_t& attribs)
{
    if (m_sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_switch_gid_t sw_gid = m_sw->get_gid();
    const auto& uc_table(m_device->m_tables.mac_termination_em_table[slice]);

    for (auto& mac_addr : m_virtual_mac_addr) {
        uint64_t prefix;
        la_status status = m_device->m_mac_addr_manager->get_prefix(mac_addr, prefix);
        return_on_error(status);

        npl_mac_termination_em_table_key_t uc_key;
        fill_npl_mac_termination_em_table_key(sw_gid, mac_addr, prefix, uc_key);

        npl_mac_termination_em_table_entry_t* uc_entry = nullptr;
        status = uc_table->lookup(uc_key, uc_entry);
        return_on_error(status);

        npl_mac_termination_em_table_value_t uc_value = uc_entry->value();
        npl_base_l3_lp_attributes_t& uc_termination_attributes(uc_value.payloads.termination_attributes.base);
        uc_termination_attributes = attribs;

        status = uc_table->set_entry_value(uc_entry, uc_value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::update_l3_lp_attributes(la_slice_id_t slice,
                                          const npl_base_l3_lp_attributes_t& attribs,
                                          const npl_l3_lp_additional_attributes_t& additional_attribs)
{
    slice_data& data(m_slice_data[slice]);

    // Unicast
    const auto& uc_table(m_device->m_tables.mac_termination_em_table[slice]);
    const auto& uc_entry = data.mac_termination_em_table_entry;
    npl_mac_termination_em_table_value_t uc_value = uc_entry->value();
    npl_base_l3_lp_attributes_t& uc_termination_attributes(uc_value.payloads.termination_attributes.base);

    uc_termination_attributes = attribs;

    la_status status = uc_table->set_entry_value(uc_entry, uc_value);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD,
                "la_svi_port_base::update_l3_lp_attributes(UC): mac_termination_em_table[%d].set_entry_value failed, status = %s",
                slice,
                la_status2str(status).c_str());
        return status;
    }

    // Unicast - Update virtual MAC payload with interface MAC payload.
    status = update_virtual_mac_payload(slice, attribs);
    return_on_error(status);

    if (m_sw->get_decap_vni_profile() == la_switch::vxlan_termination_mode_e::IGNORE_DMAC) {
        status = update_no_da_termination_table_entry(slice, attribs);
        return_on_error(status);
    }

    // Multicast
    const auto& mc_table(m_device->m_tables.mac_mc_em_termination_attributes_table[slice]);
    const auto& mc_entry = data.mac_termination_mc_table_entry;
    npl_mac_mc_em_termination_attributes_table_value_t mc_value = mc_entry->value();
    npl_base_l3_lp_attributes_t& mc_termination_attributes(mc_value.payloads.termination_attributes.base);

    mc_termination_attributes = attribs;

    status = mc_table->set_entry_value(mc_entry, mc_value);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD,
                "la_svi_port_base::update_l3_lp_attributes(IPv4MC): mac_mc_em_termination_attributes_table[%d].set_entry_value "
                "failed, status = %s",
                slice,
                la_status2str(status).c_str());
        return status;
    }

    // Place additional_attributes
    status = update_additional_l3_lp_attributes(additional_attribs);

    return status;
}

la_status
la_svi_port_base::init_virtual_mac_termination_table(la_slice_id_t slice)
{
    for (auto& mac_addr : m_virtual_mac_addr) {
        la_status status = add_virtual_mac_termination_table(slice, mac_addr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::init_mac_termination_table(la_slice_id_t slice)
{
    la_status status = LA_STATUS_EUNKNOWN;

    la_switch_gid_t sw_gid = 0;
    sw_gid = m_sw->get_gid();

    // Unicast

    const auto& uc_table(m_device->m_tables.mac_termination_em_table[slice]);
    npl_mac_termination_em_table_key_t uc_key;
    npl_mac_termination_em_table_value_t uc_value;

    status = m_vrf_port_common->get_mac_termination_table_key(sw_gid, uc_key);
    return_on_error(status);

    // Enter default values - they will be updated later by the VRF common port
    status = uc_table->insert(uc_key, uc_value, m_slice_data[slice].mac_termination_em_table_entry);
    return_on_error(status);

    // Add virtual mac entries in EM termination table.
    status = init_virtual_mac_termination_table(slice);
    return_on_error(status);

    // Multicast

    const auto& mc_table(m_device->m_tables.mac_mc_em_termination_attributes_table[slice]);
    npl_mac_mc_em_termination_attributes_table_key_t mc_key;
    npl_mac_mc_em_termination_attributes_table_value_t mc_value;

    mc_key.l2_relay_attributes_id = sw_gid;

    // Enter default values - they will be updated later by the VRF common port
    // TODO - use insert instead of set
    status = mc_table->set(mc_key, mc_value, m_slice_data[slice].mac_termination_mc_table_entry);
    return_on_error(status);

    if (m_sw->get_decap_vni_profile() == la_switch::vxlan_termination_mode_e::IGNORE_DMAC) {
        status = update_no_da_termination_table_entry(slice);
        return_on_error(status);
    }

    return status;
}

la_status
la_svi_port_base::teardown_virtual_mac_termination_table(la_slice_id_t slice)
{
    for (auto& mac_addr : m_virtual_mac_addr) {
        la_status status = remove_virtual_mac_termination_table(slice, mac_addr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::teardown_mac_termination_table(la_slice_id_t slice)
{
    la_switch_gid_t sw_gid = 0;
    if (m_sw != nullptr) {
        sw_gid = m_sw->get_gid();
    }

    // Unicast
    const auto& uc_table(m_device->m_tables.mac_termination_em_table[slice]);
    npl_mac_termination_em_table_key_t uc_key;
    slice_data& data(m_slice_data[slice]);

    la_status status = m_vrf_port_common->get_mac_termination_table_key(sw_gid, uc_key);
    return_on_error(status);

    status = uc_table->erase(uc_key);
    return_on_error(status);

    if (m_sw->get_decap_vni_profile() == la_switch::vxlan_termination_mode_e::IGNORE_DMAC) {
        status = remove_no_da_termination_table_entry(slice);
        return_on_error(status);
    }

    data.mac_termination_em_table_entry = nullptr;

    // Remove virtual mac entries from EM termination table.
    status = teardown_virtual_mac_termination_table(slice);
    return_on_error(status);

    // Multicast
    const auto& mc_table(m_device->m_tables.mac_mc_em_termination_attributes_table[slice]);
    const auto& mc_entry = m_slice_data[slice].mac_termination_mc_table_entry;
    status = mc_table->erase(mc_entry->key());
    return_on_error(status);

    m_slice_data[slice].mac_termination_mc_table_entry = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode)
{
    return m_vrf_port_common->set_ttl_inheritance_mode(mode);
}

la_mpls_ttl_inheritance_mode_e
la_svi_port_base::get_ttl_inheritance_mode() const
{
    return m_vrf_port_common->get_ttl_inheritance_mode();
}

la_status
la_svi_port_base::set_qos_inheritance_mode(la_mpls_qos_inheritance_mode_e mode)
{
    start_api_call("mode=", mode);
    return m_vrf_port_common->set_qos_inheritance_mode(mode);
}

la_mpls_qos_inheritance_mode_e
la_svi_port_base::get_qos_inheritance_mode() const
{
    return m_vrf_port_common->get_qos_inheritance_mode();
}

la_status
la_svi_port_base::set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter)
{
    start_api_call("type=", type, "counter=", counter);
    return m_vrf_port_common->set_ingress_counter(type, counter);
}

la_status
la_svi_port_base::get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const
{
    return m_vrf_port_common->get_ingress_counter(type, out_counter);
}

la_status
la_svi_port_base::set_egress_counter(la_counter_set::type_e type, la_counter_set* counter)
{
    start_api_call("type=", type, "counter=", counter);
    return m_vrf_port_common->set_egress_counter(type, counter);
}

la_status
la_svi_port_base::get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const
{
    return m_vrf_port_common->get_egress_counter(type, out_counter);
}

la_status
la_svi_port_base::get_egress_vlan_tag(la_vlan_tag_t& out_tag1, la_vlan_tag_t& out_tag2) const
{
    return m_vrf_port_common->get_egress_vlan_tag(out_tag1, out_tag2);
}

la_status
la_svi_port_base::set_meter(const la_meter_set* meter)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_svi_port_base::get_meter(const la_meter_set*& out_meter) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_svi_port_base::set_source_based_forwarding(const la_l3_destination* l3_destination, bool label_present, la_mpls_label label)
{
    start_api_call("l3_destination=", l3_destination, "label_present=", label_present, "label=", label);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_svi_port_base::clear_source_based_forwarding()
{
    start_api_call("");

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_svi_port_base::get_source_based_forwarding(const la_l3_destination*& out_l3_destination,
                                              bool& out_label_present,
                                              la_mpls_label& out_label) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_svi_port_base::get_load_balancing_profile(la_l3_port::lb_profile_e& out_lb_profile) const
{
    start_api_getter_call();

    return m_vrf_port_common->get_load_balancing_profile(out_lb_profile);
}

la_status
la_svi_port_base::set_load_balancing_profile(la_l3_port::lb_profile_e lb_profile)
{
    start_api_call("lb_profile=", lb_profile);

    return m_vrf_port_common->set_load_balancing_profile(lb_profile);
}

la_status
la_svi_port_base::set_drop_counter_offset(la_stage_e stage, size_t offset)
{
    start_api_call("stage=", stage, "offset=", offset);

    return m_vrf_port_common->set_drop_counter_offset(stage, offset);
}

la_status
la_svi_port_base::get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const
{
    start_api_getter_call("stage=", stage);

    return m_vrf_port_common->get_drop_counter_offset(stage, out_offset);
}

la_status
la_svi_port_base::add_mac_move_nh(la_mac_addr_t mac_addr, la_next_hop_base* nh)
{
    auto nh_sptr = m_device->get_sptr(nh);
    m_mac_move_map[mac_addr].nhs.insert(nh_sptr);
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::delete_mac_move_nh(la_mac_addr_t nh_mac, la_next_hop_base* nh)
{
    auto it = m_mac_move_map.find(nh_mac);
    if (it != m_mac_move_map.end()) {
        auto nh_sptr = m_device->get_sptr(nh);
        it->second.nhs.erase(nh_sptr);
    } else {
        return LA_STATUS_ENOTFOUND;
    }
    if (it->second.empty()) {
        m_mac_move_map.erase(nh_mac);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::add_mac_move_ipv4_host(la_mac_addr_t mac_addr, la_ipv4_addr_t ipv4_host, la_class_id_t class_id)
{
    m_mac_move_map[mac_addr].ipv4_hosts.emplace(ipv4_host, class_id);
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::delete_mac_move_ipv4_host(la_ipv4_addr_t ipv4_host)
{
    la_mac_addr_t mac_addr;
    la_status status = get_ipv4_host(ipv4_host, mac_addr);
    return_on_error(status);

    auto it = m_mac_move_map.find(mac_addr);
    if (it != m_mac_move_map.end()) {
        la_ipv4_hosts_t ip_host(ipv4_host, LA_CLASS_ID_DEFAULT);
        it->second.ipv4_hosts.erase(ip_host);
    } else {
        return LA_STATUS_ENOTFOUND;
    }
    if (it->second.empty()) {
        m_mac_move_map.erase(mac_addr);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::add_mac_move_ipv6_host(la_mac_addr_t mac_addr, la_ipv6_addr_t ipv6_host, la_class_id_t class_id)
{
    m_mac_move_map[mac_addr].ipv6_hosts.emplace(ipv6_host, class_id);
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::delete_mac_move_ipv6_host(la_ipv6_addr_t ipv6_host)
{
    la_mac_addr_t mac_addr;
    la_status status = get_ipv6_host(ipv6_host, mac_addr);
    return_on_error(status);

    auto it = m_mac_move_map.find(mac_addr);
    if (it != m_mac_move_map.end()) {
        la_ipv6_hosts_t ip_host(ipv6_host, LA_CLASS_ID_DEFAULT);
        it->second.ipv6_hosts.erase(ip_host);
    } else {
        return LA_STATUS_ENOTFOUND;
    }
    if (it->second.empty()) {
        m_mac_move_map.erase(mac_addr);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::process_mac_move_notification(la_mac_addr_t mac_addr)
{
    auto entry = m_mac_move_map.find(mac_addr);
    la_status status = LA_STATUS_SUCCESS;
    if (entry == m_mac_move_map.end()) {
        return LA_STATUS_SUCCESS;
    }
    auto& nhs_hosts = entry->second;
    for (auto host : nhs_hosts.ipv4_hosts) {
        if (host.class_id == LA_CLASS_ID_DEFAULT) {
            status = m_vrf_port_common->modify_ipv4_host(host.host, mac_addr);
            return_on_error(status);
        } else {
            status = m_vrf_port_common->modify_ipv4_host(host.host, mac_addr, host.class_id);
            return_on_error(status);
        }
    }
    for (auto host : nhs_hosts.ipv6_hosts) {
        if (host.class_id == LA_CLASS_ID_DEFAULT) {
            status = m_vrf_port_common->modify_ipv6_host(host.host, mac_addr);
            return_on_error(status);
        } else {
            status = m_vrf_port_common->modify_ipv6_host(host.host, mac_addr, host.class_id);
            return_on_error(status);
        }
    }
    for (auto nh : nhs_hosts.nhs) {
        status = nh->modify_mac_move_dsp_or_dspa();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_ingress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    la_status status = m_vrf_port_common->set_ingress_sflow_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_ingress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();
    la_status status = m_vrf_port_common->get_ingress_sflow_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_egress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    la_status status = m_vrf_port_common->set_egress_sflow_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_csc_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status = m_vrf_port_common->set_csc_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_csc_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_csc_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_egress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();
    la_status status = m_vrf_port_common->get_egress_sflow_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::update_no_da_termination_table_entry(la_slice_id_t slice)
{
    slice_data& data(m_slice_data[slice]);
    const auto& uc_entry = data.mac_termination_em_table_entry;
    npl_mac_termination_em_table_value_t uc_value = uc_entry->value();
    npl_base_l3_lp_attributes_t& uc_termination_attributes(uc_value.payloads.termination_attributes.base);

    la_status status = update_no_da_termination_table_entry(slice, uc_termination_attributes);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_rcy_sm_vlans(la_vlan_id_t vid1, la_vlan_id_t vid2)
{
    m_rcy_sm_vid1 = vid1;
    m_rcy_sm_vid2 = vid2;
    la_status status = m_vrf_port_common->set_rcy_sm_vlans(vid1, vid2);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_rcy_sm_vlans(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2)
{
    out_vid1 = m_rcy_sm_vid1;
    out_vid2 = m_rcy_sm_vid2;
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_inject_up_source_port(la_l2_service_port* inject_up_source_port)
{
    start_api_call("inject_up_source_port=", inject_up_source_port);

    if (m_inject_up_port != nullptr) {
        log_err(HLD, "inject-up already configured for the switch");
        return LA_STATUS_EEXIST;
    }

    if (inject_up_source_port == nullptr) {
        log_err(HLD, "invalid input argument");
        return LA_STATUS_EINVAL;
    }

    auto l2_port_sptr = m_device->get_sptr<la_l2_service_port_base>(inject_up_source_port);

    la_status status = validate_and_set_rcy_sm_vlans(l2_port_sptr);
    return_on_error(status);

    status = populate_recycled_inject_up_info_table(l2_port_sptr);
    return_on_error(status);

    status = l2_port_sptr->populate_inject_up_port_parameters();
    return_on_error(status);

    m_inject_up_port = l2_port_sptr;
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::update_no_da_termination_table_entry()
{
    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_status status = update_no_da_termination_table_entry(slice);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_inject_up_source_port(la_l2_service_port*& out_inject_up_source_port) const
{
    start_api_getter_call();
    if (m_inject_up_port == nullptr) {
        log_err(HLD, "inject_up_source_port is not set for switch 0x%x", get_gid());
        return LA_STATUS_EINVAL;
    }
    out_inject_up_source_port = m_inject_up_port.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::remove_no_da_termination_table_entry()
{
    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_status status = remove_no_da_termination_table_entry(slice);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

int
la_svi_port_base::get_vxlan_shared_overlay_nh_count()
{
    return m_vxlan_shared_overlay_nh_count;
}

void
la_svi_port_base::update_vxlan_shared_overlay_nh_count(int delta)
{
    m_vxlan_shared_overlay_nh_count += delta;
}

la_mac_addr_t
la_svi_port_base::get_vxlan_shared_overlay_nh_mac()
{
    return m_vxlan_shared_overlay_nh_mac;
}

void
la_svi_port_base::set_vxlan_shared_overlay_nh_mac(la_mac_addr_t nh_mac)
{
    m_vxlan_shared_overlay_nh_mac = nh_mac;
}

la_status
la_svi_port_base::validate_and_set_rcy_sm_vlans(const la_l2_service_port_base_wptr& inject_up_port)
{
    la_vlan_id_t l2_vid1, l2_vid2;
    const la_switch* l2_sw = nullptr;

    inject_up_port->get_attached_switch(l2_sw);
    if (m_sw->get_gid() != l2_sw->get_gid()) {
        log_err(HLD, "inject-up source port and svi are not attached to same switch");
        return LA_STATUS_EINVAL;
    }

    inject_up_port->get_service_mapping_vids(l2_vid1, l2_vid2);
    if ((l2_vid1 == LA_VLAN_ID_INVALID) || (l2_vid2 == LA_VLAN_ID_INVALID)) {
        log_err(HLD, "invalid inject-up port service mapping vlans for SVI 0x%x", get_gid());
        return LA_STATUS_EINVAL;
    }

    set_rcy_sm_vlans(l2_vid1, l2_vid2);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_inject_up_source_port_dsp(la_l2_port_gid_t& out_npp_gid) const
{
    if (m_inject_up_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    const la_system_port* sp = m_inject_up_port->get_ethernet_port()->get_system_port();
    out_npp_gid = (NPL_DESTINATION_MASK_DSP | sp->get_gid());
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_inject_up_source_port_gid(la_l2_port_gid_t& out_port_gid) const
{
    if (m_inject_up_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    out_port_gid = (NPL_DESTINATION_MASK_L2_DLP | m_inject_up_port->get_gid());
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_vrf(const la_vrf* vrf)
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

    m_vrf = m_device->get_sptr<const la_vrf_impl>(vrf);
    la_status status = m_vrf_port_common->set_vrf(m_vrf);
    return_on_error(status);

    register_vrf_dependency(m_vrf);

    return LA_STATUS_SUCCESS;
}

void
la_svi_port_base::register_vrf_dependency(const la_vrf_impl_wcptr& vrf)
{
    m_device->add_object_dependency(vrf, this);
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::VRF_FALLBACK_CHANGED);
    m_device->add_attribute_dependency(vrf, this, registered_attributes);
}

void
la_svi_port_base::deregister_vrf_dependency(const la_vrf_impl_wcptr& vrf)
{
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::VRF_FALLBACK_CHANGED);
    m_device->remove_attribute_dependency(vrf, this, registered_attributes);
    m_device->remove_object_dependency(vrf, this);
}

la_status
la_svi_port_base::set_egress_dhcp_snooping_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status = m_vrf_port_common->set_egress_dhcp_snooping_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_egress_dhcp_snooping_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_egress_dhcp_snooping_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::get_filter_group(const la_filter_group*& out_filter_group) const
{
    start_api_call("");

    out_filter_group = m_filter_group.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_base::set_filter_group(la_filter_group* filter_group)
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

} // namespace silicon_one
