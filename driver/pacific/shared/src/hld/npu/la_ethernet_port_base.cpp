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

#include "la_ethernet_port_base.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_switch_impl.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "system/la_system_port_base.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_ethernet_port_base::la_ethernet_port_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_id(LA_L2_PORT_GID_INVALID),
      m_port_type(port_type_e::SIMPLE),
      m_copc_profile(0),
      m_transparent_ptp_enabled(false),
      m_traffic_matrix_type(traffic_matrix_type_e::INTERNAL),
      m_mtu(LA_MTU_MAX),
      m_svi_egress_tag_mode(svi_egress_tag_mode_e::KEEP),
      m_service_mapping_type(service_mapping_type_e::LARGE),
      m_port_vid(LA_VLAN_ID_INVALID),
      m_default_pcpdei(la_vlan_pcpdei()),
      m_decrement_ttl(true),
      m_security_group_tag(0),
      m_security_group_policy_enforcement(false)
{
}

la_ethernet_port_base::~la_ethernet_port_base()
{
}

la_status
la_ethernet_port_base::initialize(la_object_id_t oid, la_system_port_base* system_port, la_l2_port_gid_t port_gid, port_type_e type)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    if (system_port->has_port_dependency()) {
        return LA_STATUS_EBUSY;
    }

    m_system_port = m_device->get_sptr(system_port);
    m_id = port_gid;
    m_port_type = type;
    la_system_port_base::port_type_e sys_port_type = system_port->get_port_type();

    bool instantiate_remotes = false;
    la_status status = m_device->get_bool_property(la_device_property_e::INSTANTIATE_REMOTE_SYSTEM_PORTS, instantiate_remotes);
    return_on_error(status);

    bool svl_mode = false;
    status = m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    return_on_error(status);

    instantiate_remotes |= svl_mode;

    if (sys_port_type != la_system_port_base::port_type_e::REMOTE || instantiate_remotes) {
        la_slice_ifg ifg = {.slice = m_system_port->get_slice(), .ifg = m_system_port->get_ifg()};

        if (ifg.slice != LA_SLICE_ID_INVALID) {
            la_status status = add_ifg(ifg);
            return_on_error(status);
        }

        la_status status = initialize_common();
        return_on_error(status);

        m_device->add_ifg_dependency(system_port, this);
    }

    m_device->add_object_dependency(system_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::initialize(la_object_id_t oid, la_spa_port_base* spa_port, la_l2_port_gid_t port_gid, port_type_e type)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    m_spa_port = m_device->get_sptr(spa_port);
    m_id = port_gid;
    m_port_type = type;

    vector<la_slice_ifg> ifgs = spa_port->get_ifgs();
    for (la_slice_ifg ifg : ifgs) {
        la_status status = add_ifg(ifg);

        return_on_error(status);
    }

    la_status status = initialize_common();
    return_on_error(status);

    m_device->add_ifg_dependency(m_spa_port, this);
    m_device->add_object_dependency(m_spa_port, this);
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::SPA_MEMBERSHIP_CHANGED);
    m_device->add_attribute_dependency(m_spa_port, this, registered_attributes);

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::initialize_common()
{
    la_status status = update_npp_attributes();
    return_on_error(status);

    status = set_source_pif_entry(nullptr);
    return_on_error(status);

    status = set_inject_up_entry(nullptr);
    return_on_error(status);

    status = do_set_mtu();
    return_on_error(status);

    status = configure_security_group_policy_attributes();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::destroy_common()
{
    la_status status = erase_inject_up_entry();
    return_on_error(status);

    status = erase_source_pif_entry();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_mtu_t
la_ethernet_port_base::get_mtu() const
{
    start_api_getter_call();

    return (m_mtu);
}

la_status
la_ethernet_port_base::set_mtu(la_mtu_t mtu)
{
    start_api_call("mtu=", mtu);

    if ((mtu > LA_MTU_MAX) || (mtu < LA_MTU_MIN)) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_mtu == mtu) {
        return LA_STATUS_SUCCESS;
    }

    m_mtu = mtu;

    return do_set_mtu();
}

la_status
la_ethernet_port_base::set_service_mapping_type(service_mapping_type_e type)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::destroy()
{
    if (m_system_port != nullptr) {
        m_device->remove_object_dependency(m_system_port, this);
        m_device->remove_ifg_dependency(m_system_port, this);
    }

    if (m_spa_port != nullptr) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::SPA_MEMBERSHIP_CHANGED);
        m_device->remove_attribute_dependency(m_spa_port, this, registered_attributes);
        m_device->remove_object_dependency(m_spa_port, this);
        m_device->remove_ifg_dependency(m_spa_port, this);
    }

    if (m_ac_profile != nullptr) {
        m_device->remove_object_dependency(m_ac_profile, this);
    }

    if (m_system_port != nullptr) {
        la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();

        if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
            // TODO - destroy_common();
        }
    }

    // TODO - cleanup SPA port

    slice_ifg_vec_t enabled_ifgs = m_ifg_use_count->get_ifgs();
    for (auto ifg : enabled_ifgs) {
        la_status status = remove_ifg(ifg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        if (op.action.attribute_management.op == attribute_management_op::SPA_MEMBERSHIP_CHANGED) {
            la_system_port_base* system_port_base = const_cast<la_system_port_base*>(
                static_cast<const la_system_port_base*>(op.action.attribute_management.spa.sys_port));
            la_system_port_base::port_type_e sys_port_type = system_port_base->get_port_type();
            if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
                if (op.action.attribute_management.spa.is_added == true) {
                    // Set security group policy attributes
                    la_status status;
                    status = system_port_base->update_npp_sgt_attributes(m_security_group_tag);
                    return_on_error(status);
                    status = system_port_base->update_dsp_sgt_attributes(m_security_group_policy_enforcement);
                    return_on_error(status);
                    return set_inject_up_entry(system_port_base, m_ac_profile.get());
                } else {
                    // Reset security group policy attributes
                    la_status status;
                    status = system_port_base->update_npp_sgt_attributes(0);
                    return_on_error(status);
                    status = system_port_base->update_dsp_sgt_attributes(false);
                    return_on_error(status);
                    return erase_inject_up_entry(system_port_base);
                }
            } else {
                return LA_STATUS_SUCCESS;
            }
        }
    }
    log_err(HLD,
            "la_ethernet_port_base::notify_change received unsupported notification (%s)",
            silicon_one::to_string(op.type_e).c_str());
    return LA_STATUS_EUNKNOWN;
}

la_status
la_ethernet_port_base::set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::clear_acl_group(la_acl_direction_e dir)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_port_type(port_type_e& out_type) const
{
    out_type = m_port_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::get_port_vid(la_vlan_id_t& out_vid) const
{
    out_vid = m_port_vid;

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::set_port_vid(la_vlan_id_t port_vid)
{
    start_api_call("port_vid=", port_vid);
    transaction txn;

    if (m_port_vid == port_vid) {
        return LA_STATUS_SUCCESS;
    }

    la_vlan_id_t orig_port_vid = m_port_vid;
    m_port_vid = port_vid;
    txn.on_fail([&]() { m_port_vid = orig_port_vid; });

    txn.status = update_npp_attributes();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::get_allowed_vlans(la_vlan_set_t* out_allowed_vlans)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::set_allowed_vlans(const la_vlan_set_t allowed_vlans)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_security_mode(la_port_security_mode_e* out_security_mode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::set_security_mode(la_port_security_mode_e security_mode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::set_ingress_counter(la_counter_set::type_e counter_type, la_counter_set* counter)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_ingress_counter(la_counter_set::type_e counter_type, la_counter_set*& out_counter) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::set_egress_counter(la_counter_set::type_e counter_type, la_counter_set* counter)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_egress_counter(la_counter_set::type_e counter_type, la_counter_set*& out_counter) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_ac_profile(la_ac_profile*& out_ac_profile) const
{
    start_api_getter_call();

    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }

    out_ac_profile = m_ac_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::set_ac_profile(la_ac_profile* ac_profile)
{
    start_api_call("ac_profile=", ac_profile);
    // Check parameters
    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }

    if (ac_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ac_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (ac_profile == m_ac_profile.get()) {
        return LA_STATUS_SUCCESS;
    }

    // Update source PIF attributes
    la_ac_profile_impl* new_profile = static_cast<la_ac_profile_impl*>(ac_profile);

    if (m_device->is_in_use(this) && (m_ac_profile != nullptr)) {
        if (new_profile->need_fallback() != m_ac_profile->need_fallback()) {
            if (m_ac_ports_entries.size()) {
                return LA_STATUS_EBUSY;
            }
        }
    }

    la_status status = set_source_pif_entry(new_profile);
    return_on_error(status);

    status = set_inject_up_entry(new_profile);
    return_on_error(status);

    if (m_ac_profile != nullptr) {
        m_device->remove_object_dependency(m_ac_profile, this);
    }

    m_device->add_object_dependency(ac_profile, this);
    m_ac_profile = m_device->get_sptr(new_profile);

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::erase_source_pif_entry()
{
    la_status status = LA_STATUS_SUCCESS;
    if (m_spa_port != nullptr) {
        status = m_spa_port->clear_source_pif();
    } else if (m_system_port != nullptr) {
        la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();
        if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
            status = m_system_port->erase_source_pif_table_entries();
        }
    }

    return status;
}

la_status
la_ethernet_port_base::get_ac_port(la_vlan_id_t vid1, la_vlan_id_t vid2, const la_object*& out_object) const
{
    start_api_getter_call();

    ac_port_key key = {.vid1 = vid1, .vid2 = vid2};

    auto it = m_ac_ports_entries.find(key);
    if (it == m_ac_ports_entries.end()) {
        out_object = nullptr;
    } else {
        out_object = it->second.get();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::get_transparent_ptp_enabled(bool& out_enabled) const
{
    start_api_call("");

    out_enabled = m_transparent_ptp_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::set_transparent_ptp_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    m_transparent_ptp_enabled = enabled;

    return update_npp_attributes();
}

la_status
la_ethernet_port_base::do_set_mtu()
{
    la_status status = LA_STATUS_SUCCESS;

    if (m_spa_port != nullptr) {
        status = m_spa_port->set_mtu(m_mtu);
    } else if (m_system_port != nullptr) {
        status = m_system_port->set_mtu(m_mtu);
    }

    return status;
}

la_status
la_ethernet_port_base::get_service_mapping_type(service_mapping_type_e& out_type) const
{
    out_type = m_service_mapping_type;
    return LA_STATUS_SUCCESS;
}

la_vlan_pcpdei
la_ethernet_port_base::get_ingress_default_pcpdei() const
{
    start_api_getter_call();

    return (m_default_pcpdei);
}

la_status
la_ethernet_port_base::set_ingress_default_pcpdei(la_vlan_pcpdei pcpdei)
{
    start_api_call("pcpdei=", pcpdei);
    transaction txn;

    if (m_default_pcpdei.flat == pcpdei.flat) {
        return LA_STATUS_SUCCESS;
    }

    la_vlan_pcpdei orig_port_default_pcpdei = m_default_pcpdei;
    m_default_pcpdei = pcpdei;
    txn.on_fail([&]() { m_default_pcpdei = orig_port_default_pcpdei; });

    txn.status = update_npp_attributes();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_ethernet_port_base::type() const
{
    return object_type_e::ETHERNET_PORT;
}

std::string
la_ethernet_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_ethernet_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_ethernet_port_base::oid() const
{
    return m_oid;
}

const la_device*
la_ethernet_port_base::get_device() const
{
    return m_device.get();
}

la_l2_port_gid_t
la_ethernet_port_base::get_id() const
{
    return m_id;
}

la_status
la_ethernet_port_base::add_ifg(la_slice_ifg ifg)
{
    transaction txn;

    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    // If slice is already configured, bail
    if (!ifg_added) {
        return LA_STATUS_SUCCESS;
    }
    // Propagate slice change upwards
    txn.status = m_device->notify_ifg_added(this, ifg);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::remove_ifg(la_slice_ifg ifg)
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

    txn.status = m_device->notify_ifg_removed(this, ifg);
    return_on_error(txn.status);
    return LA_STATUS_SUCCESS;
}

la_ethernet_port_base::system_port_base_vec
la_ethernet_port_base::get_underlying_local_system_port_vec() const
{
    system_port_base_vec out_sys_ports;
    if (m_system_port != nullptr) {
        la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();

        if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
            out_sys_ports.push_back(m_system_port);
        }
    } else if (m_spa_port != nullptr) {
        system_port_vec_t spa_members;
        m_spa_port->get_members(spa_members);
        for (auto sys_port : spa_members) {
            la_system_port_base* sys_port_impl = static_cast<la_system_port_base*>(sys_port);
            la_system_port_base::port_type_e sys_port_type = sys_port_impl->get_port_type();

            if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
                out_sys_ports.push_back(m_device->get_sptr(sys_port_impl));
            }
        }
    }

    return out_sys_ports;
}

void
la_ethernet_port_base::set_ac_port(la_vlan_id_t vid1, la_vlan_id_t vid2, la_object_wcptr ac_port)
{
    ac_port_key key = {.vid1 = vid1, .vid2 = vid2};
    m_ac_ports_entries[key] = ac_port;
}

void
la_ethernet_port_base::clear_ac_port(la_vlan_id_t vid1, la_vlan_id_t vid2)
{
    ac_port_key key = {.vid1 = vid1, .vid2 = vid2};
    m_ac_ports_entries.erase(key);
}

const la_system_port*
la_ethernet_port_base::get_system_port() const
{
    start_api_getter_call();

    return m_system_port.get();
}

const la_spa_port*
la_ethernet_port_base::get_spa_port() const
{
    start_api_getter_call();

    return m_spa_port.get();
}

slice_ifg_vec_t
la_ethernet_port_base::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_status
la_ethernet_port_base::update_npp_attributes()
{
    la_status status = LA_STATUS_SUCCESS;
    auto slices = m_ifg_use_count->get_slices();

    npl_mac_af_npp_attributes_table_t::value_type value = populate_mac_af_npp_attributes();

    if (m_spa_port != nullptr) {
        status = m_spa_port->set_mac_af_npp_attributes(value);
    } else if (m_system_port != nullptr) {
        la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();
        if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
            status = m_system_port->set_mac_af_npp_attributes(value);
        }
    }

    return status;
}

npl_initial_pd_nw_rx_data_t
la_ethernet_port_base::populate_initial_pd_nw_rx_data(const la_ac_profile_impl* ac_profile) const
{
    npl_initial_pd_nw_rx_data_t init_data;
    init_data.initial_mapping_type = (m_port_type == port_type_e::SIMPLE) ? NPL_L2_VLAN_MAPPING : NPL_L2_SERVICE_MAPPING;
    init_data.initial_mac_lp_type = NPL_LP_TYPE_LAYER_2;
    init_data.initial_vlan_profile = (ac_profile) ? ac_profile->get_id() : 0;
    init_data.initial_lp_type = NPL_L2_LP_TYPE_NPP;
    init_data.mapping_key.initial_lp_id.id = m_id;
    init_data.mapping_key.mpls_label_placeholder = 0; /* TODO: should be initialized by MPLS configuration */
    init_data.pfc_enable = 0;
    if (get_underlying_port_type() == object_type_e::RECYCLE_PORT) {
        init_data.initial_is_rcy_if = 1;
    } else {
        init_data.initial_is_rcy_if = 0;
    }
    // init_data.initial_is_rcy_if = 0;
    init_data.init_data.initial_npp_attributes_index = 0; // this is set by the system port
    init_data.init_data.initial_slice_id = 0;             // this is set by the system port
    return init_data;
}

la_object::object_type_e
la_ethernet_port_base::get_underlying_port_type() const
{
    system_port_base_vec sys_ports = get_underlying_local_system_port_vec();
    for (auto sys_port : sys_ports) {
        auto underlying_port = sys_port->get_underlying_port();
        return (underlying_port->type());
    }
    return la_object::object_type_e::SYSTEM_PORT;
}

la_status
la_ethernet_port_base::set_inject_up_entry(la_ac_profile_impl* ac_profile)
{
    npl_initial_pd_nw_rx_data_t v = populate_initial_pd_nw_rx_data(ac_profile);

    system_port_base_vec sys_ports = get_underlying_local_system_port_vec();
    for (auto sys_port : sys_ports) {
        la_status status = sys_port->set_inject_up_entry(v);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::set_inject_up_entry(la_system_port_base* sys_port, la_ac_profile_impl* ac_profile)
{
    if (sys_port == nullptr) {
        return LA_STATUS_EINVAL;
    }
    npl_initial_pd_nw_rx_data_t v = populate_initial_pd_nw_rx_data(ac_profile);
    la_status status = sys_port->set_inject_up_entry(v);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::erase_inject_up_entry(la_system_port_base* sys_port)
{
    if (sys_port == nullptr) {
        return LA_STATUS_EINVAL;
    }
    la_status status = sys_port->erase_inject_up_entry();
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::erase_inject_up_entry()
{
    system_port_base_vec sys_ports = get_underlying_local_system_port_vec();
    for (auto sys_port : sys_ports) {
        la_status status = sys_port->erase_inject_up_entry();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::set_meter(const la_meter_set* meter)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_meter(const la_meter_set*& out_meter) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

bool
la_ethernet_port_base::is_member(const la_system_port_wcptr& system_port) const
{
    if (m_spa_port != nullptr) {
        return (m_spa_port->is_member(system_port));
    }
    return (m_system_port == system_port);
}

bool
la_ethernet_port_base::is_aggregate() const
{
    return (m_spa_port != nullptr);
}

la_status
la_ethernet_port_base::get_svi_egress_tag_mode(svi_egress_tag_mode_e& out_mode) const
{
    out_mode = m_svi_egress_tag_mode;
    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::set_svi_egress_tag_mode(svi_egress_tag_mode_e mode)
{
    start_api_call("svi_egress_tag_mode=", mode);

    m_svi_egress_tag_mode = mode;
    bool mask_eve = (mode == svi_egress_tag_mode_e::STRIP);
    if (m_spa_port != nullptr) {
        return m_spa_port->set_mask_eve(mask_eve);
    }

    if (m_system_port != nullptr) {
        return m_system_port->set_mask_eve(mask_eve);
    }

    return LA_STATUS_EINVAL;
}

la_object*
la_ethernet_port_base::get_underlying_port() const
{
    if (m_system_port != nullptr) {
        return m_system_port.get();
    }

    return m_spa_port.get();
}

bool
la_ethernet_port_base::get_decrement_ttl() const
{
    start_api_getter_call();

    return m_decrement_ttl;
}

la_status
la_ethernet_port_base::set_decrement_ttl(bool decrement_ttl)
{
    start_api_call("decrement=", decrement_ttl);

    m_decrement_ttl = decrement_ttl;
    // set dsp_l3_attributes table
    la_status status = LA_STATUS_SUCCESS;

    if (m_spa_port != nullptr) {
        status = m_spa_port->set_decrement_ttl(decrement_ttl);
    } else if (m_system_port != nullptr) {
        status = m_system_port->set_decrement_ttl(m_decrement_ttl);
    }

    return status;
}

la_status
la_ethernet_port_base::set_stack_mc_prune(bool prune_enable)
{
    start_api_call("prune_enable=", prune_enable);

    la_status status = LA_STATUS_SUCCESS;

    if (m_spa_port != nullptr) {
        status = m_spa_port->set_stack_prune(prune_enable);
    } else if (m_system_port != nullptr) {
        status = m_system_port->set_stack_prune(prune_enable);
    }

    return status;
}

la_status
la_ethernet_port_base::get_stack_mc_prune(bool& prune_enabled) const
{
    start_api_getter_call();

    la_status status = LA_STATUS_SUCCESS;

    if (m_spa_port != nullptr) {
        status = m_spa_port->get_stack_prune(prune_enabled);
    } else if (m_system_port != nullptr) {
        status = m_system_port->get_stack_prune(prune_enabled);
    }

    return status;
}

la_status
la_ethernet_port_base::set_copc_profile(la_control_plane_classifier::ethernet_profile_id_t ethernet_profile_id)
{
    start_api_call("ethernet_profile_id=", ethernet_profile_id);

    transaction txn;
    la_uint8_t old_copc_trap_profile = m_copc_profile;

    m_copc_profile = ethernet_profile_id;
    txn.on_fail([&]() { m_copc_profile = old_copc_trap_profile; });

    txn.status = update_npp_attributes();
    return_on_error(txn.status);

    return txn.status;
}

la_status
la_ethernet_port_base::get_copc_profile(la_control_plane_classifier::ethernet_profile_id_t& out_ethernet_profile_id) const
{
    start_api_getter_call();

    out_ethernet_profile_id = m_copc_profile;

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::set_traffic_matrix_interface_type(traffic_matrix_type_e type)
{
    start_api_call("type=", type);

    if (m_traffic_matrix_type == type) {
        return LA_STATUS_SUCCESS;
    }

    m_traffic_matrix_type = type;
    return update_npp_attributes();
}

la_status
la_ethernet_port_base::get_traffic_matrix_interface_type(traffic_matrix_type_e& out_traffic_matrix_type) const
{
    start_api_getter_call();

    out_traffic_matrix_type = m_traffic_matrix_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_base::set_security_group_tag(la_sgt_t sgt)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_security_group_tag(la_sgt_t& out_sgt) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::set_security_group_policy_enforcement(bool enforcement)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ethernet_port_base::get_security_group_policy_enforcement(bool& out_enforcement) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
