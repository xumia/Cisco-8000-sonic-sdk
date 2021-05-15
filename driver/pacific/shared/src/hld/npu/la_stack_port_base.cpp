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

#include "la_stack_port_base.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "system/la_system_port_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

using namespace std;
namespace silicon_one
{

la_stack_port_base::la_stack_port_base(const la_device_impl_wptr& device) : m_device(device)
{
    m_remote_punt_mac.flat = 0;
    m_peer_device_id = 0;
}

la_stack_port_base::~la_stack_port_base()
{
}

la_status
la_stack_port_base::initialize_common()
{
    la_status status;
    status = set_source_pif_entry();
    return_on_error(status);

    if (m_spa_port != nullptr) {
        status = m_spa_port->set_stack_prune(true);
    } else if (m_system_port != nullptr) {
        la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();
        if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
            status = m_system_port->set_stack_prune(true);
        }
    }

    return status;
}

la_status
la_stack_port_base::initialize(la_object_id_t oid, const la_system_port_base_wptr& system_port)
{
    m_oid = oid;

    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    if (system_port->has_port_dependency()) {
        return LA_STATUS_EBUSY;
    }

    m_system_port = system_port;
    la_system_port_base::port_type_e sys_port_type = system_port->get_port_type();

    if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
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

    m_remote_punt_system_port = m_system_port;

    return LA_STATUS_SUCCESS;
}

la_status
la_stack_port_base::initialize(la_object_id_t oid, const la_spa_port_base_wptr& spa_port)
{
    m_oid = oid;
    m_spa_port = spa_port;
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());

    vector<la_slice_ifg> ifgs = spa_port->get_ifgs();
    for (la_slice_ifg ifg : ifgs) {
        la_status status = add_ifg(ifg);

        return_on_error(status);
    }

    la_status status = initialize_common();
    return_on_error(status);

    m_device->add_ifg_dependency(spa_port, this);
    m_device->add_object_dependency(spa_port, this);

    bit_vector registered_attributes((la_uint64_t)attribute_management_op::SPA_MEMBERSHIP_CHANGED);
    m_device->add_attribute_dependency(m_spa_port, this, registered_attributes);

    return LA_STATUS_SUCCESS;
}

la_status
la_stack_port_base::destroy_common()
{
    la_status status;
    status = erase_source_pif_entry();
    return_on_error(status);

    return status;
}

la_status
la_stack_port_base::destroy()
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

    for (auto sp_voq_pair : m_control_traffic_voq_map) {
        m_device->remove_object_dependency(sp_voq_pair.second, this);
    }
    m_control_traffic_voq_map.clear();

    la_status status;
    auto slices = m_ifg_use_count->get_slices();
    for (la_slice_id_t slice : slices) {
        status = erase_rx_obm_code_table_entry(slice);
    }

    slice_ifg_vec_t enabled_ifgs = m_ifg_use_count->get_ifgs();
    for (auto ifg : enabled_ifgs) {
        status = remove_ifg(ifg);
    }

    destroy_common();

    return LA_STATUS_SUCCESS;
}

la_status
la_stack_port_base::notify_change(dependency_management_op op)
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
                    set_source_pif_entry();
                    system_port_base->set_stack_prune(true);
                    if (m_ifg_use_count->is_slice_in_use(system_port_base->get_slice()) != true) {
                        set_rx_obm_code_table_entry(system_port_base->get_slice());
                    }
                    return LA_STATUS_SUCCESS;
                } else {
                    auto sys_port_wptr = m_device->get_sptr(op.action.attribute_management.spa.sys_port);
                    erase_control_traffic_queueing(sys_port_wptr);
                    system_port_base->erase_source_pif_table_entries();
                    if (m_ifg_use_count->is_slice_in_use(system_port_base->get_slice()) != true) {
                        erase_rx_obm_code_table_entry(system_port_base->get_slice());
                    }
                    return LA_STATUS_SUCCESS;
                }
            } else {
                return LA_STATUS_EINVAL;
            }
        }
    }
    log_err(
        HLD, "la_stack_port_base::notify_change received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
    return LA_STATUS_EUNKNOWN;
}

la_object::object_type_e
la_stack_port_base::type() const
{
    return object_type_e::STACK_PORT;
}

std::string
la_stack_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_stack_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_stack_port_base::oid() const
{
    return m_oid;
}

const la_device*
la_stack_port_base::get_device() const
{
    return m_device.get();
}

la_status
la_stack_port_base::add_ifg(la_slice_ifg ifg)
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
    // Propagate slice change upwards
    txn.status = m_device->notify_ifg_added(this, ifg);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_stack_port_base::remove_ifg(la_slice_ifg ifg)
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

const la_system_port*
la_stack_port_base::get_system_port() const
{
    start_api_getter_call();

    return m_system_port.get();
}

const la_spa_port*
la_stack_port_base::get_spa_port() const
{
    start_api_getter_call();

    return m_spa_port.get();
}

slice_ifg_vec_t
la_stack_port_base::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_status
la_stack_port_base::erase_source_pif_entry()
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

bool
la_stack_port_base::is_member(const la_system_port_wcptr& system_port) const
{
    if (m_spa_port != nullptr) {
        return (m_spa_port->is_member(system_port));
    }
    return (m_system_port == system_port);
}

bool
la_stack_port_base::is_aggregate() const
{
    return (m_spa_port != nullptr);
}

la_object*
la_stack_port_base::get_underlying_port() const
{
    if (m_system_port != nullptr) {
        return m_system_port.get();
    }

    return m_spa_port.get();
}

la_status
la_stack_port_base::set_local_punt_system_port(la_system_port* system_port)
{
    start_api_call("system_port=", system_port);

    la_status status = LA_STATUS_SUCCESS;
    const auto& system_port_base = m_device->get_sptr<la_system_port_base>(system_port);
    m_local_punt_system_port = system_port_base;

    slice_ifg_vec_t enabled_ifgs = m_ifg_use_count->get_ifgs();
    for (auto ifg : enabled_ifgs) {
        if (ifg.slice != LA_SLICE_ID_INVALID) {
            status = set_rx_obm_code_table_entry(ifg.slice);
            return_on_error(status);
        }
    }
    return status;
}

la_status
la_stack_port_base::set_remote_punt_system_port(la_system_port* system_port)
{
    start_api_call("system_port=", system_port);

    const auto& system_port_base = m_device->get_sptr<la_system_port_base>(system_port);
    if (m_spa_port != nullptr) {
        if (is_member(system_port_base)) {
            m_remote_punt_system_port = system_port_base;
            return LA_STATUS_SUCCESS;
        } else {
            return LA_STATUS_EINVAL;
        }
    } else if (m_system_port != nullptr) {
        if (m_system_port == system_port_base) {
            m_remote_punt_system_port = system_port_base;
            return LA_STATUS_SUCCESS;
        } else {
            return LA_STATUS_EINVAL;
        }
    }
    return LA_STATUS_EINVAL;
}

la_status
la_stack_port_base::set_remote_punt_src_mac(la_mac_addr_t mac_addr)
{
    start_api_call("mac_addr=", mac_addr);

    m_remote_punt_mac.flat = mac_addr.flat;
    return LA_STATUS_SUCCESS;
}

la_status
la_stack_port_base::get_remote_punt_mac(la_mac_addr_t& out_mac_addr) const
{
    if (m_remote_punt_system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    out_mac_addr.flat = m_remote_punt_mac.flat;

    return LA_STATUS_SUCCESS;
}

const la_system_port*
la_stack_port_base::get_remote_punt_system_port() const
{
    return m_remote_punt_system_port.get();
}

la_status
la_stack_port_base::set_rx_obm_code_table_entry(la_slice_id_t slice)
{
    la_status status;

    if (m_local_punt_system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    const auto& rx_obm_code_table(m_device->m_tables.rx_obm_code_table[slice]);
    npl_rx_obm_code_table_key_t key;
    npl_rx_obm_code_table_value_t value;
    npl_rx_obm_code_table_entry_t* entry = nullptr;

    bit_vector64_t key_bv(NPL_TX2RX_SCHED_RCY_DATA_TX_REDIRECT_TO_DEST);
    key.tx_to_rx_rcy_data.unpack(key_bv);

    la_system_port_gid_t gid = (m_local_punt_system_port)->get_gid();

    destination_id dest_id = destination_id(NPL_DESTINATION_MASK_DSP | gid);
    npl_destination_t dest{.val = dest_id.val};

    value.payloads.rx_obm_action.phb.tc = 0;
    value.payloads.rx_obm_action.phb.dp = 0;
    value.payloads.rx_obm_action.destination = dest;
    value.payloads.rx_obm_action.punt_encap_data_lsb.punt_nw_encap_ptr.ptr = 0;
    value.payloads.rx_obm_action.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_HOST_DMA_ENCAP_TYPE;
    value.payloads.rx_obm_action.punt_encap_data_lsb.punt_controls.mirror_local_encap_format = 0;

    status = rx_obm_code_table->set(key, value, entry);

    return status;
}

la_status
la_stack_port_base::erase_rx_obm_code_table_entry(la_slice_id_t slice)
{
    la_status status;

    const auto& rx_obm_code_table(m_device->m_tables.rx_obm_code_table[slice]);
    npl_rx_obm_code_table_key_t key;

    bit_vector64_t key_bv(NPL_TX2RX_SCHED_RCY_DATA_TX_REDIRECT_TO_DEST);
    key.tx_to_rx_rcy_data.unpack(key_bv);

    status = rx_obm_code_table->erase(key);

    return status;
}

destination_id
la_stack_port_base::get_destination_id(resolution_step_e prev_step) const
{
    if (m_remote_punt_system_port != nullptr) {
        return silicon_one::get_destination_id(m_remote_punt_system_port, prev_step);
    } else {
        return DESTINATION_ID_INVALID;
    }
}

la_device_id_t
la_stack_port_base::get_peer_device_id()
{
    start_api_getter_call();

    return m_peer_device_id;
}

la_status
la_stack_port_base::set_peer_device_id(la_device_id_t peer_device_id)
{
    start_api_call("peer_device_id=", peer_device_id);

    la_status status = LA_STATUS_SUCCESS;

    m_peer_device_id = peer_device_id;

    status = set_peer_device_reachable_stack_port_destination();
    return_on_error(status);

    return status;
}

la_stack_port_base::control_traffic_voq_map_t::const_iterator
la_stack_port_base::find_in_voq_map(const la_system_port_wcptr& sys_port) const
{
    auto it = std::find_if(m_control_traffic_voq_map.begin(),
                           m_control_traffic_voq_map.end(),
                           [sys_port](const std::pair<la_system_port_wcptr, la_voq_set_wptr>& e) { return e.first == sys_port; });

    return it;
}

la_status
la_stack_port_base::set_control_traffic_queueing(la_system_port* system_port, la_voq_set* voq_set)
{
    start_api_call("system_port=", system_port, " voq_set=", voq_set);

    if (system_port == nullptr) {
        log_err(HLD, "invalid system_port");
        return LA_STATUS_EINVAL;
    }

    if (voq_set == nullptr) {
        log_err(HLD, "invalid voq set");
        return LA_STATUS_EINVAL;
    }

    auto system_port_sptr = m_device->get_sptr(system_port);

    if (is_member(system_port_sptr) == false) {
        log_err(HLD, "system_port doesn't belong to stack port");
        return LA_STATUS_EINVAL;
    }

    auto voq_set_sptr = m_device->get_sptr(voq_set);

    auto sp_voq_pair = find_in_voq_map(system_port_sptr);
    if (sp_voq_pair != m_control_traffic_voq_map.end()) {
        if (sp_voq_pair->second.get() == voq_set) {
            return LA_STATUS_SUCCESS;
        } else {
            /* new voq_set is not expected */
            return LA_STATUS_EBUSY;
        }
    }

    auto system_port_base = std::static_pointer_cast<const la_system_port_base>(system_port_sptr);
    la_status status = system_port_base->is_valid_voq_mapping(voq_set_sptr);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "invalid voq mapping for system_port");
        return status;
    }

    status = system_port_base->program_stack_control_traffic_voq_mapping(voq_set_sptr);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "set voq mapping failed");
        return status;
    }

    m_device->add_object_dependency(voq_set_sptr, this);

    m_control_traffic_voq_map[system_port_sptr] = voq_set_sptr;

    return LA_STATUS_SUCCESS;
}

uint32_t
la_stack_port_base::get_control_traffic_destination_id(la_system_port* system_port, la_uint_t voq_offset)
{
    start_api_getter_call();

    if (system_port == nullptr) {
        log_err(HLD, "invalid system_port");
        return DESTINATION_ID_INVALID.val;
    }

    auto system_port_sptr = m_device->get_sptr(system_port);

    if (is_member(system_port_sptr) == false) {
        log_err(HLD, "system_port doesn't belong to stack port");
        return DESTINATION_ID_INVALID.val;
    }

    auto sp_voq_pair = find_in_voq_map(system_port_sptr);

    if (sp_voq_pair != m_control_traffic_voq_map.end()) {
        auto sp_voq = sp_voq_pair->second.get();

        if (voq_offset >= sp_voq->get_set_size()) {
            log_err(HLD, "invalid voq_offset");
            return DESTINATION_ID_INVALID.val;
        }

        destination_id base_dest_id = silicon_one::get_destination_id(sp_voq, RESOLUTION_STEP_FORWARD_L2);
        return (base_dest_id.val + voq_offset);
    }

    return DESTINATION_ID_INVALID.val;
}

la_status
la_stack_port_base::erase_control_traffic_queueing(const la_system_port_wcptr& system_port)
{
    auto sp_voq_pair = find_in_voq_map(system_port);
    if (sp_voq_pair != m_control_traffic_voq_map.end()) {
        auto system_port_base = system_port.weak_ptr_static_cast<const la_system_port_base>();
        system_port_base->clear_voq_mapping(sp_voq_pair->second);
        m_device->remove_object_dependency(sp_voq_pair->second, this);
        m_control_traffic_voq_map.erase(sp_voq_pair);
    }
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
