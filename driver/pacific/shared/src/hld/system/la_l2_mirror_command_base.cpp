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

#include <sstream>

#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "nplapi/npl_constants.h"
#include "npu/counter_utils.h"
#include "npu/la_counter_set_impl.h"
#include "npu/resolution_utils.h"
#include "qos/la_meter_set_exact_impl.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"
#include "system/la_l2_mirror_command_base.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_punt_inject_port_base.h"
#include "system/la_spa_port_base.h"

namespace silicon_one
{

static la_uint_t
calculate_probability(double probability)
{
    la_uint_t sampling_rate = probability * (MIRROR_SAMPLING_SPACE_SIZE - 1);
    return sampling_rate;
}

la_l2_mirror_command_base::la_l2_mirror_command_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_mirror_gid(0),
      m_system_port_gid(0),
      m_mac_addr(),
      m_vlan_tag(),
      m_voq_offset(0),
      m_probability(1.0f),
      m_encap_type(NPL_PUNT_NW_NO_ENCAP_TYPE),
      m_mirror_to_dest(false),
      m_truncate(false),
      m_destination({.val = 0}),
      m_is_mc_lpts(false),
      m_final_system_port(nullptr),
      m_stack_port(nullptr)
{
}

la_l2_mirror_command_base::~la_l2_mirror_command_base()
{
}

destination_id
la_l2_mirror_command_base::get_mirror_destination_id()
{
    bool svl_mode = false;
    destination_id dest_id = destination_id(0);

    const la_system_port_base* sp_base;
    if (m_pi_port && (m_system_port == nullptr)) {
        sp_base = static_cast<const la_system_port_base*>(m_pi_port->get_system_port());
    } else {
        sp_base = static_cast<const la_system_port_base*>(m_system_port.get());
    }

    if (sp_base == nullptr) {
        return dest_id;
    }

    auto sp_sptr = m_device->get_sptr(sp_base);
    auto actual_dsp = get_actual_dsp(sp_sptr);
    la_voq_set* voq_set = actual_dsp->get_voq_set();

    m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);

    if (!svl_mode) {
        dest_id = destination_id(NPL_DESTINATION_MASK_BVN | (voq_set->get_base_voq_id() + m_voq_offset));
    } else {
        if (sp_base->get_port_type() != la_system_port_base::port_type_e::REMOTE) {
            dest_id = destination_id(NPL_DESTINATION_MASK_BVN | (voq_set->get_base_voq_id() + m_voq_offset));
        } else {
            // BVN based destination cannot be used for remote ports in SVL mode
            dest_id = destination_id(NPL_DESTINATION_MASK_DSP | (m_system_port_gid));
        }
    }
    return dest_id;
}

la_status
la_l2_mirror_command_base::resolve_final_system_port()
{
    bool svl_mode = false;

    const la_system_port_base* sp_base;
    if (m_pi_port != nullptr) {
        sp_base = static_cast<const la_system_port_base*>(m_pi_port->get_system_port());
    } else if (m_system_port != nullptr) {
        sp_base = static_cast<const la_system_port_base*>(m_system_port.get());
    } else if (m_npu_host_port != nullptr) {
        sp_base = static_cast<const la_system_port_base*>(m_npu_host_port->get_system_port());
    } else {
        return LA_STATUS_EINVAL;
    }

    if (sp_base == nullptr) {
        return LA_STATUS_EINVAL;
    }

    m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);

    if (svl_mode && sp_base->get_port_type() == la_system_port_base::port_type_e::REMOTE) {
        const la_stack_port* stack_port;
        la_status status = m_device->get_stack_port_from_remote_sys_port_gid(m_system_port_gid, stack_port);
        return_on_error(status);
        m_stack_port = m_device->get_sptr<const la_stack_port_base>(stack_port);

        auto stack_sys_port = stack_port->get_system_port();
        if (stack_sys_port != nullptr) {
            m_final_system_port = m_device->get_sptr<const la_system_port_base>(stack_sys_port);
        } else {
            auto spa_port = stack_port->get_spa_port();
            status = spa_port->get_member(0, stack_sys_port);
            return_on_error(status);
            m_final_system_port = m_device->get_sptr<const la_system_port_base>(stack_sys_port);
        }
    } else {
        m_final_system_port = m_device->get_sptr<const la_system_port_base>(sp_base);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::initialize_common()
{
    transaction txn;

    la_uint_t sampling_rate = calculate_probability(m_probability);
    txn.status = configure_ibm_command_and_rx_obm_table(sampling_rate);
    return_on_error(txn.status);
    m_mirror_type == MIRROR_INGRESS
        ? txn.on_fail([=]() { m_device->clear_rx_obm_punt_src_and_code(m_mirror_gid, NPL_PUNT_SRC_INBOUND_MIRROR); })
        : txn.on_fail([=]() { m_device->clear_rx_obm_punt_src_and_code(m_mirror_gid, NPL_PUNT_SRC_OUTBOUND_MIRROR); });

    if ((m_encap_type == NPL_PUNT_NW_ETH_ENCAP_TYPE) || (m_encap_type == NPL_PUNT_NW_PFC_ENCAP_TYPE)) {
        txn.status = configure_redirect_encap(m_encap_ptr);
        return_on_error(txn.status);
        txn.on_fail([=]() { m_device->clear_redirect_eth_encap(m_encap_ptr); });
    }

    if (m_mirror_type == MIRROR_INGRESS) {
        // Handle special mirror initialize cases (2nd and 4th)
        switch (m_pfc_mirroring) {
        case PILOT:
            txn.status = configure_cud_entry(
                m_mirror_hw_id, NPL_REDIRECT_CODE_PFC_PILOT, silicon_one::la_device_impl::NPU_HOST_PFC_ENCAP_PTR);
            break;
        case MEASUREMENT:
            txn.status = configure_cud_entry(m_mirror_hw_id, NPL_REDIRECT_CODE_PFC_MEASUREMENT, m_encap_ptr);
            break;
        case NONE:
            txn.status = configure_cud_entry(m_mirror_hw_id, m_mirror_gid, m_encap_ptr);
        }
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_cud_entry(m_mirror_hw_id); });

        txn.status = m_device->configure_mirror_code_to_ibm(m_mirror_hw_id, m_mirror_hw_id);
        return_on_error(txn.status);
        txn.on_fail([=]() { m_device->clear_mirror_code_to_ibm(m_mirror_hw_id); });

        if ((m_encap_type == NPL_PUNT_NW_PFC_ENCAP_TYPE) || (m_encap_type == NPL_PUNT_NW_NO_ENCAP_TYPE)) {
            txn.status = configure_ibm_uc_cmd_to_encap_data_table(m_mirror_hw_id);
            return_on_error(txn.status);
            txn.on_fail([=]() { teardown_ibm_uc_cmd_to_encap_data_table(m_mirror_hw_id); });
        }

        txn.status = configure_mirror_to_dsp_in_npu_soft_header_table(0);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_mirror_to_dsp_in_npu_soft_header_table(); });
    } else {
        // MIRROR_EGRESS
        txn.status = configure_recycle_slice_entry(m_mirror_hw_id);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_recycle_slice_entry(m_mirror_hw_id); });

        if ((m_encap_type != NPL_PUNT_NW_PFC_ENCAP_TYPE) && (m_encap_type != NPL_PUNT_NW_NPU_HOST_ENCAP_TYPE)) {
            txn.status = configure_recycle_override_entry(m_mirror_hw_id);
            return_on_error(txn.status);
            txn.on_fail([=]() { remove_recycle_override_entry(m_mirror_hw_id); });
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::initialize_hw_id_and_encap_ptr(la_mirror_gid_t mirror_gid)
{
    if (mirror_gid > la_device_impl::MAX_EGRESS_MIRROR_GID) {
        m_mirror_type = MIRROR_INGRESS;
        m_mirror_hw_id = mirror_gid - la_device_impl::MIRROR_GID_INGRESS_OFFSET;
    } else {
        m_mirror_type = MIRROR_EGRESS;
        m_mirror_hw_id = mirror_gid;
    }
    m_encap_ptr = m_mirror_type == MIRROR_EGRESS ? m_mirror_hw_id : m_mirror_hw_id + la_device_impl::MIRROR_GID_INGRESS_OFFSET;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::initialize(la_object_id_t oid,
                                      la_mirror_gid_t mirror_gid,
                                      const la_punt_inject_port_base_wptr& pi_port,
                                      const la_system_port_base_wptr& system_port,
                                      la_mac_addr_t mac_addr,
                                      const la_vlan_tag_tci_t& vlan_tag,
                                      la_uint_t voq_offset,
                                      const la_meter_set_wptr& meter,
                                      double probability)
{
    m_oid = oid;
    if ((m_pi_port != nullptr) || (m_system_port != nullptr)) {
        return LA_STATUS_EINVAL;
    }

    if ((probability < 0.0) || (probability > 1.0f)) {
        return LA_STATUS_EINVAL;
    }

    if (system_port != nullptr) {
        m_is_mc_lpts = true;
    }

    // Supports only statistical meter.
    if ((meter != nullptr) && (meter->get_type() != la_meter_set::type_e::STATISTICAL)) {
        log_err(HLD, "Only STATISTICAL meter is valid for the mirror session.");
        return LA_STATUS_EINVAL;
    }

    auto meter_set_impl = meter.weak_ptr_static_cast<la_meter_set_impl>();

    if ((meter_set_impl != nullptr) && (meter_set_impl->get_set_size() != 1)) {
        log_err(HLD, "meter-set size %lu is not valid for the mirror session.", meter_set_impl->get_set_size());
        return LA_STATUS_EINVAL;
    }

    initialize_hw_id_and_encap_ptr(mirror_gid);

    m_mirror_gid = mirror_gid;
    m_pi_port = pi_port;
    m_system_port = system_port;
    m_mac_addr.flat = mac_addr.flat;
    m_vlan_tag.raw = vlan_tag.raw;
    m_voq_offset = voq_offset;
    m_meter = meter_set_impl;
    m_probability = probability;
    m_encap_type = NPL_PUNT_NW_ETH_ENCAP_TYPE;

    transaction txn;

    if (m_meter != nullptr) {
        // Attach meter
        txn.status = meter_set_impl->attach_user(m_device->get_sptr(this), true);
        return_on_error(txn.status);
        txn.on_fail([=]() { meter_set_impl->detach_user(m_device->get_sptr(this)); });
    }

    // PACKET-DMA-WA
    la_system_port_wcptr sys_port;
    if (system_port == nullptr) {
        sys_port = m_device->get_sptr(m_pi_port->get_system_port());
    } else {
        sys_port = system_port;
    }
    auto actual_dsp = get_actual_dsp(sys_port);
    m_system_port_gid = actual_dsp->get_gid();

    destination_id dest_id = get_mirror_destination_id();
    m_destination = {.val = dest_id.val};

    txn.status = resolve_final_system_port();
    return_on_error(txn.status);

    txn.status = initialize_common();
    return_on_error(txn.status);

    if (m_mirror_type == MIRROR_INGRESS) {
        txn.status = configure_stack_remote_mirror_destination_map(m_mirror_hw_id, m_destination);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_stack_remote_mirror_destination_map(m_mirror_hw_id); });
    }

    // Update object dependencies
    if (pi_port != nullptr) {
        m_device->add_object_dependency(pi_port, this);
    }

    if (system_port != nullptr) {
        m_device->add_object_dependency(system_port, this);
    }

    if (m_stack_port != nullptr) {
        m_device->add_object_dependency(m_stack_port, this);
        auto spa_port = m_stack_port->get_spa_port();
        if (spa_port != nullptr) {
            bit_vector registered_attributes((la_uint64_t)attribute_management_op::SPA_MEMBERSHIP_CHANGED);
            m_device->add_attribute_dependency(spa_port, this, registered_attributes);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::initialize(la_object_id_t oid,
                                      la_mirror_gid_t mirror_gid,
                                      const la_npu_host_port_base_wptr& npu_host_port,
                                      la_uint_t voq_offset,
                                      double probability)
{
    transaction txn;
    m_oid = oid;
    if (m_pi_port != nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (npu_host_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    initialize_hw_id_and_encap_ptr(mirror_gid);

    m_mirror_gid = mirror_gid;
    m_npu_host_port = npu_host_port;

    // pfc pilot mirror cmd
    m_pfc_mirroring = pfc_mirror_e::PILOT;

    // MAC address and vlan tag is not used in the datapath but is used in some
    // common init code. Initialize it to some pattern.
    m_mac_addr.flat = 0xdeadbeefcafe;
    m_vlan_tag.raw = 0x123;
    m_voq_offset = voq_offset;
    m_probability = probability;
    m_encap_type = NPL_PUNT_NW_NPU_HOST_ENCAP_TYPE;
    m_system_port_gid = m_npu_host_port->get_system_port()->get_gid();

    txn.status = resolve_final_system_port();
    return_on_error(txn.status);

    txn.status = initialize_common();
    return_on_error(txn.status);

    // Update object dependencies
    if (m_npu_host_port != nullptr) {
        m_device->add_object_dependency(npu_host_port, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::initialize(la_object_id_t oid,
                                      la_mirror_gid_t mirror_gid,
                                      const la_ethernet_port_base_wptr& eth_port,
                                      const la_system_port_base_wptr& system_port,
                                      la_uint_t voq_offset,
                                      double probability)
{
    m_oid = oid;
    transaction txn;
    const la_spa_port* spa;
    const la_system_port* sp;

    if ((m_eth_port != nullptr) || (m_system_port != nullptr)) {
        return LA_STATUS_EEXIST;
    }

    if (eth_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    initialize_hw_id_and_encap_ptr(mirror_gid);

    spa = eth_port->get_spa_port();
    if ((system_port != nullptr) && (spa != nullptr)) {
        system_port_vec_t spa_members;
        txn.status = spa->get_members(spa_members);
        return_on_error(txn.status);

        auto it = std::find(spa_members.begin(), spa_members.end(), system_port.get());
        if (it == spa_members.end()) {
            return LA_STATUS_EINVAL;
        }
        m_system_port_gid = system_port->get_gid();
    } else {
        if (system_port == nullptr) {
            return LA_STATUS_EINVAL;
        }
        sp = eth_port->get_system_port();
        if (sp != system_port.get()) {
            return LA_STATUS_EINVAL;
        }
        m_system_port_gid = sp->get_gid();
    }

    m_mirror_gid = mirror_gid;
    m_eth_port = eth_port;
    m_system_port = system_port;
    m_voq_offset = voq_offset;
    m_probability = probability;
    m_encap_type = NPL_PUNT_NW_NO_ENCAP_TYPE;

    destination_id dest_id = get_mirror_destination_id();
    m_destination = {.val = dest_id.val};

    txn.status = resolve_final_system_port();
    return_on_error(txn.status);

    txn.status = initialize_common();
    return_on_error(txn.status);

    if (m_mirror_type == MIRROR_INGRESS) {
        txn.status = configure_stack_remote_mirror_destination_map(m_mirror_hw_id, m_destination);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_stack_remote_mirror_destination_map(m_mirror_hw_id); });
    }

    // Update object dependencieas
    if (eth_port != nullptr) {
        m_device->add_object_dependency(eth_port, this);
    }
    if (system_port != nullptr) {
        m_device->add_object_dependency(system_port, this);
    }
    if (m_stack_port != nullptr) {
        m_device->add_object_dependency(m_stack_port, this);
        auto spa_port = m_stack_port->get_spa_port();
        if (spa_port != nullptr) {
            bit_vector registered_attributes((la_uint64_t)attribute_management_op::SPA_MEMBERSHIP_CHANGED);
            m_device->add_attribute_dependency(spa_port, this, registered_attributes);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::initialize(la_object_id_t oid,
                                      la_mirror_gid_t mirror_gid,
                                      const la_punt_inject_port_base_wptr& pi_port,
                                      la_uint_t voq_offset,
                                      double probability)
{
    m_oid = oid;
    if (m_pi_port != nullptr) {
        return LA_STATUS_EINVAL;
    }

    initialize_hw_id_and_encap_ptr(mirror_gid);

    m_mirror_gid = mirror_gid;
    m_pi_port = pi_port;
    m_voq_offset = voq_offset;
    m_probability = probability;
    m_encap_type = NPL_PUNT_NW_PFC_ENCAP_TYPE;

    m_mac_addr.flat = 0xdeadbeefcafe;
    m_vlan_tag.raw = 0x123;

    transaction txn;
    txn.status = resolve_final_system_port();
    return_on_error(txn.status);

    m_pfc_mirroring = pfc_mirror_e::MEASUREMENT;

    txn.status = initialize_common();
    return_on_error(txn.status);

    txn.status = configure_redirect_code(m_mirror_gid, NPL_PUNT_NW_PFC_ENCAP_TYPE, m_encap_ptr);
    return_on_error(txn.status);

    // Update object dependencies
    if (pi_port != nullptr) {
        m_device->add_object_dependency(pi_port, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::destroy()
{
    la_status status = LA_STATUS_SUCCESS;

    switch (m_mirror_type) {
    case MIRROR_EGRESS: {
        if ((m_encap_type != NPL_PUNT_NW_PFC_ENCAP_TYPE) && (m_encap_type != NPL_PUNT_NW_NPU_HOST_ENCAP_TYPE)) {
            status = remove_recycle_override_entry(m_mirror_hw_id);
            return_on_error(status);
        }

        status = teardown_recycle_slice_entry(m_mirror_hw_id);
        return_on_error(status);

        break;
    }
    case MIRROR_INGRESS: {
        if ((m_encap_type == NPL_PUNT_NW_PFC_ENCAP_TYPE) || (m_encap_type == NPL_PUNT_NW_NO_ENCAP_TYPE)) {
            status = teardown_ibm_uc_cmd_to_encap_data_table(m_mirror_hw_id);
            return_on_error(status);
        }

        status = teardown_mirror_to_dsp_in_npu_soft_header_table();
        return_on_error(status);

        status = teardown_cud_entry(m_mirror_hw_id);
        return_on_error(status);

        status = m_device->clear_mirror_code_to_ibm(m_mirror_hw_id);
        return_on_error(status);

        status = teardown_stack_remote_mirror_destination_map(m_mirror_gid);
        return_on_error(status);

        break;
    }
    default:
        break;
    }

    if ((m_encap_type == NPL_PUNT_NW_ETH_ENCAP_TYPE) || (m_encap_type == NPL_PUNT_NW_PFC_ENCAP_TYPE)) {
        if ((!m_is_mc_lpts) && (m_stack_port == nullptr)) {
            status = m_device->clear_redirect_eth_encap(m_encap_ptr);
            return_on_error(status);
        }
    }

    status = m_device->clear_rx_obm_punt_src_and_code(m_mirror_gid, NPL_PUNT_SRC_INBOUND_MIRROR);
    return_on_error(status);

    status = m_device->clear_rx_obm_punt_src_and_code(m_mirror_gid, NPL_PUNT_SRC_OUTBOUND_MIRROR);
    return_on_error(status);

    if (m_meter != nullptr) {
        status = m_meter->detach_user(m_device->get_sptr(this));
        return_on_error(status);
        m_meter = nullptr;
    }

    if (m_counter != nullptr) {
        const la_system_port_base* sp_impl = get_system_port();
        if (sp_impl == nullptr) {
            return LA_STATUS_EINVAL;
        }

        for (auto slice_ifg : get_ifgs()) {
            status = teardown_mirror_egress_attributes_table(slice_ifg.slice);
            return_on_error(status);
        }
    }

    // Remove object dependencies
    if (m_pi_port != nullptr) {
        m_device->remove_object_dependency(m_pi_port, this);
        m_pi_port = nullptr;
    }
    if (m_system_port != nullptr) {
        m_device->remove_object_dependency(m_system_port, this);
        m_system_port = nullptr;
    }
    if (m_eth_port != nullptr) {
        m_device->remove_object_dependency(m_eth_port, this);
        m_eth_port = nullptr;
    }
    if (m_npu_host_port != nullptr) {
        m_device->remove_object_dependency(m_npu_host_port, this);
        m_npu_host_port = nullptr;
    }
    if (m_stack_port != nullptr) {
        auto spa_port = m_stack_port->get_spa_port();
        if (spa_port != nullptr) {
            bit_vector registered_attributes((la_uint64_t)attribute_management_op::SPA_MEMBERSHIP_CHANGED);
            m_device->remove_attribute_dependency(spa_port, this, registered_attributes);
        }
        m_device->remove_object_dependency(m_stack_port, this);
        m_stack_port = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_mirror_gid_t
la_l2_mirror_command_base::get_gid() const
{
    return m_mirror_gid;
}

la_status
la_l2_mirror_command_base::get_mac(la_mac_addr_t& out_mac_addr) const
{
    out_mac_addr.flat = m_mac_addr.flat;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::get_vlan_tag(la_vlan_tag_tci_t& out_vlan_tag) const
{
    out_vlan_tag.raw = m_vlan_tag.raw;

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_l2_mirror_command_base::type() const
{
    return object_type_e::L2_MIRROR_COMMAND;
}

const la_device*
la_l2_mirror_command_base::get_device() const
{
    return m_device.get();
}

std::string
la_l2_mirror_command_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_l2_mirror_command_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_l2_mirror_command_base::oid() const
{
    return m_oid;
}

const la_punt_inject_port*
la_l2_mirror_command_base::get_punt_inject_port() const
{
    return m_pi_port.get();
}

const la_system_port_base*
la_l2_mirror_command_base::get_system_port() const
{
    const la_system_port_base* sp_impl;

    if (m_pi_port != nullptr) {
        sp_impl = static_cast<const la_system_port_base*>(m_pi_port->get_system_port());
    } else if (m_system_port != nullptr) {
        sp_impl = static_cast<const la_system_port_base*>(m_system_port.get());
    } else {
        sp_impl = nullptr;
    }

    return sp_impl;
}

mirror_type_e
la_l2_mirror_command_base::get_mirror_type() const
{
    return m_mirror_type;
}

slice_ifg_vec_t
la_l2_mirror_command_base::get_ifgs() const
{
    if (m_pi_port != nullptr) {
        return m_pi_port->get_ifgs();
    }

    dassert_crit(m_system_port != nullptr);
    auto actual_dsp = get_actual_dsp(m_system_port);
    la_slice_ifg slice_ifg = {.slice = actual_dsp->get_slice(), .ifg = actual_dsp->get_ifg()};

    slice_ifg_vec_t slice_ifg_vec;
    slice_ifg_vec.push_back(slice_ifg);
    return slice_ifg_vec;
}

la_status
la_l2_mirror_command_base::set_probability(double probability)
{
    start_api_call("probability=", probability);

    if ((probability < 0.0) || (probability > 1.0f)) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t sampling_rate = calculate_probability(probability);
    la_status status = configure_ibm_command_and_rx_obm_table(sampling_rate);
    return_on_error(status);

    m_probability = probability;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::get_probability(double& out_probability) const
{
    out_probability = m_probability;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::configure_ibm_command_and_rx_obm_table(la_uint_t sampling_rate)
{
    auto sp_impl = static_cast<const la_system_port_base*>(m_final_system_port.get());

    if (sp_impl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_system_port_wcptr rcy_sp;
    if ((m_pi_port != nullptr) && (m_stack_port == nullptr)) {
        rcy_sp = m_pi_port->get_actual_system_port();
    }
    auto rcy_sp_base = rcy_sp.weak_ptr_static_cast<const la_system_port_base>();

    la_status status = (rcy_sp_base)
                           ? rcy_sp_base->configure_ibm_command(m_mirror_hw_id, sampling_rate, m_mirror_to_dest, m_voq_offset)
                           : sp_impl->configure_ibm_command(m_mirror_hw_id, sampling_rate, m_mirror_to_dest, m_voq_offset);

    return_on_error(status);

    bool recycle = ((m_stack_port == nullptr)
                    && ((m_pi_port != nullptr) || (sp_impl->get_port_type() == la_system_port_base::port_type_e::PCI)));
    if (recycle) {
        npl_punt_source_e punt_source
            = (m_mirror_type == MIRROR_INGRESS) ? NPL_PUNT_SRC_INBOUND_MIRROR : NPL_PUNT_SRC_OUTBOUND_MIRROR;

        la_voq_set* voq_set = sp_impl->get_voq_set();
        la_voq_gid_t voq_id = voq_set->get_base_voq_id() + m_voq_offset;

        status = configure_rx_obm_punt_src_and_code(punt_source, voq_id);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::set_voq_offset(la_uint_t voq_offset)
{
    start_api_call("voq_offset=", voq_offset);

    if (voq_offset >= NUM_OQ_PER_PIF) {
        return LA_STATUS_EINVAL;
    }

    if (m_voq_offset == voq_offset) {
        return LA_STATUS_SUCCESS;
    }

    m_voq_offset = voq_offset;

    la_uint_t sampling_rate = calculate_probability(m_probability);
    la_status status = configure_ibm_command_and_rx_obm_table(sampling_rate);
    return_on_error(status);

    status = configure_recycle_slice_entry(m_mirror_gid);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_uint_t
la_l2_mirror_command_base::get_voq_offset() const
{
    start_api_getter_call();
    return m_voq_offset;
}

la_status
la_l2_mirror_command_base::set_mirror_to_dest(bool mirror_to_dest)
{
    start_api_call("mirror_to_dest=", mirror_to_dest);

    auto sp_impl = m_device->get_sptr<const la_system_port_base>(m_pi_port->get_system_port());
    if (sp_impl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t sampling_rate = calculate_probability(m_probability);
    la_status status = sp_impl->configure_ibm_command(m_mirror_gid, sampling_rate, mirror_to_dest, m_voq_offset);
    return_on_error(status);

    m_mirror_to_dest = mirror_to_dest;

    return LA_STATUS_SUCCESS;
}

bool
la_l2_mirror_command_base::get_mirror_to_dest(void) const
{
    return m_mirror_to_dest;
}

bool
la_l2_mirror_command_base::get_truncate(void) const
{
    return m_truncate;
}

la_status
la_l2_mirror_command_base::add_l2_mirror_command_counter(la_counter_set* counter)
{
    if (counter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (!of_same_device(counter, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    size_t counter_set_size = counter->get_set_size();
    if (counter_set_size != 1) {
        return LA_STATUS_EINVAL;
    }

    la_counter_set* prev_counter = m_counter.get();
    if (counter == prev_counter) {
        return LA_STATUS_SUCCESS;
    }

    la_counter_set_impl* counter_impl = static_cast<la_counter_set_impl*>(counter);
    la_status status = counter_impl->add_pq_counter_user(
        m_device->get_sptr(this), la_counter_set::type_e::PORT, COUNTER_DIRECTION_EGRESS, true /*is_aggregate*/);
    return_on_error(status);

    m_device->add_object_dependency(counter_impl, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::remove_l2_mirror_command_counter()
{
    la_counter_set* counter = m_counter.get();

    if (counter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_counter_set_impl* counter_impl = static_cast<la_counter_set_impl*>(counter);
    m_device->remove_object_dependency(counter_impl, this);

    la_status status = counter_impl->remove_pq_counter_user(m_device->get_sptr(this));
    return_on_error(status);

    m_counter = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::configure_mirror_egress_attributes_table(la_slice_id_t slice, la_counter_set* counter)
{
    npl_mirror_egress_attributes_table_t::key_type k1;
    npl_mirror_egress_attributes_table_t::key_type k2;
    npl_mirror_egress_attributes_table_t::value_type v;
    npl_mirror_egress_attributes_table_t::entry_pointer_type e = nullptr;

    k1.mirror_code = m_mirror_gid;
    k1.is_ibm.val = NPL_TRUE_VALUE;
    k2.mirror_code = m_mirror_gid;
    k2.is_ibm.val = NPL_FALSE_VALUE;
    v.payloads.set_mirror_egress_attributes.counter
        = populate_counter_ptr_slice(m_device->get_sptr(counter), slice, COUNTER_DIRECTION_EGRESS);

    la_status status = m_device->m_tables.mirror_egress_attributes_table[slice]->set(k1, v, e);
    return_on_error(status);

    status = m_device->m_tables.mirror_egress_attributes_table[slice]->set(k2, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::teardown_mirror_egress_attributes_table(la_slice_id_t slice)
{
    npl_mirror_egress_attributes_table_t::key_type k;

    for (auto is_ibm : {NPL_TRUE_VALUE, NPL_FALSE_VALUE}) {
        k.mirror_code = m_mirror_gid;
        k.is_ibm.val = is_ibm;
        la_status status = m_device->m_tables.mirror_egress_attributes_table[slice]->erase(k);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::do_set_counter(la_counter_set* counter)
{
    la_status status = add_l2_mirror_command_counter(counter);
    return_on_error(status);

    const la_system_port_base* sp_impl = get_system_port();

    if (sp_impl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    for (auto slice_ifg : get_ifgs()) {
        status = configure_mirror_egress_attributes_table(slice_ifg.slice, counter);
        if (status != LA_STATUS_SUCCESS) {
            remove_l2_mirror_command_counter();
            return status;
        }
    }

    // Remove the previous counter
    la_counter_set* prev_counter = m_counter.get();
    if (prev_counter != counter) {
        la_status status = remove_l2_mirror_command_counter();
        return_on_error(status);
    }

    m_counter = m_device->get_sptr(counter);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::set_counter(la_counter_set* counter)
{
    start_api_call("counter=", counter);

    return do_set_counter(counter);
}

la_status
la_l2_mirror_command_base::get_counter(la_counter_set*& out_counter) const
{
    start_api_getter_call();

    out_counter = m_counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::teardown_ibm_uc_cmd_to_encap_data_table(la_uint_t key)
{
    npl_ibm_uc_cmd_to_encap_data_table_t::key_type k;
    k.tx_fabric_tx_cud_4_0_ = key;

    const auto& tables(m_device->m_tables.ibm_uc_cmd_to_encap_data_table);
    la_status status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k);

    return status;
}

la_status
la_l2_mirror_command_base::configure_ibm_uc_cmd_to_encap_data_table(la_uint_t key)
{
    npl_ibm_uc_cmd_to_encap_data_table_t::key_type k;
    npl_ibm_uc_cmd_to_encap_data_table_t::value_type v;

    k.tx_fabric_tx_cud_4_0_ = key;
    v.action = NPL_IBM_UC_CMD_TO_ENCAP_DATA_TABLE_ACTION_WRITE;

    la_uint_t encap_ptr;
    la_uint_t mirror_or_redirect_code;

    if (m_encap_type == NPL_PUNT_NW_NO_ENCAP_TYPE) {
        mirror_or_redirect_code = key;
        encap_ptr = 0;
    } else {
        mirror_or_redirect_code = NPL_REDIRECT_CODE_PFC_MEASUREMENT;
        encap_ptr = m_encap_ptr;
    }

    npl_punt_encap_data_t& punt_encap_data(v.payloads.ibm_uc_fabric_encap.punt_encap_data);
    la_status status = populate_punt_encap_data(mirror_or_redirect_code, punt_encap_data, encap_ptr);

    return_on_error(status);
    const auto& tables(m_device->m_tables.ibm_uc_cmd_to_encap_data_table);
    status = per_slice_tables_insert(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);

    return status;
}

la_status
la_l2_mirror_command_base::configure_redirect_encap(la_uint_t encap_ptr)
{
    la_mac_addr_t port_mac_addr;
    la_status status;

    if (m_is_mc_lpts || (m_stack_port != nullptr)) {
        return LA_STATUS_SUCCESS;
    }

    if (m_pi_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (m_encap_type == NPL_PUNT_NW_PFC_ENCAP_TYPE) {
        port_mac_addr.flat = (0x12345678LL << 16) | (NPL_FI_MACRO_ID_OAMP << 8) | (NPL_PFC_AA_RECEIVE_MACRO);
    } else {
        status = m_pi_port->get_mac(port_mac_addr);
        return_on_error(status);
    }

    status = m_device->configure_redirect_eth_encap(encap_ptr, m_mac_addr, port_mac_addr, m_vlan_tag);
    return status;
}

la_status
la_l2_mirror_command_base::configure_recycle_slice_entry(la_uint_t mirror_hw_id)
{
    npl_rx_obm_code_table_key_t k;
    npl_rx_obm_code_table_value_t v;

    populate_rx_obm_code_table_key(mirror_hw_id, k);

    v.payloads.rx_obm_action.phb.tc = 0;
    v.payloads.rx_obm_action.phb.dp = 0;
    v.payloads.rx_obm_action.destination = m_destination;
    v.payloads.rx_obm_action.punt_encap_data_lsb.punt_nw_encap_type = m_encap_type;
    if (m_encap_type != NPL_PUNT_NW_NO_ENCAP_TYPE) {
        v.payloads.rx_obm_action.punt_encap_data_lsb.punt_nw_encap_ptr.ptr = mirror_hw_id;
    }
    v.payloads.rx_obm_action.punt_encap_data_lsb.punt_controls.mirror_local_encap_format = 0; // outbound mirror

    const auto& tables(m_device->m_tables.rx_obm_code_table);
    la_status status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return status;
}

la_status
la_l2_mirror_command_base::teardown_recycle_slice_entry(la_uint_t mirror_hw_id)
{
    npl_rx_obm_code_table_key_t k;
    populate_rx_obm_code_table_key(mirror_hw_id, k);

    const auto& tables(m_device->m_tables.rx_obm_code_table);
    la_status status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k);

    return status;
}

la_status
la_l2_mirror_command_base::set_meter(const la_meter_set* meter)
{
    start_api_call("meter=", meter);

    if ((meter != nullptr) && (!of_same_device(meter, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Supports only statistical meter.
    if ((meter != nullptr) && (meter->get_type() != la_meter_set::type_e::STATISTICAL)) {
        log_err(HLD, "Only STATISTICAL meter is valid for the mirror session.");
        return LA_STATUS_EINVAL;
    }

    auto meter_set_impl = const_cast<la_meter_set_impl*>(static_cast<const la_meter_set_impl*>(meter));

    if ((meter_set_impl != nullptr) && (meter_set_impl->get_set_size() != 1)) {
        log_err(HLD, "meter-set size %lu is not valid for the mirror session.", meter_set_impl->get_set_size());
        return LA_STATUS_EINVAL;
    }

    // Meter supported only on the pi port going to PCI/DMA
    if (m_pi_port == nullptr) {
        log_err(HLD, "PI port is null for the mirror session.");
        return LA_STATUS_EINVAL;
    }

    if (m_meter.get() == meter_set_impl) {
        return LA_STATUS_SUCCESS;
    }

    transaction txn;
    if (meter != nullptr) {
        // Attach to the new meter
        txn.status = meter_set_impl->attach_user(m_device->get_sptr(this), true);
        return_on_error(txn.status);
        txn.on_fail([=]() { meter_set_impl->detach_user(m_device->get_sptr(this)); });
    }

    // Detach from the current meter
    if (m_meter != nullptr) {
        txn.status = m_meter->detach_user(m_device->get_sptr(this));
        return_on_error(txn.status);
    }

    m_meter = m_device->get_sptr(meter_set_impl);

    la_uint_t sampling_rate = calculate_probability(m_probability);
    txn.status = configure_ibm_command_and_rx_obm_table(sampling_rate);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::get_meter(const la_meter_set*& out_meter) const
{
    out_meter = m_meter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_base::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        if (op.action.attribute_management.op == attribute_management_op::SPA_MEMBERSHIP_CHANGED) {
            la_system_port_base* system_port_base = const_cast<la_system_port_base*>(
                static_cast<const la_system_port_base*>(op.action.attribute_management.spa.sys_port));
            la_system_port_base::port_type_e sys_port_type = system_port_base->get_port_type();
            if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
                if (op.action.attribute_management.spa.is_added == true) {
                    // spa member add
                    break;
                } else {
                    // spa member delete, check if current obj holds reference
                    if (m_final_system_port == system_port_base) {
                        // assign new
                        const la_system_port* stack_sys_port;
                        auto spa_port = m_stack_port->get_spa_port();
                        la_status status = spa_port->get_member(0, stack_sys_port);
                        return_on_error(status);
                        m_final_system_port = m_device->get_sptr<const la_system_port_base>(stack_sys_port);
                        la_uint_t sampling_rate = calculate_probability(m_probability);
                        status = configure_ibm_command_and_rx_obm_table(sampling_rate);
                        return_on_error(status);
                    } else {
                        // not a remote mirror
                        break;
                    }
                }
            } else {
                // remote spa membership change
                break;
            }
        }
        break;
    default:
        break;
    }
    return LA_STATUS_SUCCESS;
}
} // namespace silicon_one
