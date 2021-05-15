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

#include "la_system_port_base.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_base.h"
#include "system/la_remote_port_impl.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/la_voq_set_impl.h"

#include "device_utils_base.h"
#include "hld_utils.h"
#include "hld_utils_base.h"
#include "npu/resolution_utils.h"
#include "tm/la_system_port_scheduler_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"
#include "nplapi/npl_enums.h"

#include <sstream>

namespace silicon_one
{

la_system_port_base_wcptr
la_system_port_base::upcast_from_api(const la_device_impl_wptr& device, const la_system_port* ptr)
{
    return upcast_from_api(device, device->get_sptr(ptr));
}
la_system_port_base_wcptr
la_system_port_base::upcast_from_api(const la_device_impl_wptr& device, la_system_port_wcptr wptr)
{
    return wptr.weak_ptr_static_cast<const la_system_port_base>();
}

la_system_port_base::la_system_port_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_gid(-1),
      m_port_type(port_type_e::INVALID),
      m_destination_device_id(LA_DEVICE_ID_INVALID),
      m_slice_id(LA_SLICE_ID_INVALID),
      m_source_group_offset(0),
      m_ifg_id(LA_IFG_ID_INVALID),
      m_serdes_base(LA_SERDES_INVALID),
      m_pif_base(LA_PIF_INVALID),
      m_pif_count(LA_PIF_INVALID),
      m_ect_voq_set(nullptr),
      m_mc_pruning_high(la_device_impl::SPA_LB_KEY_RANGE_SIZE - 1),
      m_mc_pruning_low(0),
      m_mtu(LA_MTU_MAX),
      m_port_extender_vid(NON_EXTENDED_PORT),
      m_oq_pair_mac_id(0),
      m_mask_eve(false),
      m_pfc_enabled(false),
      m_decrement_ttl(true),
      m_stack_prune(false)
{
}

la_system_port_base::~la_system_port_base()
{
}

la_status
la_system_port_base::destroy_common_local()
{
    la_status status = erase_slice_rx_map_npp_to_ssp();
    return_on_error(status);

    status = release_npp_attributes_index();
    return_on_error(status);

    status = erase_slice_tx_dsp_attributes();
    return_on_error(status);

    if (m_port_extender_vid != NON_EXTENDED_PORT) {
        status = m_mac_port->remove_port_extension(m_port_extender_vid, m_oq_pair_mac_id);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::notify_change(dependency_management_op op)
{
    log_err(HLD, "%s: received unsupported notification (%s)", __PRETTY_FUNCTION__, silicon_one::to_string(op.type_e).c_str());

    return LA_STATUS_EUNKNOWN;
}

la_status
la_system_port_base::initialize(la_object_id_t oid,
                                const la_mac_port_wptr& mac_port,
                                la_system_port_gid_t gid,
                                const la_voq_set_wptr& voq_set,
                                const la_tc_profile_wcptr& tc_profile)
{
    la_status status = pre_initialize(oid, mac_port, gid, voq_set);
    return_on_error(status);

    m_mac_port = mac_port.weak_ptr_static_cast<la_mac_port_base>();
    if (m_mac_port->is_channelized()) {
        return LA_STATUS_EINVAL;
    }

    m_port_type = port_type_e::MAC;
    m_slice_id = m_mac_port->get_slice();
    m_ifg_id = m_mac_port->get_ifg();
    m_serdes_base = m_mac_port->get_first_serdes_id();
    m_pif_base = m_mac_port->get_first_pif_id_internal();
    m_pif_count = m_mac_port->get_num_of_pif();
    m_intf_scheduler = m_device->get_sptr(m_mac_port->get_scheduler());

    status = initialize_common_local(mac_port, voq_set, tc_profile);
    if (status != LA_STATUS_SUCCESS) {
        m_mac_port = nullptr;
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::initialize(la_object_id_t oid,
                                const la_mac_port_wptr& mac_port,
                                la_port_extender_vid_t port_extender_vid,
                                la_system_port_gid_t gid,
                                const la_voq_set_wptr& voq_set,
                                const la_tc_profile_wcptr& tc_profile)
{
    if (port_extender_vid > MAX_PORT_EXTENDER_VID) {
        return LA_STATUS_EINVAL;
    }

    m_mac_port = mac_port.weak_ptr_static_cast<la_mac_port_base>();
    if (!(m_mac_port->is_channelized())) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_mac_port->add_port_extension(port_extender_vid, m_oq_pair_mac_id);
    return_on_error(status);

    m_port_extender_vid = port_extender_vid;
    status = pre_initialize(oid, mac_port, gid, voq_set);
    return_on_error(status);

    m_port_type = port_type_e::MAC;
    m_slice_id = m_mac_port->get_slice();
    m_ifg_id = m_mac_port->get_ifg();
    m_serdes_base = m_mac_port->get_first_serdes_id();
    m_pif_base = m_mac_port->get_first_pif_id_internal();
    m_pif_count = m_mac_port->get_num_of_pif();
    m_intf_scheduler = m_device->get_sptr(m_mac_port->get_scheduler());

    status = initialize_common_local(mac_port, voq_set, tc_profile);
    if (status != LA_STATUS_SUCCESS) {
        m_mac_port = nullptr;
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::initialize(la_object_id_t oid,
                                const la_recycle_port_wptr& recycle_port,
                                la_system_port_gid_t gid,
                                const la_voq_set_wptr& voq_set,
                                const la_tc_profile_wcptr& tc_profile)
{
    la_status status = pre_initialize(oid, recycle_port, gid, voq_set);
    return_on_error(status);

    m_recycle_port = recycle_port.weak_ptr_static_cast<la_recycle_port_base>();
    m_port_type = port_type_e::RECYCLE;
    m_slice_id = m_recycle_port->get_slice();
    m_ifg_id = m_recycle_port->get_ifg();
    m_serdes_base = RECYCLE_SERDES_ID;
    m_pif_base = RECYCLE_PIF_ID;
    m_pif_count = 1;
    m_intf_scheduler = m_device->get_sptr(m_recycle_port->get_scheduler());

    status = initialize_common_local(recycle_port, voq_set, tc_profile);
    if (status != LA_STATUS_SUCCESS) {
        m_recycle_port = nullptr;
        return status;
    }

    npl_initial_pd_nw_rx_data_t init_data;
    memset(&init_data, 0, sizeof(npl_initial_pd_nw_rx_data_t)); // Empty struct. We only need slice, ifg and pif.

    status = set_inject_up_entry(init_data);
    if (status != LA_STATUS_SUCCESS) {
        m_recycle_port = nullptr;
        return status;
    }

    status = set_recycled_inject_up_entry();
    if (status != LA_STATUS_SUCCESS) {
        m_recycle_port = nullptr;
        return status;
    }

    const auto& voq_set_impl = voq_set.weak_ptr_static_cast<la_voq_set_impl>();

    status = voq_set_impl->force_local_voq_enable(true);
    return_on_error(status);

    size_t ifg_idx = m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(m_slice_id, m_ifg_id);

    m_device->m_per_ifg_recycle_sp[ifg_idx] = m_device->get_sptr(this); // PACKET-DMA-WA

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::initialize(la_object_id_t oid,
                                const la_npu_host_port_base_wptr& npu_host_port,
                                la_system_port_gid_t gid,
                                const la_voq_set_wptr& voq_set,
                                const la_tc_profile_wcptr& tc_profile)
{
    la_status status = pre_initialize(oid, npu_host_port, gid, voq_set);
    return_on_error(status);

    m_npu_host_port = npu_host_port;
    m_port_type = port_type_e::NPU_HOST;
    auto s_ifg = m_device->get_slice_id_manager()->get_npu_host_port_ifg();
    m_slice_id = s_ifg.slice;
    m_ifg_id = s_ifg.ifg;
    m_serdes_base = HOST_SERDES_ID;
    m_pif_base = HOST_PIF_ID;
    m_pif_count = 1;
    m_intf_scheduler = m_device->get_sptr(m_npu_host_port->get_scheduler());

    status = initialize_common_local(npu_host_port, voq_set, tc_profile);
    if (status != LA_STATUS_SUCCESS) {
        m_npu_host_port = nullptr;
        return status;
    }

    const auto& voq_set_impl = voq_set.weak_ptr_static_cast<la_voq_set_impl>();

    status = voq_set_impl->force_local_voq_enable(true);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::initialize(la_object_id_t oid,
                                const la_pci_port_wptr& pci_port,
                                la_system_port_gid_t gid,
                                const la_voq_set_wptr& voq_set,
                                const la_tc_profile_wcptr& tc_profile)
{
    return initialize_for_pci(oid, pci_port, gid, voq_set, tc_profile);
}

la_status
la_system_port_base::initialize(la_object_id_t oid,
                                const la_remote_port_wptr& remote_port,
                                la_system_port_gid_t gid,
                                const la_voq_set_wptr& voq_set,
                                const la_tc_profile_wcptr& tc_profile)
{
    la_status status = pre_initialize(oid, remote_port, gid, voq_set);
    return_on_error(status);

    m_remote_port = remote_port.weak_ptr_static_cast<la_remote_port_impl>();
    m_port_type = port_type_e::REMOTE;
    m_slice_id = m_remote_port->get_remote_slice();
    m_ifg_id = m_remote_port->get_remote_ifg();
    m_serdes_base = m_remote_port->get_remote_first_serdes_id();
    m_pif_base = m_remote_port->get_remote_first_pif_id();
    m_pif_count = m_remote_port->get_remote_num_of_pif();
    const la_remote_device* remote_device = m_remote_port->get_remote_device();
    m_destination_device_id = remote_device->get_remote_device_id();
    bool svl_mode = false;
    status = m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (svl_mode == false) {
        status = initialize_common(remote_port, voq_set, tc_profile);
        return_on_error(status);
    } else {
        // Remote ports in SVL mode doesn't require any VOQ settings
        m_device->add_object_dependency(remote_port, this);
        // we should not update DSP attributes
        return LA_STATUS_SUCCESS;
    }

    bool instantiate_remotes = false;
    status = m_device->get_bool_property(la_device_property_e::INSTANTIATE_REMOTE_SYSTEM_PORTS, instantiate_remotes);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (instantiate_remotes) {
        status = set_slice_tx_dsp_attributes();

        la_slice_ifg ifg = {.slice = m_slice_id, .ifg = m_ifg_id};
        status = m_device->notify_ifg_added(this, ifg);

        if (status != LA_STATUS_SUCCESS) {
            erase_slice_tx_dsp_attributes();
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::pre_initialize(la_object_id_t oid,
                                    const la_object_wptr& port,
                                    la_system_port_gid_t gid,
                                    const la_voq_set_wptr& voq_set)
{
    m_oid = oid;
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_device->is_in_use(port) == true && m_port_extender_vid == NON_EXTENDED_PORT) {
        return LA_STATUS_EBUSY;
    }

    bool svl_mode = false;
    la_status status = m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (svl_mode == false) {
        if (voq_set == nullptr) {
            return LA_STATUS_EINVAL;
        }

        if (!of_same_device(voq_set, this)) {
            return LA_STATUS_EDIFFERENT_DEVS;
        }

        const auto& voq_set_impl = voq_set.weak_ptr_static_cast<la_voq_set_impl>();
        if (!voq_set_impl->all_cgm_profiles_assigned()) {
            return LA_STATUS_EINVAL;
        }
    }

    m_ttl_inheritance_mode = la_2_npl_mpls_ttl_inheritance_mode(m_device->get_ttl_inheritance_mode());
    m_gid = gid;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::initialize_common_local(const la_object_wptr& port,
                                             const la_voq_set_wptr& voq_set,
                                             const la_tc_profile_wcptr& tc_profile)
{
    m_destination_device_id = m_device->get_id();

    la_status status = initialize_common(port, voq_set, tc_profile);
    return_on_error(status);

    status = allocate_npp_attributes_index();
    return_on_error(status);

    status = configure_slice_rx_map_npp_to_ssp();
    return_on_error(status);

    std::shared_ptr<la_system_port_scheduler_impl> scheduler;
    status = m_device->create_system_port_scheduler(m_slice_id, m_ifg_id, m_pif_base, m_intf_scheduler, scheduler);
    return_on_error(status);
    m_scheduler = scheduler;

    status = set_slice_tx_dsp_attributes();
    if (status != LA_STATUS_SUCCESS) {
        erase_slice_tx_dsp_attributes();
        return status;
    }

    la_slice_ifg ifg = {.slice = m_slice_id, .ifg = m_ifg_id};
    status = m_device->notify_ifg_added(this, ifg);

    if (status != LA_STATUS_SUCCESS) {
        erase_slice_tx_dsp_attributes();
        return status;
    }

    const auto& voq_set_impl = voq_set.weak_ptr_static_cast<la_voq_set_impl>();

    status = voq_set_impl->force_local_voq_enable(false);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::initialize_common(const la_object_wptr& port,
                                       const la_voq_set_wptr& voq_set,
                                       const la_tc_profile_wcptr& tc_profile)
{
    if (tc_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(tc_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (voq_set == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(voq_set, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_device->is_in_use(voq_set)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = set_voq_mapping(voq_set);
    return_on_error(status);

    m_voq_set = voq_set;

    status = set_tc_profile_core(tc_profile);
    return_on_error(status);

    // If the port type is NPU host, we don't need to create a
    // dependency since there is a dependency in the reverse
    // direction.
    if (m_port_type != port_type_e::NPU_HOST) {
        m_device->add_object_dependency(port, this);
    }

    m_device->add_object_dependency(m_voq_set, this);

    return LA_STATUS_SUCCESS;
}

size_t
la_system_port_base::get_base_oq() const
{
    size_t num_oq_per_ifg;
    if (m_remote_port != nullptr) {
        size_t num_pif_per_ifg = device_utils::get_num_of_pif_per_ifg(m_remote_port->get_remote_device_revision());
        num_oq_per_ifg = (NUM_OQ_PER_PIF * num_pif_per_ifg) + NUM_OQ_PER_PIF + NUM_OQ_PER_PIF;
    } else {
        num_oq_per_ifg = NUM_OQ_PER_IFG;
    }

    auto base = (m_ifg_id * num_oq_per_ifg + m_pif_base * NUM_OQ_PER_PIF + m_oq_pair_mac_id * NUM_OQ_PER_EXTENDED_PORT);

    return (base);
}

la_status
la_system_port_base::is_valid_voq_mapping(const la_voq_set_wptr& voq_set_api) const
{
    auto voq_set = voq_set_api.weak_ptr_static_cast<const la_voq_set_base>();
    if (m_slice_id != voq_set->get_destination_slice()) {
        log_err(
            HLD, "Port's slice doesn't match VOQ set's destination slice (%d != %d)", m_slice_id, voq_set->get_destination_slice());
        return LA_STATUS_EINVAL;
    }

    if (m_ifg_id != voq_set->get_destination_ifg()) {
        log_err(HLD, "Port's IFG doesn't match VOQ set's destination IFG (%d != %d)", m_ifg_id, voq_set->get_destination_ifg());
        return LA_STATUS_EINVAL;
    }

    if (m_destination_device_id != voq_set->get_destination_device()) {
        log_err(HLD,
                "Port's destination device ID doesn't match VOQ set's destination device ID (%d != %d)",
                m_destination_device_id,
                voq_set->get_destination_device());
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(voq_set, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_device->is_in_use(voq_set)) {
        return LA_STATUS_EBUSY;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::clear_voq_mapping(const la_voq_set_wptr& voq_set) const
{
    if (voq_set == nullptr) {
        return LA_STATUS_EINVAL;
    }
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        if (!m_device->is_network_slice(slice_id)) {
            continue;
        }

        const auto& table(m_device->m_tables.filb_voq_mapping[slice_id]);
        npl_filb_voq_mapping_t::key_type key;

        for (size_t voq_offset = 0; voq_offset < voq_set->get_set_size(); voq_offset++) {
            key.rxpdr_output_voq_nr = voq_set->get_base_voq_id() + voq_offset;
            la_status status = table->erase(key);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::set_voq_mapping(const la_voq_set_wptr& voq_set)
{
    la_status status = is_valid_voq_mapping(voq_set);
    return_on_error(status);

    status = program_voq_mapping(voq_set, false /* is_lp */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::set_tc_profile(const la_tc_profile* tc_profile)
{
    start_api_call("tc_profile=", tc_profile);

    return set_tc_profile_core(m_device->get_sptr(tc_profile));
}

la_status
la_system_port_base::allocate_npp_attributes_index()
{
    // Allocate the NPP attributes index
    bool index_allocated = m_device->m_index_generators.slice[m_slice_id].npp_attributes.allocate(m_npp_attributes_index);
    if (!index_allocated) {
        return LA_STATUS_ERESOURCE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::release_npp_attributes_index()
{
    m_device->m_index_generators.slice[m_slice_id].npp_attributes.release(m_npp_attributes_index);

    npl_mac_af_npp_attributes_table_t::key_type key;
    key.npp_attributes_index = m_npp_attributes_index;
    npl_mac_af_npp_attributes_table_t::entry_pointer_type entry_ptr = nullptr;
    la_status status = m_device->m_tables.mac_af_npp_attributes_table[m_slice_id]->lookup(key, entry_ptr);
    if (status == LA_STATUS_SUCCESS) {
        return m_device->m_tables.mac_af_npp_attributes_table[m_slice_id]->erase(key);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::set_mac_af_npp_attributes(const npl_mac_af_npp_attributes_table_t::value_type& value)
{
    npl_mac_af_npp_attributes_table_t::key_type key;
    npl_mac_af_npp_attributes_table_t::entry_pointer_type entry = nullptr;

    // Create the key
    key.npp_attributes_index = m_npp_attributes_index;

    // Update the NPP attributes table
    la_status status = m_device->m_tables.mac_af_npp_attributes_table[m_slice_id]->set(key, value, entry);

    return status;
}

la_status
la_system_port_base::configure_slice_rx_map_npp_to_ssp()
{
    npl_rx_map_npp_to_ssp_table_t::key_type key;
    npl_rx_map_npp_to_ssp_table_t::value_type value;
    npl_rx_map_npp_to_ssp_table_t::entry_pointer_type entry = nullptr;

    key.npp_attributes_index = m_npp_attributes_index;
    value.action = NPL_RX_MAP_NPP_TO_SSP_TABLE_ACTION_WRITE;
    value.payloads.local_npp_to_ssp_result.ssp.ssp_12 = m_gid;
    value.payloads.local_npp_to_ssp_result.ssp.slice_id = m_slice_id;
    value.payloads.local_npp_to_ssp_result.split_voq.split_voq_enabled = (m_source_group_offset != 0);
    value.payloads.local_npp_to_ssp_result.split_voq.source_group_offset = m_source_group_offset;

    return m_device->m_tables.rx_map_npp_to_ssp_table[m_slice_id]->insert(key, value, entry);
}

la_status
la_system_port_base::erase_slice_rx_map_npp_to_ssp()
{
    npl_rx_map_npp_to_ssp_table_t::key_type key;
    key.npp_attributes_index = m_npp_attributes_index;
    la_status status = m_device->m_tables.rx_map_npp_to_ssp_table[m_slice_id]->erase(key);

    return status;
}

la_system_port_gid_t
la_system_port_base::get_gid() const
{
    return m_gid;
}

la_status
la_system_port_base::get_port_extended_vid(la_port_extender_vid_t& out_port_extender_vid) const
{
    if (m_port_extender_vid == NON_EXTENDED_PORT) {
        return LA_STATUS_EINVAL;
    }

    out_port_extender_vid = m_port_extender_vid;
    return LA_STATUS_SUCCESS;
}

la_system_port_scheduler*
la_system_port_base::get_scheduler() const
{
    return m_scheduler.get();
}

la_voq_set*
la_system_port_base::get_voq_set() const
{
    return m_voq_set.get();
}

la_status
la_system_port_base::set_ect_voq_set(la_voq_set* voq_set)
{
    start_api_call("voq_set=", voq_set);

    bool ecn_queuing_enabled = false;
    la_status status = m_device->get_bool_property(la_device_property_e::ENABLE_ECN_QUEUING, ecn_queuing_enabled);
    return_on_error(status);

    if (!ecn_queuing_enabled) {
        return LA_STATUS_EINVAL;
    }

    if (m_port_type != port_type_e::MAC) {
        return LA_STATUS_EINVAL;
    }

    if (m_mac_port->is_channelized()) {
        return LA_STATUS_EINVAL;
    }

    if (voq_set == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(voq_set, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_device->is_in_use(voq_set)) {
        return LA_STATUS_EBUSY;
    }

    const la_voq_set_wptr& voq_set_wptr = m_device->get_sptr(voq_set);
    const auto& voq_set_impl = voq_set_wptr.weak_ptr_static_cast<la_voq_set_impl>();
    if (!voq_set_impl->all_cgm_profiles_assigned()) {
        return LA_STATUS_EINVAL;
    }

    status = set_voq_mapping(voq_set_wptr);
    return_on_error(status);

    status = voq_set_impl->force_local_voq_enable(false);
    return_on_error(status);

    if (m_ect_voq_set != nullptr) {
        m_device->remove_object_dependency(m_ect_voq_set, this);
    }

    m_ect_voq_set = voq_set_wptr;

    status = set_tc_profile_core(m_tc_profile);
    return_on_error(status);

    m_device->add_object_dependency(m_ect_voq_set, this);

    return LA_STATUS_SUCCESS;
}

la_voq_set*
la_system_port_base::get_ect_voq_set() const
{
    return m_ect_voq_set.get();
}

la_object::object_type_e
la_system_port_base::type() const
{
    return object_type_e::SYSTEM_PORT;
}

std::string
la_system_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_system_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_system_port_base::oid() const
{
    return m_oid;
}

const la_device*
la_system_port_base::get_device() const
{
    return m_device.get();
}

la_slice_id_t
la_system_port_base::get_slice() const
{
    return m_slice_id;
}

la_voq_gid_t
la_system_port_base::get_base_voq() const
{
    return m_voq_set->get_base_voq_id();
}

la_voq_gid_t
la_system_port_base::get_ect_voq_base() const
{
    bool ecn_queuing_enabled = false;
    la_status status = m_device->get_bool_property(la_device_property_e::ENABLE_ECN_QUEUING, ecn_queuing_enabled);
    if (status != LA_STATUS_SUCCESS) {
        return (la_device_impl::MAX_VOQS_PER_NETWORK_SLICE - 1);
    }

    if (!ecn_queuing_enabled) {
        return (la_device_impl::MAX_VOQS_PER_NETWORK_SLICE - 1);
    }

    if (m_ect_voq_set == nullptr) {
        return (la_device_impl::MAX_VOQS_PER_NETWORK_SLICE - 1);
    }

    return m_ect_voq_set->get_base_voq_id();
}

la_uint_t
la_system_port_base::get_base_serdes() const
{
    return m_serdes_base;
}

la_uint_t
la_system_port_base::get_base_pif() const
{
    return m_pif_base;
}

la_object*
la_system_port_base::get_underlying_port() const
{
    if (m_mac_port != nullptr)
        return m_mac_port.get();
    if (m_recycle_port != nullptr)
        return m_recycle_port.get();
    if (m_pci_port != nullptr)
        return m_pci_port.get();
    if (m_remote_port != nullptr)
        return m_remote_port.get();
    if (m_npu_host_port != nullptr)
        return m_npu_host_port.get();
    return nullptr;
}

la_status
la_system_port_base::mac_port_reconfig_handler(la_mac_port::port_speed_e mac_port_speed)
{
    la_status status = m_scheduler->update_port_speed(mac_port_speed);
    return_on_error(status, HLD, ERROR, "%s::%s(...); failed to update port speed", silicon_one::to_string(this).c_str(), __func__);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::is_test_mode_punt_to_egress(bool& test_mode_punt_to_egress)
{
    la_status status
        = m_device->get_bool_property(la_device_property_e::TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST, test_mode_punt_to_egress);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::set_slice_tx_dsp_attributes()
{
    if (m_port_type == port_type_e::REMOTE) {
        return LA_STATUS_SUCCESS;
    }

    // Configure common layers
    npl_dsp_attr_common_t common_attributes;

    populate_common_dsp_attributes(common_attributes);

    // Configure l2 attributes
    npl_dsp_l2_attributes_table_t::key_type l2_key;
    npl_dsp_l2_attributes_table_t::value_type l2_value;
    npl_dsp_l2_attributes_table_t::entry_pointer_type l2_entry = nullptr;

    l2_value.action = NPL_DSP_L2_ATTRIBUTES_TABLE_ACTION_WRITE;
    l2_value.payloads.dsp_l2_attributes.mc_pruning_low = m_mc_pruning_low;
    l2_value.payloads.dsp_l2_attributes.mc_pruning_high = m_mc_pruning_high;
    l2_value.payloads.dsp_l2_attributes.dsp_attr_common = common_attributes;

    for (la_uint_t offset = 0; offset < m_pif_count; offset++) {
        la_status status = calculate_network_txpp(l2_key, offset);
        status = m_device->m_tables.dsp_l2_attributes_table[m_slice_id]->set(l2_key, l2_value, l2_entry);
        if (status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    // Configure l3 attributes
    npl_dsp_l3_attributes_table_t::key_type l3_key;
    npl_dsp_l3_attributes_table_t::value_type l3_value;
    npl_dsp_l3_attributes_table_t::entry_pointer_type l3_entry = nullptr;

    l3_value.action = NPL_DSP_L3_ATTRIBUTES_TABLE_ACTION_WRITE;
    l3_value.payloads.dsp_l3_attributes.mpls_ip_ttl_propagation = m_ttl_inheritance_mode;
    l3_value.payloads.dsp_l3_attributes.mtu = m_mtu;
    l3_value.payloads.dsp_l3_attributes.no_decrement_ttl = !m_decrement_ttl;
    l3_value.payloads.dsp_l3_attributes.dsp_attr_common = common_attributes;

    for (la_uint_t offset = 0; offset < m_pif_count; offset++) {
        la_status status = calculate_network_txpp(l3_key, offset);
        status = m_device->m_tables.dsp_l3_attributes_table[m_slice_id]->set(l3_key, l3_value, l3_entry);
        if (status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::set_mask_eve(bool mask_eve)
{
    if (m_port_type != port_type_e::MAC) {
        return LA_STATUS_SUCCESS;
    }

    m_mask_eve = mask_eve;
    return set_slice_tx_dsp_attributes();
}

la_status
la_system_port_base::set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode)
{
    if ((m_port_type != port_type_e::MAC) && (m_port_type != port_type_e::PCI) && (m_port_type != port_type_e::RECYCLE)) {
        return LA_STATUS_SUCCESS;
    }

    m_ttl_inheritance_mode = la_2_npl_mpls_ttl_inheritance_mode(mode);
    return set_slice_tx_dsp_attributes();
}

la_mpls_ttl_inheritance_mode_e
la_system_port_base::get_ttl_inheritance_mode() const
{
    la_mpls_ttl_inheritance_mode_e curr_mode = npl_2_la_mpls_ttl_inheritance_mode(m_ttl_inheritance_mode);

    return curr_mode;
}

la_mtu_t
la_system_port_base::get_mtu() const
{
    return m_mtu;
}

la_status
la_system_port_base::erase_slice_tx_dsp_attributes()
{
    npl_dsp_l2_attributes_table_t::key_type l2_key;
    npl_dsp_l3_attributes_table_t::key_type l3_key;

    for (la_uint_t offset = 0; offset < m_pif_count; offset++) {
        la_status status;
        status = calculate_network_txpp(l2_key, offset);
        return_on_error(status);
        status = calculate_network_txpp(l3_key, offset);
        return_on_error(status);

        status = m_device->m_tables.dsp_l2_attributes_table[m_slice_id]->erase(l2_key);
        return_on_error(status);

        status = m_device->m_tables.dsp_l3_attributes_table[m_slice_id]->erase(l3_key);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::erase_source_pif_table_entries()
{
    la_uint_t num_of_entries = (m_port_extender_vid == NON_EXTENDED_PORT) ? m_pif_count : 1;
    for (la_uint_t pif_offset = 0; pif_offset < num_of_entries; pif_offset++) {
        la_status status = (m_port_extender_vid == NON_EXTENDED_PORT) ? erase_pif_source_pif_table_entry(m_pif_base + pif_offset)
                                                                      : erase_port_extender_map_rx_data_table();
        if (status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EUNKNOWN;
        }
    }
    return LA_STATUS_SUCCESS;
}

uint64_t
la_system_port_base::get_npp_attributes_index() const
{
    return m_npp_attributes_index;
}

la_system_port_base::port_type_e
la_system_port_base::get_port_type() const
{
    return m_port_type;
}

la_ifg_id_t
la_system_port_base::get_ifg() const
{
    return m_ifg_id;
}

const la_tc_profile*
la_system_port_base::get_tc_profile() const
{
    return m_tc_profile.get();
}

bool
la_system_port_base::has_port_dependency() const
{
    bool found = false;
    auto depend_list = m_device->get_dependent_objects(this);

    for (auto& dependent : depend_list) {
        la_object::object_type_e object_type = dependent->type();
        switch (object_type) {
        case la_object::object_type_e::BFD_SESSION:
        case la_object::object_type_e::NPU_HOST_PORT:
            /* Allow BFD_SESSION and NPUH port to be dependent */
            break;
        case la_object::object_type_e::SYSTEM_PORT: {
            auto dependent_sys_port = static_cast<la_system_port_base*>(dependent);
            if (dependent_sys_port->m_pci_port == nullptr) {
                found = true;
            }
        } break;
        default:
            found = true;
            break;
        }
    }

    return found;
}

la_status
la_system_port_base::set_decrement_ttl(bool decrement_ttl)
{
    m_decrement_ttl = decrement_ttl;
    return set_slice_tx_dsp_attributes();
}

bool
la_system_port_base::get_decrement_ttl() const
{
    return m_decrement_ttl;
}

la_status
la_system_port_base::set_stack_prune(bool prune)
{
    m_stack_prune = prune;
    return set_slice_tx_dsp_attributes();
}

la_status
la_system_port_base::get_stack_prune(bool& prune) const
{
    prune = m_stack_prune;
    return LA_STATUS_SUCCESS;
}

la_system_port_base_wcptr
la_system_port_base::get_punt_recycle_port() const
{
    return m_punt_recycle_port;
}

la_slice_id_t
la_system_port_base::get_default_punt_slice() const
{
    la_slice_id_t slice = 0;
    return slice;
}

void
la_system_port_base::populate_rx_obm_code_key_value(bool is_sched_rcy,
                                                    npl_rx_obm_code_table_key_t& out_key,
                                                    npl_rx_obm_code_table_value_t& out_value) const
{
    destination_id dest_id = destination_id(NPL_DESTINATION_MASK_DSP | m_gid);
    npl_destination_t dest{.val = dest_id.val};

    bit_vector64_t key_bv(is_sched_rcy ? NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_SCHEDULED_RCY_DMA_PORT
                                       : NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT);
    out_key.unpack(key_bv);
    out_value.payloads.rx_obm_action.phb.tc = 0; // TODO
    out_value.payloads.rx_obm_action.phb.dp = 0; // TODO
    out_value.payloads.rx_obm_action.destination = dest;
    out_value.payloads.rx_obm_action.punt_encap_data_lsb.punt_nw_encap_ptr.ptr = 0; // TODO
    out_value.payloads.rx_obm_action.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_HOST_DMA_ENCAP_TYPE;
    out_value.payloads.rx_obm_action.punt_encap_data_lsb.punt_controls.mirror_local_encap_format = 0; // Not inbound mirror
}

la_status
la_system_port_base::set_slice_rx_obm_code()
{
    dassert_crit(m_port_type == port_type_e::PCI);

    la_status status = do_set_slice_rx_obm_code(m_punt_recycle_port);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::do_set_slice_rx_obm_code(const la_system_port_base_wcptr& recycle_sys_port)
{
    dassert_crit(recycle_sys_port->get_port_type() == port_type_e::RECYCLE);

    // Populate table's key and value
    npl_rx_obm_code_table_key_t key;
    npl_rx_obm_code_table_value_t value;
    populate_rx_obm_code_key_value(true /*is_sched_rcy*/, key, value);

    // Configure the table
    la_slice_id_t rcy_port_slice = recycle_sys_port->get_slice();
    const auto& table(m_device->m_tables.rx_obm_code_table[rcy_port_slice]);
    npl_rx_obm_code_table_entry_t* entry = nullptr;
    la_status status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::set_rx_obm_code_for_tests()
{
    dassert_crit(m_port_type == port_type_e::PCI);

    // In case we are in HW unit testing - need to redirect non-sched recycled packets to pci port
    bool test_mode_punt_to_egress = false;
    auto status = is_test_mode_punt_to_egress(test_mode_punt_to_egress);
    return_on_error(status);

    if (!test_mode_punt_to_egress) {
        return LA_STATUS_SUCCESS;
    }

    // Populate table's key and value
    npl_rx_obm_code_table_key_t key;
    npl_rx_obm_code_table_value_t value;
    populate_rx_obm_code_key_value(false /*is_sched_rcy*/, key, value);

    // Send all output packets to PCI port on slice 0
    const auto& tables(m_device->m_tables.rx_obm_code_table);
    if (m_slice_id == get_default_punt_slice()) {
        status = per_slice_tables_insert(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK}, key, value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::erase_slice_rx_obm_code()
{
    dassert_crit(m_port_type == port_type_e::PCI);

    la_status status = do_erase_slice_rx_obm_code(m_punt_recycle_port);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::do_erase_slice_rx_obm_code(const la_system_port_base_wcptr& recycle_sys_port)
{
    dassert_crit(recycle_sys_port.weak_ptr_static_cast<const la_system_port_base>()->get_port_type() == port_type_e::RECYCLE);

    npl_rx_obm_code_table_key_t key;
    npl_rx_obm_code_table_value_t dummy_value;
    populate_rx_obm_code_key_value(true /*is_sched_rcy*/, key, dummy_value);

    auto rcy_port_slice = recycle_sys_port->get_slice();
    const auto& table(m_device->m_tables.rx_obm_code_table[rcy_port_slice]);
    la_status status = table->erase(key);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::erase_rx_obm_code_for_tests()
{
    dassert_crit(m_port_type == port_type_e::PCI);

    bool test_mode_punt_to_egress = false;
    auto status = is_test_mode_punt_to_egress(test_mode_punt_to_egress);
    return_on_error(status);

    if (!test_mode_punt_to_egress) {
        return LA_STATUS_SUCCESS;
    }

    npl_rx_obm_code_table_key_t key;
    npl_rx_obm_code_table_value_t dummy_value;
    populate_rx_obm_code_key_value(false /*is_sched_rcy*/, key, dummy_value);

    // TODO change : all slices should point at pci port in slice 0
    const auto& tables(m_device->m_tables.rx_obm_code_table);
    if (m_slice_id == get_default_punt_slice()) {
        status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK}, key);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::update_npp_sgt_attributes(la_sgt_t security_group_tag)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_base::update_dsp_sgt_attributes(bool security_group_policy_enforcement)
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
