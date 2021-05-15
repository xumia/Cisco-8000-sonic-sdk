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

#include "la_vxlan_next_hop_base.h"
#include "api/npu/la_l3_port.h"
#include "nplapi/npl_constants.h"
#include "nplapi/nplapi_tables.h"
#include "npu/counter_utils.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_switch_impl.h"
#include "npu/resolution_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_vxlan_next_hop_base::la_vxlan_next_hop_base(const la_device_impl_wptr& device) : m_device(device)
{
}

la_vxlan_next_hop_base::~la_vxlan_next_hop_base()
{
}

la_object::object_type_e
la_vxlan_next_hop_base::type() const
{
    return la_object::object_type_e::VXLAN_NEXT_HOP;
}

std::string
la_vxlan_next_hop_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_vxlan_next_hop_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_vxlan_next_hop_base::oid() const
{
    return m_oid;
}

la_status
la_vxlan_next_hop_base::add_ifg(la_slice_ifg ifg)
{
    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::remove_ifg(la_slice_ifg ifg)
{
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    return LA_STATUS_SUCCESS;
}

void
la_vxlan_next_hop_base::init_vxlan_nh(la_mac_addr_t nh_mac_addr,
                                      const la_l3_port_wptr& port,
                                      const la_l2_service_port_wptr& vxlan_port,
                                      la_device_impl::vxlan_nh_t& nh)
{
    const auto& svi_port = port.weak_ptr_static_cast<la_svi_port_base>();
    nh.l3_port_id = svi_port->get_gid();

    if (vxlan_port == nullptr) {
        nh.vxlan_port_id = 0;
    } else {
        const auto& l2_service_port_impl = vxlan_port.weak_ptr_static_cast<la_l2_service_port_base>();
        nh.vxlan_port_id = l2_service_port_impl->get_gid();
    }

    nh.dmac = nh_mac_addr;
}

void
la_vxlan_next_hop_base::vxlan_add_nh(la_mac_addr_t nh_mac_addr,
                                     const la_l3_port_wptr& port,
                                     const la_l2_service_port_wptr& vxlan_port)
{
    la_device_impl::vxlan_nh_t nh;
    init_vxlan_nh(nh_mac_addr, port, vxlan_port, nh);

    m_device->m_vxlan_nh_map[nh] = m_device->get_sptr(this);
}

void
la_vxlan_next_hop_base::vxlan_remove_nh(la_mac_addr_t nh_mac_addr,
                                        const la_l3_port_wptr& port,
                                        const la_l2_service_port_wptr& vxlan_port)
{
    la_device_impl::vxlan_nh_t nh;
    init_vxlan_nh(nh_mac_addr, port, vxlan_port, nh);

    m_device->m_vxlan_nh_map.erase(nh);
}

const la_vxlan_next_hop_wptr
la_vxlan_next_hop_base::vxlan_lookup_nh(la_mac_addr_t nh_mac_addr,
                                        const la_l3_port_wptr& port,
                                        const la_l2_service_port_wptr& vxlan_port)
{
    la_device_impl::vxlan_nh_t nh;
    init_vxlan_nh(nh_mac_addr, port, vxlan_port, nh);

    auto it = m_device->m_vxlan_nh_map.find(nh);
    if (it == m_device->m_vxlan_nh_map.end()) {
        return nullptr;
    }

    return (it->second);
}

la_status
la_vxlan_next_hop_base::initialize(la_object_id_t oid,
                                   la_mac_addr_t nh_mac_addr,
                                   const la_l3_port_wptr& port,
                                   const la_l2_service_port_wptr& vxlan_port)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;

    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (port->type() != la_object::object_type_e::SVI_PORT) {
        return LA_STATUS_EINVAL;
    }

    if (vxlan_port != nullptr) {
        const auto& l2_service_port_impl = vxlan_port.weak_ptr_static_cast<la_l2_service_port_base>();
        if (l2_service_port_impl->get_port_type() != la_l2_service_port::port_type_e::VXLAN) {
            return LA_STATUS_EINVAL;
        }
    }

    if (vxlan_lookup_nh(nh_mac_addr, port, vxlan_port) != nullptr) {
        LA_STATUS_EEXIST;
    }

    m_mac_addr = nh_mac_addr;
    m_l3_port = port;
    m_vxlan_port = vxlan_port;

    for (la_slice_ifg ifg : get_all_network_ifgs(m_device)) {
        la_status status = add_ifg(ifg);
        return_on_error(status);
    }

    la_status status = configure_l3vxlan_nh(nh_mac_addr, m_l3_port, m_vxlan_port);
    return_on_error(status);

    vxlan_add_nh(nh_mac_addr, m_l3_port, m_vxlan_port);

    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::notify_change(dependency_management_op op)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = teardown_l3vxlan_nh();
    return_on_error(status);

    vxlan_remove_nh(m_mac_addr, m_l3_port, m_vxlan_port);

    auto ifgs = m_ifg_use_count->get_ifgs();
    for (la_slice_ifg ifg : ifgs) {
        la_status status = remove_ifg(ifg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::get_mac(la_mac_addr_t& out_mac_addr) const
{
    start_api_getter_call();
    out_mac_addr = m_mac_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::get_router_port(la_l3_port*& out_port) const
{
    start_api_getter_call();
    out_port = m_l3_port.get();
    return LA_STATUS_SUCCESS;
}

const la_device*
la_vxlan_next_hop_base::get_device() const
{
    return m_device.get();
}

slice_ifg_vec_t
la_vxlan_next_hop_base::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_status
la_vxlan_next_hop_base::instantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::uninstantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::allocate_sa_msb_index(la_mac_addr_t sa, uint64_t& index)
{
    la_status status;
    la_uint32_t sa_msb;

    sa_msb = sa.flat >> 16;
    status = m_device->m_profile_allocators.l3vxlan_smac_msb_index->reallocate(m_l3vxlan_smac_msb_index_profile, sa_msb);
    return_on_error(status);

    if (m_l3vxlan_smac_msb_index_profile.use_count() == 1) {
        npl_l3_vxlan_overlay_sa_table_key_t k;
        npl_l3_vxlan_overlay_sa_table_value_t v;
        npl_l3_vxlan_overlay_sa_table_entry_wptr_t e;

        k.sa_prefix_index = m_l3vxlan_smac_msb_index_profile->id();
        v.action = NPL_L3_VXLAN_OVERLAY_SA_TABLE_ACTION_WRITE;
        v.payloads.overlay_sa_msb = sa_msb;

        status = m_device->m_tables.l3_vxlan_overlay_sa_table->insert(k, v, e);
        if (status != LA_STATUS_SUCCESS) {
            m_l3vxlan_smac_msb_index_profile.reset();
            log_err(HLD, "l3_vxlan_overlay_sa_table insertion failed, status=%s", la_status2str(status).c_str());
            return status;
        }
    }
    index = m_l3vxlan_smac_msb_index_profile->id();
    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::free_sa_msb_index()
{
    la_status status;

    if (m_l3vxlan_smac_msb_index_profile.use_count() == 1) {
        npl_l3_vxlan_overlay_sa_table_key_t k;

        k.sa_prefix_index = m_l3vxlan_smac_msb_index_profile->id();
        status = m_device->m_tables.l3_vxlan_overlay_sa_table->erase(k);
        return_on_error(status);
    }

    m_l3vxlan_smac_msb_index_profile.reset();
    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::update_l3relay_to_vni_table(la_mac_addr_t nh_mac_addr,
                                                    const la_svi_port_base_wptr& svi_port,
                                                    uint64_t sa_prefix_index,
                                                    uint64_t overlay_nh_id)
{
    la_status status;
    la_mac_addr_t sa;

    // get the src mac address of the port
    status = svi_port->get_mac(sa);
    return_on_error(status);

    const la_vrf* svi_vrf;
    status = svi_port->get_vrf(svi_vrf);
    return_on_error(status);

    const la_switch* sw;
    status = svi_port->get_switch(sw);
    return_on_error(status);

    la_vni_t vni;
    la_switch_impl* sw_impl = const_cast<la_switch_impl*>(static_cast<const la_switch_impl*>(sw));
    status = sw_impl->get_encap_vni(vni);
    return_on_error(status);

    la_counter_set* encap_counter;
    status = sw->get_vxlan_encap_counter(encap_counter);
    return_on_error(status);

    // create overlay nh
    npl_ip_relay_to_vni_table_key_t k;
    npl_ip_relay_to_vni_table_value_t v;
    npl_ip_relay_to_vni_table_entry_wptr_t e;

    k.overlay_nh = overlay_nh_id;
    k.l3_relay_id.id = (uint64_t)svi_vrf->get_gid();

    v.payloads.l3_vxlan_relay_encap_data.vni = vni;
    v.payloads.l3_vxlan_relay_encap_data.overlay_nh_data.mac_da = nh_mac_addr.flat;
    v.payloads.l3_vxlan_relay_encap_data.overlay_nh_data.sa_prefix_index = sa_prefix_index;
    v.payloads.l3_vxlan_relay_encap_data.overlay_nh_data.sa_lsb = sa.word[0];
    v.action = NPL_IP_RELAY_TO_VNI_TABLE_ACTION_WRITE;

    for (la_slice_pair_id_t slice_pair : m_ifg_use_count->get_slice_pairs()) {
        v.payloads.l3_vxlan_relay_encap_data.vni_counter
            = populate_counter_ptr_slice_pair(m_device->get_sptr(encap_counter), slice_pair, COUNTER_DIRECTION_EGRESS);
        status = m_device->m_tables.ip_relay_to_vni_table[slice_pair]->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::configure_l3vxlan_nh(la_mac_addr_t nh_mac_addr,
                                             const la_l3_port_wptr& port,
                                             const la_l2_service_port_wptr& l2_port)
{
    la_status status;
    la_l2_service_port_base_wptr vxlan_port;

    bool shared_overlay_nh;
    const auto& svi_port = port.weak_ptr_static_cast<la_svi_port_base>();
    uint64_t overlay_nh_id;
    uint64_t sa_prefix_index;
    la_mac_addr_t sa;

    if (l2_port != nullptr) {
        if (l2_port->get_port_type() != la_l2_service_port::port_type_e::VXLAN) {
            return LA_STATUS_EINVAL;
        }
        vxlan_port = l2_port.weak_ptr_static_cast<la_l2_service_port_base>();
        shared_overlay_nh = true;
        if (svi_port->get_vxlan_shared_overlay_nh_count() != 0) {
            auto sh_nh = svi_port->get_vxlan_shared_overlay_nh_mac();
            if (sh_nh.flat != nh_mac_addr.flat) {
                return LA_STATUS_EINVAL;
            }
        }
    } else {
        status = find_vxlan_port(nh_mac_addr, svi_port, vxlan_port);
        return_on_error(status);
        shared_overlay_nh = false;
    }

    if ((l2_port == nullptr) || (svi_port->get_vxlan_shared_overlay_nh_count() == 0)) {
        status = vxlan_port->update_l3_destination_for_l3vxlan(shared_overlay_nh);
        return_on_error(status);

        // get the src mac address of the port
        status = svi_port->get_mac(sa);
        return_on_error(status);

        status = allocate_sa_msb_index(sa, sa_prefix_index);
        return_on_error(status);

        overlay_nh_id = vxlan_port->get_overlay_nh_id();
        status = update_l3relay_to_vni_table(nh_mac_addr, svi_port, sa_prefix_index, overlay_nh_id);
        return_on_error(status);

        if (shared_overlay_nh) {
            svi_port->set_vxlan_shared_overlay_nh_mac(nh_mac_addr);
        } else {
            if (overlay_nh_id) {
                status = update_l3relay_to_vni_table(nh_mac_addr, svi_port, sa_prefix_index, 0);
                return_on_error(status);
            }
        }
    }

    if (l2_port != nullptr) {
        svi_port->update_vxlan_shared_overlay_nh_count(1);
    }

    m_device->add_object_dependency(port, this);

    if (m_resolution_data.fec_impl == nullptr) {
        la_l3_fec_impl_sptr fec;

        status = m_device->create_l3_fec_wrapper(vxlan_port.weak_ptr_static_cast<la_l2_destination>(), fec);
        return_on_error(status);

        lpm_destination_id lpm_dest_id = silicon_one::get_lpm_destination_id(fec, RESOLUTION_STEP_FORWARD_L3);
        m_device->m_l3_destinations[lpm_dest_id.val] = m_device->get_sptr(this);

        m_resolution_data.fec_impl = fec;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::teardown_l3vxlan_nh()
{
    la_status status;
    bool shared_overlay_nh;
    uint64_t overlay_nh_id;

    const auto& svi_port = m_l3_port.weak_ptr_static_cast<la_svi_port_base>();

    if ((m_vxlan_port == nullptr) || (svi_port->get_vxlan_shared_overlay_nh_count() == 1)) {
        la_l2_service_port_base_wptr vxlan_port;

        if (m_vxlan_port != nullptr) {
            if (m_vxlan_port->get_port_type() != la_l2_service_port::port_type_e::VXLAN) {
                return LA_STATUS_EINVAL;
            }
            vxlan_port = m_vxlan_port.weak_ptr_static_cast<la_l2_service_port_base>();
            shared_overlay_nh = true;
        } else {
            status = find_vxlan_port(m_mac_addr, svi_port, vxlan_port);
            return_on_error(status);
            shared_overlay_nh = false;
        }

        const la_vrf* svi_vrf;
        status = svi_port->get_vrf(svi_vrf);
        return_on_error(status);

        npl_ip_relay_to_vni_table_key_t k;

        overlay_nh_id = vxlan_port->get_overlay_nh_id();
        k.overlay_nh = overlay_nh_id;
        k.l3_relay_id.id = svi_vrf->get_gid();

        for (la_slice_pair_id_t slice_pair : m_ifg_use_count->get_slice_pairs()) {
            status = m_device->m_tables.ip_relay_to_vni_table[slice_pair]->erase(k);
            return_on_error(status);
        }

        if (!shared_overlay_nh) {
            if (overlay_nh_id) {
                k.overlay_nh = 0;
                for (la_slice_pair_id_t slice_pair : m_ifg_use_count->get_slice_pairs()) {
                    status = m_device->m_tables.ip_relay_to_vni_table[slice_pair]->erase(k);
                    return_on_error(status);
                }
            }
        }

        status = free_sa_msb_index();
        return_on_error(status);
    }

    if (m_vxlan_port != nullptr) {
        svi_port->update_vxlan_shared_overlay_nh_count(-1);
    }

    m_device->remove_object_dependency(m_l3_port, this);

    if (m_resolution_data.fec_impl != nullptr) {
        lpm_destination_id lpm_dest_id
            = silicon_one::get_lpm_destination_id(m_resolution_data.fec_impl, RESOLUTION_STEP_FORWARD_L3);

        status = m_device->do_destroy(m_resolution_data.fec_impl);
        return_on_error(status);

        m_device->m_l3_destinations[lpm_dest_id.val] = nullptr;
        m_resolution_data.fec_impl = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::find_vxlan_port(la_mac_addr_t nh_mac_addr,
                                        const la_svi_port_base_wptr& svi_port,
                                        la_l2_service_port_base_wptr& vxlan_port) const
{
    la_status status;
    la_l2_destination_wcptr l2_destination;

    status = get_l2_destination(svi_port, nh_mac_addr, l2_destination);
    return_on_error(status);

    if (l2_destination->type() != la_object::object_type_e::L2_SERVICE_PORT) {
        return LA_STATUS_ENOTFOUND;
    }

    const auto& l2_service_port = l2_destination.weak_ptr_static_cast<const la_l2_service_port_base>();
    vxlan_port = l2_service_port.weak_ptr_const_cast<la_l2_service_port_base>();

    if (vxlan_port->get_port_type() != la_l2_service_port::port_type_e::VXLAN) {
        return LA_STATUS_ENOTFOUND;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vxlan_next_hop_base::get_vxlan_port(la_l2_port*& out_vxlan_port) const
{
    start_api_getter_call();

    out_vxlan_port = m_vxlan_port.get();
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
