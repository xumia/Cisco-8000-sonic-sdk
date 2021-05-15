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

#include "la_next_hop_base.h"
#include "api/npu/la_l3_port.h"
#include "nplapi/npl_constants.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_next_hop_impl_common.h"
#include "npu/la_svi_port_base.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_next_hop_base::la_next_hop_base(const la_device_impl_wptr& device) : m_device(device), m_gid(0), m_next_hop_common(device)
{
}

la_next_hop_base::~la_next_hop_base() = default;

la_object::object_type_e
la_next_hop_base::type() const
{
    return la_object::object_type_e::NEXT_HOP;
}

std::string
la_next_hop_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_next_hop_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_next_hop_base::oid() const
{
    return m_oid;
}

la_status
la_next_hop_base::populate_nh_payload_l3_info(npl_nh_payload_t& out_nh_payload, const la_l3_port_wptr& l3_port) const
{
    // Update mac bits
    la_mac_addr_t mac_sa;
    la_status status = get_l3_port_mac(mac_sa);
    return_on_error(status);

    uint64_t sa_prefix_index;
    status = m_device->m_mac_addr_manager->get_index(mac_sa, sa_prefix_index);
    return_on_error(status);

    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l3_sa_lsb.sa_prefix_index = sa_prefix_index;
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l3_sa_lsb.tpid_sa_lsb.sa_lsb = m_device->m_mac_addr_manager->get_lsbits(mac_sa);

    // Update tag info. Max of 1 tag is supported.
    la_vlan_tag_t tag1 = LA_VLAN_TAG_UNTAGGED, tag2 = LA_VLAN_TAG_UNTAGGED;
    object_type_e l3_type = l3_port->type();

    if (l3_type == la_object::object_type_e::SVI_PORT) {
        const auto& svi_port = l3_port.weak_ptr_static_cast<la_svi_port_base>();
        status = svi_port->get_egress_vlan_tag(tag1, tag2);
        return_on_error(status);
    }

    if (l3_type == la_object::object_type_e::L3_AC_PORT) {
        const auto& port = l3_port.weak_ptr_static_cast<la_l3_ac_port_impl>();
        status = port->get_egress_vlan_tag(tag1, tag2);
        return_on_error(status);
    }

    if (is_vlan_tag_eq(tag1, LA_VLAN_TAG_UNTAGGED)) {
        out_nh_payload.eve_vid1 = 0;
        out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l3_sa_lsb.tpid_sa_lsb.tpid = 0x8100;
    } else {
        out_nh_payload.eve_vid1 = tag1.tci.fields.vid;
        out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l3_sa_lsb.tpid_sa_lsb.tpid = tag1.tpid;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_base::configure_per_slice_tx_tables(la_slice_id_t slice)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_base::teardown_per_slice_tx_tables(la_slice_id_t slice)
{
    return LA_STATUS_SUCCESS;
}

la_next_hop_gid_t
la_next_hop_base::get_gid() const
{
    return m_next_hop_common.get_gid();
}

la_status
la_next_hop_base::add_ifg(la_slice_ifg ifg)
{
    return m_next_hop_common.add_ifg(ifg);
}

la_status
la_next_hop_base::remove_ifg(la_slice_ifg ifg)
{
    return m_next_hop_common.remove_ifg(ifg);
}

la_status
la_next_hop_base::get_mac(la_mac_addr_t& out_mac_addr) const
{
    out_mac_addr = m_mac_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_base::set_mac(la_mac_addr_t mac_addr)
{
    start_api_call("mac_addr=", mac_addr);
    la_mac_addr_t mac_addr_old = m_mac_addr;
    m_mac_addr = mac_addr;

    la_status status = m_next_hop_common.update_next_hop_mac_addr(mac_addr);
    if (status != LA_STATUS_SUCCESS) {
        m_mac_addr = mac_addr_old;
    }
    return_on_error(status);

    la_l3_port_wptr l3_port;
    status = m_next_hop_common.get_router_port(l3_port);
    return_on_error(status);

    if (l3_port != nullptr && l3_port->type() == la_object::object_type_e::SVI_PORT) {
        status = modify_mac_move_dsp_or_dspa();
        return_on_error(status);
        const auto& svi_port = l3_port.weak_ptr_static_cast<la_svi_port_base>();
        status = svi_port->delete_mac_move_nh(mac_addr_old, this);
        return_on_error(status);
        status = svi_port->add_mac_move_nh(m_mac_addr, this);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

const la_l2_service_port_base_wptr
la_next_hop_base::get_nh_l2_port(const la_svi_port_base_wptr& svi_port) const
{ // this function is used only for svi
    la_l2_service_port_base_wptr out_l2_port = nullptr;

    la_l2_destination_wptr l2_dest;
    la_status status = m_next_hop_common.get_nh_l2_destination(l2_dest);

    if (status == LA_STATUS_SUCCESS) {
        if (l2_dest->type() == la_object::object_type_e::L2_SERVICE_PORT) {
            out_l2_port = l2_dest.weak_ptr_static_cast<la_l2_service_port_base>();
        }
    }
    if (status == LA_STATUS_ENOTFOUND) {
        la_l2_service_port* inject_up_port = nullptr;
        svi_port->get_inject_up_source_port(inject_up_port);
        if (inject_up_port != nullptr) {
            out_l2_port = m_device->get_sptr<la_l2_service_port_base>(inject_up_port);
        }
    }

    return out_l2_port;
}

la_status
la_next_hop_base::set_nh_l2_port(const la_l2_service_port_base_wptr& l2_port)
{
    bit_vector l2_dlp_attributes((la_uint64_t)attribute_management_op::L2_DLP_ATTRIB_CHANGED);

    if (m_l2_port != nullptr) {
        // remove dependency with the exisitng l2_port
        m_device->remove_attribute_dependency(m_l2_port, this, l2_dlp_attributes);
        m_device->remove_object_dependency(m_l2_port, this);
    }

    m_l2_port = l2_port;
    if (l2_port != nullptr) {
        log_debug(HLD, "Setting L2Port 0x%x for nh: 0x%x", l2_port->get_gid(), m_gid);
        // add dependency to new l2_port
        m_device->add_object_dependency(m_l2_port, this);
        m_device->add_attribute_dependency(m_l2_port, this, l2_dlp_attributes);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_base::modify_nh_l2_port()
{
    la_l3_port_wptr l3_port;
    la_status status = m_next_hop_common.get_router_port(l3_port);
    return_on_error(status);

    if ((m_nh_type == nh_type_e::NORMAL) && (l3_port != nullptr)) {
        if (l3_port->type() == la_object::object_type_e::SVI_PORT) {
            const auto& svi_port = l3_port.weak_ptr_static_cast<la_svi_port_base>();
            const auto l2_port = get_nh_l2_port(svi_port);
            status = set_nh_l2_port(l2_port);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_base::set_svi_nh_type(nh_type_e nh_type)
{
    la_l3_port_wptr l3_port;
    la_status status = m_next_hop_common.get_router_port(l3_port);
    return_on_error(status);

    const auto& svi_port = l3_port.weak_ptr_static_cast<la_svi_port_base>();

    if ((m_nh_type == nh_type_e::NORMAL) && (nh_type == nh_type_e::DROP)) {
        set_nh_l2_port(nullptr);
        status = svi_port->delete_mac_move_nh(m_mac_addr, this);
        return_on_error(status);
    }

    if ((m_nh_type == nh_type_e::NORMAL) && (nh_type == nh_type_e::GLEAN)) {
        set_nh_l2_port(nullptr);
        status = svi_port->delete_mac_move_nh(m_mac_addr, this);
        return_on_error(status);
        status = update_global_tx_tables();
        return_on_error(status);
    }

    if ((m_nh_type == nh_type_e::GLEAN) && (nh_type == nh_type_e::NORMAL)) {
        status = update_global_tx_tables();
        return_on_error(status);
        status = svi_port->add_mac_move_nh(m_mac_addr, this);
        return_on_error(status);
        auto l2_port = get_nh_l2_port(svi_port);
        status = set_nh_l2_port(l2_port);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_base::get_nh_type(nh_type_e& out_nh_type) const
{
    out_nh_type = m_nh_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_base::get_router_port(la_l3_port*& out_port) const
{
    la_l3_port_wptr port_wptr;
    auto status = m_next_hop_common.get_router_port(port_wptr);
    return_on_error(status);
    out_port = port_wptr.get();

    return LA_STATUS_SUCCESS;
}

const la_device*
la_next_hop_base::get_device() const
{
    return m_device.get();
}

slice_ifg_vec_t
la_next_hop_base::get_ifgs() const
{
    return m_next_hop_common.get_ifgs();
}

std::vector<la_slice_id_t>
la_next_hop_base::get_slices() const
{
    return m_next_hop_common.get_slices();
}

std::vector<la_slice_pair_id_t>
la_next_hop_base::get_slice_pairs() const
{
    return m_next_hop_common.get_slice_pairs();
}

la_status
la_next_hop_base::get_dsp_or_dspa(la_l2_port_gid_t& out_npp_gid, bool& out_is_aggregate) const
{
    return m_next_hop_common.get_dsp_or_dspa(out_npp_gid, out_is_aggregate);
}

la_status
la_next_hop_base::get_l3_port_mac(la_mac_addr_t& out_mac_addr) const
{
    return m_next_hop_common.get_l3_port_mac(out_mac_addr);
}

} // namespace silicon_one
