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

#include "la_ip_tunnel_destination_impl.h"
#include "la_ecmp_group_impl.h"
#include "la_gre_port_impl.h"
#include "nplapi/npl_constants.h"
#include "npu/la_next_hop_base.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "counter_utils.h"
#include "hld_utils.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_ip_tunnel_destination_impl::la_ip_tunnel_destination_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_ip_tunnel_destination_gid(LA_L3_DESTINATION_GID_INVALID),
      m_underlay_destination(nullptr),
      m_ip_tunnel_port(nullptr)
{
}

la_ip_tunnel_destination_impl::~la_ip_tunnel_destination_impl()
{
}

const la_device*
la_ip_tunnel_destination_impl::get_device() const
{
    return m_device.get();
}

la_object::object_type_e
la_ip_tunnel_destination_impl::type() const
{
    return la_object::object_type_e::IP_TUNNEL_DESTINATION;
}

std::string
la_ip_tunnel_destination_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_ip_tunnel_destination_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_ip_tunnel_destination_impl::oid() const
{
    return m_oid;
}

la_l3_destination_gid_t
la_ip_tunnel_destination_impl::get_gid() const
{
    return m_ip_tunnel_destination_gid;
}

const la_l3_port*
la_ip_tunnel_destination_impl::get_ip_tunnel_port() const
{
    start_api_getter_call("");
    return m_ip_tunnel_port.get();
}

const la_l3_destination*
la_ip_tunnel_destination_impl::get_underlay_destination() const
{
    start_api_getter_call("");
    return m_underlay_destination.get();
}

resolution_step_e
la_ip_tunnel_destination_impl::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step == RESOLUTION_STEP_FORWARD_L3) {
        return RESOLUTION_STEP_STAGE0_CE_PTR;
    }

    if (prev_step == RESOLUTION_STEP_STAGE0_ECMP) {
        return RESOLUTION_STEP_STAGE0_CE_PTR;
    }

    return RESOLUTION_STEP_INVALID;
}

lpm_destination_id
la_ip_tunnel_destination_impl::get_lpm_destination_id(resolution_step_e prev_step) const
{
    return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK | m_ip_tunnel_destination_gid);
}

destination_id
la_ip_tunnel_destination_impl::get_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_STAGE0_CE_PTR: {
        return destination_id(NPL_DESTINATION_MASK_CE_PTR | m_ip_tunnel_destination_gid);
    }

    default: {
        return DESTINATION_ID_INVALID;
    }
    }
}

la_status
la_ip_tunnel_destination_impl::initialize(la_object_id_t oid,
                                          la_l3_destination_gid_t ip_tunnel_destination_gid,
                                          const la_l3_port_wcptr& ip_tunnel_port,
                                          const la_l3_destination_wcptr& underlay_destination)
{
    m_oid = oid;
    if (ip_tunnel_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (underlay_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    m_ip_tunnel_destination_gid = ip_tunnel_destination_gid;
    m_ip_tunnel_port = ip_tunnel_port;

    la_status status = update_destination(ip_tunnel_port, underlay_destination, true);
    return_on_error(status);

    add_dependency(underlay_destination);
    m_device->add_object_dependency(ip_tunnel_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_tunnel_destination_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = teardown_ip_tunnel_destination_table();
    return_on_error(status);

    status = uninstantiate_resolution_object(m_underlay_destination, RESOLUTION_STEP_STAGE0_CE_PTR);
    return_on_error(status);

    m_device->remove_object_dependency(m_ip_tunnel_port, this);
    remove_dependency(m_underlay_destination);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_tunnel_destination_impl::set_underlay_destination(const la_l3_destination* underlay_destination)
{
    start_api_call("destination=", underlay_destination);

    const auto& underlay_destination_sp = m_device->get_sptr(underlay_destination);

    if (m_underlay_destination == underlay_destination_sp) {
        return LA_STATUS_SUCCESS;
    }

    const auto old_destination = m_underlay_destination;

    la_status status = update_destination(m_ip_tunnel_port, underlay_destination_sp, false);
    return_on_error(status);

    status = uninstantiate_resolution_object(old_destination, RESOLUTION_STEP_STAGE0_CE_PTR);
    return_on_error(status);

    remove_dependency(old_destination);
    add_dependency(underlay_destination_sp);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_tunnel_destination_impl::update_destination(const la_l3_port_wcptr& ip_tunnel_port,
                                                  const la_l3_destination_wcptr& underlay_destination,
                                                  bool is_init)
{
    transaction txn;

    // we only support GRE and IP tunnel for now
    if ((ip_tunnel_port->type() != object_type_e::GRE_PORT) && (ip_tunnel_port->type() != object_type_e::IP_OVER_IP_TUNNEL_PORT)) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(underlay_destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_object::object_type_e underlay_dest_type = underlay_destination->type();
    if ((underlay_dest_type != object_type_e::NEXT_HOP) && (underlay_dest_type != object_type_e::ECMP_GROUP)) {
        log_err(HLD, "invalid underlay_destination type, type=%d", (int)underlay_destination->type());
        return LA_STATUS_EINVAL;
    }

    if (underlay_dest_type == object_type_e::ECMP_GROUP) {
        const auto& ecmp_group = underlay_destination.weak_ptr_static_cast<const la_ecmp_group_impl>();
        if (ecmp_group->get_ecmp_level() != la_ecmp_group::level_e::LEVEL_2) {
            log_err(HLD, "underlay ECMP level should be 2");
            return LA_STATUS_EINVAL;
        }
    }

    la_device_impl::resolution_lp_table_format_e format = la_device_impl::resolution_lp_table_format_e::NARROW;

    txn.status = m_device->validate_destination_gid_format_match(format, m_ip_tunnel_destination_gid, is_init);
    return_on_error(txn.status);

    txn.status = instantiate_resolution_object(underlay_destination, RESOLUTION_STEP_STAGE0_CE_PTR, this);
    return_on_error(txn.status);

    txn.on_fail([=]() { uninstantiate_resolution_object(underlay_destination, RESOLUTION_STEP_STAGE0_CE_PTR); });

    if (!is_init) {
        txn.status = m_device->clear_destination_gid_format(m_ip_tunnel_destination_gid);
        return_on_error(txn.status);
    }

    txn.status = m_device->update_destination_gid_format(format, m_ip_tunnel_destination_gid);
    return_on_error(txn.status);

    txn.on_fail([=]() { m_device->clear_destination_gid_format(m_ip_tunnel_destination_gid); });

    m_underlay_destination = underlay_destination;

    txn.status = configure_ip_tunnel_destination_table();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

void
la_ip_tunnel_destination_impl::add_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->add_object_dependency(destination, this);
}

void
la_ip_tunnel_destination_impl::remove_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->remove_object_dependency(destination, this);
}

la_status
la_ip_tunnel_destination_impl::notify_change(dependency_management_op op)
{
    log_err(HLD, "la_ip_tunnel_destination_impl::%s: not expect get called", __func__);
    return LA_STATUS_EUNKNOWN;

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_tunnel_destination_impl::configure_ip_tunnel_destination_table()
{
    if ((m_ip_tunnel_port->type() != object_type_e::GRE_PORT)
        && (m_ip_tunnel_port->type() != object_type_e::IP_OVER_IP_TUNNEL_PORT)) {
        log_err(HLD, "invalid tunnel type for ip tunnel destination, type=%d", (int)m_ip_tunnel_port->type());
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    npl_resolution_stage_assoc_data_narrow_entry_t tunnel_entry{};

    if (m_underlay_destination->type() == object_type_e::NEXT_HOP) {
        // Next hop
        auto& entry(tunnel_entry.stage0_ce_ptr_l3_nh_ip_tunnel);
        entry.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_IP_TUNNEL;

        const auto& gre_port_impl = m_ip_tunnel_port.weak_ptr_static_cast<const la_gre_port_impl>();
        uint64_t ip_tunnel_gid = gre_port_impl->get_gid();
        entry.ip_tunnel = ip_tunnel_gid;

        const auto& nh_impl = m_underlay_destination.weak_ptr_static_cast<const la_next_hop_base>();
        entry.l3_nh = nh_impl->get_gid();

        destination_id key = get_destination_id(RESOLUTION_STEP_FORWARD_L3);
        la_status status = m_device->m_resolution_configurators[0].configure_dest_map_entry(key, tunnel_entry, m_res_cfg_handle);
        return status;
    } else {
        // ECMP
        auto& entry(tunnel_entry.stage0_ce_ptr_level2_ecmp_ip_tunnel);
        entry.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_LEVEL2_ECMP_IP_TUNNEL;

        const auto& gre_port_impl = m_ip_tunnel_port.weak_ptr_static_cast<const la_gre_port_impl>();
        uint64_t ip_tunnel_gid = gre_port_impl->get_gid();
        entry.ip_tunnel = ip_tunnel_gid;

        auto ecmp_dest_id = silicon_one::get_destination_id(m_underlay_destination, RESOLUTION_STEP_STAGE0_CE_PTR);
        entry.level2_ecmp = ecmp_dest_id.val;

        destination_id key = get_destination_id(RESOLUTION_STEP_FORWARD_L3);
        la_status status = m_device->m_resolution_configurators[0].configure_dest_map_entry(key, tunnel_entry, m_res_cfg_handle);
        return status;
    }
}

la_status
la_ip_tunnel_destination_impl::teardown_ip_tunnel_destination_table()
{
    la_status status = m_device->m_resolution_configurators[0].unconfigure_entry(m_res_cfg_handle);
    return status;
}

la_status
la_ip_tunnel_destination_impl::instantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_tunnel_destination_impl::uninstantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_tunnel_destination_impl::get_resolution_cfg_handle(const resolution_cfg_handle_t*& out_cfg_handle) const
{
    out_cfg_handle = &m_res_cfg_handle;
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
