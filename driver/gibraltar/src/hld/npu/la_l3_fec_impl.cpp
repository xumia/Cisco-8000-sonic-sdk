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

#include "la_l3_fec_impl.h"
#include "api/npu/la_l3_port.h"
#include "la_ecmp_group_impl.h"
#include "nplapi/npl_constants.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_gibraltar.h"
#include "npu/la_next_hop_gibraltar.h"
#include "npu/la_prefix_object_gibraltar.h"
#include "resolution_utils.h"
#include "system/la_system_port_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_l3_fec_impl::la_l3_fec_impl(const la_device_impl_wptr& device) : m_device(device), m_gid(0)
{
}

la_l3_fec_impl::~la_l3_fec_impl()
{
}

void
la_l3_fec_impl::save_destination(const la_l3_destination_wptr& destination)
{
    m_l3_destination = destination;
}

void
la_l3_fec_impl::save_destination(const la_l2_destination_wptr& destination)
{
    m_l2_destination = destination;
}
la_status
la_l3_fec_impl::config_fec_table(npl_fec_table_value_t value)
{
    const auto& table(m_device->m_tables.fec_table);
    npl_fec_table_key_t key;
    key.fec.id = m_gid;

    la_status status = table->set(key, value, m_fec_table_entry);
    return status;
}

la_status
la_l3_fec_impl::config_rpf_fec_table(npl_destination_t dest)
{
    const auto& table(m_device->m_tables.rpf_fec_table);
    npl_rpf_fec_table_key_t key;
    npl_rpf_fec_table_value_t value;

    key.fec = m_gid;
    value.payloads.found.dst = dest;

    la_status status = table->set(key, value, m_rpf_fec_table_entry);

    return status;
}

template <class _DestinationType>
la_status
la_l3_fec_impl::do_initialize(la_object_id_t oid,
                              la_fec_gid_t fec_gid,
                              bool is_internal_wrapper,
                              const weak_ptr_unsafe<_DestinationType>& destination)
{
    m_oid = oid;
    m_gid = fec_gid;
    m_is_wrapper = is_internal_wrapper;

    la_status status = update_fec(destination);
    return_on_error(status);

    save_destination(destination);

    add_dependency(destination);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_fec_impl::initialize(la_object_id_t oid,
                           la_fec_gid_t fec_gid,
                           bool is_internal_wrapper,
                           const la_l3_destination_wptr& destination)
{
    return do_initialize(oid, fec_gid, is_internal_wrapper, destination);
}

la_status
la_l3_fec_impl::initialize(la_object_id_t oid,
                           la_fec_gid_t fec_gid,
                           bool is_internal_wrapper,
                           const la_l2_destination_wptr& destination)
{
    return do_initialize(oid, fec_gid, is_internal_wrapper, destination);
}

la_status
la_l3_fec_impl::destroy()
{
    if (m_device->is_in_use(shared_from_this())) { // Must use shared from this because internal fec objects are not registered
        return LA_STATUS_EBUSY;
    }

    if (m_l3_destination != nullptr) {
        remove_dependency(m_l3_destination);

        object_type_e dest_type = m_l3_destination->type();
        switch (dest_type) {
        case object_type_e::NEXT_HOP:
        case object_type_e::PREFIX_OBJECT:
        case object_type_e::ECMP_GROUP: {
            la_status status = remove_basic_routing();
            return status;
        }

        default:
            return LA_STATUS_EUNKNOWN;
        }
    }

    if (m_l2_destination != nullptr) {
        remove_dependency(m_l2_destination);

        la_status status = remove_l3_vxlan();
        return status;
    }

    return LA_STATUS_EUNKNOWN;
}

void
la_l3_fec_impl::add_dependency(const la_l3_destination_wptr& destination)
{
    m_device->add_object_dependency(destination, shared_from_this());
}

void
la_l3_fec_impl::add_dependency(const la_l2_destination_wptr& destination)
{
    m_device->add_object_dependency(destination, this);
}

void
la_l3_fec_impl::remove_dependency(const la_l3_destination_wptr& destination)
{
    m_device->remove_object_dependency(destination, shared_from_this());
}

void
la_l3_fec_impl::remove_dependency(const la_l2_destination_wptr& destination)
{
    m_device->remove_object_dependency(destination, this);
}
la_status
la_l3_fec_impl::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {
    default:
        return LA_STATUS_EUNKNOWN;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_fec_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        return update_dependent_attributes(op);
    default:
        log_err(HLD, "received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_l3_fec_impl::update_fec(const la_l3_destination_wptr& destination)
{
    la_object::object_type_e dest_type = destination->type();

    if (dest_type == la_object::object_type_e::ECMP_GROUP) {
        const auto& ecmp_group = destination.weak_ptr_static_cast<la_ecmp_group_impl>();
        if (ecmp_group->get_ecmp_level() != la_ecmp_group::level_e::LEVEL_2) {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    if (dest_type == la_object::object_type_e::PREFIX_OBJECT) {
        const auto& pfx_obj = destination.weak_ptr_static_cast<const la_prefix_object_base>();
        if (!pfx_obj->is_resolution_forwarding_supported()) {
            return LA_STATUS_EINVAL;
        }
    }

    la_status status = instantiate_resolution_object(destination, RESOLUTION_STEP_FEC);
    return_on_error(status);

    switch (dest_type) {
    case la_object::object_type_e::NEXT_HOP: {
        auto nh = destination.weak_ptr_static_cast<la_next_hop_gibraltar>();
        la_status status = configure_basic_routing(nh);
        return_on_error(status);
    } break;
    case la_object::object_type_e::ECMP_GROUP: {
        auto ecmp = destination.weak_ptr_static_cast<la_ecmp_group_impl>();
        la_status status = configure_basic_routing(ecmp);
        return_on_error(status);
    } break;
    case la_object::object_type_e::PREFIX_OBJECT: {
        auto pfx_obj = destination.weak_ptr_static_cast<la_prefix_object_base>();
        la_status status = configure_basic_routing(pfx_obj);
        return_on_error(status);
    } break;
    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (m_l3_destination == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    status = uninstantiate_resolution_object(m_l3_destination, RESOLUTION_STEP_FEC);
    return status;
}

la_status
la_l3_fec_impl::update_fec(const la_l2_destination_wptr& destination)
{
    start_api_call("destination=", destination);
    object_type_e dest_type = destination->type();

    if (dest_type != la_object::object_type_e::L2_SERVICE_PORT) {
        return LA_STATUS_EINVAL;
    }

    la_status status = instantiate_resolution_object(destination, RESOLUTION_STEP_FEC);
    return_on_error(status);
    auto vxlan_port = destination.weak_ptr_static_cast<la_l2_service_port_base>();
    status = configure_l3_vxlan(vxlan_port);
    return_on_error(status);

    if (m_l2_destination == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    status = uninstantiate_resolution_object(m_l2_destination, RESOLUTION_STEP_FEC);
    return status;
}

template <class _DestinationType>
la_status
la_l3_fec_impl::do_set_destination(const weak_ptr_unsafe<_DestinationType>& destination)
{
    start_api_call("destination=", destination);

    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = update_fec(destination);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_fec_impl::set_destination(la_l3_destination* destination)
{
    la_l3_destination_wptr destination_wptr = m_device->get_sptr(destination);
    la_status status = do_set_destination(destination_wptr);
    return_on_error(status);
    remove_dependency(m_l3_destination);
    save_destination(destination_wptr);
    add_dependency(destination_wptr);
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_fec_impl::set_destination(la_l2_destination* destination)
{
    la_l2_destination_wptr destination_wptr = m_device->get_sptr(destination);
    la_status status = do_set_destination(destination_wptr);
    return_on_error(status);
    remove_dependency(m_l2_destination);
    save_destination(destination_wptr);
    add_dependency(destination_wptr);
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_l3_fec_impl::type() const
{
    return object_type_e::FEC;
}

std::string
la_l3_fec_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_l3_fec_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_l3_fec_impl::oid() const
{
    return m_oid;
}

const la_device*
la_l3_fec_impl::get_device() const
{
    return m_device.get();
}

la_l3_destination_gid_t
la_l3_fec_impl::get_gid() const
{
    return m_gid;
}

la_l3_destination*
la_l3_fec_impl::get_destination() const
{
    return m_l3_destination.get();
}

la_status
la_l3_fec_impl::configure_basic_routing(const la_next_hop_gibraltar_wptr& nh)
{
    npl_fec_table_value_t value;
    npl_destination_t rpf_fec_table_dest = {.val = 0};
    la_status status = nh->get_fec_table_value(value, rpf_fec_table_dest);
    return_on_error(status);

    // Configure the RPF FEC table first so that it is ready when there's a hit in the FEC table
    status = config_rpf_fec_table(rpf_fec_table_dest);
    return_on_error(status);

    // Configure the FEC table
    status = config_fec_table(value);
    if (status != LA_STATUS_SUCCESS) {
        // Try to rollback
        const auto& table(m_device->m_tables.rpf_fec_table);
        npl_rpf_fec_table_key_t key = m_rpf_fec_table_entry->key();
        la_status status = table->erase(key);
        if (status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EDOUBLE_FAULT;
        }

        m_rpf_fec_table_entry = nullptr;

        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_fec_impl::configure_basic_routing(const la_prefix_object_base_wptr& pfx_obj)
{
    npl_fec_table_value_t value;
    auto gb_pfx_obj = pfx_obj.weak_ptr_static_cast<la_prefix_object_gibraltar>();
    la_status status = gb_pfx_obj->get_fec_table_value(value);
    return_on_error(status);

    // Configure the FEC table
    status = config_fec_table(value);
    return_on_error(status);

    // TBD: erase m_rpf_fec_table_entry

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_fec_impl::configure_basic_routing(const la_ecmp_group_impl_wptr& ecmp)
{
    npl_fec_table_value_t value;
    la_status status = ecmp->get_fec_table_value(value);
    return_on_error(status);

    // Configure the FEC table
    status = config_fec_table(value);
    return_on_error(status);

    // TBD: erase m_rpf_fec_table_entry

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_fec_impl::configure_l3_vxlan(const la_l2_service_port_base_wptr& vxlan_port)
{
    npl_fec_table_value_t value;
    auto status = vxlan_port.weak_ptr_static_cast<la_l2_service_port_gibraltar>()->get_fec_table_value(value);
    return_on_error(status);

    // Configure the FEC table
    status = config_fec_table(value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_fec_impl::remove_basic_routing()
{
    la_status status = teardown_resolution_step_fec();
    return_on_error(status);

    if (m_rpf_fec_table_entry != nullptr) {
        const auto& table(m_device->m_tables.rpf_fec_table);
        npl_rpf_fec_table_key_t key = m_rpf_fec_table_entry->key();
        status = table->erase(key);
        return_on_error(status);

        m_rpf_fec_table_entry = nullptr;
    }

    status = uninstantiate_resolution_object(m_l3_destination, RESOLUTION_STEP_FEC);
    return status;
}

la_status
la_l3_fec_impl::remove_l3_vxlan()
{
    la_status status = teardown_resolution_step_fec();
    return_on_error(status);

    status = uninstantiate_resolution_object(m_l2_destination, RESOLUTION_STEP_FEC);
    return status;
}

la_status
la_l3_fec_impl::teardown_resolution_step_fec()
{
    if (m_fec_table_entry != nullptr) {
        const auto& table(m_device->m_tables.fec_table);
        npl_fec_table_key_t key = m_fec_table_entry->key();
        la_status status = table->erase(key);
        return_on_error(status);

        m_fec_table_entry = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

lpm_destination_id
la_l3_fec_impl::get_lpm_destination_id(resolution_step_e prev_step) const
{
    return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_FEC_MASK | m_gid);
}

destination_id
la_l3_fec_impl::get_destination_id(resolution_step_e prev_step) const
{
    return destination_id(NPL_DESTINATION_MASK_FEC | m_gid);
}

} // namespace silicon_one
