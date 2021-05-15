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

#include "la_counter_set_impl.h"
#include "la_l3_ac_port_impl.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_svi_port_base.h"
#include "system/la_device_impl.h"
#include "system/la_l2_mirror_command_base.h"
#include "tm/voq_counter_set.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"
#include "system/slice_id_manager_base.h"

#include <sstream>

namespace silicon_one
{

la_counter_set_impl::la_counter_set_impl(const la_device_impl_wptr& device)
    : m_device(device), m_direction(COUNTER_DIRECTION_INVALID), m_counter_type(type_e::INVALID), m_meter(nullptr)
{
}

la_counter_set_impl::~la_counter_set_impl()
{
}

la_status
la_counter_set_impl::initialize(la_object_id_t oid, size_t set_size)
{
    m_oid = oid;
    m_slice_id_manager = m_device->get_slice_id_manager();
    for (size_t i = 0; i < COUNTER_DIRECTION_NUM; i++) {
        m_ifg_use_count[i] = make_unique<ifg_use_count>(m_slice_id_manager);
    }
    // A set size of 16 is enough to accomodate 8 VOQs x 2 (Dropped & Enqueued)
    // A set size of 32 is needed to support 32 class map counter offsets
    if ((set_size < 1) || (set_size > PER_QOS_TC_SET_SIZE)) {
        return LA_STATUS_EOUTOFRANGE;
    }

    m_set_size = set_size;

    m_cached_packets.resize(set_size, 0);
    m_cached_bytes.resize(set_size, 0);

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg, m_direction);
        } else {
            return remove_ifg(op.action.ifg_management.ifg, m_direction);
        }

    default:
        log_err(HLD,
                "la_counter_set_impl::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_object::object_type_e
la_counter_set_impl::type() const
{
    return object_type_e::COUNTER_SET;
}

std::string
la_counter_set_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_counter_set_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_counter_set_impl::oid() const
{
    return m_oid;
}

la_device*
la_counter_set_impl::get_device() const
{
    return m_device.get();
}

size_t
la_counter_set_impl::get_set_size() const
{
    return m_set_size;
}

la_counter_set::type_e
la_counter_set_impl::get_type() const
{
    return m_counter_type;
}

counter_direction_e
la_counter_set_impl::get_direction() const
{
    return m_direction;
}

la_status
la_counter_set_impl::get_allocation(la_slice_id_t slice, counter_direction_e direction, counter_allocation& out_allocation) const
{
    la_slice_id_t slice_idx = slice / 2;
    if (m_meter != nullptr) {
        la_slice_ifg slice_ifg = {.slice = slice, .ifg = 0};
        return (m_meter->get_allocation(slice_ifg, out_allocation));
    }

    const auto& it = m_allocations[direction].find(slice_idx);

    if (it == m_allocations[direction].end()) {
        return LA_STATUS_ENOTFOUND;
    }

    out_allocation = it->second;

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::get_user_type(type_e counter_type, const la_object_wcptr& user, counter_user_type_e& out_user_type) const
{
    la_status status = LA_STATUS_SUCCESS;

    if (counter_type == type_e::QOS) {
        // User doens't matter in this case since there's only a single q-counter in a stage
        out_user_type = COUNTER_USER_TYPE_QOS;

        return LA_STATUS_SUCCESS;
    }

    // Port counters

    la_object::object_type_e object_type = user->type();

    switch (object_type) {
    case la_object::object_type_e::L2_SERVICE_PORT: {
        const auto& service_port = user.weak_ptr_static_cast<const la_l2_service_port_base>();
        if (service_port->get_port_type() == la_l2_service_port::port_type_e::AC) {
            out_user_type = COUNTER_USER_TYPE_L2_AC_PORT;
        } else if ((service_port->get_port_type() == la_l2_service_port::port_type_e::PWE)
                   || (service_port->get_port_type() == la_l2_service_port::port_type_e::PWE_TAGGED)) {
            out_user_type = COUNTER_USER_TYPE_L2_PWE_PORT;
        } else {
            out_user_type = COUNTER_USER_TYPE_TUNNEL;
        }
    }

    break;
    case la_object::object_type_e::L3_AC_PORT:
        out_user_type = COUNTER_USER_TYPE_L3_AC_PORT;
        break;
    case la_object::object_type_e::NEXT_HOP:
        out_user_type = COUNTER_USER_TYPE_MPLS_NH;
        break;
    case la_object::object_type_e::PREFIX_OBJECT:
        out_user_type = (counter_type == type_e::MPLS_TRAFFIC_MATRIX) ? COUNTER_USER_TYPE_SR_DM : COUNTER_USER_TYPE_MPLS_GLOBAL;
        break;
    case la_object::object_type_e::SVI_PORT:
        out_user_type = COUNTER_USER_TYPE_SVI_OR_ADJACENCY;
        break;
    case la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT:
    case la_object::object_type_e::GRE_PORT:
    case la_object::object_type_e::GUE_PORT:
        out_user_type = COUNTER_USER_TYPE_TUNNEL;
        break;
    case object_type_e::L2_MIRROR_COMMAND:
        out_user_type = COUNTER_USER_TYPE_L2_MIRROR;
        break;
    default:
        status = LA_STATUS_EINVAL;
    }

    return status;
}

bool
la_counter_set_impl::get_aggregation() const
{
    return m_is_aggregate;
}

la_status
la_counter_set_impl::add_ifg(la_slice_ifg ifg, counter_direction_e direction)
{
    bool ifg_added, slice_added, slice_pair_added;
    transaction txn;
    counter_allocation allocation;

    if (m_meter != nullptr) {
        // allocation comes from Meter bank via meter
        return LA_STATUS_SUCCESS;
    }

    m_ifg_use_count[direction]->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([=]() {
        bool dummy;
        m_ifg_use_count[direction]->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (!slice_pair_added) {
        return LA_STATUS_SUCCESS;
    }

    size_t num_of_ifgs = m_is_aggregate ? NUM_IFGS_PER_SLICE * 2 : 1;
    size_t slice_idx = ifg.slice / 2;

    if (m_user_type == COUNTER_USER_TYPE_SECURITY_GROUP_CELL) {
        if (slice_pair_added) {
            // sgacl counter allocations should be done from the device.
            la_status status = m_device->assign_sgacl_counter_allocation(slice_idx, allocation);
            return_on_error(status);
            m_allocations[direction][slice_idx] = allocation;
            log_debug(HLD,
                      "%s: slice_ifg=%d/%d allocation=%s",
                      __func__,
                      ifg.slice,
                      ifg.ifg,
                      m_allocations[direction][slice_idx].to_string().c_str());
        }
        return LA_STATUS_SUCCESS;
    }

    log_debug(HLD,
              "la_counter_set_impl::add_ifg: allocate - dir %d, size %zd, slice %d, ifg %d, num %zd, utype %d",
              (int)direction,
              m_set_size,
              ifg.slice,
              ifg.ifg,
              num_of_ifgs,
              (int)m_user_type);
    txn.status = m_device->m_counter_bank_manager->allocate(
        true /*is_slice_pair*/, direction, m_set_size, ifg, num_of_ifgs, m_user_type, allocation);
    log_debug(HLD, "la_counter_set_impl::add_ifg: allocate => result %d, %s", txn.status.value(), allocation.to_string().c_str());
    return_on_error(txn.status);

    m_allocations[direction][slice_idx] = allocation;

    return txn.status;
}

la_status
la_counter_set_impl::remove_ifg(la_slice_ifg ifg, counter_direction_e direction)
{
    bool ifg_removed, slice_removed, slice_pair_removed;

    m_ifg_use_count[direction]->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    if (!slice_pair_removed) {
        return LA_STATUS_SUCCESS;
    }

    if (m_user_type == COUNTER_USER_TYPE_SECURITY_GROUP_CELL) {
        if (slice_pair_removed) {
            counter_allocation allocation;
            size_t pair_idx = ifg.slice / 2;
            allocation = m_allocations[direction][pair_idx];
            // Return the allocation back to the device.
            la_status status = m_device->release_sgacl_counter_allocation(pair_idx, allocation);
            return_on_error(status);
            auto it = m_allocations[direction].find(pair_idx);
            if (it == m_allocations[direction].end()) {
                return LA_STATUS_EUNKNOWN;
            }
            m_allocations[direction].erase(it);
        }
        return LA_STATUS_SUCCESS;
    }

    if (m_meter != nullptr) {
        // allocation comes from Meter bank via meter
        for (size_t counter_index = 0; counter_index < m_set_size; counter_index++) {
            uint64_t bytes;
            uint64_t packets;
            auto colors = {la_qos_color_e::GREEN, la_qos_color_e::YELLOW, la_qos_color_e::RED};
            for (auto color : colors) {
                la_status status
                    = m_meter->read(counter_index, true /* force_update*/, true /*clear_on_read*/, color, bytes, packets);
                return_on_error(status);
                m_cached_bytes[counter_index] += bytes;
                m_cached_packets[counter_index] += packets;
            }
        }

        return LA_STATUS_SUCCESS;
    }

    // Get the corresponding allocation
    counter_allocation allocation;
    la_status status = get_allocation(ifg.slice, direction, allocation);
    return_on_error(status);

    // Update the counter cache
    for (size_t counter_index = 0; counter_index < m_set_size; counter_index++) {
        // Reading from all slices
        uint64_t bytes;
        uint64_t packets;

        m_device->m_counter_bank_manager->read_counter(
            allocation, counter_index, true /* force_update*/, true /*clear_on_read*/, bytes, packets);
        size_t bytes_counter_adjustment = get_bytes_counter_adjustment(direction, packets);
        m_cached_bytes[counter_index] += (bytes + bytes_counter_adjustment);
        m_cached_packets[counter_index] += packets;
    }

    // Release the allocation
    m_device->m_counter_bank_manager->release(m_user_type, allocation);

    // Remove the allocation from the allocations map
    size_t slice_idx = ifg.slice / 2;
    auto it = m_allocations[direction].find(slice_idx);
    if (it == m_allocations[direction].end()) {
        return LA_STATUS_EUNKNOWN;
    }

    m_allocations[direction].erase(it);

    return LA_STATUS_SUCCESS;
}

size_t
la_counter_set_impl::get_bytes_counter_adjustment(counter_direction_e direction, size_t packets)
{
    if (direction != COUNTER_DIRECTION_EGRESS) {
        // rx counters don't need any compensation
        return 0;
    }

    size_t bytes_to_add = packets * la_device_impl::CRC_HEADER_SIZE;
    return bytes_to_add;
}

la_status
la_counter_set_impl::read(la_slice_ifg ifg,
                          size_t counter_index,
                          bool force_update,
                          bool clear_on_read,
                          size_t& out_packets,
                          size_t& out_bytes)
{
    start_api_getter_call();

    out_packets = 0;
    out_bytes = 0;

    if (counter_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status stat = m_slice_id_manager->is_slice_ifg_valid(ifg);
    return_on_error(stat);

    if (get_type() == la_counter_set::type_e::VOQ) {
        log_err(HLD, "la_counter_set_impl::%s: Operation not supported for VOQ counters", __func__);
        return LA_STATUS_EINVAL;
    }

    if (m_meter != nullptr) {
        auto colors = {la_qos_color_e::GREEN, la_qos_color_e::YELLOW, la_qos_color_e::RED};
        for (auto color : colors) {
            size_t packets = 0;
            size_t bytes = 0;

            la_status status = m_meter->read(ifg, counter_index, color, packets, bytes);
            return_on_error(status);

            out_packets += packets;
            out_bytes += bytes;
        }

        return LA_STATUS_SUCCESS;
    }

    size_t gifg = m_slice_id_manager->slice_ifg_2_global_ifg(ifg);

    for (counter_direction_e direction = COUNTER_DIRECTION_INGRESS; direction < COUNTER_DIRECTION_NUM;
         direction = (counter_direction_e)((size_t)direction + 1)) {

        for (auto it = m_allocations[direction].cbegin(); it != m_allocations[direction].cend(); it++) {
            size_t curr_bytes = 0, curr_packets = 0;
            const counter_allocation& allocation = it->second;
            size_t alloc_gifg = m_slice_id_manager->slice_ifg_2_global_ifg(allocation.get_ifg());
            bool is_inside_alloc = (gifg >= alloc_gifg) && (gifg < alloc_gifg + allocation.get_num_of_ifgs());
            if (is_inside_alloc) {
                // If allocation holds the given IFG then read the counter and break
                m_device->m_counter_bank_manager->read_counter_ifg(
                    allocation, ifg, counter_index, force_update, clear_on_read, curr_bytes, curr_packets);
                out_bytes += curr_bytes;
                size_t bytes_counter_adjustment = get_bytes_counter_adjustment(direction, out_packets);
                out_bytes += bytes_counter_adjustment;
                out_packets += curr_packets;
                break;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::read(size_t counter_index, bool force_update, bool clear_on_read, size_t& out_packets, size_t& out_bytes)
{
    start_api_getter_call("counter_index=", counter_index, "force_update=", force_update, "clear_on_read=", clear_on_read);

    if (counter_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (get_type() == la_counter_set::type_e::VOQ) {
        return read_voq_counter_set(counter_index, force_update, clear_on_read, out_packets, out_bytes);
    }

    out_bytes = m_cached_bytes[counter_index];
    out_packets = m_cached_packets[counter_index];

    if (m_meter != nullptr) {
        auto colors = {la_qos_color_e::GREEN, la_qos_color_e::YELLOW, la_qos_color_e::RED};
        for (auto color : colors) {
            uint64_t bytes = 0;
            uint64_t packets = 0;

            la_status status = m_meter->read(counter_index, force_update, clear_on_read, color, packets, bytes);
            return_on_error(status);

            out_bytes += bytes;
            out_packets += packets;
        }

    } else {
        for (counter_direction_e direction = COUNTER_DIRECTION_INGRESS; direction < COUNTER_DIRECTION_NUM;
             direction = (counter_direction_e)((size_t)direction + 1)) {
            // Reading from all slices
            for (auto it = m_allocations[direction].cbegin(); it != m_allocations[direction].cend(); it++) {
                uint64_t bytes;
                uint64_t packets;
                const counter_allocation& allocation = it->second;

                m_device->m_counter_bank_manager->read_counter(
                    allocation, counter_index, force_update, clear_on_read, bytes, packets);
                size_t bytes_counter_adjustment = get_bytes_counter_adjustment(direction, packets);
                bytes += bytes_counter_adjustment;
                out_bytes += bytes;
                out_packets += packets;
            }
        }
    }

    if (clear_on_read) {
        m_cached_bytes[counter_index] = 0;
        m_cached_packets[counter_index] = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::read(la_slice_id_t slice_id,
                          size_t counter_index,
                          bool force_update,
                          bool clear_on_read,
                          size_t& out_packets,
                          size_t& out_bytes)
{
    start_api_getter_call(
        "slice_id=", slice_id, "counter_index=", counter_index, "force_update=", force_update, "clear_on_read=", clear_on_read);

    if (counter_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (get_type() != la_counter_set::type_e::VOQ) {
        log_err(HLD, "la_counter_set_impl::%s: Operation supported only for VOQ counters", __func__);
        return LA_STATUS_EINVAL;
    }

    size_t voq_counter_set_id = m_base_voq / voq_counter_set::NUM_VOQS_IN_SET;

    voq_counter_set_sptr& vcs(m_device->m_voq_counter_sets[voq_counter_set_id]);

    if (!vcs) {
        return LA_STATUS_EINVAL;
    }

    return vcs->read(m_base_voq, slice_id, counter_index, force_update, clear_on_read, out_packets, out_bytes);
}

la_status
la_counter_set_impl::read_voq_counter_set(size_t counter_index,
                                          bool force_update,
                                          bool clear_on_read,
                                          size_t& out_packets,
                                          size_t& out_bytes)
{
    size_t voq_counter_set_id = m_base_voq / voq_counter_set::NUM_VOQS_IN_SET;

    voq_counter_set_sptr& vcs(m_device->m_voq_counter_sets[voq_counter_set_id]);

    if (!vcs) {
        return LA_STATUS_EINVAL;
    }

    return vcs->read(m_base_voq, counter_index, force_update, clear_on_read, out_packets, out_bytes);
}

la_status
la_counter_set_impl::add_ace_counter(counter_direction_e direction, const slice_ifg_vec_t& slice_ifgs)
{
    transaction txn;

    txn.status = validate_ace_counter(direction);
    return_on_error(txn.status);

    bool is_aggregate = true;
    init_counter_data(m_set_size, la_counter_set::type_e::DROP, COUNTER_USER_TYPE_SEC_ACE, direction, is_aggregate);

    for (auto& slice_ifg : slice_ifgs) {
        txn.status = add_ifg(slice_ifg, direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_ace_counter(const slice_ifg_vec_t& slice_ifgs)
{
    for (auto& slice_ifg : slice_ifgs) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    if (!m_ifg_use_count[m_direction]->is_in_use()) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_drop_counter(counter_direction_e direction, const slice_ifg_vec_t& slice_ifgs)
{
    transaction txn;

    txn.status = validate_drop_counter(direction);
    return_on_error(txn.status);

    // Drop counter can be attached to several objects, each residing on a different IFG.
    bool is_aggregate = true;
    init_counter_data(m_set_size, la_counter_set::type_e::DROP, COUNTER_USER_TYPE_DROP, direction, is_aggregate);

    for (auto& slice_ifg : slice_ifgs) {
        txn.status = add_ifg(slice_ifg, direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_drop_counter(const slice_ifg_vec_t& slice_ifgs)
{
    for (auto& slice_ifg : slice_ifgs) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    if (!m_ifg_use_count[m_direction]->is_in_use()) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_internal_error_counter(counter_direction_e direction)
{
    return add_drop_counter(direction, m_device->get_used_ifgs());
}

la_status
la_counter_set_impl::add_trap_counter(counter_direction_e direction)
{
    transaction txn;

    txn.status = validate_trap_counter(direction);
    return_on_error(txn.status);

    init_counter_data(m_set_size, la_counter_set::type_e::DROP, COUNTER_USER_TYPE_TRAP, direction, true /* is_aggregate */);

    for (la_slice_ifg slice_ifg : m_device->get_used_ifgs()) {
        txn.status = add_ifg(slice_ifg, direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_trap_counter(counter_direction_e direction)
{
    if (direction != m_direction) {
        return (LA_STATUS_EINVAL);
    }

    for (la_slice_ifg slice_ifg : m_device->get_used_ifgs()) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    if (!m_ifg_use_count[m_direction]->is_in_use()) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_mcg_counter(la_slice_ifg& slice_ifg)
{
    la_status status = validate_mcg_counter();
    return_on_error(status);

    init_counter_data(
        m_set_size, la_counter_set::type_e::MCG, COUNTER_USER_TYPE_MCG, COUNTER_DIRECTION_EGRESS, false /* is_aggregate */);

    for (size_t i = 0; i < NUM_IFGS_PER_DEVICE; i++) {
        status = m_device->get_next_ifg_for_mcg_counter(slice_ifg);
        return_on_error_log(status, HLD, ERROR, "No IFG available for MCG counters");

        status = add_ifg(slice_ifg, m_direction);
        if (status != LA_STATUS_ERESOURCE) {
            break;
        }
    }

    return status;
}

la_status
la_counter_set_impl::remove_mcg_counter(const la_slice_ifg& slice_ifg)
{
    la_status status = remove_ifg(slice_ifg, m_direction);
    return_on_error(status);

    if (!m_ifg_use_count[m_direction]->is_in_use()) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_bfd_counter()
{
    transaction txn;

    txn.status = validate_bfd_counter();
    return_on_error(txn.status);

    init_counter_data(
        m_set_size, la_counter_set::type_e::BFD, COUNTER_USER_TYPE_BFD, COUNTER_DIRECTION_INGRESS, true /* is_aggregate */);

    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        txn.status = add_ifg(slice_ifg, m_direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, m_direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_bfd_counter()
{
    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    bool in_use = m_ifg_use_count[COUNTER_DIRECTION_INGRESS]->is_in_use();
    if (!in_use) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_ip_tunnel_transit_counter()
{
    transaction txn;

    txn.status = validate_ip_tunnel_transit_counter();
    return_on_error(txn.status);

    init_counter_data(m_set_size,
                      la_counter_set::type_e::IP_TUNNEL,
                      COUNTER_USER_TYPE_TUNNEL,
                      COUNTER_DIRECTION_INGRESS,
                      true /* is_aggregate */);

    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        txn.status = add_ifg(slice_ifg, m_direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, m_direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_ip_tunnel_transit_counter()
{
    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    bool in_use = m_ifg_use_count[COUNTER_DIRECTION_INGRESS]->is_in_use();
    if (!in_use) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_ip_tunnel_transit_counter() const
{
    if (m_set_size != static_cast<size_t>(la_ip_tunnel_type_e::LAST)) {
        return LA_STATUS_EINVAL;
    }

    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::IP_TUNNEL || m_user_type != COUNTER_USER_TYPE_TUNNEL || m_is_aggregate == false) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_global_lsp_prefix_counter(type_e counter_type)
{
    transaction txn;

    txn.status = validate_global_lsp_prefix_counter();
    return_on_error(txn.status);

    counter_user_type_e user_type
        = (counter_type == type_e::MPLS_TRAFFIC_MATRIX) ? COUNTER_USER_TYPE_SR_DM : COUNTER_USER_TYPE_MPLS_GLOBAL;
    init_counter_data(m_set_size, counter_type, user_type, COUNTER_DIRECTION_EGRESS, true /* is_aggregate */);

    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        txn.status = add_ifg(slice_ifg, m_direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, m_direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_global_lsp_prefix_counter()
{
    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    bool in_use = m_ifg_use_count[COUNTER_DIRECTION_EGRESS]->is_in_use();
    if (!in_use) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_erspan_session_counter()
{
    transaction txn;

    txn.status = validate_erspan_session_counter();
    return_on_error(txn.status);

    init_counter_data(
        m_set_size, la_counter_set::type_e::ERSPAN, COUNTER_USER_TYPE_ERSPAN, COUNTER_DIRECTION_EGRESS, true /* is_aggregate */);

    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        txn.status = add_ifg(slice_ifg, m_direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, m_direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_erspan_session_counter()
{
    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    bool in_use = m_ifg_use_count[COUNTER_DIRECTION_INGRESS]->is_in_use();
    if (!in_use) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_mpls_decap_counter()
{
    transaction txn;

    txn.status = validate_mpls_decap_counter();
    return_on_error(txn.status);

    init_counter_data(m_set_size,
                      la_counter_set::type_e::MPLS_DECAP,
                      COUNTER_USER_TYPE_MPLS_DECAP,
                      COUNTER_DIRECTION_INGRESS,
                      true /* is_aggregate */);

    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        txn.status = add_ifg(slice_ifg, m_direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, m_direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_mpls_decap_counter()
{
    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    bool in_use = m_ifg_use_count[COUNTER_DIRECTION_INGRESS]->is_in_use();
    if (!in_use) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_vni_decap_counter()
{
    transaction txn;

    txn.status = validate_vni_counter();
    return_on_error(txn.status);

    init_counter_data(
        m_set_size, la_counter_set::type_e::VNI, COUNTER_USER_TYPE_VNI, COUNTER_DIRECTION_INGRESS, true /* is_aggregate */);

    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        txn.status = add_ifg(slice_ifg, m_direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, m_direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_vni_decap_counter()
{
    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    bool in_use = m_ifg_use_count[COUNTER_DIRECTION_INGRESS]->is_in_use();
    if (!in_use) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_vni_encap_counter()
{
    transaction txn;

    txn.status = validate_vni_counter();
    return_on_error(txn.status);

    init_counter_data(
        m_set_size, la_counter_set::type_e::VNI, COUNTER_USER_TYPE_VNI, COUNTER_DIRECTION_EGRESS, true /* is_aggregate */);

    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        txn.status = add_ifg(slice_ifg, m_direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, m_direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_vni_encap_counter()
{
    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    bool in_use = m_ifg_use_count[COUNTER_DIRECTION_EGRESS]->is_in_use();
    if (!in_use) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::add_pq_counter_user(const la_object_wcptr& user,
                                         type_e counter_type,
                                         counter_direction_e direction,
                                         bool is_aggregate)
{
    transaction txn;

    txn.status = validate_pq_user_counter(user, counter_type, direction, is_aggregate);
    return_on_error(txn.status);

    counter_user_type_e user_type;
    get_user_type(counter_type, user, user_type); // Validated above. No need to check return value
    init_counter_data(m_set_size, counter_type, user_type, direction, is_aggregate);

    if (counter_type == type_e::QOS && direction == COUNTER_DIRECTION_INGRESS) {
        if (m_meter == nullptr) {
            txn.status = create_internal_meter(m_set_size);
            return_on_error(txn.status);
            txn.on_fail([=]() { destroy_internal_meter(); });
        }

        txn.status = m_meter->attach_user(user, is_aggregate);
        return_on_error(txn.status);
    }

    slice_ifg_vec_t ifgs = get_ifgs(user);
    for (auto& ifg : ifgs) {
        txn.status = add_ifg(ifg, m_direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(ifg, m_direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_pq_counter_user(const la_object_wcptr& user)
{
    slice_ifg_vec_t ifgs = get_ifgs(user);

    for (auto& ifg : ifgs) {
        la_status status = remove_ifg(ifg, m_direction);
        return_on_error(status);
    }

    if (m_meter != nullptr) {
        la_status status = m_meter->detach_user(user);
        return_on_error(status);

        if (!(m_device->is_in_use(m_meter))) {
            status = destroy_internal_meter();
            return_on_error(status);
        }
    }
    if (!m_ifg_use_count[m_direction]->is_in_use()) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_pq_user_counter(const la_object_wcptr& user,
                                              type_e counter_type,
                                              counter_direction_e direction,
                                              bool is_aggregate) const
{
    counter_user_type_e user_type;
    la_status status = get_user_type(counter_type, user, user_type);
    return_on_error(status, HLD, ERROR, "%s: unknown user type for object %s", __func__, user->to_string().c_str());

    // Make sure the port set size is adequate
    if (counter_type == la_counter_set::type_e::PORT) {
        if (!is_valid_set_size()) {
            return LA_STATUS_EINVAL;
        }
    }

    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if ((counter_type != m_counter_type) || (direction != m_direction) || (user_type != m_user_type)
        || (is_aggregate != m_is_aggregate)) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_ace_counter(counter_direction_e direction) const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::DROP || m_user_type != COUNTER_USER_TYPE_SEC_ACE || m_direction != direction) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_drop_counter(counter_direction_e direction) const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::DROP || m_user_type != COUNTER_USER_TYPE_DROP || m_direction != direction) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_trap_counter(counter_direction_e direction) const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::DROP || m_user_type != COUNTER_USER_TYPE_TRAP || m_direction != direction
        || m_is_aggregate == false) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_mcg_counter() const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::MCG || m_user_type != COUNTER_USER_TYPE_MCG || m_is_aggregate == false) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_bfd_counter() const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::BFD || m_user_type != COUNTER_USER_TYPE_BFD || m_is_aggregate == false) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_global_lsp_prefix_counter() const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::PORT || m_user_type != COUNTER_USER_TYPE_MPLS_GLOBAL || m_is_aggregate == false) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_erspan_session_counter() const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::ERSPAN || m_user_type != COUNTER_USER_TYPE_ERSPAN || m_is_aggregate == false) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_mpls_decap_counter() const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::MPLS_DECAP || m_user_type != COUNTER_USER_TYPE_MPLS_DECAP
        || m_is_aggregate == false) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_vni_counter() const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::VNI || m_user_type != COUNTER_USER_TYPE_VNI || m_is_aggregate == false) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::validate_security_group_cell_counter() const
{
    if (m_counter_type == type_e::INVALID) {
        return LA_STATUS_SUCCESS;
    }

    if (m_counter_type != la_counter_set::type_e::SECURITY_GROUP_CELL || m_user_type != COUNTER_USER_TYPE_SECURITY_GROUP_CELL
        || m_direction != COUNTER_DIRECTION_INGRESS
        || m_is_aggregate == false) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

void
la_counter_set_impl::init_counter_data(size_t set_size,
                                       type_e counter_type,
                                       counter_user_type_e user_type,
                                       counter_direction_e direction,
                                       bool is_aggregate)
{
    m_set_size = set_size;
    m_counter_type = counter_type;
    m_user_type = user_type;
    m_direction = direction;
    m_is_aggregate = is_aggregate;
}

bool
la_counter_set_impl::is_valid_set_size() const
{
    return ((m_set_size == 1) || (m_set_size == 2) || (m_set_size >= (size_t)la_l3_protocol_e::LAST));
}

void
la_counter_set_impl::set_voq_base(la_voq_gid_t base_voq_id)
{
    init_counter_data(
        m_set_size, la_counter_set::type_e::VOQ, COUNTER_USER_TYPE_VOQ, COUNTER_DIRECTION_INGRESS, false /* is_aggregate */);

    m_base_voq = base_voq_id;
}

la_status
la_counter_set_impl::destroy_internal_meter()
{
    la_status status = m_device->do_destroy(m_meter);
    return_on_error(status);

    m_meter = nullptr;
    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::create_internal_meter(size_t size)
{
    la_meter_set_impl_wptr meter;
    transaction txn;

    txn.status = m_device->do_create_meter(la_meter_set::type_e::PER_IFG_EXACT, size, meter);
    return_on_error(txn.status);
    txn.on_fail([=]() { m_device->do_destroy(meter); });

    auto meter_set = meter.weak_ptr_static_cast<la_meter_set_exact_impl>();
    for (size_t meter_index = 0; meter_index < size; meter_index++) {
        txn.status = meter_set->set_committed_bucket_coupling_mode(meter_index, la_meter_set::coupling_mode_e::TO_EXCESS_BUCKET);
        return_on_error(txn.status);

        txn.status = meter_set->set_meter_profile(meter_index, m_device->m_exact_meter_profile.get());
        return_on_error(txn.status);

        txn.status = meter_set->set_meter_action_profile(meter_index, m_device->m_exact_meter_action_profile.get());
        return_on_error(txn.status);

        // Max meter rate to mimic counter behaviour.
        for (la_slice_ifg slice_ifg : m_device->get_used_ifgs()) {

            la_rate_t meter_cir = (meter_set->get_shaper_max_rate(meter_index, true) * UNITS_IN_GIGA);
            txn.status = meter_set->set_cir(meter_index, slice_ifg, meter_cir);
            return_on_error(txn.status);
            la_rate_t meter_eir = (meter_set->get_shaper_max_rate(meter_index, false) * UNITS_IN_GIGA);
            txn.status = meter_set->set_eir(meter_index, slice_ifg, meter_eir);
            return_on_error(txn.status);
        }
    }

    m_meter = meter_set;

    m_meter->set_counter_user_type(COUNTER_USER_TYPE_QOS);

    return LA_STATUS_SUCCESS;
}

bool
la_counter_set_impl::is_using_meter() const
{
    return (m_meter != nullptr);
}

la_status
la_counter_set_impl::add_security_group_cell_counter()
{
    transaction txn;

    txn.status = validate_security_group_cell_counter();
    return_on_error(txn.status);

    init_counter_data(m_set_size,
                      la_counter_set::type_e::SECURITY_GROUP_CELL,
                      COUNTER_USER_TYPE_SECURITY_GROUP_CELL,
                      COUNTER_DIRECTION_INGRESS,
                      true /* is_aggregate */);

    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        txn.status = add_ifg(slice_ifg, m_direction);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(slice_ifg, m_direction); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_counter_set_impl::remove_security_group_cell_counter()
{
    for (la_slice_ifg slice_ifg : get_all_network_ifgs(m_device)) {
        la_status status = remove_ifg(slice_ifg, m_direction);
        return_on_error(status);
    }

    bool in_use = m_ifg_use_count[COUNTER_DIRECTION_INGRESS]->is_in_use();
    if (!in_use) {
        m_counter_type = type_e::INVALID;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
