// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_bfd_session_base.h"

#include "nplapi/npl_constants.h"
#include "npu/counter_utils.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_next_hop_base.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_l2_punt_destination_impl.h"
#include "system/la_npu_host_destination_impl.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_punt_inject_port_base.h"
#include "system/la_system_port_base.h"
#include "system/slice_id_manager_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

namespace silicon_one
{

using namespace std::chrono;

static constexpr int BFD_PACKET_LENGTH = 52;

la_bfd_session_base::la_bfd_session_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_npuh_id(0),
      m_session_id(0),
      m_detection_timer_armed(la_armed_state_e::NOT_ARMED),
      m_delay_arm_timer(0),
      m_punt_destination(nullptr),
      m_counter(nullptr),
      m_system_port(nullptr),
      m_l3_port(nullptr),
      m_next_hop(nullptr),
      m_inject_up_source_port(nullptr),
      m_packet_intervals(nullptr),
      m_transmit_interval(nullptr),
      m_detection_time(nullptr),
      m_local_ipv6_addr(nullptr),
      m_local_diag_code(la_bfd_diagnostic_code_e::NO_DIAGNOSTIC),
      m_phase_count(0),
      m_echo_mode_enabled(false),
      m_punt_destination_remote(false),
      m_tc(0),
      m_label_ttl(0)
{
    m_tos.flat = 0;
    m_label.label = 0;
}

la_bfd_session_base::~la_bfd_session_base() = default;

la_status
la_bfd_session_base::initialize(la_object_id_t oid,
                                la_bfd_discriminator local_discriminator,
                                type_e session_type,
                                la_l3_protocol_e protocol,
                                const la_punt_destination_wcptr& punt_destination)
{
    m_oid = oid;
    m_local_discriminator = local_discriminator;
    m_type = session_type;
    m_protocol = protocol;

    // Initialize the traffic class to highest priority
    m_tc = 7;

    if (!punt_destination) {
        return LA_STATUS_EINVAL;
    }

    if (m_device != punt_destination->get_device()) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    m_punt_destination = punt_destination;
    m_device->add_object_dependency(punt_destination, this);

    auto status = update_rx_entry();
    return_on_error(status);

    m_session_id = index_handle(m_device->m_index_generators.bfd_session_ids);
    if (!m_session_id) {
        log_err(HLD, "Out of internal bfd session ids");
        return LA_STATUS_ERESOURCE;
    }

    // Check if the destination for this session is not on this device.
    // If it is remote we don't need to program the session in the NPU host.
    set_remote_session_flag();

    if (is_remote()) {
        return LA_STATUS_SUCCESS;
    }

    m_npuh_id = index_handle(m_device->m_index_generators.npuh_mep_ids);
    if (!m_npuh_id) {
        log_err(HLD, "Out of internal NPU host ids");
        return LA_STATUS_ERESOURCE;
    }

    /* Initialize the remote state for this session. */
    la_bfd_flags bf;
    bf.flat = 0;
    status = set_remote_state(bf);
    return_on_error(status);

    /*
     * If its echo mode, initialize intervals to zero.
     * This allows more sharing of NPL code between echo and async.
     */
    if (m_type == type_e::ECHO) {
        auto desired_min_tx_interval = std::chrono::microseconds(0);
        auto required_min_rx_interval = std::chrono::microseconds(0);
        status = set_intervals_internal(desired_min_tx_interval, required_min_rx_interval, 0);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
la_bfd_session_base::set_remote_session_flag()
{
    if (!m_punt_destination) {
        m_punt_destination_remote = true;
        return;
    }

    // If the punt destination is not an NPU host, it must be remote
    if (m_punt_destination->type() != object_type_e::NPU_HOST_DESTINATION) {
        m_punt_destination_remote = true;
        return;
    }

    auto npu_host_impl = m_punt_destination.weak_ptr_static_cast<const la_npu_host_destination_impl>();
    auto npu_port = npu_host_impl->get_npu_host_port();
    if (!npu_port) {
        // If we can't get the npu port, consider it a remote session
        m_punt_destination_remote = true;
    } else {
        m_punt_destination_remote = npu_port->is_remote();
    }
}

bool
la_bfd_session_base::is_remote() const
{
    return m_punt_destination_remote;
}

la_status
la_bfd_session_base::destroy()
{
    m_device->remove_oam_delay_arm(m_device->get_sptr(this));
    m_detection_timer_armed = la_armed_state_e::NOT_ARMED;

    la_status status = teardown_entries();
    return_on_error(status);

    if (m_transmit_interval) {
        uint32_t use_count = m_transmit_interval.use_count();
        uint32_t old_id = m_transmit_interval->id();

        // Release the interval
        m_transmit_interval.reset();

        // If this was the last session using it, clear the entry in hw.
        if (use_count == 1) {
            set_npu_host_max_ccm_counter(old_id, 0);
        }
    }

    if (m_punt_destination) {
        m_device->remove_object_dependency(m_punt_destination, this);
    }

    if (m_system_port) {
        m_device->remove_object_dependency(m_system_port, this);
    }

    if (m_l3_port) {
        m_device->remove_object_dependency(m_l3_port, this);
    }

    if (m_counter) {
        m_counter->remove_bfd_counter();
        m_device->remove_object_dependency(m_counter, this);
    }

    return LA_STATUS_SUCCESS;
}

destination_id
la_bfd_session_base::rx_destination_id() const
{
    if (m_punt_destination == nullptr) {
        return DESTINATION_ID_INVALID;
    }

    return get_destination_id(m_punt_destination, RESOLUTION_STEP_FIRST);
}

static npl_bfd_session_protocol_e
l3_protocol_to_bfd_protocol(la_l3_protocol_e l3_protocol)
{
    if (l3_protocol == la_l3_protocol_e::IPV6_UC) {
        return NPL_BFD_SESSION_IPV6;
    } else {
        return NPL_BFD_SESSION_IPV4;
    }
}

la_status
la_bfd_session_base::populate_rx_key(npl_bfd_rx_table_key_t& key) const
{
    auto local_discr_msb = (to_utype(m_local_discriminator) >> 16) & 0xffff;

    key.your_discr_31_16_ = local_discr_msb;
    key.your_discr_23_16_ = local_discr_msb & 0xff;

    uint16_t dest_port;

    switch (m_type) {
    case la_bfd_session::type_e::ECHO:
        dest_port = NPL_UDP_BFD_ECHO_PORT;
        break;
    case la_bfd_session::type_e::MICRO:
        dest_port = NPL_UDP_BFD_MICRO_HOP_PORT;
        break;
    case la_bfd_session::type_e::MULTI_HOP:
        dest_port = NPL_UDP_BFD_MULTI_HOP_PORT;
        break;
    case la_bfd_session::type_e::SINGLE_HOP:
    default:
        dest_port = NPL_UDP_BFD_SINGLE_HOP_PORT;
        break;
    }

    key.dst_port = dest_port;
    key.protocol_type = l3_protocol_to_bfd_protocol(m_protocol);

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::update_rx_entry()
{
    npl_bfd_rx_table_t::key_type k;
    npl_bfd_rx_table_t::value_type v;
    npl_bfd_rx_table_t::entry_pointer_type e = nullptr;
    auto result = &v.payloads.bfd_em_lookup_result;

    populate_rx_key(k);

    result->encap_result = 1;
    result->meter = 0; // TODO: support bfd session meters
    result->destination = rx_destination_id().val;

    uint16_t local_discr_msb = k.your_discr_31_16_;
    uint16_t dest_port = k.dst_port;

    bfd_rx_entry_data_t entry = {local_discr_msb, dest_port, m_protocol, rx_destination_id().val};

    la_status status = m_device->m_profile_allocators.bfd_rx_entries->reallocate(m_rx_entry, entry);
    return_on_error(status, HLD, ERROR, "Out of local bfd rx entries profiles");

    auto profile_entry = m_rx_entry->value();
    if (profile_entry.destination != entry.destination) {
        log_err(HLD,
                "BFD rx entry's destination does not match previous rx entries with the same key = %s",
                silicon_one::to_string(m_local_discriminator).c_str());
        return LA_STATUS_ENOTFOUND;
    }

    if (m_rx_entry.use_count() != 1) {
        return LA_STATUS_SUCCESS;
    }

    switch (m_punt_destination->type()) {
    case object_type_e::NPU_HOST_DESTINATION:
        result->punt_encap_data.punt_nw_encap_ptr.ptr = la_device_impl::NPU_HOST_BFD_ENCAP_PTR;
        result->punt_encap_data.punt_nw_encap_type = NPL_PUNT_NW_NPU_HOST_ENCAP_TYPE;
        break;
    case object_type_e::L2_PUNT_DESTINATION: {
        auto punt_dest_impl = m_punt_destination.weak_ptr_static_cast<const la_l2_punt_destination_impl>();
        result->punt_encap_data.punt_nw_encap_type = NPL_PUNT_NW_ETH_ENCAP_TYPE;
        result->punt_encap_data.punt_nw_encap_ptr.ptr = punt_dest_impl->get_gid();
    } break;
    default:
        return LA_STATUS_EINVAL;
    }

    return (m_device->m_tables.bfd_rx_table->set(k, v, e));
}

la_status
la_bfd_session_base::erase_rx_entry()
{
    npl_bfd_rx_table_t::key_type k;

    // Only erase if this is the last session using this entry
    if (m_rx_entry.use_count() != 1) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = populate_rx_key(k);
    // If we can not populate the key, we'll just assume that
    // the entry was never created.
    if (status != LA_STATUS_SUCCESS) {
        return LA_STATUS_SUCCESS;
    }

    status = m_device->m_tables.bfd_rx_table->erase(k);

    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    return status;
}

la_object::object_type_e
la_bfd_session_base::type() const
{
    return object_type_e::BFD_SESSION;
}

const la_device*
la_bfd_session_base::get_device() const
{
    return m_device.get();
}

la_object_id_t
la_bfd_session_base::oid() const
{
    return m_oid;
}

std::string
la_bfd_session_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_bfd_session_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_status
la_bfd_session_base::get_session_type(type_e& out_type) const
{
    start_api_getter_call();

    out_type = m_type;
    return LA_STATUS_SUCCESS;
}

bool
la_bfd_session_base::get_echo_mode_enabled() const
{
    start_api_getter_call();

    return m_echo_mode_enabled;
}

la_status
la_bfd_session_base::set_echo_mode_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    // Don't allow enabling an echo session for an echo session or multi-hop
    if ((m_type == type_e::ECHO) || (m_type == type_e::MULTI_HOP)) {
        return LA_STATUS_EINVAL;
    }

    // If no change, just return success
    if (m_echo_mode_enabled == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_echo_mode_enabled = enabled;
    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_local_discriminator(la_bfd_discriminator& out_local_discriminator) const
{
    start_api_getter_call();

    out_local_discriminator = m_local_discriminator;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_remote_discriminator(la_bfd_discriminator remote_discriminator)
{
    start_api_call("remote_discriminator=", remote_discriminator);

    if (remote_discriminator == m_remote_discriminator) {
        return LA_STATUS_SUCCESS;
    }

    m_remote_discriminator = remote_discriminator;

    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_remote_discriminator(la_bfd_discriminator& out_remote_discriminator) const
{
    start_api_getter_call();

    out_remote_discriminator = m_remote_discriminator;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_local_state(la_bfd_diagnostic_code_e diag_code, la_bfd_flags flags)
{
    start_api_call("diag_code=", diag_code, "bfd_flags=", flags);

    // local flags and diag code are not applicable to ECHO
    if (m_type != type_e::ECHO) {
        // Check if there was any change to avoid updating hardware
        if ((m_local_diag_code == diag_code) && (m_local_flags.flat == flags.flat)) {
            return LA_STATUS_SUCCESS;
        }

        m_local_diag_code = diag_code;
        m_local_flags = flags;

        return update_npuh_entries();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::get_local_state(la_bfd_diagnostic_code_e& out_diag_code, la_bfd_flags& out_flags) const
{
    start_api_getter_call();

    out_diag_code = m_local_diag_code;
    out_flags = m_local_flags;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_remote_state(la_bfd_flags remote_flags)
{
    start_api_call("remote_flags=", remote_flags);

    if (m_remote_flags.flat == remote_flags.flat) {
        return LA_STATUS_SUCCESS;
    }

    m_remote_flags = remote_flags;

    return update_rmep_state_table();
}

la_status
la_bfd_session_base::get_remote_state(la_bfd_flags& out_flags) const
{
    start_api_getter_call();

    out_flags = m_remote_flags;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_intervals_internal(microseconds desired_min_tx_interval,
                                            microseconds required_min_rx_interval,
                                            uint8_t detection_time_multiplier)
{
    bfd_packet_intervals intervals{};

    intervals.desired_min_tx_interval = desired_min_tx_interval;
    intervals.required_min_rx_interval = required_min_rx_interval;
    intervals.detection_time_multiplier = detection_time_multiplier;

    la_status status = m_device->m_profile_allocators.npu_host_packet_intervals->reallocate(m_packet_intervals, intervals);
    return_on_error(status, HLD, ERROR, "Out of packet interval profiles");

    return update_npuh_entries();
}

la_status
la_bfd_session_base::set_intervals(microseconds desired_min_tx_interval,
                                   microseconds required_min_rx_interval,
                                   uint8_t detection_time_multiplier)
{
    start_api_call("desired_min_tx_interval=",
                   desired_min_tx_interval,
                   "required_min_rx_interval=",
                   required_min_rx_interval,
                   "detection_time_multiplier=",
                   detection_time_multiplier);

    // Setting intervals are not applicable to echo mode
    if (m_type == type_e::ECHO) {
        return LA_STATUS_SUCCESS;
    }

    // Check if there is any change to avoid writing to hardware.
    if (m_packet_intervals) {
        bfd_packet_intervals intervals = m_packet_intervals->value();
        if ((intervals.desired_min_tx_interval == desired_min_tx_interval)
            && (intervals.required_min_rx_interval == required_min_rx_interval)
            && (intervals.detection_time_multiplier == detection_time_multiplier)) {
            return LA_STATUS_SUCCESS;
        }
    }

    return set_intervals_internal(desired_min_tx_interval, required_min_rx_interval, detection_time_multiplier);
}

la_status
la_bfd_session_base::get_intervals(microseconds& out_desired_min_tx_interval,
                                   microseconds& out_required_min_rx_interval,
                                   uint8_t& out_detection_time_multiplier) const
{
    start_api_getter_call();

    if (!m_packet_intervals) {
        return LA_STATUS_ENOTFOUND;
    }

    bfd_packet_intervals intervals = m_packet_intervals->value();

    out_desired_min_tx_interval = intervals.desired_min_tx_interval;
    out_required_min_rx_interval = intervals.required_min_rx_interval;
    out_detection_time_multiplier = intervals.detection_time_multiplier;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_l3_port(la_l3_port* l3_port)
{
    start_api_call("l3_port=", l3_port);

    if (l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (m_type != type_e::SINGLE_HOP && m_type != type_e::ECHO) {
        log_err(HLD, "Set L3 port only for micro or echo sessions");
        return LA_STATUS_EINVAL;
    }

    if (m_device != l3_port->get_device()) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_l3_port != nullptr) {
        log_err(HLD, "L3 port already set");
        return LA_STATUS_EBUSY;
    }

    m_l3_port = m_device->get_sptr(l3_port);

    la_status status = update_npuh_entries();
    if (status != LA_STATUS_SUCCESS) {
        m_l3_port = nullptr;
        return status;
    }

    m_device->add_object_dependency(l3_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::get_l3_port(la_l3_port*& out_l3_port) const
{
    start_api_getter_call();

    out_l3_port = m_l3_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_system_port(la_system_port* system_port)
{
    start_api_call("system_port=", system_port);

    if (m_type != type_e::MICRO) {
        log_err(HLD, "Set system port only on micro sessions");
        return LA_STATUS_EINVAL;
    }

    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (m_device != system_port->get_device()) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_system_port != nullptr) {
        log_err(HLD, "System port already set");
        return LA_STATUS_EBUSY;
    }

    m_system_port = m_device->get_sptr(static_cast<la_system_port_base*>(system_port));

    m_device->add_object_dependency(system_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::get_system_port(la_system_port*& out_system_port) const
{
    start_api_getter_call();

    out_system_port = m_system_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_inject_down_destination(const la_next_hop* next_hop)
{
    start_api_call("next_hop=", next_hop);

    const auto& nh = m_device->get_sptr<la_next_hop_base>(next_hop);

    if (next_hop) {
        la_next_hop::nh_type_e nh_type;
        la_status status = nh->get_nh_type(nh_type);
        return_on_error(status);

        if (nh_type != la_next_hop::nh_type_e::NORMAL) {
            return LA_STATUS_EINVAL;
        }
    }
    m_next_hop = nh;

    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_inject_down_destination(const la_next_hop*& out_next_hop)
{
    start_api_getter_call();

    out_next_hop = m_next_hop.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_inject_up_source_port(const la_l3_ac_port* port)
{
    start_api_call("port=", port);

    m_inject_up_source_port = m_device->get_sptr<la_l3_ac_port_impl>(port);

    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_inject_up_source_port(const la_l3_ac_port*& out_l3_ac_port)
{
    start_api_getter_call();

    out_l3_ac_port = m_inject_up_source_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::get_punt_destination(const la_punt_destination*& out_destination) const
{
    start_api_getter_call();

    out_destination = m_punt_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_transmit_interval(microseconds interval)
{
    start_api_call("interval=", interval);

    // check if there was any change
    if (m_transmit_interval && (m_transmit_interval->value() == interval)) {
        return LA_STATUS_SUCCESS;
    }

    bool clear_old_value = false;
    uint64_t old_id = 0;

    // Check if we are about to release the old transmit interval. If so,
    // we need to clear it. The profile allocator will delay reallocating it.
    if (m_transmit_interval && (m_transmit_interval.use_count() == 1)) {
        clear_old_value = true;
        old_id = m_transmit_interval->id();
    }

    la_status status = m_device->m_profile_allocators.npu_host_max_ccm_counters->reallocate(m_transmit_interval, interval);
    return_on_error(status, HLD, ERROR, "Out of transmit interval profiles");

    // Set a random phase count between 0 to the max counter value
    // to randomize the sending of bfd packets between sessions.
    uint32_t max_ccm_counter = 0;
    get_ccm_counter(max_ccm_counter);

    if (max_ccm_counter != 0) {
        m_phase_count = rand() % max_ccm_counter;
    } else {
        m_phase_count = 0;
    }

    status = update_npuh_entries();
    return_on_error(status);

    // Check if we need to clear the old transmit profile.
    if (clear_old_value) {
        return set_npu_host_max_ccm_counter(old_id, 0);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::get_transmit_interval(microseconds& out_interval) const
{
    start_api_getter_call();

    if (!m_transmit_interval) {
        return LA_STATUS_ENOTFOUND;
    }

    out_interval = m_transmit_interval->value();

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_ip_tos(la_ip_tos tos)
{
    start_api_call("tos=", tos);

    m_tos = tos;

    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_ip_tos(la_ip_tos& out_tos) const
{
    start_api_getter_call();

    out_tos = m_tos;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_local_address(la_ipv4_addr_t local_addr)
{
    start_api_call("local_addr=", local_addr);

    if (m_protocol != la_l3_protocol_e::IPV4_UC) {
        log_err(HLD, "Not an IPv4 session");
        return LA_STATUS_EINVAL;
    }

    m_local_ipv4_addr = local_addr;

    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_local_address(la_ipv4_addr_t& out_local_addr) const
{
    start_api_getter_call();

    if (m_protocol != la_l3_protocol_e::IPV4_UC) {
        log_err(HLD, "Not an IPv4 session");
        return LA_STATUS_EINVAL;
    }

    out_local_addr = m_local_ipv4_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_mpls_encap(la_mpls_label label, la_uint8_t ttl)
{
    start_api_call("label=", label, "ttl=", ttl);

    // Don't allow special MPLS label encap.
    if (label.label <= LA_MPLS_LABEL_EXTENSION) {
        return LA_STATUS_EINVAL;
    }

    // Currently only allowed on session using inject up.
    if (!using_inject_up()) {
        return LA_STATUS_EINVAL;
    }

    m_label = label;
    m_label_ttl = ttl;
    return update_npuh_entries();
}

la_status
la_bfd_session_base::clear_mpls_encap()
{
    start_api_call("");

    m_label.label = 0;
    m_label_ttl = 0;
    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_mpls_encap(la_mpls_label& out_label, la_uint8_t& out_ttl) const
{
    start_api_getter_call();

    if (m_label.label == 0) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    out_label = m_label;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_local_address(la_ipv6_addr_t local_addr)
{
    start_api_call("local_addr=", local_addr);

    if (m_protocol != la_l3_protocol_e::IPV6_UC) {
        log_err(HLD, "Not an IPv6 session");
        return LA_STATUS_EINVAL;
    }

    la_status status = m_device->m_profile_allocators.bfd_local_ipv6_addresses->reallocate(m_local_ipv6_addr, local_addr);
    return_on_error(status, HLD, ERROR, "Out of local ipv6 address profiles");

    // In c++17, could put these tables in a tuple and loop with a fold expression.
    // In c++11, the choice is between this unrolling by hand or summoning a template horror.
    {
        npl_bfd_ipv6_sip_A_table_t::key_type k{};
        npl_bfd_ipv6_sip_A_table_t::value_type v{};
        npl_bfd_ipv6_sip_A_table_t::entry_pointer_type e = nullptr;

        k.bfd_ipv6_selector.data = m_local_ipv6_addr->id();
        v.payloads.bfd_local_ipv6_A_sip.sip = local_addr.d_addr[0];

        la_status status = m_device->m_tables.bfd_ipv6_sip_A_table->set(k, v, e);
        return_on_error(status);
    }

    {
        npl_bfd_ipv6_sip_B_table_t::key_type k{};
        npl_bfd_ipv6_sip_B_table_t::value_type v{};
        npl_bfd_ipv6_sip_B_table_t::entry_pointer_type e = nullptr;

        k.bfd_ipv6_selector.data = m_local_ipv6_addr->id();
        v.payloads.bfd_local_ipv6_B_sip.sip = local_addr.d_addr[1];

        la_status status = m_device->m_tables.bfd_ipv6_sip_B_table->set(k, v, e);
        return_on_error(status);
    }

    {
        npl_bfd_ipv6_sip_C_table_t::key_type k{};
        npl_bfd_ipv6_sip_C_table_t::value_type v{};
        npl_bfd_ipv6_sip_C_table_t::entry_pointer_type e = nullptr;

        k.bfd_ipv6_selector.data = m_local_ipv6_addr->id();
        v.payloads.bfd_local_ipv6_C_sip.sip = local_addr.d_addr[2];

        la_status status = m_device->m_tables.bfd_ipv6_sip_C_table->set(k, v, e);
        return_on_error(status);
    }

    {
        npl_bfd_ipv6_sip_D_table_t::key_type k{};
        npl_bfd_ipv6_sip_D_table_t::value_type v{};
        npl_bfd_ipv6_sip_D_table_t::entry_pointer_type e = nullptr;

        k.bfd_ipv6_selector.data = m_local_ipv6_addr->id();
        v.payloads.bfd_local_ipv6_D_sip.sip = local_addr.d_addr[3];

        la_status status = m_device->m_tables.bfd_ipv6_sip_D_table->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::get_local_address(la_ipv6_addr_t& out_local_addr) const
{
    start_api_getter_call();

    if (!m_local_ipv6_addr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_local_addr = m_local_ipv6_addr->value();
    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_remote_address(la_ipv4_addr_t remote_addr)
{
    start_api_call("remote_addr=", remote_addr);

    if (m_protocol != la_l3_protocol_e::IPV4_UC) {
        log_err(HLD, "Not an IPv4 session");
        return LA_STATUS_EINVAL;
    }

    m_remote_ipv4_addr = remote_addr;
    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_remote_address(la_ipv4_addr_t& out_remote_addr) const
{
    start_api_getter_call();

    if (m_protocol != la_l3_protocol_e::IPV4_UC) {
        log_err(HLD, "Not an IPv4 session");
        return LA_STATUS_ENOTFOUND;
    }

    out_remote_addr = m_remote_ipv4_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_remote_address(la_ipv6_addr_t remote_addr)
{
    start_api_call("remote_addr=", remote_addr);

    if (m_protocol != la_l3_protocol_e::IPV6_UC) {
        log_err(HLD, "Not an IPv6 session");
        return LA_STATUS_EINVAL;
    }

    m_remote_ipv6_addr = remote_addr;

    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_remote_address(la_ipv6_addr_t& out_remote_addr) const
{
    start_api_getter_call();

    if (m_protocol != la_l3_protocol_e::IPV6_UC) {
        log_err(HLD, "Remote address is not v6");
        return LA_STATUS_ENOTFOUND;
    }

    out_remote_addr = m_remote_ipv6_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_counter(la_counter_set* counter)
{
    start_api_call("counter=", counter);

    if (counter == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(counter, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    transaction txn;

    m_device->remove_object_dependency(m_counter, this);
    txn.on_fail([=]() { m_device->add_object_dependency(m_counter, this); });

    la_counter_set_impl_wptr counter_impl = m_device->get_sptr<la_counter_set_impl>(counter);

    txn.status = counter_impl->add_bfd_counter();
    return_on_error(txn.status);

    std::swap(m_counter, counter_impl);
    txn.on_fail([=]() {
        m_counter = counter_impl;
        update_npuh_entries();
    });

    txn.status = update_npuh_entries();
    if (txn.status != LA_STATUS_SUCCESS) {
        return txn.status;
    }

    m_device->add_object_dependency(m_counter, this);

    if (counter_impl) {
        m_device->remove_object_dependency(counter_impl, this);
        counter_impl->remove_bfd_counter();
    }

    return txn.status;
}

la_status
la_bfd_session_base::get_counter(la_counter_set*& out_counter) const
{
    start_api_getter_call();

    out_counter = m_counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_detection_time(microseconds detection_time)
{
    start_api_call("detection_time=", detection_time);

    // Don't do anything if there was no change in the detection time
    if (m_detection_time && (m_detection_time->value() == detection_time)) {
        return LA_STATUS_SUCCESS;
    }

    if (detection_time == microseconds::zero()) {
        // Release profile
        m_detection_time.reset();
    } else {
        la_status status = m_device->m_profile_allocators.npu_host_detection_times->reallocate(m_detection_time, detection_time);
        return_on_error(status, HLD, ERROR, "Out of detection time profiles");
    }

    return update_npuh_entries();
}

la_status
la_bfd_session_base::get_detection_time(microseconds& out_detection_time) const
{
    start_api_getter_call();

    if (!m_detection_time) {
        out_detection_time = microseconds::zero();
        return LA_STATUS_SUCCESS;
    }

    out_detection_time = m_detection_time->value();

    return LA_STATUS_SUCCESS;
}

uint32_t
la_bfd_session_base::get_internal_id() const
{
    start_api_getter_call();

    return m_npuh_id;
}

la_status
la_bfd_session_base::set_traffic_class(la_traffic_class_t tc)
{
    start_api_call("tc=", tc);

    if (tc == m_tc) {
        return LA_STATUS_SUCCESS;
    }

    la_traffic_class_t old_tc = m_tc;
    m_tc = tc;

    la_status status = update_npuh_entries();
    if (status != LA_STATUS_SUCCESS) {
        m_tc = old_tc;
    }

    return status;
}

la_status
la_bfd_session_base::get_traffic_class(la_traffic_class_t& out_tc) const
{
    start_api_getter_call();

    out_tc = m_tc;

    return LA_STATUS_SUCCESS;
}

bool
la_bfd_session_base::using_inject_up() const
{
    if (m_type == type_e::MULTI_HOP) {
        return true;
    }

    if (m_inject_up_source_port) {
        return true;
    }

    return false;
}

static uint16_t
calc_ipv4_checksum_for_bfd(la_ipv4_addr_t sa, la_ipv4_addr_t da, la_ip_tos tos, uint8_t ttl)
{
    uint32_t sum = 0x4500; // IP packet start

    // Sum the fields
    sum += ttl << 8;
    sum += to_utype(la_l4_protocol_e::UDP);
    sum += BFD_PACKET_LENGTH;
    sum += sa.s_addr >> 16;
    sum += sa.s_addr & 0xffff;
    sum += da.s_addr >> 16;
    sum += da.s_addr & 0xffff;
    sum += tos.flat;

    // Reduce to 16 bits per RFC
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return ~sum;
}

static uint32_t
calculate_checksum(uint32_t field)
{
    uint32_t sum;
    sum = (field >> 16);
    sum += field & 0xffff;

    return sum;
}

static uint32_t
calculate_checksum(la_ipv6_addr_t addr)
{
    uint32_t sum = 0;
    for (auto word : addr.w_addr) {
        sum += word;
    }

    return sum;
}

uint16_t
la_bfd_session_base::calc_udp_checksum() const
{
    uint32_t sum = 0;

    // Calculate the checksum on the udp header
    switch (m_type) {
    case type_e::ECHO:
        sum += NPL_UDP_BFD_ECHO_PORT;
        sum += NPL_UDP_BFD_ECHO_PORT;
        break;
    case type_e::MICRO:
        sum += NPL_UDP_BFD_CONTROL_SRC_PORT;
        sum += NPL_UDP_BFD_MICRO_HOP_PORT;
        break;
    case type_e::SINGLE_HOP:
        sum += NPL_UDP_BFD_CONTROL_SRC_PORT;
        sum += NPL_UDP_BFD_SINGLE_HOP_PORT;
        break;
    case type_e::MULTI_HOP:
        sum += NPL_UDP_BFD_CONTROL_SRC_PORT;
        sum += NPL_UDP_BFD_MULTI_HOP_PORT;
        break;
    }

    // Length
    sum += NPL_SIZEOF_UDP_HEADER + NPL_SIZEOF_BFD_HEADER;

    // BFD header
    if (m_type == type_e::ECHO) {
        sum += (NPL_BFD_ASYNC_VERSION << 13);
        sum += calculate_checksum(to_utype(m_local_discriminator));
        sum += NPL_SIZEOF_BFD_HEADER_N;

    } else {
        microseconds out_desired_min_tx_interval;
        microseconds out_required_min_rx_interval;
        uint8_t out_detection_time_multiplier;

        sum += (NPL_BFD_ASYNC_VERSION << 13) | (to_utype(m_local_diag_code) << 8) | m_local_flags.flat;
        sum += calculate_checksum(to_utype(m_local_discriminator));
        sum += calculate_checksum(to_utype(m_remote_discriminator));

        la_status status = get_intervals(out_desired_min_tx_interval, out_required_min_rx_interval, out_detection_time_multiplier);
        // return 0 if data has not been initialized yet
        if (status != LA_STATUS_SUCCESS) {
            return 0;
        }
        sum += (out_detection_time_multiplier << 8) | NPL_SIZEOF_BFD_HEADER_N;
        sum += calculate_checksum(out_desired_min_tx_interval.count());
        sum += calculate_checksum(out_required_min_rx_interval.count());
        sum += (m_echo_mode_enabled) ? 1 : 0;
    }

    // Pseudo IP header
    sum += to_utype(la_l4_protocol_e::UDP);
    sum += NPL_SIZEOF_UDP_HEADER + NPL_SIZEOF_BFD_HEADER;

    if (m_protocol == la_l3_protocol_e::IPV4_UC) {
        sum += calculate_checksum(m_local_ipv4_addr.s_addr);
        sum += calculate_checksum(m_remote_ipv4_addr.s_addr);
    } else {
        la_ipv6_addr_t local_addr;
        get_local_address(local_addr);
        sum += calculate_checksum(local_addr);
        sum += calculate_checksum(m_remote_ipv6_addr);
    }

    // Reduce to 16 bits per RFC
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return ~sum;
}

uint32_t
la_bfd_session_base::inject_down_destination_id() const
{
    if (m_type == type_e::MICRO) {
        // For Micro BFD get the destination from the system port
        if (!m_system_port) {
            return -1;
        }

        return m_system_port->get_gid() | NPL_DESTINATION_MASK_DSP;
    }

    if (!m_next_hop || is_aggregate_nh(m_next_hop)) {
        return -1;
    }

    la_l3_port* l3_port = nullptr;
    la_status status = m_next_hop->get_router_port(l3_port);
    if (status != LA_STATUS_SUCCESS) {
        return -1;
    }

    const la_l3_ac_port_impl* ac_port = static_cast<const la_l3_ac_port_impl*>(l3_port);
    if (ac_port == nullptr) {
        return -1;
    }

    auto ep = static_cast<const la_ethernet_port_base*>(ac_port->get_ethernet_port());
    if (ep == nullptr) {
        return -1;
    }

    auto dest = get_destination_id(ep, RESOLUTION_STEP_FIRST);

    return dest.val;
}

la_status
la_bfd_session_base::populate_mp_data_payload(npl_bfd_mp_table_app_t& payload) const
{
    auto& shared_msb = payload.shared.shared_msb;
    auto& shared_lsb = payload.shared.shared_lsb;

    if (m_protocol == la_l3_protocol_e::IPV4_UC) {
        // For inject-up, we set ttl to 0 so it can be decremented to 255.
        uint8_t ttl = using_inject_up() ? 0 : 255;
        la_ipv4_addr_t dip = m_remote_ipv4_addr;

        shared_msb.transport_label.transport = NPL_BFD_TRANSPORT_IPV4;
        shared_msb.trans_data.ipv4.dip = dip.s_addr;
        shared_msb.trans_data.ipv4.checksum = calc_ipv4_checksum_for_bfd(m_local_ipv4_addr, dip, m_tos, ttl);
    } else {
        la_ipv6_addr_t dip = m_remote_ipv6_addr;

        shared_msb.transport_label.transport = NPL_BFD_TRANSPORT_IPV6;
        shared_msb.trans_data.ipv6.ipv6_dip_a = dip.s_addr;
    }

    shared_msb.transport_label.requires_label = (m_label.label == 0) ? 0 : 1;
    shared_lsb.udp_checksum = calc_udp_checksum();

    if (using_inject_up()) {
        if (m_inject_up_source_port) {
            la_vlan_id_t vlan1{};
            la_vlan_id_t vlan2{};
            auto& inject_up_data = shared_lsb.inject_data.inject_up_data;
            auto& qos_data = inject_up_data.bfd_ih_app.inject_specific_data.inject_data.inject_up_eth.qos_or_dest.inject_up_qos;

            m_inject_up_source_port->get_service_mapping_vids(vlan1, vlan2);
            inject_up_data.inject_vlan_id = vlan1;

            auto ep = static_cast<const la_ethernet_port_base*>(m_inject_up_source_port->get_ethernet_port());
            auto sp = static_cast<const la_system_port_base*>(ep->get_system_port());

            shared_lsb.inject_ifg_id = m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(sp->get_slice(), sp->get_ifg());
            qos_data.inject_up_phb.tc = m_tc;
            // Default mapping maps the fwd_qos_tag to dscp.
            qos_data.inject_up_fwd_qos_tag = m_tos.fields.dscp;

            inject_up_data.bfd_ih_app.inject_specific_data.inject_data.inject_up_eth.from_port.up_ssp = sp->get_gid();

            auto counter_ptr = populate_counter_ptr_slice(m_counter, sp->get_slice(), COUNTER_DIRECTION_INGRESS);
            inject_up_data.bfd_ih_app.counter_ptr = counter_ptr;
        }
    } else {
        la_slice_ifg s_ifg = m_device->get_slice_id_manager()->get_npu_host_port_ifg();
        shared_lsb.inject_ifg_id = m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(s_ifg);

        la_l3_port* inject_l3_port = nullptr;
        if (m_next_hop) {
            shared_lsb.inject_data.inject_down_data.bfd_ih_down.inject_down_encap_nh.down_nh = m_next_hop->get_gid();
            m_next_hop->get_router_port(inject_l3_port);
        }

        if (inject_l3_port) {
            shared_lsb.inject_data.inject_down_data.bfd_ih_down.inject_down_encap_nh.down_l3_dlp
                = get_l3_dlp_encap(inject_l3_port->get_gid());
        }

        if (m_protocol == la_l3_protocol_e::IPV4_UC) {
            shared_lsb.inject_data.inject_down_data.bfd_ih_down.inject_down_encap_nh.down_l3_dlp.properties
                .monitor_or_l3_dlp_ip_type.l3_dlp_ip_type
                = NPL_IPV4_L3_DLP;
        } else {
            shared_lsb.inject_data.inject_down_data.bfd_ih_down.inject_down_encap_nh.down_l3_dlp.properties
                .monitor_or_l3_dlp_ip_type.l3_dlp_ip_type
                = NPL_IPV6_L3_DLP;
        }

        shared_lsb.inject_data.inject_down_data.inject_down.inject_destination.val = inject_down_destination_id();

        shared_lsb.inject_data.inject_down_data.inject_down.inject_down_encap_type = NPL_INJECT_DOWN_ENCAP_TYPE_DLP_NH_TO_ETH;
        shared_lsb.inject_data.inject_down_data.inject_down.inject_phb.tc = m_tc;

        auto counter_ptr = populate_counter_ptr_slice(m_counter, s_ifg.slice, COUNTER_DIRECTION_INGRESS);
        shared_lsb.inject_data.inject_down_data.counter_ptr = counter_ptr;
    }

    return LA_STATUS_SUCCESS;
}

bool
la_bfd_session_base::should_transmit() const
{
    if (!m_transmit_interval) {
        return false;
    }

    if (using_inject_up()) {
        // Inject up requires inject up port
        if (!m_inject_up_source_port) {
            return false;
        }
    } else {
        // Inject-down requires next-hop
        if (!m_next_hop) {
            return false;
        }

        // Micro-bfd (per bundle member) additionally requires system port
        if (m_type == type_e::MICRO && !m_system_port) {
            return false;
        }
    }

    return true;
}

la_status
la_bfd_session_base::update_mp_table()
{
    npl_mp_data_table_t::key_type k{};
    npl_mp_data_table_t::value_type v{};
    npl_mp_data_table_t::entry_pointer_type e = nullptr;

    // Note that we allocate 2 MP entries per session.
    k.line_id.id = m_npuh_id * 2;

    la_status status = populate_mp_data_payload(v.payloads.mp_data_result.npu_host_mp_data.npu_host_mp_data.host_data
                                                    .overload_union_app_defined.app.mp_rd_data.mp_data_union.bfd);
    return_on_error(status);

    v.payloads.mp_data_result.npu_host_mp_data.npu_host_mp_data.host_data.overload_union_app_defined.app.mp_type = NPL_BFD_MEP;
    v.payloads.mp_data_result.ccm_valid = should_transmit();

    if (m_transmit_interval) {
        v.payloads.mp_data_result.ccm_period = m_transmit_interval->id();
        v.payloads.mp_data_result.npu_host_mp_data.npu_host_data_res_count_phase.ccm_count_phase = m_phase_count;
    } else {
        v.payloads.mp_data_result.ccm_period = 0;
    }

    v.payloads.mp_data_result.mp_valid = should_transmit();
    v.payloads.mp_data_result.aux_ptr = m_npuh_id;

    status = m_device->m_tables.mp_data_table->set(k, v, e);
    return_on_error(status);

    npl_mp_data_table_t::value_type v2{};
    k.line_id.id = m_npuh_id * 2 + 1;
    v2.payloads.mp_data_result.mp_valid = 0;
    v2.payloads.mp_data_result.ccm_valid = 0;
    v2.payloads.mp_data_result.ccm_period = 0;
    v2.payloads.mp_data_result.aux_ptr = m_npuh_id;

    auto transmit_b = &v2.payloads.mp_data_result.npu_host_mp_data.npu_host_mp_data.host_data.overload_union_app_defined.app
                           .mp_rd_data.mp_data_union.bfd_extra.extra_tx_b;
    transmit_b->local_state_and_flags = m_local_flags.flat;

    if (m_local_ipv6_addr) {
        transmit_b->sip_selector = m_local_ipv6_addr->id();
    }
    auto label_ptr = &v2.payloads.mp_data_result.npu_host_mp_data.npu_host_mp_data.host_data.overload_union_app_defined.app
                          .mp_rd_data.mp_data_union.bfd_extra.mpls_label;

    label_ptr->label = m_label.label;
    label_ptr->bos = 1;
    label_ptr->exp = 0;
    label_ptr->ttl = m_label_ttl;

    return m_device->m_tables.mp_data_table->set(k, v2, e);
}

la_status
la_bfd_session_base::erase_mp_entry()
{
    npl_mp_data_table_t::key_type k{};
    npl_mp_data_table_t::value_type v{};
    npl_mp_data_table_t::entry_pointer_type e = nullptr;

    k.line_id.id = m_npuh_id * 2;

    // Clear out the entry
    m_device->m_tables.mp_data_table->set(k, v, e);

    la_status status = m_device->m_tables.mp_data_table->erase(k);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    k.line_id.id = m_npuh_id * 2 + 1;
    status = m_device->m_tables.mp_data_table->erase(k);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_SUCCESS;
}

npl_bfd_em_t
la_bfd_session_base::em_mp_payload() const
{
    auto payload = npl_bfd_em_t();

    payload.rmep_id = m_npuh_id;
    payload.mep_id = m_npuh_id * 2;
    payload.access_rmep = 1;
    payload.access_mp = 1;
    payload.mp_data_select = 0;

    return payload;
}

void
la_bfd_session_base::set_em_key(npl_em_mp_table_t::key_type& key)
{
    key.your_discr = to_utype(m_local_discriminator);
    switch (m_type) {
    case type_e::ECHO:
        key.udp_dest_port = NPL_UDP_BFD_ECHO_PORT;
        break;
    case type_e::MICRO:
        key.udp_dest_port = NPL_UDP_BFD_MICRO_HOP_PORT;
        break;
    case type_e::SINGLE_HOP:
        key.udp_dest_port = NPL_UDP_BFD_SINGLE_HOP_PORT;
        break;
    case type_e::MULTI_HOP:
        key.udp_dest_port = NPL_UDP_BFD_MULTI_HOP_PORT;
        break;
    }
}

la_status
la_bfd_session_base::update_em_mp_table()
{
    npl_em_mp_table_t::key_type k{};
    npl_em_mp_table_t::value_type v{};
    npl_em_mp_table_t::entry_pointer_type e = nullptr;

    set_em_key(k);
    v.payloads.bfd_em_payload.bfd = em_mp_payload();

    return m_device->m_tables.em_mp_table->set(k, v, e);
}

la_status
la_bfd_session_base::erase_em_mp_entry()
{
    npl_em_mp_table_t::key_type k{};

    set_em_key(k);

    la_status status = m_device->m_tables.em_mp_table->erase(k);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_SUCCESS;
}

npl_bfd_aux_payload_t
la_bfd_session_base::aux_payload() const
{
    auto payload = npl_bfd_aux_payload_t();

    if (m_type == type_e::ECHO) {
        // For echo mode, we set the remote discr in the data structures to
        // the local discriminator so that the common NPL code updates the
        // correct field in the header.
        payload.shared.local_discriminator = 0;
        payload.shared.remote_discriminator = to_utype(m_local_discriminator);
    } else {
        payload.shared.local_discriminator = to_utype(m_local_discriminator);
        payload.shared.remote_discriminator = to_utype(m_remote_discriminator);
    }
    payload.shared.tos = m_tos.flat;
    payload.shared.local_diag_code = to_utype(m_local_diag_code);
    payload.shared.requires_inject_up = using_inject_up();
    switch (m_type) {
    case type_e::ECHO:
        payload.shared.session_type = NPL_BFD_TYPE_ECHO;
        break;
    case type_e::MICRO:
        payload.shared.session_type = NPL_BFD_TYPE_MICRO;
        break;
    case type_e::SINGLE_HOP:
        payload.shared.session_type = NPL_BFD_TYPE_SINGLE_HOP;
        break;
    case type_e::MULTI_HOP:
        payload.shared.session_type = NPL_BFD_TYPE_MULTI_HOP;
        break;
    }

    payload.transmit.interval_selector = m_packet_intervals ? m_packet_intervals->id() : 0;
    payload.transmit.echo_mode_enabled = m_echo_mode_enabled;

    if (m_protocol == la_l3_protocol_e::IPV4_UC) {
        payload.transmit.prot_trans.ipv4.sip = m_local_ipv4_addr.s_addr;
    } else {
        // Too table-specific magic shifts to even define constants for these.
        payload.shared.prot_shared.ipv6.ipv6_dip_c = (m_remote_ipv6_addr.s_addr >> 88);
        payload.transmit.prot_trans.ipv6.ipv6_dip_b = (m_remote_ipv6_addr.s_addr >> 56);
    }

    return payload;
}

la_status
la_bfd_session_base::update_aux_data_table()
{
    npl_mp_aux_data_table_t::key_type k{};
    npl_mp_aux_data_table_t::value_type v{};
    npl_mp_aux_data_table_t::entry_pointer_type e = nullptr;

    k.aux_table_key.rd_address = m_npuh_id;
    v.payloads.aux_table_result.unpack(aux_payload().pack()); // Can we have proper result structure?

    return m_device->m_tables.mp_aux_data_table->set(k, v, e);
}

la_status
la_bfd_session_base::erase_aux_entry()
{
    npl_mp_aux_data_table_t::key_type k{};

    k.aux_table_key.rd_address = m_npuh_id;

    la_status status = m_device->m_tables.mp_aux_data_table->erase(k);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_SUCCESS;
}

bool
la_bfd_session_base::is_armed() const
{
    return !(m_detection_timer_armed == la_armed_state_e::NOT_ARMED);
}

la_status
la_bfd_session_base::do_disarm_detection_timer()
{
    // If the detection timer was previous not armed just return.
    if (m_detection_timer_armed == la_armed_state_e::NOT_ARMED) {
        return LA_STATUS_SUCCESS;
    }

    if (m_detection_timer_armed == la_armed_state_e::DELAYED_ARM) {
        m_device->remove_oam_delay_arm(m_device->get_sptr(this));
    }
    m_detection_timer_armed = la_armed_state_e::NOT_ARMED;
    return update_rmep_state_table();
}

la_status
la_bfd_session_base::disarm_detection_timer()
{
    start_api_call("");

    return do_disarm_detection_timer();
}

bool
la_bfd_session_base::check_arm_detection_timer(microseconds interval)
{
    if (m_detection_timer_armed != la_armed_state_e::DELAYED_ARM) {
        // If the session is either armed or not armed, remove it from the delay list.
        return true;
    }

    m_delay_arm_timer -= interval.count();
    if (m_delay_arm_timer <= 0) {
        m_detection_timer_armed = la_armed_state_e::ARMED;
        update_rmep_state_table();
        // now the session is armed, remove it from the delay list.
        return true;
    }

    return false;
}

la_status
la_bfd_session_base::do_arm_detection_timer()
{
    if (!m_detection_time) {
        return LA_STATUS_EINVAL;
    }

    if (m_detection_timer_armed != la_armed_state_e::DELAYED_ARM) {
        m_device->add_oam_delay_arm(m_device->get_sptr(this));
        m_detection_timer_armed = la_armed_state_e::DELAYED_ARM;
    }

    m_delay_arm_timer = m_detection_time->value().count();

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::arm_detection_timer()
{
    start_api_call("");

    return do_arm_detection_timer();
}

la_status
la_bfd_session_base::update_rmep_state_table()
{
    npl_rmep_state_table_t::key_type k{};
    npl_rmep_state_table_t::value_type v{};
    npl_rmep_state_table_t::entry_pointer_type e = nullptr;

    k.rmep_key.id = m_npuh_id;

    v.payloads.rmep_result_rmep_state_table_result.rmep_data = m_remote_flags.flat;

    if (m_detection_time) {
        v.payloads.rmep_result_rmep_state_table_result.rmep_valid = (m_detection_timer_armed == la_armed_state_e::ARMED) ? 1 : 0;
        v.payloads.rmep_result_rmep_state_table_result.rmep_profile = m_detection_time->id();
    }

    return m_device->m_tables.rmep_state_table->set(k, v, e);
}

la_status
la_bfd_session_base::erase_rmep_state_table_entry()
{
    npl_rmep_state_table_t::key_type k{};
    npl_rmep_state_table_t::value_type v{};
    npl_rmep_state_table_t::entry_pointer_type e = nullptr;

    k.rmep_key.id = m_npuh_id;

    // Clear out the entry
    m_device->m_tables.rmep_state_table->set(k, v, e);

    la_status status = m_device->m_tables.rmep_state_table->erase(k);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::update_rmep_interval_mapping_table()
{
    if (!m_detection_time) {
        return LA_STATUS_SUCCESS;
    }

    // Note that for the interval timer the device clock is scaled down by 8 in hw.
    auto interval = m_detection_time->value() / m_device->m_device_clock_interval / 8;

    return set_npu_host_interval_mapping(m_detection_time->id(), interval);
}

la_status
la_bfd_session_base::update_required_tx_interval_table()
{
    npl_bfd_required_tx_interval_table_t::key_type k{};
    npl_bfd_required_tx_interval_table_t::value_type v{};
    npl_bfd_required_tx_interval_table_t::entry_pointer_type e = nullptr;

    if (!m_packet_intervals) {
        return LA_STATUS_SUCCESS;
    }

    k.interval_selector = m_packet_intervals->id();
    v.payloads.required_min_tx_interval = m_packet_intervals->value().required_min_rx_interval.count();

    return m_device->m_tables.bfd_required_tx_interval_table->set(k, v, e);
}

la_status
la_bfd_session_base::update_desired_tx_interval_table()
{
    npl_bfd_desired_tx_interval_table_t::key_type k{};
    npl_bfd_desired_tx_interval_table_t::value_type v{};
    npl_bfd_desired_tx_interval_table_t::entry_pointer_type e = nullptr;

    if (!m_packet_intervals) {
        return LA_STATUS_SUCCESS;
    }

    k.interval_selector = m_packet_intervals->id();
    v.payloads.desired_min_tx_interval = m_packet_intervals->value().desired_min_tx_interval.count();

    return m_device->m_tables.bfd_desired_tx_interval_table->set(k, v, e);
}

la_status
la_bfd_session_base::update_detection_time_multiplier_table()
{
    npl_bfd_detection_multiple_table_t::key_type k{};
    npl_bfd_detection_multiple_table_t::value_type v{};
    npl_bfd_detection_multiple_table_t::entry_pointer_type e = nullptr;

    if (!m_packet_intervals) {
        return LA_STATUS_SUCCESS;
    }

    k.interval_selector = m_packet_intervals->id();
    v.payloads.detection_mult = m_packet_intervals->value().detection_time_multiplier;

    return m_device->m_tables.bfd_detection_multiple_table->set(k, v, e);
}

la_status
la_bfd_session_base::get_ccm_counter(uint32_t& ccm_counter)
{
    if (!m_transmit_interval) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    /*
     * Convert to ccm cycles by dividing by the ccm cycle interval
     */
    ccm_counter = m_transmit_interval->value() / m_device->ccm_interval;

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::set_max_ccm_counter()
{
    uint32_t max_ccm_counter;

    if (get_ccm_counter(max_ccm_counter) != LA_STATUS_SUCCESS) {
        // return ok since all fields have not been initialized yet
        return LA_STATUS_SUCCESS;
    }

    return set_npu_host_max_ccm_counter(m_transmit_interval->id(), max_ccm_counter);
}

la_status
la_bfd_session_base::update_npuh_entries()
{
    if (is_remote()) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = update_detection_time_multiplier_table();
    return_on_error(status);

    status = update_required_tx_interval_table();
    return_on_error(status);

    status = update_desired_tx_interval_table();
    return_on_error(status);

    status = update_aux_data_table();
    return_on_error(status);

    status = update_mp_table();
    return_on_error(status);

    status = update_em_mp_table();
    return_on_error(status);

    status = set_max_ccm_counter();
    return_on_error(status);

    status = update_rmep_interval_mapping_table();
    return_on_error(status);

    status = update_rmep_state_table();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::teardown_entries()
{
    la_status status = erase_rx_entry();
    return_on_error(status);

    if (is_remote()) {
        return LA_STATUS_SUCCESS;
    }

    status = erase_em_mp_entry();
    return_on_error(status);

    status = erase_mp_entry();
    return_on_error(status);

    status = erase_aux_entry();
    return_on_error(status);

    status = erase_rmep_state_table_entry();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_bfd_session_base::handle_timeout(type_e& out_type, la_bfd_discriminator& out_local_discriminator, bool& out_was_armed)
{
    start_api_call("");

    out_local_discriminator = m_local_discriminator;
    out_type = m_type;

    // Check if detection was already armed.
    if (m_detection_timer_armed == la_armed_state_e::ARMED) {
        out_was_armed = true;
    } else {
        out_was_armed = false;
    }

    la_status status = disarm_detection_timer();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
