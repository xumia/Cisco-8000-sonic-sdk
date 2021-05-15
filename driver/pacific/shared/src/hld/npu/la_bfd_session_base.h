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

#ifndef __LA_BFD_SESSION_BASE_H__
#define __LA_BFD_SESSION_BASE_H__

#include "api/npu/la_bfd_session.h"
#include "common/profile_allocator.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

class la_bfd_session_base : public la_bfd_session
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    ~la_bfd_session_base();

    la_status initialize(la_object_id_t oid,
                         la_bfd_discriminator local_discriminator,
                         la_bfd_session::type_e session_type,
                         la_l3_protocol_e protocol,
                         const la_punt_destination_wcptr& punt_destination);

    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_bfd_session API-s
    la_status get_session_type(type_e& out_type) const override;
    la_status get_local_discriminator(la_bfd_discriminator& out_local_discriminator) const override;
    la_status set_remote_discriminator(la_bfd_discriminator remote_discriminator) override;
    la_status get_remote_discriminator(la_bfd_discriminator& out_remote_discriminator) const override;
    la_status set_local_state(la_bfd_diagnostic_code_e diag_code, la_bfd_flags flags) override;
    la_status get_local_state(la_bfd_diagnostic_code_e& out_diag_code, la_bfd_flags& out_flags) const override;
    la_status set_remote_state(la_bfd_flags flags) override;
    la_status get_remote_state(la_bfd_flags& out_flags) const override;
    la_status set_intervals(std::chrono::microseconds desired_min_tx_interval,
                            std::chrono::microseconds required_min_rx_interval,
                            uint8_t detection_time_multiplier) override;
    la_status get_intervals(std::chrono::microseconds& out_desired_min_tx_interval,
                            std::chrono::microseconds& out_required_min_rx_interval,
                            uint8_t& out_detection_time_multiplier) const override;
    la_status set_l3_port(la_l3_port* l3_port) override;
    la_status get_l3_port(la_l3_port*& out_l3_port) const override;
    la_status set_system_port(la_system_port* system_port) override;
    la_status get_system_port(la_system_port*& out_system_port) const override;
    la_status get_punt_destination(const la_punt_destination*& out_destination) const override;
    la_status set_inject_down_destination(const la_next_hop* next_hop) override;
    la_status get_inject_down_destination(const la_next_hop*& out_next_hop) override;
    la_status set_inject_up_source_port(const la_l3_ac_port* port) override;
    la_status get_inject_up_source_port(const la_l3_ac_port*& out_l3_ac_port) override;
    la_status set_transmit_interval(std::chrono::microseconds interval) override;
    la_status get_transmit_interval(std::chrono::microseconds& out_interval) const override;
    la_status set_ip_tos(la_ip_tos tos) override;
    la_status get_ip_tos(la_ip_tos& out_tos) const override;
    la_status set_local_address(la_ipv4_addr_t local_addr) override;
    la_status get_local_address(la_ipv4_addr_t& out_local_addr) const override;
    la_status set_local_address(la_ipv6_addr_t local_addr) override;
    la_status get_local_address(la_ipv6_addr_t& out_local_addr) const override;
    la_status set_remote_address(la_ipv4_addr_t remote_addr) override;
    la_status get_remote_address(la_ipv4_addr_t& out_remote_addr) const override;
    la_status set_remote_address(la_ipv6_addr_t remote_addr) override;
    la_status get_remote_address(la_ipv6_addr_t& remote_addr) const override;
    la_status set_counter(la_counter_set* counter) override;
    la_status get_counter(la_counter_set*& out_counter) const override;
    la_status set_detection_time(std::chrono::microseconds detection_time) override;
    la_status get_detection_time(std::chrono::microseconds& out_detection_time) const override;

    la_status arm_detection_timer() override;
    la_status disarm_detection_timer() override;
    bool check_arm_detection_timer(std::chrono::microseconds interval);

    uint32_t get_internal_id() const override;

    bool get_echo_mode_enabled() const override;
    la_status set_echo_mode_enabled(bool enabled) override;
    la_status get_traffic_class(la_traffic_class_t& out_tc) const override;
    la_status set_traffic_class(la_traffic_class_t tc) override;

    bool is_remote() const;
    la_status handle_timeout(type_e& out_type, la_bfd_discriminator& out_local_discriminator, bool& out_was_armed);
    la_status set_mpls_encap(la_mpls_label label, la_uint8_t ttl) override;
    la_status clear_mpls_encap() override;
    la_status get_mpls_encap(la_mpls_label& out_label, la_uint8_t& out_ttl) const override;
    bool is_armed() const;
    la_status do_disarm_detection_timer();
    la_status do_arm_detection_timer();

    // internal API-s

protected:
    explicit la_bfd_session_base(const la_device_impl_wptr& device);

    // For serialization purposes only
    la_bfd_session_base() = default;

    // Containing device
    la_device_impl_wptr m_device;

    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    index_handle m_npuh_id;
    index_handle m_session_id;
    type_e m_type;
    la_bfd_discriminator m_local_discriminator;
    la_bfd_discriminator m_remote_discriminator{};

    enum la_armed_state_e {
        NOT_ARMED,
        DELAYED_ARM,
        ARMED,
    };

    la_armed_state_e m_detection_timer_armed;
    la_int_t m_delay_arm_timer;
    la_ip_tos m_tos;

    la_l3_protocol_e m_protocol{};
    la_punt_destination_wcptr m_punt_destination;

    la_counter_set_impl_wptr m_counter;

    // For micro-bfd
    la_system_port_base_wptr m_system_port;
    // For single-hop/echo/multi-hop bfd
    la_l3_port_wptr m_l3_port;

    // Next-hop for inject-down
    la_next_hop_base_wcptr m_next_hop;
    // Source-port for inject-up
    la_l3_ac_port_impl_wcptr m_inject_up_source_port;

    // Time intervals
    profile_allocator<bfd_packet_intervals>::profile_ptr m_packet_intervals;
    profile_allocator<std::chrono::microseconds>::profile_ptr m_transmit_interval;
    profile_allocator<std::chrono::microseconds>::profile_ptr m_detection_time;

    // Addresses
    profile_allocator<la_ipv6_addr_t>::profile_ptr m_local_ipv6_addr;
    la_ipv4_addr_t m_local_ipv4_addr{};
    la_ipv4_addr_t m_remote_ipv4_addr{};
    la_ipv6_addr_t m_remote_ipv6_addr{};

    profile_allocator<bfd_rx_entry_data_t>::profile_ptr m_rx_entry{};

    // BFD flags
    la_bfd_diagnostic_code_e m_local_diag_code;
    la_bfd_flags m_local_flags{};
    la_bfd_flags m_remote_flags{};

    /// counter to introduce jitter between sessions.
    uint32_t m_phase_count;

    // Whether there is an echo session associated with the Async session
    bool m_echo_mode_enabled;

    bool using_inject_up() const;
    bool should_transmit() const;

    uint32_t inject_down_destination_id() const;
    destination_id rx_destination_id() const;

    la_status populate_rx_key(npl_bfd_rx_table_key_t& key) const;

    la_status update_rx_entry();
    la_status erase_rx_entry();

    la_status populate_mp_data_payload(npl_bfd_mp_table_app_t& payload) const;
    la_status update_mp_table();
    la_status erase_mp_entry();

    npl_bfd_em_t em_mp_payload() const;
    la_status update_em_mp_table();
    la_status erase_em_mp_entry();

    npl_bfd_aux_payload_t aux_payload() const;
    la_status update_aux_data_table();
    la_status erase_aux_entry();

    la_status update_rmep_state_table();
    la_status erase_rmep_state_table_entry();

    la_status update_rmep_interval_mapping_table();
    la_status update_detection_time_multiplier_table();
    la_status update_required_tx_interval_table();
    la_status update_desired_tx_interval_table();
    la_status set_max_ccm_counter();
    la_status get_ccm_counter(uint32_t& ccm_counter);
    la_status update_npuh_entries();
    la_status teardown_entries();

    uint16_t calc_udp_checksum() const;
    void set_em_key(npl_em_mp_table_t::key_type& key);
    la_status set_intervals_internal(std::chrono::microseconds desired_min_tx_interval,
                                     std::chrono::microseconds required_min_rx_interval,
                                     uint8_t detection_time_multiplier);

    void set_remote_session_flag();
    bool m_punt_destination_remote;
    la_traffic_class_t m_tc;
    la_mpls_label m_label;
    la_uint8_t m_label_ttl;

    // Helper functions.
    virtual la_status set_npu_host_interval_mapping(uint64_t entry, uint64_t value) = 0;
    virtual la_status set_npu_host_max_ccm_counter(uint64_t entry, uint64_t value) = 0;
};

} // namespace silicon_one

#endif
