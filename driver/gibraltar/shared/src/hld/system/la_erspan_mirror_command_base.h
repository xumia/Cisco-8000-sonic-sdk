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

#ifndef __LA_ERSPAN_MIRROR_COMMAND_BASE_H__
#define __LA_ERSPAN_MIRROR_COMMAND_BASE_H__

#include "api/system/la_erspan_mirror_command.h"
#include "api/system/la_mirror_command.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "common/la_ip_addr.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_erspan_mirror_command_base : public la_erspan_mirror_command, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_erspan_mirror_command_base(const la_device_impl_wptr& device);
    ~la_erspan_mirror_command_base() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid,
                         type_e type,
                         la_mirror_gid_t mirror_gid,
                         la_erspan_session_id_t session_id,
                         la_mac_addr_t mac_addr,
                         la_mac_addr_t source_mac_addr,
                         la_vlan_tag_t vlan_tag,
                         la_ip_addr tunnel_dest_addr,
                         la_ip_addr tunnel_source_addr,
                         la_uint_t ttl,
                         la_ip_dscp dscp,
                         la_uint_t voq_offset,
                         const la_system_port* dsp,
                         double probability,
                         la_ip_version_e ip_version);
    la_status initialize(la_object_id_t oid,
                         type_e type,
                         la_mirror_gid_t mirror_gid,
                         la_mac_addr_t mac_addr,
                         la_mac_addr_t source_mac_addr,
                         la_vlan_tag_t vlan_tag,
                         la_ip_addr tunnel_dest_addr,
                         la_ip_addr tunnel_source_addr,
                         la_uint_t ttl,
                         la_ip_dscp dscp,
                         la_uint16_t sport,
                         la_uint16_t dport,
                         la_uint_t voq_offset,
                         const la_system_port* dsp,
                         double probability,
                         la_ip_version_e ip_version);
    la_status destroy();

    // la_mirror_command API-s
    la_mirror_gid_t get_gid() const override;

    // la_erspan_mirror_command API-s
    la_erspan_session_id_t get_session_id() const override;
    la_status set_mac(la_mac_addr_t mac_addr) override;
    la_status get_mac(la_mac_addr_t& out_mac_addr) const override;
    la_status set_source_mac(la_mac_addr_t mac_addr) override;
    la_status get_source_mac(la_mac_addr_t& out_mac_addr) const override;
    la_status set_egress_vlan_tag(la_vlan_tag_t vlan_tag) override;
    la_status get_egress_vlan_tag(la_vlan_tag_t& out_vlan_tag) const override;
    la_status set_tunnel_destination(la_ip_addr ip_addr) override;
    la_ip_addr get_tunnel_destination() const override;
    la_status set_tunnel_source(la_ip_addr ip_addr) override;
    la_ip_addr get_tunnel_source() const override;
    la_status set_ttl(la_uint_t ttl) override;
    la_uint_t get_ttl() const override;
    la_status set_dscp(la_ip_dscp dscp) override;
    la_ip_dscp get_dscp() const override;
    la_status set_source_port(la_uint16_t sport) override;
    la_status get_source_port(la_uint16_t& out_sport) const override;
    la_status set_destination_port(la_uint16_t dport) override;
    la_status get_destination_port(la_uint16_t& out_dport) const override;
    la_status set_voq_offset(la_uint_t offset) override;
    la_uint_t get_voq_offset() const override;
    la_status set_counter(la_counter_set* counter) override;
    la_status get_counter(la_counter_set*& out_counter) const override;
    la_status set_egress_port(const la_system_port* dsp) override;
    const la_system_port* get_system_port() const override;
    la_status set_probability(double probability) override;
    la_status get_probability(double& out_probability) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    mirror_type_e get_mirror_type() const;

protected:
    la_erspan_mirror_command_base() = default;
    la_status initialize_common(la_uint_t mirror_gid);

    virtual la_status populate_punt_encap_data(la_uint_t mirror_code,
                                               npl_punt_encap_data_t& punt_encap_data,
                                               la_uint_t encap_ptr) const = 0;
    virtual la_status configure_cud_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr) = 0;
    virtual la_status teardown_cud_entry(la_uint_t mirror_hw_id) = 0;

    // Verify validity of ports
    la_status verify_parameters(const la_system_port* dsp) const;
    la_status verify_dsp(const la_system_port* dsp) const;

    la_status do_set_probability(double probability);
    virtual la_status configure_ibm_command_table(la_uint_t sampling_rate) = 0;
    la_status configure_ibm_uc_cmd_to_encap_data_table(la_uint_t key);
    la_status teardown_ibm_uc_cmd_to_encap_data_table(la_uint_t key);
    virtual la_status configure_mirror_to_dsp_in_npu_soft_header_table(uint8_t value) = 0;
    virtual la_status teardown_mirror_to_dsp_in_npu_soft_header_table() = 0;
    la_status configure_redirect_encap(uint64_t encap_ptr, int is_rx_redirect) const;
    la_status configure_mirror_egress_attributes_table(la_slice_id_t slice, la_counter_set* counter);
    la_status teardown_mirror_egress_attributes_table(la_slice_id_t slice);
    la_status configure_punt_tunnel_transport_encap_table(uint64_t encap_ptr);
    la_status teardown_punt_tunnel_transport_encap_table(uint64_t encap_ptr);
    bool get_truncate() const override;

    la_status do_set_counter(la_counter_set* counter);
    la_status add_erspan_session_counter(la_counter_set* counter);
    la_status remove_erspan_session_counter();

    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Mirror command GID
    la_mirror_gid_t m_mirror_gid;

    la_uint8_t m_mirror_hw_id;

    // Mirror type
    mirror_type_e m_mirror_type;

    la_uint_t m_encap_ptr;

    // ERSPAN session type
    type_e m_type;

    // ERSPAN session ID
    la_erspan_session_id_t m_session_id;

    // Destination MAC for the ERSPAN session
    la_mac_addr_t m_mac_addr;

    // Source MAC for the ERSPAN session
    la_mac_addr_t m_source_mac_addr;

    // Vlan tag for the ERSPAN session
    la_vlan_tag_t m_vlan_tag;

    // Destination IP Address for the ERSPAN session
    la_ip_addr m_tunnel_dest_addr;

    // Source IP Address for the ERSPAN session
    la_ip_addr m_tunnel_source_addr;

    // TTL for the ERSPAN session
    la_uint_t m_ttl;

    // DSCP for the ERSPAN session
    la_ip_dscp m_dscp;

    // Source port for the ERSPAN session
    la_uint16_t m_sport;

    // Destination port for the ERSPAN session
    la_uint16_t m_dport;

    // Offset from base VOQ for the ERSPAN session
    la_uint_t m_voq_offset;

    // Meter set for the ERSPAN session
    la_counter_set_wptr m_counter;

    // Destination system port
    la_system_port_wcptr m_dsp;

    // Sampling probability
    double m_probability;

    // Whether to truncate the copy.
    bool m_truncate;

    // Transport protocol IP version
    la_ip_version_e m_ip_version;
};
}

#endif // __LA_ERSPAN_MIRROR_COMMAND_BASE_H__
