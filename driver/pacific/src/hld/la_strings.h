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

#ifndef __LA_STRINGS_H__
#define __LA_STRINGS_H__

#include <sstream>

#include "api/cgm/la_voq_cgm_profile.h"
#include "api/npu/la_ac_profile.h"
#include "api/npu/la_acl.h"
#include "api/npu/la_acl_scaled.h"
#include "api/npu/la_bfd_session.h"
#include "api/npu/la_copc.h"
#include "api/npu/la_counter_set.h"
#include "api/npu/la_ecmp_group.h"
#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_filter_group.h"
#include "api/npu/la_gre_port.h"
#include "api/npu/la_ip_tunnel_port.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_lpts.h"
#include "api/npu/la_lsr.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_prefix_object.h"
#include "api/npu/la_protection_monitor.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_te_tunnel.h"
#include "api/npu/la_vrf.h"
#include "api/npu/la_vxlan_next_hop.h"
#include "api/qos/la_egress_qos_profile.h"
#include "api/qos/la_ingress_qos_profile.h"
#include "api/qos/la_meter_markdown_profile.h"
#include "api/qos/la_meter_profile.h"
#include "api/system/la_device.h"
#include "api/system/la_erspan_mirror_command.h"
#include "api/system/la_fabric_port.h"
#include "api/system/la_hbm_handler.h"
#include "api/system/la_mac_port.h"
#include "api/tm/la_fabric_port_scheduler.h"
#include "api/tm/la_output_queue_scheduler.h"
#include "api/tm/la_system_port_scheduler.h"
#include "api/tm/la_voq_set.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_bfd_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_notification_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"
#include "api/types/la_tunnel_types.h"
#include "common/gen_utils.h"
#include "common/la_ip_addr.h"
#include "common/logger.h"
#include "hld_types.h"
#include "system/la_system_port_base.h"

#include <chrono>
#include <sstream>

/// @file
/// @brief Leaba common structs/enums to strings definitions.

namespace silicon_one
{

enum { LOG_BUFFER_SIZE = 256 };

// Log format for API logging of route_entry in ipvX_route_bulk_update APIs.
// This log format is optimized for route download performance in that it does not log parameter data-types and user_data fields.
constexpr auto route_entry_api_log_format = "#Bulk update# action=%s,prefix=%s/%u,destination=%s,latency_sensitive=%s";

std::string to_string(const char* value);

std::string to_string(std::string& value);

std::string to_string(const la_object* object);

template <class T>
std::string
to_string(const weak_ptr_unsafe<T> owptr)
{
    return to_string(owptr.get());
}

template <class T>
std::string
to_string(const std::shared_ptr<T> osptr)
{
    return to_string(osptr.get());
}

/// @brief return L4 protocol as a string.
///
/// @param[in]  protocol   L4 protocol.
std::string to_string(la_l4_protocol_e protocol);

/// @brief return LPTS result as a string.
///
/// @param[in]  result   LPTS result.
std::string to_string(const la_lpts_result& result);

/// @brief return LPTS l4 ports  as a string.
///
/// @param[in]  ports   LPTS ports.
std::string to_string(const la_lpts_key_l4_ports& ports);

/// @brief return LPTS ipv4 key  as a string.
///
/// @param[in]  ipv4   LPTS ipv4 key.
std::string to_string(const la_lpts_key_ipv4& ipv4);

/// @brief return LPTS ipv6 key  as a string.
///
/// @param[in]  ipv6   LPTS ipv6 key.
std::string to_string(const la_lpts_key_ipv6& ipv6);

/// @brief return LPTS key fields as a string.
///
/// @param[in]  fields   LPTS key fields.
std::string to_string(const la_lpts_key_fields& fields);

/// @brief return LPTS key as a string.
///
/// @param[in]  key   LPTS key.
std::string to_string(const la_lpts_key& key);

/// @brief return state for the specific port as a string.
///
/// @param[in]  state   stp state for the port.
std::string to_string(la_port_stp_state_e state);

/// @brief return key selector for the ac profile as a string.
///
/// @param[in]  key selector   key selector of the profile.
std::string to_string(la_ac_profile::key_selector_e key_selector);

/// @brief return qos mode for the ac profile as a string.
///
/// @param[in]  qos mode   qos mode of the profile.
std::string to_string(la_ac_profile::qos_mode_e qos_mode);

/// @brief return generic T vector as a string of T's
///
/// @param[in]  t_vec   vector of entries of type T.
template <typename T>
std::string to_string(const std::vector<T>& t_vec);

/// @brief return multicast replication paradigm as string.
///
/// @param[in]  paradigm   replication paradigm.
std::string to_string(la_replication_paradigm_e rep_paradigm);

/// @brief return la_acl_direction_e as string.
///
/// @param[in]  dir     direction type.
std::string to_string(la_acl_direction_e dir);

/// @brief return la_acl_mirror_src_e as string.
///
/// @param[in]  mirror   mirror source type.
std::string to_string(la_acl_mirror_src_e mirror);

/// @brief return la_acl_counter_type_e as string.
///
/// @param[in]  counter   counter type.
std::string to_string(la_acl_counter_type_e counter);

/// @brief return la_acl_action_type_e as string.
///
/// @param[in]  action   Action type.
std::string to_string(la_acl_action_type_e action);

/// @brief return la_acl_packet_format_e as string.
///
/// @param[in]  format   Format type.
std::string to_string(la_acl_packet_format_e format);

/// @brief return la_acl_packet_processing_stage_e as string.
///
/// @param[in]  stage   Stage type.
std::string to_string(la_acl_packet_processing_stage_e stage);

/// @brief return la_stage_e as string.
///
/// @param[in]  stage   Stage ingress/egress.
std::string to_string(la_stage_e stage);

/// @brief return counter set type as string.
///
/// @param[in]  counter_type   counter set's type.
std::string to_string(la_counter_set::type_e counter_type);

/// @brief return serder_counter_e as string.
///
/// @param[in]  counter_type   serdes counter type.
std::string to_string(la_mac_port::serdes_counter_e counter_type);

/// @brief return monitor_state_e as string.
///
/// @param[in]  monitor_state    monitor_state type.
std::string to_string(la_protection_monitor::monitor_state_e monitor_state);

/// @brief return scheduling_mode  type as string.
///
/// @param[in]  scheduling_mode   output_queue_scheduler scheduling_mode.
std::string to_string(la_output_queue_scheduler::scheduling_mode_e scheduling_mode);

/// @brief return type of notification management as string
///
/// @param[in]  type    Type of notification management.
std::string to_string(dependency_management_op::management_type_e type);

std::string to_string(la_status status);

/// @brief return la_slice_mode_e as string.
///
/// @param[in]  slice_mode    slice_mode type.
std::string to_string(la_slice_mode_e slice_mode);

/// @brief convert la_ethernet_port::event_e to string.
///
/// @param[in]  event            event.
std::string to_string(la_ethernet_port::event_e event);

/// @brief return stage as string
///
/// @param[in]  stage            stage.
std::string to_string(la_acl::stage_e stage);

/// @brief return type as string
///
/// @param[in]  type            type.
std::string to_string(la_acl::type_e type);

/// @brief return type of notification management as string
///
/// @param[in]  type    Type of notification management.
std::string to_string(la_device::init_phase_e phase);

/// @brief return object type as string
///
/// @param[in]  type            object type.
std::string la_object_type_to_string(la_object::object_type_e type);

/// @brief return vlan_edit_command as string
///
/// @param[in]  vlan_edit_command            vlan edit command .
std::string to_string(const la_vlan_edit_command& edit_command);

/// @brief return la_vlan_tag_tci_fields_t as string
///
/// @param[in]  vlan_tag_tci_fields            vlan_tag_tci_fields.
std::string to_string(const la_vlan_tag_tci_fields_t& fields);

/// @brief return la_vlan_tag_tci_t as string
///
/// @param[in]  vlan_tag_tci            vlan_tag_tci.
std::string to_string(const la_vlan_tag_tci_t& vlan_tag_tci);

/// @brief return la_vlan_tag_t as string
///
/// @param[in]  vlan_tag            vlan_tag.
std::string to_string(const la_vlan_tag_t& vlan_tag);

/// @brief return la_route_entry_action_e as string
///
/// @param[in]  action              route entry action.
std::string to_string(const la_route_entry_action_e& action);

/// @brief return la_ipv4_route_entry_parameters_vec as string
///
/// @param[in]   parameters          ipv4 route entry parameters.
std::string to_string(const la_ipv4_route_entry_parameters_vec& vec);

/// @brief return la_ipv4_route_entry_parameters as string
///
/// @param[in]   parameters          ipv4 route entry parameters.
std::string to_string(const la_ipv4_route_entry_parameters& parameters);

/// @brief return la_ipv6_route_entry_parameters_vec as string
///
/// @param[in]   parameters          ipv6 route entry parameters.
std::string to_string(const la_ipv6_route_entry_parameters_vec& vec);

/// @brief return la_ipv6_route_entry_parameters as string
///
/// @param[in]   parameters          ipv6 route entry parameters.
std::string to_string(const la_ipv6_route_entry_parameters& parameters);

/// @brief return la_ipv4_addr_t as string
///
/// @param[in]  ipv4_addr            ipv4 address.
std::string to_string(const la_ipv4_addr_t& ipv4_addr);

/// @brief return la_ipv4_prefix_t as string
///
/// @param[in]  ipv4_prefix            ipv4 prefix.
std::string to_string(const la_ipv4_prefix_t& ipv4_prefix);

/// @brief return la_ipv6_addr_t as string
///
/// @param[in]  ipv6_addr            ipv6 address.
std::string to_string(const la_ipv6_addr_t& ipv6_addr);

/// @brief return la_ipv6_prefix_t as string
///
/// @param[in]  ipv6_prefix            ipv6 prefix.
std::string to_string(const la_ipv6_prefix_t& ipv6_prefix);

/// @brief return la_ip_addr as string
///
/// @param[in]  ip_addr              IP address.
std::string to_string(const la_ip_addr& ip_addr);

/// @brief Return la_egress_qos_marking_source_e as string.
std::string to_string(la_egress_qos_marking_source_e qos_marking_source);

/// @brief Return la_temperature_sensor_e as string.
std::string to_string(la_temperature_sensor_e sensor);

/// @brief Return la_voltage_sensor_e as string.
std::string to_string(la_voltage_sensor_e sensor);

/// @brief Return loopback_mode_e as string.
std::string to_string(la_mac_port::loopback_mode_e mode);

/// @brief Return la_mac_port::pcs_test_mode_e as a string.
std::string to_string(la_mac_port::pcs_test_mode_e val);

/// @brief Return la_mac_port::pma_test_mode_e as string.
std::string to_string(la_mac_port::pma_test_mode_e mode);

/// @brief Return la_mac_port::serdes_test_mode_e as a string.
std::string to_string(la_mac_port::serdes_test_mode_e val);

/// @brief Return la_mac_port::serdes_tuning_mode_e as a string.
std::string to_string(la_mac_port::serdes_tuning_mode_e val);

/// @brief Return la_vlan_pcpdei as string.
std::string to_string(const la_vlan_pcpdei& pcpdei);

/// @brief Return la_ip_dscp as string.
std::string to_string(const la_ip_dscp& dscp);

/// @brief Return la_ip_tos as string.
std::string to_string(const la_ip_tos& tos);

/// @brief Return la_mpls_tc as string.
std::string to_string(const la_mpls_tc& mpls_tc);

/// @brief Return la_packet_vlan_format_t as string.
std::string to_string(const la_packet_vlan_format_t& tag_format);

/// @brief Return la_acl_key_type_e as string.
std::string to_string(la_acl_key_type_e key_type);

/// @brief Return la_acl_scaled::scale_field_e as string.
std::string to_string(la_acl_scaled::scale_field_e scale_field);

/// @brief Return la_device::la_ipv4_erspan_encapsulation as string.
std::string to_string(const la_erspan_mirror_command::ipv4_encapsulation& encap_data);

/// @brief Return la_device::la_ipv6_erspan_encapsulation as string.
std::string to_string(const la_erspan_mirror_command::ipv6_encapsulation& encap_data);

/// @brief Return la_egress_qos_profile::encapsulating_headers_qos_values as string.
std::string to_string(const la_egress_qos_profile::encapsulating_headers_qos_values& encap_qos_values);

/// @brief Return la_qos_color_e as string.
std::string to_string(la_qos_color_e qos_color);

/// @brief Return la_forwarding_header_e as string.
std::string to_string(la_forwarding_header_e forwarding_header);

/// @brief Return la_lb_mode_e as string.
std::string to_string(la_lb_mode_e lb_mode);

/// @brief Return la_l3_port::la_lb_profile_e as string.
std::string to_string(la_l3_port::lb_profile_e lb_profile);

/// @brief Return la_mpls_label as string.
std::string to_string(const la_mpls_label& mpls_label);

/// @brief Return la_mpls_label_vec_t as string.
std::string to_string(const la_mpls_label_vec_t& vec);

/// @brief Return la_slice_ifg as string.
std::string to_string(const la_slice_ifg& slice_ifg);

/// @brief Return la_mpls_qos_inheritance_mode_e as string.
std::string to_string(la_mpls_qos_inheritance_mode_e inheritance_mode);

/// @brief Return la_mpls_ttl_inheritance_mode_e as string.
std::string to_string(la_mpls_ttl_inheritance_mode_e inheritance_mode);

/// @brief Return la_lp_attribute_inheritance_mode_e as string.
std::string to_string(la_lp_attribute_inheritance_mode_e inheritance_mode);

/// @brief Return la_tunnel_encap_qos_mode_e as string.
std::string to_string(la_tunnel_encap_qos_mode_e encap_qos_mode);

/// @brief Return la_ip_tunnel_mode_e as string.
std::string to_string(la_ip_tunnel_mode_e tunnel_mode);

/// @brief Return mac_addr as string.
std::string to_string(const la_mac_addr_t& mac_addr);

/// @brief return Next hop type as a string.
///
/// @param[in]  nh_type   Type of the Next Hop
std::string to_string(const la_next_hop::nh_type_e nh_type);

/// @brief return Prefix object type as a string.
///
/// @param[in]  type   Type of the Prefix object
std::string to_string(const la_prefix_object::prefix_type_e type);

/// @brief return Counter mode as a string.
///
/// @param[in]  counter_mode   Counter mode for Prefix object.
std::string to_string(const la_prefix_object::lsp_counter_mode_e counter_mode);

/// @brief return TE tunnel type as a string.
///
/// @param[in]  type   Type of the TE tunnel
std::string to_string(const la_te_tunnel::tunnel_type_e type);

/// @brief return priority_group  as a string.
///
/// @param[in]  priority_group   priority group of the system port scheduler
std::string to_string(const la_system_port_scheduler::priority_group_e priority_group);

/// @brief return la_ethernet_port::port_type_e  as a string.
///
/// @param[in]  port_type   port_type.
std::string to_string(const la_ethernet_port::port_type_e port_type);

/// @brief Return wred_action_e as string.
std::string to_string(la_voq_cgm_profile::wred_action_e action);

/// @brief Return la_voq_set::state_e as string.
std::string to_string(la_voq_set::state_e state);

/// @brief Return la_meter_profile::type_e as string.
std::string to_string(la_meter_profile::type_e profile_type);

/// @brief Return la_meter_profile::meter_measure_mode_e as string.
std::string to_string(la_meter_profile::meter_measure_mode_e meter_measure_mode);

/// @brief Return la_meter_profile::meter_rate_mode_e as string.
std::string to_string(la_meter_profile::meter_rate_mode_e meter_rate_mode);

/// @brief Return la_meter_profile::color_awareness_mode_e as string.
std::string to_string(la_meter_profile::color_awareness_mode_e color_awareness_mode);

/// @brief Return la_meter_profile::cascade_mode_e as string.
std::string to_string(la_meter_profile::cascade_mode_e cascade_mode);

/// @brief Return filtering_mode of the filter group as string.
std::string to_string(la_filter_group::filtering_mode_e filter_mode);

/// @brief Return la_mac_port::counter_e as string.
std::string to_string(la_mac_port::counter_e conter_type);

/// @brief Return la_oq_vsc_mapping of the oq as string.
std::string to_string(la_oq_vsc_mapping_e oq_vsc_mapping);

/// @brief Return la_mpls_tunnel_type_e as string.
std::string to_string(la_mpls_tunnel_type_e mpls_tunnel_type);

/// @brief return TTL settings as string
///
/// @param[in]  ttl_settings       ttl settings.
std::string to_string(const la_mpls_ttl_settings& ttl_settings);

/// @brief Return la_lp_mac_learning_mode as string.
std::string to_string(la_lp_mac_learning_mode_e mac_learning_mode);

/// @brief Return la_l3_protocol_e as string.
std::string to_string(la_l3_protocol_e l3_protocol);

/// @brief Return la_ip_version_e as string.
std::string to_string(la_ip_version_e ip_version);

/// @brief Return la_rate_limiters_packet_type_e as string.
std::string to_string(la_rate_limiters_packet_type_e packet_type);

/// @brief Return port_speed_e as string.
std::string to_string(la_mac_port::port_speed_e port_speed);

/// @brief Return fec_mode_e as string.
std::string to_string(la_mac_port::fec_mode_e fec_mode);

/// @brief Return fec_bypass_e as string.
std::string to_string(la_mac_port::fec_bypass_e fec_bypass);

/// @brief Return fc_mode_e as string.
std::string to_string(la_mac_port::fc_mode_e fc_mode);

/// @brief Return fc_direction_e as string.
std::string to_string(la_mac_port::fc_direction_e fc_dir);

/// @brief Return la_mac_port::tc_protocol_e as string.
std::string to_string(la_mac_port::tc_protocol_e protocol);

std::string to_string(la_mac_port::serdes_param_stage_e stage);
std::string to_string(la_mac_port::serdes_param_e param);
std::string to_string(la_mac_port::serdes_param_mode_e mode);
std::string to_string(la_mac_port::state_e state);

/// @brief Return la_layer_e as string.
std::string to_string(la_layer_e layer);

/// @brief Return la_event_e as string.
std::string to_string(la_event_e event);

/// @brief Return urpf_mode as string.
std::string to_string(la_l3_port::urpf_mode_e urpf_mode);

/// @brief Return limit_type_e as string.
std::string to_string(limit_type_e limit_type);

/// @brief Return la_precision_type_e as string.
std::string to_string(la_precision_type_e precision_type);

/// @brief Return la_l3_destination_vec_t as string.
std::string to_string(const la_l3_destination_vec_t& vec);

/// @brief Return la_device_id_vec_t as string.
std::string to_string(const la_device_id_vec_t& vec);

/// @brief Return lpts_type_e as string.
std::string to_string(lpts_type_e type);

/// @brief Return copc_type_e as string.
std::string to_string(la_control_plane_classifier::type_e type);

/// @brief Return la_device_property_e as string.
std::string to_string(la_device_property_e device_property);

/// @brief Return fabric_ouput_queue_e as string.
std::string to_string(la_fabric_port_scheduler::fabric_ouput_queue_e fabric_ouput_queue);

/// @brief Return ACL command type as string.
std::string to_string(la_acl_cmd_type_e cmd_type);

/// @brief Return ACL command action as string.
std::string to_string(la_acl_command_action cmd);

/// @brief Return ACL command action as string.
std::string to_string(const la_acl_command_actions& cmd);

/// @brief Return la_notification_action_e as string.
std::string to_string(la_notification_action_e sw_action);

/// @brief Return la_notification_type_e as string.
std::string to_string(la_notification_type_e type);

/// @brief Return la_notification_type_e as string.
std::string to_string(la_link_notification_type_e type);

/// @brief Return link_down_interrupt_info as string.
std::string to_string(const link_down_interrupt_info& info);

/// @brief Return link_down_interrupt_info as string.
std::string to_string(const link_error_interrupt_info& info);

/// @brief Return resolution_step_e as string.
std::string to_string(resolution_step_e type);

/// @brief Return la_meter_set::type_e as string.
std::string to_string(la_meter_set::type_e type);

/// @brief Return la_meter_set::coupling_mode_e as string.
std::string to_string(la_meter_set::coupling_mode_e coupling_mode);

/// @brief Return la_fabric_port::link_protocol_e as string.
std::string to_string(la_fabric_port::link_protocol_e link_protocol);

/// @brief Return la_fabric_port::port_status as string.
std::string to_string(la_fabric_port::port_status status);

/// @brief Return la_clos_direction_e as string.
std::string to_string(la_clos_direction_e clos_direction);

// @brief String representation of the port type
std::string to_string(la_system_port_base::port_type_e port_type);

/// @brief return VOQ counter set type as string.
///
/// @param[in]  counter_type   counter set's type.
std::string to_string(la_voq_set::voq_counter_type_e voq_counter_type);

/// @brief Return la_bfd_diagnostic_code_e as string.
std::string to_string(la_bfd_diagnostic_code_e& code);

/// @brief Return la_bfd_discriminator as string.
std::string to_string(const la_bfd_discriminator& discriminator);

/// @brief Return la_bfd_session::type_e as string.
std::string to_string(la_bfd_session::type_e bfd_session_type);

/// @brief Return la_bfd_session::la_bfd_flags as string.
std::string to_string(la_bfd_flags flags);

/// @brief Return device_mode_e as string.
std::string to_string(device_mode_e device_mode);

/// @brief Return milliseconds as string.
std::string to_string(std::chrono::milliseconds interval);

/// @brief Return microseconds as string.
std::string to_string(std::chrono::microseconds interval);

/// @brief Return seconds as string.
std::string to_string(std::chrono::seconds interval);

/// @brief Return Counter user type as string.
std::string to_string(counter_user_type_e user_type);

/// @brief Return Counter user type as string.
std::string to_string(counter_direction_e user_type);

/// @brief Return ECMP level as a string.
std::string to_string(la_ecmp_group::level_e level);

/// @brief Return ACL field values
std::string to_string(const la_acl_key_ipv4_flags& flags);
std::string to_string(const la_acl_key_ipv4_fragment& flags);
std::string to_string(const la_acl_key_ipv6_fragment_extension& frag);
std::string to_string(const la_acl_field& field);
std::string to_string(la_acl_field_type_e type);
std::string to_string(la_acl_scale_field_type_e type);
std::string to_string(const la_acl_key& key);
std::string to_string(const la_acl_scale_field_key& key);
std::string to_string(const la_acl_key_def_vec_t& key_def_vec);
std::string to_string(const la_acl_command_def_vec_t& command_def_vec);
std::string to_string(const la_acl_udf_desc& udf_desc);
std::string to_string(const la_acl_field_def& field);
std::string to_string(const la_acl_action_def& action);
std::string to_string(const la_acl_vec_t& acl);

/// @brief Return PCL field values
std::string to_string(const la_pcl_v4_vec_t& prefixes);
std::string to_string(const la_pcl_v6_vec_t& prefixes);
std::string to_string(const la_pcl_v4& prefix);
std::string to_string(const la_pcl_v6& prefix);

/// @brief Return nanoseconds as string.
std::string to_string(std::chrono::nanoseconds interval);

/// @brief Return la_mac_port::pfc_config_queue_state_e as string.
std::string to_string(la_mac_port::pfc_config_queue_state_e state);

/// @brief Return la_mac_port::pfc_queue_state_e as string.
std::string to_string(la_mac_port::pfc_queue_state_e state);

/// @brief Return la_rx_cgm_headroom_mode_e as string.
std::string to_string(la_rx_cgm_headroom_mode_e mode);

/// @brief Return la_ttl_inheritance_mode_e as string
std::string to_string(la_ip_tunnel_port::la_ttl_inheritance_mode_e& ttl_i_m);

/// @brief Return svi_egress_tag_mode_e as string
std::string to_string(silicon_one::la_ethernet_port::svi_egress_tag_mode_e& svi_egress_tag_mode);

/// @brief Return test_feature_e as string
std::string to_string(la_device::test_feature_e& feature);

/// @brief Return learn_mode_e as string
std::string to_string(la_device::learn_mode_e& learn_mode);

/// @brief Return fabric_mac_ports_mode_e as string
std::string to_string(la_device::fabric_mac_ports_mode_e& fabric_mac_ports_mode_e);

/// @brief Return sms_bytes_quantization_thresholds as string
std::string to_string(const la_voq_cgm_profile::sms_bytes_quantization_thresholds& thresholds);

/// @brief Return sms_packets_quantization_thresholds as string
std::string to_string(const la_voq_cgm_profile::sms_packets_quantization_thresholds& thresholds);

/// @brief Return sms_age_quantization_thresholds as string
std::string to_string(const la_voq_cgm_profile::sms_age_quantization_thresholds& thresholds);

/// @brief Return wred_regions_probabilties as string
std::string to_string(const la_voq_cgm_profile::wred_regions_probabilties& probabilities);

/// @brief Return wred_blocks_quantization_thresholds as string
std::string to_string(const la_voq_cgm_profile::wred_blocks_quantization_thresholds& thresholds);

/// @brief Return la_voq_cgm_quantization_thresholds as string
std::string to_string(const la_voq_cgm_quantization_thresholds& thresholds);

/// @brief Return la_voq_cgm_probability_regions as string
std::string to_string(const la_voq_cgm_probability_regions& probabilities);

/// @brief Return la_cgm_sms_bytes_quantization_thresholds as string
std::string to_string(const la_cgm_sms_bytes_quantization_thresholds& thresholds);

/// @brief Return la_cgm_sms_packets_quantization_thresholds as string
std::string to_string(const la_cgm_sms_packets_quantization_thresholds& thresholds);

/// @brief Return la_cgm_hbm_number_of_voqs_quantization_thresholds as string
std::string to_string(const la_cgm_hbm_number_of_voqs_quantization_thresholds& thresholds);

/// @brief Return la_cgm_hbm_blocks_by_voq_quantization_thresholds as string
std::string to_string(const la_cgm_hbm_blocks_by_voq_quantization_thresholds& thresholds);

/// @brief Return la_cgm_hbm_pool_free_blocks_quantization_thresholds as string
std::string to_string(const la_cgm_hbm_pool_free_blocks_quantization_thresholds& thresholds);

/// @brief Return la_rx_pdr_sms_bytes_drop_thresholds as string
std::string to_string(const la_rx_pdr_sms_bytes_drop_thresholds& thresholds);

/// @brief Return la_rx_cgm_sms_bytes_quantization_thresholds as string
std::string to_string(const la_rx_cgm_sms_bytes_quantization_thresholds& thresholds);

/// @brief Return la_rx_cgm_sqg_thresholds as string
std::string to_string(const la_rx_cgm_sqg_thresholds& thresholds);

/// @brief Return la_rx_cgm_sq_profile_thresholds as string
std::string to_string(const la_rx_cgm_sq_profile_thresholds& thresholds);

/// @brief Return la_rx_cgm_policy_status as string
std::string to_string(const la_rx_cgm_policy_status& status);

/// @brief Return la_tx_cgm_oq_profile_thresholds as string
std::string to_string(const la_tx_cgm_oq_profile_thresholds& thresholds);

/// @brief Return la_fabric_valid_links_thresholds as string
std::string to_string(const la_fabric_valid_links_thresholds& thresholds);

/// @brief Return la_fabric_congested_links_thresholds as string
std::string to_string(const la_fabric_congested_links_thresholds& thresholds);

/// @brief Return ostc_thresholds as string
std::string to_string(const la_mac_port::ostc_thresholds& thresholds);

/// @brief Return la_voq_sms_evicted_buffers_key.
std::string to_string(const la_voq_sms_evicted_buffers_key& key);

/// @brief Return la_voq_sms_evicted_buffers_drop_val.
std::string to_string(const la_voq_sms_evicted_buffers_drop_val& val);

/// @brief Return la_voq_sms_evict_key.
std::string to_string(const la_voq_sms_evict_key& key);

/// @brief Return la_voq_sms_evict_val.
std::string to_string(const la_voq_sms_evict_val& val);

/// @brief Return la_voq_sms_wred_drop_probability_selector_key.
std::string to_string(const la_voq_sms_wred_drop_probability_selector_key& key);

/// @brief Return la_voq_sms_wred_drop_probability_selector_drop_val.
std::string to_string(const la_voq_sms_wred_drop_probability_selector_drop_val& val);

/// @brief Return la_voq_sms_wred_mark_probability_selector_key.
std::string to_string(const la_voq_sms_wred_mark_probability_selector_key& key);

/// @brief Return la_voq_sms_wred_mark_probability_selector_mark_val.
std::string to_string(const la_voq_sms_wred_mark_probability_selector_mark_val& val);

/// @brief Return la_voq_sms_size_in_bytes_color_key.
std::string to_string(const la_voq_sms_size_in_bytes_color_key& key);

/// @brief Return la_voq_sms_size_in_bytes_drop_val.
std::string to_string(const la_voq_sms_size_in_bytes_drop_val& val);

/// @brief Return la_voq_sms_size_in_bytes_mark_val.
std::string to_string(const la_voq_sms_size_in_bytes_mark_val& val);

/// @brief Return la_voq_sms_size_in_bytes_evict_key.
std::string to_string(const la_voq_sms_size_in_bytes_evict_key& key);

/// @brief Return la_voq_sms_size_in_bytes_evict_val.
std::string to_string(const la_voq_sms_size_in_bytes_evict_val& val);

/// @brief Return la_voq_sms_dequeue_size_in_bytes_key.
std::string to_string(const la_voq_sms_dequeue_size_in_bytes_key& key);

/// @brief Return la_voq_sms_dequeue_size_in_bytes_congestion_val.
std::string to_string(const la_voq_sms_dequeue_size_in_bytes_congestion_val& val);

/// @brief Return la_voq_sms_size_in_packets_key.
std::string to_string(const la_voq_sms_size_in_packets_key& key);

/// @brief Return la_voq_sms_size_in_packets_drop_val.
std::string to_string(const la_voq_sms_size_in_packets_drop_val& val);

/// @brief Return la_voq_sms_size_in_packets_mark_val.
std::string to_string(const la_voq_sms_size_in_packets_mark_val& val);

/// @brief Return la_voq_sms_size_in_packets_evict_val.
std::string to_string(const la_voq_sms_size_in_packets_evict_val& val);

/// @brief Return la_voq_sms_size_in_packets_key.
std::string to_string(const la_voq_sms_dequeue_size_in_packets_key& key);

/// @brief Return la_voq_sms_dequeue_size_in_packets_congestion_val.
std::string to_string(const la_voq_sms_dequeue_size_in_packets_congestion_val& val);

/// @brief Return la_cgm_hbm_size_in_blocks_key.
std::string to_string(const la_cgm_hbm_size_in_blocks_key& key);

/// @brief Return la_cgm_hbm_size_in_blocks_drop_val.
std::string to_string(const la_cgm_hbm_size_in_blocks_drop_val& val);

/// @brief Return la_cgm_hbm_size_in_blocks_mark_ecn_val.
std::string to_string(const la_cgm_hbm_size_in_blocks_mark_ecn_val& val);

/// @brief Return la_voq_hbm_dequeue_size_in_blocks_key.
std::string to_string(const la_cgm_hbm_dequeue_size_in_blocks_key& key);

/// @brief Return la_voq_hbm_dequeue_size_in_blocks_congestion_val.
std::string to_string(const la_cgm_hbm_dequeue_size_in_blocks_congestion_val& val);

/// @brief Return la_cgm_wred_key.
std::string to_string(const la_cgm_wred_key& key);

/// @brief Return la_cgm_wred_drop_val.
std::string to_string(const la_cgm_wred_drop_val& val);

/// @brief Return la_cgm_wred_mark_ecn_val.
std::string to_string(const la_cgm_wred_mark_ecn_val& val);

/// @brief Return std::vector<double> as string
std::string to_string(std::vector<double>& vec);

/// @brief Return std::vector<unsigned int> as string
std::string to_string(std::vector<unsigned int>& vec);

/// @brief Return SyncE clock type as string
std::string to_string(la_device::synce_clock_sel_e synce_clock);

/// @brief Return save_state options type as string
std::string to_string(const la_device::save_state_options& options);

/// @brief Return a vector of strings as string
std::string to_string(const std::vector<std::string>& vect);

/// @brief Return la_hbm_handler::dram_buffer_cell as a string.
std::string to_string(const la_hbm_handler::dram_buffer_cell& cell);

/// @brief Return la_platform_cbs a string.
std::string to_string(const silicon_one::la_platform_cbs& cbs);

/// @brief Return tunnel termination type for a gre port as a string.
std::string to_string(la_gre_port::tunnel_termination_type_e term_type);

/// @brief Return vni profile as a string.
std::string to_string(la_switch::vxlan_termination_mode_e vni_profile);

/// @brief Return IP Tunnel type
std::string to_string(la_ip_tunnel_type_e type);

/// @brief Return LPTS application properties
std::string to_string(const la_lpts_app_properties& properties);
std::string to_string(const la_lpts_app_properties_key_fields& fields);

/// @brief Return egress_feature_mode as a string
std::string to_string(la_l2_service_port::egress_feature_mode_e mode);

/// @brief Return la_ttl_inheritance_mode_e as string.
std::string to_string(la_ttl_inheritance_mode_e ttl_mode);

/// @brief Return traffic matrix type as string.
std::string to_string(la_ethernet_port::traffic_matrix_type_e type);

/// @brief Return cfm mep direction type as a string.
std::string to_string(la_mep_direction_e mep_dir);

/// @brief Return la_fwd_class_id as string.
std::string to_string(const la_fwd_class_id& fcid);

/// @brief Return la_pbts_destination_offset as string.
std::string to_string(const la_pbts_destination_offset& offset);

/// @brief Return PBTS MAP Profile level as a string.
std::string to_string(la_pbts_map_profile::level_e level);

/// @brief Return pcl feature type as a string.
std::string to_string(pcl_feature_type_e type);

} // namespace silicon_one

#endif /* __LA_STRINGS_H__ */
