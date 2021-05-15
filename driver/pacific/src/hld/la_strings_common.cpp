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

#include <climits>
#include <sstream>
#include <string>

#include "api/system/la_l2_punt_destination.h"
#include "api/types/la_event.h"
#include "common/common_strings.h"
#include "hld_utils.h"
#include "la_strings.h"

namespace silicon_one
{

std::string
to_string(unsigned short value)
{
    return std::to_string(value);
}

std::string
to_string(unsigned int value)
{
    return std::to_string(value);
}

std::string
to_string(unsigned long long value)
{
    return std::to_string(value);
}

std::string
to_string(double value)
{
    return std::to_string(value);
}

std::string
to_string(float value)
{
    return std::to_string(value);
}

std::string
to_string(const char* value)
{
    if (value == nullptr) {
        return std::string("nullptr");
    }
    return std::string(value);
}

std::string
to_string(std::string& value)
{
    return (value);
}

std::string
to_string(const la_object* object)
{
    if (object == nullptr) {
        return std::string("nullptr");
    }
    return object->to_string();
}

std::string
to_string(la_l4_protocol_e protocol)
{
    switch (protocol) {
    case la_l4_protocol_e::ICMP:
        return "ICMP";
    case la_l4_protocol_e::HOP_BY_HOP:
        return "HOP_BY_HOP";
    case la_l4_protocol_e::IGMP:
        return "IGMP";
    case la_l4_protocol_e::TCP:
        return "TCP";
    case la_l4_protocol_e::UDP:
        return "UDP";
    case la_l4_protocol_e::RSVP:
        return "RSVP";
    case la_l4_protocol_e::GRE:
        return "GRE";
    case la_l4_protocol_e::IPV6_ICMP:
        return "IPV6_ICMP";
    case la_l4_protocol_e::EIGRP:
        return "EIGRP";
    case la_l4_protocol_e::OSPF:
        return "OSPF";
    case la_l4_protocol_e::PIM:
        return "PIM";
    case la_l4_protocol_e::VRRP:
        return "VRRP";
    case la_l4_protocol_e::L2TP:
        return "L2TP";
    case la_l4_protocol_e::IPV6_FRAGMENT:
        return "IPV6_FRAGMENT";
    case la_l4_protocol_e::RESERVED:
        return "RESERVED";
    default:
        return "Unknown protocol";
    }

    return std::string("Unknown protocol");
}

std::string
to_string(la_port_stp_state_e state)
{

    static const char* strs[] = {
            [(int)la_port_stp_state_e::BLOCKING] = "BLOCKING",
            [(int)la_port_stp_state_e::LISTENING] = "LISTENING",
            [(int)la_port_stp_state_e::LEARNING] = "LEARNING",
            [(int)la_port_stp_state_e::FORWARDING] = "FORWARDING",
    };

    if ((size_t)state < array_size(strs)) {
        return std::string(strs[(size_t)state]);
    }

    return std::string("Unknown state");
}

std::string
to_string(la_ac_profile::key_selector_e key_selector)
{

    static const char* strs[] = {
            [(int)la_ac_profile::key_selector_e::PORT] = "PORT",
            [(int)la_ac_profile::key_selector_e::PORT_PVLAN] = "PORT_PVLAN",
            [(int)la_ac_profile::key_selector_e::PORT_VLAN] = "PORT_VLAN",
            [(int)la_ac_profile::key_selector_e::PORT_VLAN_VLAN] = "PORT_VLAN_VLAN",
            [(int)la_ac_profile::key_selector_e::PORT_VLAN_VLAN_WITH_FALLBACK] = "PORT_VLAN_VLAN_WITH_FALLBACK",
    };

    if ((size_t)key_selector < array_size(strs)) {
        return std::string(strs[(size_t)key_selector]);
    }

    return std::string("Unknown key selector");
}

std::string
to_string(la_ac_profile::qos_mode_e qos_mode)
{

    static const char* strs[] = {
            [(int)la_ac_profile::qos_mode_e::L2] = "L2", [(int)la_ac_profile::qos_mode_e::L3] = "L3",
    };

    if ((size_t)qos_mode < array_size(strs)) {
        return std::string(strs[(size_t)qos_mode]);
    }

    return std::string("Unknown qos mode");
}

template <class _T>
static std::string
vec_to_string(const std::vector<_T> vec)
{
    std::stringstream log_message;
    log_message << LOG_VEC_START;
    bool is_first = true;

    for (auto entry : vec) {
        if (is_first) {
            is_first = false;
        } else {
            log_message << LOG_VEC_ELEM_SEPARATOR;
        }

        log_message << to_string(entry);
    }

    log_message << LOG_VEC_END;

    return log_message.str();
}

template <typename T>
std::string
to_string(const std::vector<T>& t_vec)
{
    return vec_to_string(t_vec);
}

std::string
to_string(la_replication_paradigm_e rep_paradigm)
{

    static const char* strs[] = {
            [(int)la_replication_paradigm_e::INGRESS] = "INGRESS", [(int)la_replication_paradigm_e::EGRESS] = "EGRESS",
    };

    if ((size_t)rep_paradigm < array_size(strs)) {
        return std::string(strs[(size_t)rep_paradigm]);
    }

    return std::string("Unknown paradigm");
}

std::string
to_string(la_stage_e stage)
{

    static const char* strs[] = {
            [(int)la_stage_e::INGRESS] = "INGRESS", [(int)la_stage_e::EGRESS] = "EGRESS",
    };

    if ((size_t)stage < array_size(strs)) {
        return std::string(strs[(size_t)stage]);
    }

    return std::string("Unknown direction");
}

std::string
to_string(la_acl_action_type_e action)
{
    static const char* strs[] = {[(int)la_acl_action_type_e::TRAFFIC_CLASS] = "TRAFFIC_CLASS",
                                 [(int)la_acl_action_type_e::COLOR] = "COLOR",
                                 [(int)la_acl_action_type_e::QOS_OR_METER_COUNTER_OFFSET] = "QOS_OR_METER_COUNTER_OFFSET",
                                 [(int)la_acl_action_type_e::ENCAP_EXP] = "ENCAP_EXP",
                                 [(int)la_acl_action_type_e::REMARK_FWD] = "REMARK_FWD",
                                 [(int)la_acl_action_type_e::REMARK_GROUP] = "REMARK_GROUP",
                                 [(int)la_acl_action_type_e::DROP] = "DROP",
                                 [(int)la_acl_action_type_e::PUNT] = "PUNT",
                                 [(int)la_acl_action_type_e::DO_MIRROR] = "DO_MIRROR",
                                 [(int)la_acl_action_type_e::MIRROR_CMD] = "MIRROR_CMD",
                                 [(int)la_acl_action_type_e::COUNTER_TYPE] = "COUNTER_TYPE",
                                 [(int)la_acl_action_type_e::COUNTER] = "COUNTER",
                                 [(int)la_acl_action_type_e::L2_DESTINATION] = "L2_DESTINATION",
                                 [(int)la_acl_action_type_e::L3_DESTINATION] = "L3_DESTINATION",
                                 [(int)la_acl_action_type_e::METER] = "METER"};

    if ((size_t)action < array_size(strs)) {
        return std::string(strs[(size_t)action]);
    }

    return std::string("Unknown counter set type");
}

std::string
to_string(la_acl_packet_processing_stage_e stage)
{
    static const char* strs[] = {[(int)la_acl_packet_processing_stage_e::PRE_FORWARDING] = "PRE_FORWARDING",
                                 [(int)la_acl_packet_processing_stage_e::POST_FORWARDING] = "POST_FORWARDING",
                                 [(int)la_acl_packet_processing_stage_e::RX_DONE] = "RX_DONE",
                                 [(int)la_acl_packet_processing_stage_e::EGRESS] = "EGRESS"};

    if ((size_t)stage < array_size(strs)) {
        return std::string(strs[(size_t)stage]);
    }

    return std::string("Unknown acl packet processing stage");
}

std::string
to_string(la_acl_direction_e dir)
{
    static const char* strs[] = {[(int)la_acl_direction_e::INGRESS] = "INGRESS", [(int)la_acl_direction_e::EGRESS] = "EGRESS"};

    if ((size_t)dir < array_size(strs)) {
        return std::string(strs[(size_t)dir]);
    }

    return std::string("Unknown acl direction");
}

std::string
to_string(la_acl_packet_format_e packet_format)
{
    static const char* strs[] = {[(int)la_acl_packet_format_e::ETHERNET] = "ETHERNET",
                                 [(int)la_acl_packet_format_e::IPV4] = "IPV4",
                                 [(int)la_acl_packet_format_e::IPV6] = "IPV6"};

    if ((size_t)packet_format < array_size(strs)) {
        return std::string(strs[(size_t)packet_format]);
    }

    return std::string("Unknown acl packet format");
}

std::string
to_string(la_acl_mirror_src_e mirror)
{
    static const char* strs[] = {[(int)la_acl_mirror_src_e::DO_MIRROR_FROM_LP] = "DO_MIRROR_FROM_LP",
                                 [(int)la_acl_mirror_src_e::DO_MIRROR_FROM_CMD] = "DO_MIRROR_FROM_CMD"};

    if ((size_t)mirror < array_size(strs)) {
        return std::string(strs[(size_t)mirror]);
    }

    return std::string("Unknown acl mirror source");
}

std::string
to_string(la_acl_counter_type_e counter)
{
    static const char* strs[] = {[(int)la_acl_counter_type_e::DO_QOS_COUNTING] = "DO_QOS_COUNTING",
                                 [(int)la_acl_counter_type_e::DO_METERING] = "DO_METERING",
                                 [(int)la_acl_counter_type_e::OVERRIDE_METERING_PTR] = "OVERRIDE_METERING_PTR",
                                 [(int)la_acl_counter_type_e::NONE] = "NONE"};

    if ((size_t)counter < array_size(strs)) {
        return std::string(strs[(size_t)counter]);
    }

    return std::string("Unknown acl counter type");
}

std::string
to_string(la_counter_set::type_e counter_type)
{

    static const char* strs[] = {
            [(int)la_counter_set::type_e::INVALID] = "INVALID",
            [(int)la_counter_set::type_e::DROP] = "DROP",
            [(int)la_counter_set::type_e::QOS] = "QOS",
            [(int)la_counter_set::type_e::PORT] = "PORT",
            [(int)la_counter_set::type_e::VOQ] = "VOQ",
            [(int)la_counter_set::type_e::METER] = "METER",
            [(int)la_counter_set::type_e::BFD] = "BFD",
            [(int)la_counter_set::type_e::ERSPAN] = "ERSPAN",
            [(int)la_counter_set::type_e::MPLS_DECAP] = "MPLS_DECAP",
            [(int)la_counter_set::type_e::VNI] = "VNI",
            [(int)la_counter_set::type_e::IP_TUNNEL] = "IP_TUNNEL",
            [(int)la_counter_set::type_e::MCG] = "MCG",
            [(int)la_counter_set::type_e::MPLS_LABEL] = "MPLS_LABEL",
            [(int)la_counter_set::type_e::MPLS_PER_PROTOCOL] = "MPLS_PER_PROTOCOL",
            [(int)la_counter_set::type_e::MPLS_TRAFFIC_MATRIX] = "MPLS_TRAFFIC_MATRIX",
    };

    if ((size_t)counter_type < array_size(strs)) {
        return std::string(strs[(size_t)counter_type]);
    }

    return std::string("Unknown counter set type");
}

std::string
to_string(la_mac_port::serdes_counter_e counter_type)
{

    static const char* strs[] = {
            [(int)la_mac_port::serdes_counter_e::PMA_TEST_ERROR] = "PMA_TEST_ERROR",
    };

    if ((size_t)counter_type < array_size(strs)) {
        return std::string(strs[(size_t)counter_type]);
    }

    return std::string("Unknown serdes counter type");
}

std::string
to_string(la_protection_monitor::monitor_state_e monitor_state)
{

    static const char* strs[] = {
            [(int)la_protection_monitor::monitor_state_e::UNTRIGGERED] = "UNTRIGGERED",
            [(int)la_protection_monitor::monitor_state_e::TRIGGERED] = "TRIGGERED",
    };

    if ((size_t)monitor_state < array_size(strs)) {
        return std::string(strs[(size_t)monitor_state]);
    }

    return std::string("Unknown monitor state");
}

std::string
to_string(la_output_queue_scheduler::scheduling_mode_e scheduling_mode)
{

    static const char* strs[] = {
            [(int)la_output_queue_scheduler::scheduling_mode_e::DIRECT_4SP] = "DIRECT_4SP",
            [(int)la_output_queue_scheduler::scheduling_mode_e::DIRECT_3SP_2WFQ] = "DIRECT_3SP_2WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::DIRECT_2SP_3WFQ] = "DIRECT_2SP_3WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::DIRECT_4WFQ] = "DIRECT_WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_SP_SP] = "LP_SP_SP",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_SP_WFQ] = "LP_SP_WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_WFQ_SP] = "LP_WFQ_SP",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_WFQ_WFQ] = "LP_WFQ_WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_4SP] = "LP_4SP",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_3SP_2WFQ] = "LP_3SP_2WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_2SP_3WFQ] = "LP_2SP_3WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_4WFQ] = "LP_4WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_8SP] = "LP_8SP",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_7SP_2WFQ] = "LP_7SP_2WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_6SP_3WFQ] = "LP_6SP_3WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_5SP_4WFQ] = "LP_5SP_4WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_4SP_5WFQ] = "LP_4SP_5WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_3SP_6WFQ] = "LP_3SP_6WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_2SP_7WFQ] = "LP_2SP_7WFQ",
            [(int)la_output_queue_scheduler::scheduling_mode_e::LP_8WFQ] = "LP_8WFQ",
    };

    if ((size_t)scheduling_mode < array_size(strs)) {
        return std::string(strs[(size_t)scheduling_mode]);
    }

    return std::string("Unknown scheduling mode type");
}

std::string
to_string(dependency_management_op::management_type_e type)
{

    static const char* strs[] = {
            [(int)dependency_management_op::management_type_e::IFG_MANAGEMENT] = "IFG_MANAGEMENT",
            [(int)dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT] = "ATTRIBUTE_MANAGEMENT",
    };

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown management type");
}

std::string
to_string(la_status status)
{
    return la_status2str(status);
}

std::string
to_string(la_slice_mode_e slice_mode)
{

    static const char* strs[] = {
            [(int)la_slice_mode_e::INVALID] = "INVALID",
            [(int)la_slice_mode_e::CARRIER_FABRIC] = "CARRIER_FABRIC",
            [(int)la_slice_mode_e::DC_FABRIC] = "DC_FABRIC",
            [(int)la_slice_mode_e::NETWORK] = "NETWORK",
    };

    if ((size_t)slice_mode < array_size(strs)) {
        return std::string(strs[(size_t)slice_mode]);
    }

    return std::string("Unknown slice mode type");
}

std::string
to_string(la_ethernet_port::event_e event)
{

    static const char* strs[] = {
            [(int)la_ethernet_port::event_e::ARP_REPLY] = "ARP_REPLY",
            [(int)la_ethernet_port::event_e::DHCPV4] = "DHCPV4",
            [(int)la_ethernet_port::event_e::DHCPV6] = "DHCPV6",
    };

    if ((size_t)event < array_size(strs)) {
        return std::string(strs[(size_t)event]);
    }

    return std::string("Unknown event");
}

std::string
to_string(la_acl::stage_e stage)
{

    static const char* strs[] = {
            [(int)la_acl::stage_e::INGRESS_TERM] = "INGRESS_TERM",
            [(int)la_acl::stage_e::INGRESS_FWD] = "INGRESS_FWD",
            [(int)la_acl::stage_e::SECOND_INGRESS_FWD] = "SECOND_INGRESS_FWD",
            [(int)la_acl::stage_e::EGRESS] = "EGRESS",
            [(int)la_acl::stage_e::LAST] = "LAST",
    };

    if ((size_t)stage < array_size(strs)) {
        return std::string(strs[(size_t)stage]);
    }

    return std::string("Unknown stage");
}

std::string
to_string(la_acl::type_e type)
{

    static const char* strs[] = {[(int)la_acl::type_e::QOS] = "QOS", [(int)la_acl::type_e::UNIFIED] = "UNIFIED"};

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown type");
}

std::string
to_string(la_device::init_phase_e phase)
{

    static const char* strs[] = {
            [(int)la_device::init_phase_e::CREATED] = "CREATED",
            [(int)la_device::init_phase_e::DEVICE] = "DEVICE",
            [(int)la_device::init_phase_e::TOPOLOGY] = "TOPOLOGY",
    };

    if ((size_t)phase < array_size(strs)) {
        return std::string(strs[(size_t)phase]);
    }

    return std::string("Unknown phase");
}

std::string
la_object_type_to_string(la_object::object_type_e type)
{
    static const char* strs[] = {
            [(int)la_object::object_type_e::AC_PROFILE] = "AC_PROFILE",
            [(int)la_object::object_type_e::ACL] = "ACL",
            [(int)la_object::object_type_e::ACL_SCALED] = "ACL_SCALED",
            [(int)la_object::object_type_e::ACL_KEY_PROFILE] = "ACL_KEY_PROFILE",
            [(int)la_object::object_type_e::ACL_COMMAND_PROFILE] = "ACL_COMMAND_PROFILE",
            [(int)la_object::object_type_e::ACL_GROUP] = "ACL_GROUP",
            [(int)la_object::object_type_e::ASBR_LSP] = "ASBR_LSP",
            [(int)la_object::object_type_e::BFD_SESSION] = "BFD_SESSION",
            [(int)la_object::object_type_e::COUNTER_SET] = "COUNTER_SET",
            [(int)la_object::object_type_e::DESTINATION_PE] = "DESTINATION_PE",
            [(int)la_object::object_type_e::DEVICE] = "DEVICE",
            [(int)la_object::object_type_e::ECMP_GROUP] = "ECMP_GROUP",
            [(int)la_object::object_type_e::EGRESS_QOS_PROFILE] = "EGRESS_QOS_PROFILE",
            [(int)la_object::object_type_e::ERSPAN_MIRROR_COMMAND] = "ERSPAN_MIRROR_COMMAND",
            [(int)la_object::object_type_e::ETHERNET_PORT] = "ETHERNET_PORT",
            [(int)la_object::object_type_e::FABRIC_MULTICAST_GROUP] = "FABRIC_MULTICAST_GROUP",
            [(int)la_object::object_type_e::FABRIC_PORT] = "FABRIC_PORT",
            [(int)la_object::object_type_e::FABRIC_PORT_SCHEDULER] = "FABRIC_PORT_SCHEDULER",
            [(int)la_object::object_type_e::FEC] = "FEC",
            [(int)la_object::object_type_e::FILTER_GROUP] = "FILTER_GROUP",
            [(int)la_object::object_type_e::FLOW_CACHE_HANDLER] = "FLOW_CACHE_HANDLER",
            [(int)la_object::object_type_e::FORUS_DESTINATION] = "FORUS_DESTINATION",
            [(int)la_object::object_type_e::GRE_PORT] = "GRE_PORT",
            [(int)la_object::object_type_e::GUE_PORT] = "GUE_PORT",
            [(int)la_object::object_type_e::HBM_HANDLER] = "HBM_HANDLER",
            [(int)la_object::object_type_e::PTP_HANDLER] = "PTP_HANDLER",
            [(int)la_object::object_type_e::IFG_SCHEDULER] = "IFG_SCHEDULER",
            [(int)la_object::object_type_e::INGRESS_QOS_PROFILE] = "INGRESS_QOS_PROFILE",
            [(int)la_object::object_type_e::INTERFACE_SCHEDULER] = "INTERFACE_SCHEDULER",
            [(int)la_object::object_type_e::IP_MULTICAST_GROUP] = "IP_MULTICAST_GROUP",
            [(int)la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT] = "IP_OVER_IP_TUNNEL_PORT",
            [(int)la_object::object_type_e::IP_TUNNEL_DESTINATION] = "IP_TUNNEL_DESTINATION",
            [(int)la_object::object_type_e::LOGICAL_PORT_SCHEDULER] = "LOGICAL_PORT_SCHEDULER",
            [(int)la_object::object_type_e::LPTS] = "LPTS",
            [(int)la_object::object_type_e::COPC] = "COPC",
            [(int)la_object::object_type_e::L2_MIRROR_COMMAND] = "L2_MIRROR_COMMAND",
            [(int)la_object::object_type_e::L2_MULTICAST_GROUP] = "L2_MULTICAST_GROUP",
            [(int)la_object::object_type_e::L2_PROTECTION_GROUP] = "L2_PROTECTION_GROUP",
            [(int)la_object::object_type_e::L3_PROTECTION_GROUP] = "L3_PROTECTION_GROUP",
            [(int)la_object::object_type_e::L2_PUNT_DESTINATION] = "L2_PUNT_DESTINATION",
            [(int)la_object::object_type_e::L2_SERVICE_PORT] = "L2_SERVICE_PORT",
            [(int)la_object::object_type_e::L3_AC_PORT] = "L3_AC_PORT",
            [(int)la_object::object_type_e::LSR] = "LSR",
            [(int)la_object::object_type_e::MAC_PORT] = "MAC_PORT",
            [(int)la_object::object_type_e::METER_ACTION_PROFILE] = "METER_ACTION_PROFILE",
            [(int)la_object::object_type_e::METER_MARKDOWN_PROFILE] = "METER_MARKDOWN_PROFILE",
            [(int)la_object::object_type_e::METER_PROFILE] = "METER_PROFILE",
            [(int)la_object::object_type_e::METER_SET] = "METER_SET",
            [(int)la_object::object_type_e::MPLS_LABEL_DESTINATION] = "MPLS_LABEL_DESTINATION",
            [(int)la_object::object_type_e::MPLS_NHLFE] = "MPLS_NHLFE",
            [(int)la_object::object_type_e::MPLS_VPN_DECAP] = "MPLS_VPN_DECAP",
            [(int)la_object::object_type_e::MPLS_VPN_ENCAP] = "MPLS_VPN_ENCAP",
            [(int)la_object::object_type_e::MLDP_VPN_DECAP] = "MLDP_VPN_DECAP",
            [(int)la_object::object_type_e::MPLS_MULTICAST_GROUP] = "MPLS_MULTICAST_GROUP",
            [(int)la_object::object_type_e::MULTICAST_PROTECTION_GROUP] = "MULTICAST_PROTECTION_GROUP",
            [(int)la_object::object_type_e::MULTICAST_PROTECTION_MONITOR] = "MULTICAST_PROTECTION_MONITOR",
            [(int)la_object::object_type_e::NEXT_HOP] = "NEXT_HOP",
            [(int)la_object::object_type_e::NPU_HOST_DESTINATION] = "NPU_HOST_DESTINATION",
            [(int)la_object::object_type_e::NPU_HOST_PORT] = "NPU_HOST_PORT",
            [(int)la_object::object_type_e::OG_LPTS_APPLICATION] = "OG_LPTS_APPLICATION",
            [(int)la_object::object_type_e::OUTPUT_QUEUE_SCHEDULER] = "OUTPUT_QUEUE_SCHEDULER",
            [(int)la_object::object_type_e::PCI_PORT] = "PCI_PORT",
            [(int)la_object::object_type_e::PCL] = "PCL",
            [(int)la_object::object_type_e::PREFIX_OBJECT] = "PREFIX_OBJECT",
            [(int)la_object::object_type_e::PROTECTION_MONITOR] = "PROTECTION_MONITOR",
            [(int)la_object::object_type_e::PUNT_INJECT_PORT] = "PUNT_INJECT_PORT",
            [(int)la_object::object_type_e::RATE_LIMITER_SET] = "RATE_LIMITER_SET",
            [(int)la_object::object_type_e::RECYCLE_PORT] = "RECYCLE_PORT",
            [(int)la_object::object_type_e::REMOTE_PORT] = "REMOTE_PORT",
            [(int)la_object::object_type_e::REMOTE_DEVICE] = "REMOTE_DEVICE",
            [(int)la_object::object_type_e::RX_CGM_SQ_PROFILE] = "RX_CGM_SQ_PROFILE",
            [(int)la_object::object_type_e::SPA_PORT] = "SPA_PORT",
            [(int)la_object::object_type_e::STACK_PORT] = "STACK_PORT",
            [(int)la_object::object_type_e::SVI_PORT] = "SVI_PORT",
            [(int)la_object::object_type_e::SWITCH] = "SWITCH",
            [(int)la_object::object_type_e::SYSTEM_PORT] = "SYSTEM_PORT",
            [(int)la_object::object_type_e::SYSTEM_PORT_SCHEDULER] = "SYSTEM_PORT_SCHEDULER",
            [(int)la_object::object_type_e::TE_TUNNEL] = "TE_TUNNEL",
            [(int)la_object::object_type_e::TC_PROFILE] = "TC_PROFILE",
            [(int)la_object::object_type_e::VOQ_CGM_PROFILE] = "VOQ_CGM_PROFILE",
            [(int)la_object::object_type_e::VOQ_SET] = "VOQ_SET",
            [(int)la_object::object_type_e::VRF] = "VRF",
            [(int)la_object::object_type_e::VXLAN_NEXT_HOP] = "VXLAN_NEXT_HOP",
            [(int)la_object::object_type_e::VOQ_CGM_EVICTED_PROFILE] = "VOQ_CGM_EVICTED_PROFILE",
            [(int)la_object::object_type_e::SECURITY_GROUP_CELL] = "SECURITY_GROUP_CELL",
            [(int)la_object::object_type_e::PBTS_MAP_PROFILE] = "PBTS_MAP_PROFILE",
            [(int)la_object::object_type_e::PBTS_GROUP] = "PBTS_GROUP",
            [(int)la_object::object_type_e::VRF_REDIRECT_DESTINATION] = "VRF_REDIRECT_DESTINATION",
            [(int)la_object::object_type_e::RTF_CONF_SET] = "RTF_CONF_SET",
    };

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown object type");
}

std::string
to_string(const la_vlan_edit_command& edit_command)
{
    std::stringstream log_message;
    log_message << LOG_STRUCT_START << "num_tags_to_pop=" << edit_command.num_tags_to_pop << LOG_STRUCT_SEPARATOR
                << "num_tags_to_push=" << edit_command.num_tags_to_push << LOG_STRUCT_SEPARATOR
                << "tag0=" << get_value_string(edit_command.tag0) << LOG_STRUCT_SEPARATOR
                << "tag1=" << get_value_string(edit_command.tag1) << LOG_STRUCT_SEPARATOR
                << "pcpdei_rewrite_only=" << get_value_string(edit_command.pcpdei_rewrite_only) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_vlan_tag_tci_fields_t& fields)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "pcp=" << fields.pcp << LOG_STRUCT_SEPARATOR << "dei=" << fields.dei << LOG_STRUCT_SEPARATOR
                << "vid=" << fields.vid << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_vlan_tag_tci_t& vlan_tag_tci)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "fields=" << get_value_string(vlan_tag_tci.fields) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_vlan_tag_t& vlan_tag)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "tpid=" << vlan_tag.tpid << LOG_STRUCT_SEPARATOR << "tci=" << get_value_string(vlan_tag.tci)
                << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_route_entry_action_e& action)
{
    static const char* strs[] = {
            [(int)la_route_entry_action_e::ADD] = "ADD",
            [(int)la_route_entry_action_e::DELETE] = "DELETE",
            [(int)la_route_entry_action_e::MODIFY] = "MODIFY",
    };

    if ((size_t)action < array_size(strs)) {
        return std::string(strs[(size_t)action]);
    }

    return std::string("Unknown action");
}

std::string
to_string(const la_ipv4_route_entry_parameters_vec& vec)
{
    return vec_to_string(vec);
}

std::string
to_string(const la_ipv6_route_entry_parameters_vec& vec)
{
    return vec_to_string(vec);
}

std::string
to_string(const la_ipv4_route_entry_parameters& parameters)
{
    std::stringstream log_message;
    log_message.flags(std::ios::hex | std::ios::showbase);

    log_message << LOG_STRUCT_START << "action=" << get_value_string(parameters.action) << LOG_STRUCT_SEPARATOR
                << "prefix=" << get_value_string(parameters.prefix) << LOG_STRUCT_SEPARATOR
                << "destination=" << get_value_string(parameters.destination) << LOG_STRUCT_SEPARATOR
                << "is_user_data_set=" << get_value_string(parameters.is_user_data_set) << LOG_STRUCT_SEPARATOR
                << "user_data=" << (size_t)parameters.user_data << LOG_STRUCT_SEPARATOR
                << "latency_sensitive=" << get_value_string(parameters.latency_sensitive) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_ipv6_route_entry_parameters& parameters)
{
    std::stringstream log_message;
    log_message.flags(std::ios::hex | std::ios::showbase);

    log_message << LOG_STRUCT_START << "action=" << get_value_string(parameters.action) << LOG_STRUCT_SEPARATOR
                << "prefix=" << get_value_string(parameters.prefix) << LOG_STRUCT_SEPARATOR
                << "destination=" << get_value_string(parameters.destination) << LOG_STRUCT_SEPARATOR
                << "is_user_data_set=" << get_value_string(parameters.is_user_data_set) << LOG_STRUCT_SEPARATOR
                << "user_data=" << (size_t)parameters.user_data << LOG_STRUCT_SEPARATOR
                << "latency_sensitive=" << get_value_string(parameters.latency_sensitive) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_ipv4_addr_t& ipv4_addr)
{
    char addr[LOG_BUFFER_SIZE];

    snprintf(
        addr, LOG_BUFFER_SIZE, "%u.%u.%u.%u", ipv4_addr.b_addr[3], ipv4_addr.b_addr[2], ipv4_addr.b_addr[1], ipv4_addr.b_addr[0]);

    return std::string(addr);
}

std::string
to_string(const la_ipv4_prefix_t& ipv4_prefix)
{
    char prefix[LOG_BUFFER_SIZE];

    snprintf(prefix,
             LOG_BUFFER_SIZE,
             "(addr=<silicon_one::la_ipv4_addr_t>%s,length=%u)",
             to_string(ipv4_prefix.addr).c_str(),
             ipv4_prefix.length);

    return std::string(prefix);
}

std::string
to_string(const la_ipv6_addr_t& ipv6_addr)
{
    char addr[LOG_BUFFER_SIZE];

    snprintf(addr,
             LOG_BUFFER_SIZE,
             "0x%x:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x",
             ipv6_addr.w_addr[7],
             ipv6_addr.w_addr[6],
             ipv6_addr.w_addr[5],
             ipv6_addr.w_addr[4],
             ipv6_addr.w_addr[3],
             ipv6_addr.w_addr[2],
             ipv6_addr.w_addr[1],
             ipv6_addr.w_addr[0]);

    return std::string(addr);
}

std::string
to_string(const la_ipv6_prefix_t& ipv6_prefix)
{
    char prefix[LOG_BUFFER_SIZE];

    snprintf(prefix,
             LOG_BUFFER_SIZE,
             "(addr=<silicon_one::la_ipv6_addr_t>%s,length=%u)",
             to_string(ipv6_prefix.addr).c_str(),
             ipv6_prefix.length);

    return std::string(prefix);
}

std::string
to_string(const la_ip_addr& ip_addr)
{
    std::stringstream log_message;
    log_message << LOG_STRUCT_START;
    if (ip_addr.is_v4()) {
        log_message << "v4_addr=" << get_value_string(ip_addr.to_v4());
    } else if (ip_addr.is_v6()) {
        log_message << "v6_addr=" << get_value_string(ip_addr.to_v6());
    } else {
        log_message << "v4_addr=null, v6_addr=null";
    }
    log_message << LOG_STRUCT_END;
    return log_message.str();
}

std::string
to_string(la_egress_qos_marking_source_e qos_marking_source)
{
    static const char* strs[] = {
            [(int)la_egress_qos_marking_source_e::QOS_GROUP] = "QOS_GROUP",
            [(int)la_egress_qos_marking_source_e::QOS_TAG] = "QOS_TAG",
    };

    if ((size_t)qos_marking_source < array_size(strs)) {
        return std::string(strs[(size_t)qos_marking_source]);
    }

    return std::string("Unknown egress qos marking source");
}

std::string
to_string(la_mac_port::loopback_mode_e mode)
{
    static const char* strs[] = {
            [(int)la_mac_port::loopback_mode_e::NONE] = "NONE",
            [(int)la_mac_port::loopback_mode_e::MII_CORE_CLK] = "MII_CORE_CLK",
            [(int)la_mac_port::loopback_mode_e::MII_SRDS_CLK] = "MII_SRDS_CLK",
            [(int)la_mac_port::loopback_mode_e::INFO_MAC_CLK] = "INFO_MAC_CLK",
            [(int)la_mac_port::loopback_mode_e::INFO_SRDS_CLK] = "INFO_SRDS_CLK",
            [(int)la_mac_port::loopback_mode_e::PMA_CORE_CLK] = "PMA_CORE_CLK",
            [(int)la_mac_port::loopback_mode_e::PMA_SRDS_CLK] = "PMA_SRDS_CLK",
            [(int)la_mac_port::loopback_mode_e::SERDES] = "SERDES",
            [(int)la_mac_port::loopback_mode_e::REMOTE_PMA] = "REMOTE_PMA",
            [(int)la_mac_port::loopback_mode_e::REMOTE_SERDES] = "REMOTE_SERDES",

    };

    if ((size_t)mode < array_size(strs)) {
        return strs[(size_t)mode];
    }

    return "Unknown loopback mode";
}

std::string
to_string(la_mac_port::pcs_test_mode_e val)
{
    const char* strs[] = {
            [(size_t)la_mac_port::pcs_test_mode_e::NONE] = "NONE",
            [(size_t)la_mac_port::pcs_test_mode_e::SCRAMBLED] = "SCRAMBLED",
            [(size_t)la_mac_port::pcs_test_mode_e::RANDOM] = "RANDOM",
            [(size_t)la_mac_port::pcs_test_mode_e::RANDOM_ZEROS] = "RANDOM_ZEROS",
            [(size_t)la_mac_port::pcs_test_mode_e::PRBS31] = "PRBS31",
            [(size_t)la_mac_port::pcs_test_mode_e::PRBS9] = "PRBS9",
    };

    if ((size_t)val < array_size(strs)) {
        return strs[(size_t)val];
    }

    return "Unknown pcs_test_mode";
}

std::string
to_string(la_mac_port::pma_test_mode_e mode)
{
    static const char* strs[] = {
            [(int)la_mac_port::pma_test_mode_e::NONE] = "NONE",
            [(int)la_mac_port::pma_test_mode_e::RANDOM] = "RANDOM",
            [(int)la_mac_port::pma_test_mode_e::PRBS31] = "PRBS31",
            [(int)la_mac_port::pma_test_mode_e::PRBS9] = "PRBS9",
            [(int)la_mac_port::pma_test_mode_e::PRBS15] = "PRBS15",
            [(int)la_mac_port::pma_test_mode_e::PRBS13] = "PRBS13",
            [(int)la_mac_port::pma_test_mode_e::JP03B] = "JP03B",
            [(int)la_mac_port::pma_test_mode_e::SSPRQ] = "SSPRQ",
            [(int)la_mac_port::pma_test_mode_e::SQUARE_WAVE] = "SQUARE_WAVE",
    };

    if ((size_t)mode < array_size(strs)) {
        return strs[(size_t)mode];
    }

    return "Unknown pma_test_mode";
}

std::string
to_string(la_mac_port::serdes_test_mode_e mode)
{
    static const char* strs[] = {
            [(int)la_mac_port::serdes_test_mode_e::NONE] = "NONE",
            [(int)la_mac_port::serdes_test_mode_e::PRBS7] = "PRBS7",
            [(int)la_mac_port::serdes_test_mode_e::PRBS9_4] = "PRBS9_4",
            [(int)la_mac_port::serdes_test_mode_e::PRBS9] = "PRBS9_5",
            [(int)la_mac_port::serdes_test_mode_e::PRBS11] = "PRBS11",
            [(int)la_mac_port::serdes_test_mode_e::PRBS13] = "PRBS13",
            [(int)la_mac_port::serdes_test_mode_e::PRBS15] = "PRBS15",
            [(int)la_mac_port::serdes_test_mode_e::PRBS16] = "PRBS16",
            [(int)la_mac_port::serdes_test_mode_e::PRBS23] = "PRBS23",
            [(int)la_mac_port::serdes_test_mode_e::PRBS31] = "PRBS31",
            [(int)la_mac_port::serdes_test_mode_e::PRBS58] = "PRBS58",
            [(int)la_mac_port::serdes_test_mode_e::JP03B] = "JP03B",
            [(int)la_mac_port::serdes_test_mode_e::PRBS_LIN] = "PRBS_LIN",
            [(int)la_mac_port::serdes_test_mode_e::PRBS_CJT] = "PRBS_CJT",
            [(int)la_mac_port::serdes_test_mode_e::SSPRQ] = "SSPRQ",
    };

    if ((size_t)mode < array_size(strs)) {
        return strs[(size_t)mode];
    }

    return "Unknown serdes_test_mode";
}

std::string
to_string(la_mac_port::serdes_tuning_mode_e val)
{
    static const char* strs[] = {
            [(int)la_mac_port::serdes_tuning_mode_e::ICAL_ONLY] = "ICAL_ONLY",
            [(int)la_mac_port::serdes_tuning_mode_e::ICAL] = "ICAL",
            [(int)la_mac_port::serdes_tuning_mode_e::PCAL] = "PCAL",
    };

    if ((size_t)val < array_size(strs)) {
        return strs[(size_t)val];
    }

    return "Unknown serdes_tuning_mode";
}

std::string
to_string(const la_vlan_pcpdei& pcpdei)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "fields.pcp=" << (size_t)pcpdei.fields.pcp << LOG_STRUCT_SEPARATOR
                << "fields.dei=" << (size_t)pcpdei.fields.dei << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_ip_dscp& dscp)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "value=" << (size_t)dscp.value << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_ip_tos& tos)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "fields.dscp=" << (size_t)tos.fields.dscp << LOG_STRUCT_SEPARATOR
                << "fields.ecn=" << (size_t)tos.fields.ecn << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_mpls_tc& mpls_tc)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "value=" << (size_t)mpls_tc.value << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_packet_vlan_format_t& tag_format)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "outer_vlan_is_priority=" << get_value_string(tag_format.outer_vlan_is_priority)
                << LOG_STRUCT_SEPARATOR << "tpid1=" << tag_format.tpid1 << LOG_STRUCT_SEPARATOR << "tpid2=" << tag_format.tpid2
                << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_acl_key_type_e key_type)
{

    static const char* strs[] = {
            [(int)la_acl_key_type_e::ETHERNET] = "ETHERNET",
            [(int)la_acl_key_type_e::IPV4] = "IPV4",
            [(int)la_acl_key_type_e::IPV6] = "IPV6",
            [(int)la_acl_key_type_e::SGACL] = "SGACL",
            [(int)la_acl_key_type_e::LAST] = "LAST",
    };

    if ((size_t)key_type < array_size(strs)) {
        return std::string(strs[(size_t)key_type]);
    }

    return std::string("Unknown acl key type");
}

std::string
to_string(la_acl_cmd_type_e cmd_type)
{
    static const char* strs[] = {
            [(int)la_acl_cmd_type_e::NOP] = "NOP",
            [(int)la_acl_cmd_type_e::INGRESS_UNIFIED] = "INGRESS_UNIFIED",
            [(int)la_acl_cmd_type_e::INGRESS_QOS] = "INGRESS_QOS",
            [(int)la_acl_cmd_type_e::EGRESS_UNIFIED] = "EGRESS_UNIFIED",
            [(int)la_acl_cmd_type_e::EGRESS_QOS] = "EGRESS_QOS",
            [(int)la_acl_cmd_type_e::PBR] = "PBR",
    };

    if ((size_t)cmd_type < array_size(strs)) {
        return std::string(strs[(size_t)cmd_type]);
    }

    return std::string("Unknown acl cmd type");
}

std::string
to_string(la_acl_command_action cmd)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "type=" << get_value_string(cmd.type);

    if (cmd.type == la_acl_action_type_e::TRAFFIC_CLASS) {
        log_message << LOG_STRUCT_SEPARATOR << "data.traffic_class=" << get_value_string(cmd.data.traffic_class);
    } else if (cmd.type == la_acl_action_type_e::COLOR) {
        log_message << LOG_STRUCT_SEPARATOR << "data.color=" << get_value_string(cmd.data.color);
    } else if (cmd.type == la_acl_action_type_e::QOS_OR_METER_COUNTER_OFFSET) {
        log_message << LOG_STRUCT_SEPARATOR << "data.qos_offset=" << get_value_string(cmd.data.qos_offset);
        log_message << LOG_STRUCT_SEPARATOR << "data.meter_offset=" << get_value_string(cmd.data.meter_offset);
    } else if (cmd.type == la_acl_action_type_e::ENCAP_EXP) {
        log_message << LOG_STRUCT_SEPARATOR << "data.encap_exp=" << get_value_string(cmd.data.encap_exp);
    } else if (cmd.type == la_acl_action_type_e::REMARK_FWD) {
        log_message << LOG_STRUCT_SEPARATOR << "data.remark_fwd=" << get_value_string(cmd.data.remark_fwd);
    } else if (cmd.type == la_acl_action_type_e::REMARK_GROUP) {
        log_message << LOG_STRUCT_SEPARATOR << "data.remark_group=" << get_value_string(cmd.data.remark_group);
    } else if (cmd.type == la_acl_action_type_e::DROP) {
        log_message << LOG_STRUCT_SEPARATOR << "data.drop=" << get_value_string(cmd.data.drop);
    } else if (cmd.type == la_acl_action_type_e::PUNT) {
        log_message << LOG_STRUCT_SEPARATOR << "data.punt=" << get_value_string(cmd.data.punt);
    } else if (cmd.type == la_acl_action_type_e::DO_MIRROR) {
        log_message << LOG_STRUCT_SEPARATOR << "data.do_mirror=" << get_value_string(cmd.data.do_mirror);
    } else if (cmd.type == la_acl_action_type_e::MIRROR_CMD) {
        log_message << LOG_STRUCT_SEPARATOR << "data.mirror_cmd=" << get_value_string(cmd.data.mirror_cmd);
    } else if (cmd.type == la_acl_action_type_e::COUNTER) {
        log_message << LOG_STRUCT_SEPARATOR << "data.counter=" << get_value_string(cmd.data.counter);
    } else if (cmd.type == la_acl_action_type_e::L2_DESTINATION) {
        log_message << LOG_STRUCT_SEPARATOR << "data.l2_dest=" << get_value_string(cmd.data.l2_dest);
    } else if (cmd.type == la_acl_action_type_e::L3_DESTINATION) {
        log_message << LOG_STRUCT_SEPARATOR << "data.l3_dest=" << get_value_string(cmd.data.l3_dest);
    } else if (cmd.type == la_acl_action_type_e::COUNTER_TYPE) {
        log_message << LOG_STRUCT_SEPARATOR << "data.counter_type=" << get_value_string(cmd.data.counter_type);
    }

    log_message << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_acl_scaled::scale_field_e scale_field)
{

    static const char* strs[] = {
            [(int)la_acl_scaled::scale_field_e::UNDEF] = "UNDEF",
            [(int)la_acl_scaled::scale_field_e::SIP] = "SIP",
            [(int)la_acl_scaled::scale_field_e::DIP] = "DIP",
            [(int)la_acl_scaled::scale_field_e::LAST] = "LAST",
    };

    if ((size_t)scale_field < array_size(strs)) {
        return std::string(strs[(size_t)scale_field]);
    }

    return std::string("Unknown acl scaled field type");
}

std::string
to_string(const la_erspan_mirror_command::ipv4_encapsulation& encap_data)
{
    std::stringstream log_message;

    if (encap_data.type == la_erspan_mirror_command::type_e::ERSPAN) {
        log_message << LOG_STRUCT_START << "session_id=" << get_value_string(encap_data.session.session_id) << LOG_STRUCT_SEPARATOR
                    << "mac_addr=" << get_value_string(encap_data.mac_addr) << LOG_STRUCT_SEPARATOR
                    << "tunnel_dest_addr=" << get_value_string(encap_data.ipv4.tunnel_dest_addr) << LOG_STRUCT_SEPARATOR
                    << "tunnel_source_addr=" << get_value_string(encap_data.ipv4.tunnel_source_addr) << LOG_STRUCT_SEPARATOR
                    << "ttl=" << get_value_string(encap_data.ipv4.ttl) << LOG_STRUCT_SEPARATOR
                    << "dscp=" << get_value_string(encap_data.ipv4.dscp) << LOG_STRUCT_END;
    }

    return log_message.str();
}

std::string
to_string(const la_erspan_mirror_command::ipv6_encapsulation& encap_data)
{
    std::stringstream log_message;

    if (encap_data.type == la_erspan_mirror_command::type_e::ERSPAN) {
        log_message << LOG_STRUCT_START << "session_id=" << get_value_string(encap_data.session.session_id) << LOG_STRUCT_SEPARATOR
                    << "mac_addr=" << get_value_string(encap_data.mac_addr) << LOG_STRUCT_SEPARATOR
                    << "tunnel_dest_addr=" << get_value_string(encap_data.ipv6.tunnel_dest_addr) << LOG_STRUCT_SEPARATOR
                    << "tunnel_source_addr=" << get_value_string(encap_data.ipv6.tunnel_source_addr) << LOG_STRUCT_SEPARATOR
                    << "ttl=" << get_value_string(encap_data.ipv6.ttl) << LOG_STRUCT_SEPARATOR
                    << "dscp=" << get_value_string(encap_data.ipv6.dscp) << LOG_STRUCT_END;
    }

    return log_message.str();
}

std::string
to_string(const la_egress_qos_profile::encapsulating_headers_qos_values& encap_qos_values)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "pcpdei=" << get_value_string(encap_qos_values.pcpdei) << LOG_STRUCT_SEPARATOR
                << "tos=" << get_value_string(encap_qos_values.tos) << LOG_STRUCT_SEPARATOR
                << "tc=" << get_value_string(encap_qos_values.tc) << LOG_STRUCT_SEPARATOR
                << "use_for_inner_labels=" << get_value_string(encap_qos_values.use_for_inner_labels) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_qos_color_e qos_color)
{

    static const char* strs[] = {
            [(int)la_qos_color_e::GREEN] = "GREEN",
            [(int)la_qos_color_e::YELLOW] = "YELLOW",
            [(int)la_qos_color_e::RED] = "RED",
            [3] = "Unknown QoS color",
            [(int)la_qos_color_e::NONE] = "NONE",
    };

    if ((size_t)qos_color < array_size(strs)) {
        return std::string(strs[(size_t)qos_color]);
    }

    return std::string("Unknown QoS color");
}

std::string
to_string(la_ip_tunnel_mode_e tunnel_mode)
{
    static const char* strs[] = {
            [(int)la_ip_tunnel_mode_e::ENCAP_DECAP] = "ENCAP_DECAP",
            [(int)la_ip_tunnel_mode_e::ENCAP_ONLY] = "ENCAP_ONLY",
            [(int)la_ip_tunnel_mode_e::DECAP_ONLY] = "DECAP_ONLY",
    };

    if ((size_t)tunnel_mode < array_size(strs)) {
        return std::string(strs[(size_t)tunnel_mode]);
    }

    return std::string("Unknown tunnel mode");
}

std::string
to_string(la_forwarding_header_e forwarding_header)
{

    static const char* strs[] = {
            [(int)la_forwarding_header_e::ETHERNET] = "ETHERNET",
            [(int)la_forwarding_header_e::IP] = "IP",
            [(int)la_forwarding_header_e::MPLS] = "MPLS",
    };

    if ((size_t)forwarding_header < array_size(strs)) {
        return std::string(strs[(size_t)forwarding_header]);
    }

    return std::string("Unknown forwarding header");
}

std::string
to_string(la_lb_mode_e lb_mode)
{

    static const char* strs[] = {
            [(int)la_lb_mode_e::CONSISTENT] = "CONSISTENT", [(int)la_lb_mode_e::DYNAMIC] = "DYNAMIC",
    };

    if ((size_t)lb_mode < array_size(strs)) {
        return std::string(strs[(size_t)lb_mode]);
    }

    return std::string("Unknown la_lb_mode_e");
}

std::string
to_string(la_l3_port::lb_profile_e lb_profile)
{

    static const char* strs[] = {
            [(int)la_l3_port::lb_profile_e::MPLS] = "MPLS",
            [(int)la_l3_port::lb_profile_e::IP] = "IP",
            [(int)la_l3_port::lb_profile_e::EL_ELI] = "EL_ELI",
    };

    if ((size_t)lb_profile < array_size(strs)) {
        return std::string(strs[(size_t)lb_profile]);
    }

    return std::string("Unknown load balancing profile");
}

std::string
to_string(const la_mpls_label& mpls_label)
{
    std::stringstream log_message;
    log_message.flags(std::ios::hex | std::ios::showbase);

    log_message << LOG_STRUCT_START << "label=" << mpls_label.label << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_mpls_label_vec_t& vec)
{
    return vec_to_string(vec);
}

std::string
to_string(const la_slice_ifg& slice_ifg)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "slice=" << slice_ifg.slice << LOG_STRUCT_SEPARATOR << "ifg=" << slice_ifg.ifg
                << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_mpls_qos_inheritance_mode_e inheritance_mode)
{

    static const char* strs[] = {
            [(int)la_mpls_qos_inheritance_mode_e::PIPE] = "PIPE", [(int)la_mpls_qos_inheritance_mode_e::UNIFORM] = "UNIFORM",
    };

    if ((size_t)inheritance_mode < array_size(strs)) {
        return std::string(strs[(size_t)inheritance_mode]);
    }

    return std::string("Unknown qos inheritance mode");
}

std::string
to_string(la_mpls_ttl_inheritance_mode_e inheritance_mode)
{

    static const char* strs[] = {
            [(int)la_mpls_ttl_inheritance_mode_e::PIPE] = "PIPE", [(int)la_mpls_ttl_inheritance_mode_e::UNIFORM] = "UNIFORM",
    };

    if ((size_t)inheritance_mode < array_size(strs)) {
        return std::string(strs[(size_t)inheritance_mode]);
    }

    return std::string("Unknown ttl inheritance mode");
}

std::string
to_string(la_lp_attribute_inheritance_mode_e inheritance_mode)
{

    static const char* strs[] = {
            [(int)la_lp_attribute_inheritance_mode_e::PORT] = "PORT", [(int)la_lp_attribute_inheritance_mode_e::TUNNEL] = "TUNNEL",
    };

    if ((size_t)inheritance_mode < array_size(strs)) {
        return std::string(strs[(size_t)inheritance_mode]);
    }

    return std::string("Unknown LP inheritance mode");
}

std::string
to_string(la_tunnel_encap_qos_mode_e encap_qos_mode)
{
    static const char* strs[] = {
            [(int)la_tunnel_encap_qos_mode_e::UNIFORM] = "UNIFORM", [(int)la_tunnel_encap_qos_mode_e::PIPE] = "PIPE",
    };

    if ((size_t)encap_qos_mode < array_size(strs)) {
        return std::string(strs[(size_t)encap_qos_mode]);
    }

    return std::string("Unknown tunnel encap qos mode");
}

std::string
to_string(const la_mac_addr_t& mac_addr)
{
    std::stringstream log_message;
    log_message.flags(std::ios::hex | std::ios::showbase);

    log_message << LOG_STRUCT_START << "flat=" << mac_addr.flat << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_next_hop::nh_type_e nh_type)
{

    static const char* strs[] = {
            [(int)la_next_hop::nh_type_e::NORMAL] = "NORMAL",
            [(int)la_next_hop::nh_type_e::GLEAN] = "GLEAN",
            [(int)la_next_hop::nh_type_e::NULL_] = "NULL_",
            [(int)la_next_hop::nh_type_e::DROP] = "DROP",
            [(int)la_next_hop::nh_type_e::USER_TRAP1] = "USER_TRAP1",
            [(int)la_next_hop::nh_type_e::USER_TRAP2] = "USER_TRAP2",
    };

    if ((size_t)nh_type < array_size(strs)) {
        return std::string(strs[(size_t)nh_type]);
    }

    return std::string("Unknown NH type");
}

std::string
to_string(const la_prefix_object::prefix_type_e type)
{

    static const char* strs[] = {
            [(int)la_prefix_object::prefix_type_e::NORMAL] = "NORMAL", [(int)la_prefix_object::prefix_type_e::GLOBAL] = "GLOBAL",
    };

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown Prefix object type");
}

std::string
to_string(const la_prefix_object::lsp_counter_mode_e counter_mode)
{

    static const char* strs[] = {
            [(int)la_prefix_object::lsp_counter_mode_e::LABEL] = "LABEL",
            [(int)la_prefix_object::lsp_counter_mode_e::PER_PROTOCOL] = "PER_PROTOCOL",
            [(int)la_prefix_object::lsp_counter_mode_e::TRAFFIC_MATRIX] = "TRAFFIC_MATRIX",
    };

    if ((size_t)counter_mode < array_size(strs)) {
        return std::string(strs[(size_t)counter_mode]);
    }

    return std::string("Unknown Counter mode type");
}

std::string
to_string(const la_te_tunnel::tunnel_type_e type)
{

    static const char* strs[] = {
            [(int)la_te_tunnel::tunnel_type_e::NORMAL] = "NORMAL", [(int)la_te_tunnel::tunnel_type_e::LDP_ENABLED] = "LDP_ENABLED",
    };

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown TE tunnel type");
}

std::string
to_string(const la_system_port_scheduler::priority_group_e priority_group)
{

    static const char* strs[] = {
            [(int)la_system_port_scheduler::priority_group_e::SINGLE0] = "SINGLE0",
            [(int)la_system_port_scheduler::priority_group_e::SINGLE1] = "SINGLE1",
            [(int)la_system_port_scheduler::priority_group_e::SINGLE2] = "SINGLE2",
            [(int)la_system_port_scheduler::priority_group_e::SINGLE3] = "SINGLE3",
            [(int)la_system_port_scheduler::priority_group_e::SP2] = "SP2",
            [(int)la_system_port_scheduler::priority_group_e::SP4] = "SP4",
            [(int)la_system_port_scheduler::priority_group_e::SP6] = "SP6",
            [(int)la_system_port_scheduler::priority_group_e::SP8] = "SP8",
            [(int)la_system_port_scheduler::priority_group_e::NONE] = "NONE",

    };

    if ((size_t)priority_group < array_size(strs)) {
        return std::string(strs[(size_t)priority_group]);
    }

    return std::string("Unknown priority group");
}

std::string
to_string(const la_ethernet_port::port_type_e port_type)
{

    static const char* strs[] = {
            [(int)la_ethernet_port::port_type_e::SIMPLE] = "SIMPLE",
            [(int)la_ethernet_port::port_type_e::AC] = "AC",
            [(int)la_ethernet_port::port_type_e::PNP] = "PNP",
            [(int)la_ethernet_port::port_type_e::CBP] = "CBP",

    };

    if ((size_t)port_type < array_size(strs)) {
        return std::string(strs[(size_t)port_type]);
    }

    return std::string("Unknown port type");
}

template <typename _ArrayType, size_t _SIZE>
std::string
to_string(const _ArrayType (&arr)[_SIZE])
{
    std::vector<_ArrayType> vec(arr, arr + _SIZE);
    return vec_to_string(vec);
}

std::string
to_string(la_voq_cgm_profile::wred_action_e action)
{

    static const char* strs[] = {
            [(int)la_voq_cgm_profile::wred_action_e::PASS] = "PASS",
            [(int)la_voq_cgm_profile::wred_action_e::DROP] = "DROP",
            [(int)la_voq_cgm_profile::wred_action_e::MARK_ECN] = "MARK_ECN",
    };

    if ((size_t)action < array_size(strs)) {
        return std::string(strs[(size_t)action]);
    }

    return std::string("Unknown wred action");
}

std::string
to_string(la_voq_set::state_e state)
{

    static const char* strs[] = {
            [(int)la_voq_set::state_e::ACTIVE] = "ACTIVE", [(int)la_voq_set::state_e::DROPPING] = "DROPPING",
    };

    if ((size_t)state < array_size(strs)) {
        return std::string(strs[(size_t)state]);
    }

    return std::string("Unknown la_voq_set::state_e");
}

std::string
to_string(la_meter_profile::type_e profile_type)
{

    static const char* strs[] = {
            [(int)la_meter_profile::type_e::GLOBAL] = "GLOBAL", [(int)la_meter_profile::type_e::PER_IFG] = "PER_IFG",

    };

    if ((size_t)profile_type < array_size(strs)) {
        return std::string(strs[(size_t)profile_type]);
    }

    return std::string("Unknown profile type");
}

std::string
to_string(la_meter_profile::meter_measure_mode_e meter_measure_mode)
{

    static const char* strs[] = {
            [(int)la_meter_profile::meter_measure_mode_e::BYTES] = "BYTES",
            [(int)la_meter_profile::meter_measure_mode_e::PACKETS] = "PACKETS",

    };

    if ((size_t)meter_measure_mode < array_size(strs)) {
        return std::string(strs[(size_t)meter_measure_mode]);
    }

    return std::string("Unknown meter measure mode");
}

std::string
to_string(la_meter_profile::meter_rate_mode_e meter_rate_mode)
{

    static const char* strs[] = {
            [(int)la_meter_profile::meter_rate_mode_e::SR_TCM] = "SR_TCM",
            [(int)la_meter_profile::meter_rate_mode_e::TR_TCM] = "TR_TCM",

    };

    if ((size_t)meter_rate_mode < array_size(strs)) {
        return std::string(strs[(size_t)meter_rate_mode]);
    }

    return std::string("Unknown meter rate mode");
}

std::string
to_string(la_meter_profile::color_awareness_mode_e color_awareness_mode)
{

    static const char* strs[] = {
            [(int)la_meter_profile::color_awareness_mode_e::BLIND] = "BLIND",
            [(int)la_meter_profile::color_awareness_mode_e::AWARE] = "AWARE",

    };

    if ((size_t)color_awareness_mode < array_size(strs)) {
        return std::string(strs[(size_t)color_awareness_mode]);
    }

    return std::string("Unknown meter color mode");
}

std::string
to_string(la_meter_profile::cascade_mode_e cascade_mode)
{
    static const char* strs[] = {
            [(int)la_meter_profile::cascade_mode_e::NOT_CASCADED] = "NOT_CASCADED",
            [(int)la_meter_profile::cascade_mode_e::CASCADED] = "CASCADED",

    };

    if ((size_t)cascade_mode < array_size(strs)) {
        return std::string(strs[(size_t)cascade_mode]);
    }

    return std::string("Unknown meter cascade mode");
}

std::string
to_string(la_filter_group::filtering_mode_e filter_mode)
{

    static const char* strs[] = {
            [(int)la_filter_group::filtering_mode_e::PERMIT] = "PERMIT", [(int)la_filter_group::filtering_mode_e::DENY] = "DENY",
    };

    if ((size_t)filter_mode < array_size(strs)) {
        return std::string(strs[(size_t)filter_mode]);
    }

    return std::string("Unknown filter mode");
}

std::string
to_string(la_mac_port::counter_e conter_type)
{

    static const char* strs[] = {
            [(int)la_mac_port::counter_e::PCS_TEST_ERROR] = "PCS_TEST_ERROR",
            [(int)la_mac_port::counter_e::PCS_BLOCK_ERROR] = "PCS_BLOCK_ERROR",
            [(int)la_mac_port::counter_e::PCS_BER] = "PCS_BER",
    };

    if ((size_t)conter_type < array_size(strs)) {
        return std::string(strs[(size_t)conter_type]);
    }

    return std::string("Unknown conter type");
}

std::string
to_string(la_oq_vsc_mapping_e oq_vsc_mapping)
{

    static const char* strs[] = {
            [(int)la_oq_vsc_mapping_e::RR0] = "RR0",
            [(int)la_oq_vsc_mapping_e::RR1] = "RR1",
            [(int)la_oq_vsc_mapping_e::RR2] = "RR2",
            [(int)la_oq_vsc_mapping_e::RR3] = "RR3",
            [(int)la_oq_vsc_mapping_e::RR0_RR2] = "RR0_RR2",
            [(int)la_oq_vsc_mapping_e::RR0_RR3] = "RR0_RR3",
            [(int)la_oq_vsc_mapping_e::RR1_RR2] = "RR1_RR2",
            [(int)la_oq_vsc_mapping_e::RR1_RR3] = "RR1_RR3",
            [(int)la_oq_vsc_mapping_e::RR4] = "RR4",
            [(int)la_oq_vsc_mapping_e::RR5] = "RR5",
            [(int)la_oq_vsc_mapping_e::RR6] = "RR6",
            [(int)la_oq_vsc_mapping_e::RR7] = "RR7",
    };

    if ((size_t)oq_vsc_mapping < array_size(strs)) {
        return std::string(strs[(size_t)oq_vsc_mapping]);
    }

    return std::string("Unknown oq vsc mapping");
}

std::string
to_string(la_mpls_tunnel_type_e mpls_tunnel_type)
{

    static const char* strs[] = {
            [(int)la_mpls_tunnel_type_e::PLAIN] = "PLAIN",
            [(int)la_mpls_tunnel_type_e::VRF_VPN] = "VRF_VPN",
            [(int)la_mpls_tunnel_type_e::PER_CE_VPN] = "PER_CE_VPN",
            [(int)la_mpls_tunnel_type_e::PWE] = "PWE",
    };

    if ((size_t)mpls_tunnel_type < array_size(strs)) {
        return std::string(strs[(size_t)mpls_tunnel_type]);
    }

    return std::string("Unknown mpls tunnel type");
}

std::string
to_string(const la_mpls_ttl_settings& ttl_settings)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "mode=" << get_value_string(ttl_settings.mode) << LOG_STRUCT_SEPARATOR
                << "ttl=" << ttl_settings.ttl << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_lp_mac_learning_mode_e mac_learning_mode)
{

    static const char* strs[] = {
            [(int)la_lp_mac_learning_mode_e::NONE] = "NONE",
            [(int)la_lp_mac_learning_mode_e::STANDALONE] = "STANDALONE",
            [(int)la_lp_mac_learning_mode_e::CPU] = "CPU",
    };

    if ((size_t)mac_learning_mode < array_size(strs)) {
        return std::string(strs[(size_t)mac_learning_mode]);
    }

    return std::string("Unknown mac learning mode");
}

std::string
to_string(la_l3_protocol_e l3_protocol)
{

    static const char* strs[] = {
            [(int)la_l3_protocol_e::IPV4_UC] = "IPV4_UC",
            [(int)la_l3_protocol_e::IPV6_UC] = "IPV6_UC",
            [(int)la_l3_protocol_e::MPLS] = "MPLS",
            [(int)la_l3_protocol_e::IPV4_MC] = "IPV4_MC",
            [(int)la_l3_protocol_e::IPV6_MC] = "IPV6_MC",
            [(int)la_l3_protocol_e::LAST] = "LAST",
    };

    if ((size_t)l3_protocol < array_size(strs)) {
        return std::string(strs[(size_t)l3_protocol]);
    }

    return std::string("Unknown l3 protocol");
}

std::string
to_string(la_ip_version_e ip_version)
{

    static const char* strs[] = {
            [(int)la_ip_version_e::IPV4] = "IPV4", [(int)la_ip_version_e::IPV6] = "IPV6",
    };

    if ((size_t)ip_version < array_size(strs)) {
        return std::string(strs[(size_t)ip_version]);
    }

    return std::string("Unknown vpn protocol");
}

std::string
to_string(la_rate_limiters_packet_type_e packet_type)
{

    static const char* strs[] = {
            [(int)la_rate_limiters_packet_type_e::BC] = "BC",
            [(int)la_rate_limiters_packet_type_e::UNKNOWN_MC] = "UNKNOWN_MC",
            [(int)la_rate_limiters_packet_type_e::UNKNOWN_UC] = "UNKNOWN_UC",
            [(int)la_rate_limiters_packet_type_e::MC] = "MC",
            [(int)la_rate_limiters_packet_type_e::UC] = "UC",
            [(int)la_rate_limiters_packet_type_e::LAST] = "LAST",
    };

    if ((size_t)packet_type < array_size(strs)) {
        return std::string(strs[(size_t)packet_type]);
    }

    return std::string("Unknown rate limiters packet type");
}

std::string
to_string(la_mac_port::port_speed_e port_speed)
{

    static const std::map<la_mac_port::port_speed_e, std::string> strs
        = {{la_mac_port::port_speed_e::E_MGIG, std::string("E_MGIG")},
           {la_mac_port::port_speed_e::E_10G, std::string("E_10G")},
           {la_mac_port::port_speed_e::E_20G, std::string("E_20G")},
           {la_mac_port::port_speed_e::E_25G, std::string("E_25G")},
           {la_mac_port::port_speed_e::E_40G, std::string("E_40G")},
           {la_mac_port::port_speed_e::E_50G, std::string("E_50G")},
           {la_mac_port::port_speed_e::E_100G, std::string("E_100G")},
           {la_mac_port::port_speed_e::E_200G, std::string("E_200G")},
           {la_mac_port::port_speed_e::E_400G, std::string("E_400G")},
           {la_mac_port::port_speed_e::E_800G, std::string("E_800G")}};

    if (strs.count(port_speed)) {
        return strs.at(port_speed);
    }

    return std::string("Unknown port speed");
}

std::string
to_string(la_mac_port::fec_mode_e fec_mode)
{

    static const char* strs[] = {
            [(int)la_mac_port::fec_mode_e::NONE] = "NONE",
            [(int)la_mac_port::fec_mode_e::KR] = "KR",
            [(int)la_mac_port::fec_mode_e::RS_KR4] = "RS_KR4",
            [(int)la_mac_port::fec_mode_e::RS_KP4] = "RS_KP4",
            [(int)la_mac_port::fec_mode_e::RS_KP4_FI] = "RS_KP4_FI",

    };

    if ((size_t)fec_mode < array_size(strs)) {
        return std::string(strs[(size_t)fec_mode]);
    }

    return std::string("Unknown fec mode");
}

std::string
to_string(la_mac_port::fec_bypass_e fec_bypass)
{
    const char* strs[] = {
            [(size_t)la_mac_port::fec_bypass_e::NONE] = "NONE",
            [(size_t)la_mac_port::fec_bypass_e::CORRECTION] = "CORRECTION",
            [(size_t)la_mac_port::fec_bypass_e::INDICATION] = "INDICATION",
            [(size_t)la_mac_port::fec_bypass_e::ALL] = "ALL",
    };
    static_assert(array_size(strs) == (size_t)la_mac_port::fec_bypass_e::ALL + 1, "bad size");
    if ((size_t)fec_bypass < array_size(strs)) {
        return strs[(size_t)fec_bypass];
    }
    return "Unknown fec_bypass";
}

std::string
to_string(la_mac_port::fc_mode_e fc_mode)
{

    static const char* strs[] = {
            [(int)la_mac_port::fc_mode_e::NONE] = "NONE",
            [(int)la_mac_port::fc_mode_e::PAUSE] = "PAUSE",
            [(int)la_mac_port::fc_mode_e::PFC] = "PFC",
            [(int)la_mac_port::fc_mode_e::CFFC] = "CFFC",

    };

    if ((size_t)fc_mode < array_size(strs)) {
        return std::string(strs[(size_t)fc_mode]);
    }

    return std::string("Unknown fc mode");
}

std::string
to_string(la_mac_port::fc_direction_e fc_dir)
{

    static const char* strs[] = {
            [(int)la_mac_port::fc_direction_e::RX] = "RX",
            [(int)la_mac_port::fc_direction_e::TX] = "TX",
            [(int)la_mac_port::fc_direction_e::BIDIR] = "BIDIR",
    };

    if ((size_t)fc_dir < array_size(strs)) {
        return std::string(strs[(size_t)fc_dir]);
    }

    return std::string("Unknown fc mode");
}

std::string
to_string(la_mac_port::tc_protocol_e protocol)
{
    static const char* strs[] = {
            [(int)la_mac_port::tc_protocol_e::ETHERNET] = "ETHERNET",
            [(int)la_mac_port::tc_protocol_e::IPV4] = "IPV4",
            [(int)la_mac_port::tc_protocol_e::IPV6] = "IPV6",
            [(int)la_mac_port::tc_protocol_e::MPLS] = "MPLS",

    };

    if ((size_t)protocol < array_size(strs)) {
        return std::string(strs[(size_t)protocol]);
    }

    return std::string("Unknown ostc protocol mode");
}

std::string
to_string(la_mac_port::serdes_param_stage_e stage)
{
    static const char* strs[] = {
            [(int)la_mac_port::serdes_param_stage_e::ACTIVATE] = "ACTIVATE",
            [(int)la_mac_port::serdes_param_stage_e::PRE_ICAL] = "PRE_ICAL",
            [(int)la_mac_port::serdes_param_stage_e::PRE_PCAL] = "PRE_PCAL",
    };

    if ((size_t)stage < array_size(strs)) {
        return std::string(strs[(size_t)stage]);
    }

    return std::string("Unknown SerDes parameter stage");
}

std::string
to_string(la_mac_port::serdes_param_e param)
{
    static const char* strs[] = {
            [(int)la_mac_port::serdes_param_e::DATAPATH_RX_GRAY_MAP] = "DATAPATH_RX_GRAY_MAP",
            [(int)la_mac_port::serdes_param_e::DATAPATH_RX_PRECODE] = "DATAPATH_RX_PRECODE",
            [(int)la_mac_port::serdes_param_e::DATAPATH_RX_SWIZZLE] = "DATAPATH_RX_SWIZZLE",
            [(int)la_mac_port::serdes_param_e::DATAPATH_TX_GRAY_MAP] = "DATAPATH_TX_GRAY_MAP",
            [(int)la_mac_port::serdes_param_e::DATAPATH_TX_PRECODE] = "DATAPATH_TX_PRECODE",
            [(int)la_mac_port::serdes_param_e::DATAPATH_TX_SWIZZLE] = "DATAPATH_TX_SWIZZLE",
            [(int)la_mac_port::serdes_param_e::DIVIDER] = "DIVIDER",
            [(int)la_mac_port::serdes_param_e::ELECTRICAL_IDLE_THRESHOLD] = "ELECTRICAL_IDLE_THRESHOLD",
            [(int)la_mac_port::serdes_param_e::HYSTERESIS_POST1_NEGATIVE] = "HYSTERESIS_POST1_NEGATIVE",
            [(int)la_mac_port::serdes_param_e::HYSTERESIS_POST1_POSETIVE] = "HYSTERESIS_POST1_POSETIVE",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE1] = "RX_CTLE_GAINSHAPE1",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE2] = "RX_CTLE_GAINSHAPE2",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_HF] = "RX_CTLE_HF",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_HF_MAX] = "RX_CTLE_HF_MAX",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_HF_MIN] = "RX_CTLE_HF_MIN",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_LF] = "RX_CTLE_LF",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_LF_MAX] = "RX_CTLE_LF_MAX",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_LF_MIN] = "RX_CTLE_LF_MIN",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_SHORT_CHANNEL_EN] = "RX_CTLE_SHORT_CHANNEL_EN",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_DC] = "RX_CTLE_DC",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_BW] = "RX_CTLE_BW",
            [(int)la_mac_port::serdes_param_e::RX_FFE_BFHF] = "RX_FFE_BFHF",
            [(int)la_mac_port::serdes_param_e::RX_FFE_BFLF] = "RX_FFE_BFLF",
            [(int)la_mac_port::serdes_param_e::RX_FFE_POST] = "RX_FFE_POST",
            [(int)la_mac_port::serdes_param_e::RX_FFE_PRE1] = "RX_FFE_PRE1",
            [(int)la_mac_port::serdes_param_e::RX_FFE_PRE2] = "RX_FFE_PRE2",
            [(int)la_mac_port::serdes_param_e::RX_FFE_PRE1_MAX] = "RX_FFE_PRE1_MAX",
            [(int)la_mac_port::serdes_param_e::RX_FFE_PRE1_MIN] = "RX_FFE_PRE1_MIN",
            [(int)la_mac_port::serdes_param_e::RX_FFE_PRE2_MAX] = "RX_FFE_PRE2_MAX",
            [(int)la_mac_port::serdes_param_e::RX_FFE_PRE2_MIN] = "RX_FFE_PRE2_MIN",
            [(int)la_mac_port::serdes_param_e::RX_FFE_SHORT_CHANNEL_EN] = "RX_FFE_SHORT_CHANNEL_EN",
            [(int)la_mac_port::serdes_param_e::RX_PCAL_EFFORT] = "RX_PCAL_EFFORT",
            [(int)la_mac_port::serdes_param_e::RX_PLL_BB] = "RX_PLL_BB",
            [(int)la_mac_port::serdes_param_e::RX_PLL_IFLT] = "RX_PLL_IFLT",
            [(int)la_mac_port::serdes_param_e::RX_PLL_INT] = "RX_PLL_INT",
            [(int)la_mac_port::serdes_param_e::RX_NRZ_EYE_THRESHOLD] = "RX_NRZ_EYE_THRESHOLD",
            [(int)la_mac_port::serdes_param_e::RX_TERM] = "RX_TERM",
            [(int)la_mac_port::serdes_param_e::TX_ATTN] = "TX_ATTN",
            [(int)la_mac_port::serdes_param_e::TX_ATTN_COLD_SIG_ENVELOPE] = "TX_ATTN_COLD_SIG_ENVELOPE",
            [(int)la_mac_port::serdes_param_e::TX_ATTN_HOT_SIG_ENVELOPE] = "TX_ATTN_HOT_SIG_ENVELOPE",
            [(int)la_mac_port::serdes_param_e::TX_PLL_BB] = "TX_PLL_BB",
            [(int)la_mac_port::serdes_param_e::TX_PLL_IFLT] = "TX_PLL_IFLT",
            [(int)la_mac_port::serdes_param_e::TX_PLL_INT] = "TX_PLL_INT",
            [(int)la_mac_port::serdes_param_e::TX_POST] = "TX_POST",
            [(int)la_mac_port::serdes_param_e::TX_POST2] = "TX_POST2",
            [(int)la_mac_port::serdes_param_e::TX_POST3] = "TX_POST3",
            [(int)la_mac_port::serdes_param_e::TX_PRE1] = "TX_PRE1",
            [(int)la_mac_port::serdes_param_e::TX_PRE2] = "TX_PRE2",
            [(int)la_mac_port::serdes_param_e::TX_PRE3] = "TX_PRE3",
            [(int)la_mac_port::serdes_param_e::RX_FAST_TUNE] = "RX_FAST_TUNE",
            [(int)la_mac_port::serdes_param_e::RX_CLK_REFSEL] = "RX_CLK_REFSEL",
            [(int)la_mac_port::serdes_param_e::TX_CLK_REFSEL] = "TX_CLK_REFSEL",
            [(int)la_mac_port::serdes_param_e::RX_AC_COUPLING_BYPASS] = "RX_AC_COUPLING_BYPASS",
            [(int)la_mac_port::serdes_param_e::RX_AFE_TRIM] = "RX_AFE_TRIM",
            [(int)la_mac_port::serdes_param_e::RX_CTLE_CODE] = "RX_CTLE_CODE",
            [(int)la_mac_port::serdes_param_e::RX_DSP_MODE] = "RX_DSP_MODE",
            [(int)la_mac_port::serdes_param_e::RX_VGA_TRACKING] = "RX_VGA_TRACKING",
            [(int)la_mac_port::serdes_param_e::CTLE_TUNE] = "CTLE_TUNE",
            [(int)la_mac_port::serdes_param_e::AUTO_RX_PRECODE_THRESHOLD] = "AUTO_RX_PRECODE_THRESHOLD",
            [(int)la_mac_port::serdes_param_e::TX_INNER_EYE1] = "TX_INNER_EYE1",
            [(int)la_mac_port::serdes_param_e::TX_INNER_EYE2] = "TX_INNER_EYE2",
            [(int)la_mac_port::serdes_param_e::TX_LUT_MODE] = "TX_LUT_MODE",
            [(int)la_mac_port::serdes_param_e::TX_MAIN] = "TX_MAIN",
            [(int)la_mac_port::serdes_param_e::DTL_KP_KF] = "DTL_KP_KF",
    };

    if ((size_t)param < array_size(strs)) {
        return std::string(strs[(size_t)param]);
    }

    return std::string("Unknown SerDes parameter");
}

std::string
to_string(la_mac_port::serdes_param_mode_e mode)
{
    static const char* strs[] = {
            [(int)la_mac_port::serdes_param_mode_e::ADAPTIVE] = "ADAPTIVE",
            [(int)la_mac_port::serdes_param_mode_e::FIXED] = "FIXED",
            [(int)la_mac_port::serdes_param_mode_e::STATIC] = "STATIC",
    };

    if ((size_t)mode < array_size(strs)) {
        return std::string(strs[(size_t)mode]);
    }

    return std::string("Unknown SerDes parameter mode");
}

std::string
to_string(la_mac_port::state_e state)
{
    static const char* strs[] = {
            [(int)la_mac_port::state_e::PRE_INIT] = "PRE_INIT",
            [(int)la_mac_port::state_e::INACTIVE] = "INACTIVE",
            [(int)la_mac_port::state_e::PCAL_STOP] = "PCAL_STOP",
            [(int)la_mac_port::state_e::AN_BASE_PAGE] = "AN_BASE_PAGE",
            [(int)la_mac_port::state_e::AN_NEXT_PAGE] = "AN_NEXT_PAGE",
            [(int)la_mac_port::state_e::AN_POLL] = "AN_POLL",
            [(int)la_mac_port::state_e::LINK_TRAINING] = "LINK_TRAINING",
            [(int)la_mac_port::state_e::AN_COMPLETE] = "AN_COMPLETE",
            [(int)la_mac_port::state_e::ACTIVE] = "ACTIVE",
            [(int)la_mac_port::state_e::WAITING_FOR_PEER] = "WAITING_FOR_PEER",
            [(int)la_mac_port::state_e::TUNING] = "TUNING",
            [(int)la_mac_port::state_e::TUNED] = "TUNED",
            [(int)la_mac_port::state_e::PCS_LOCK] = "PCS_LOCK",
            [(int)la_mac_port::state_e::PCS_STABLE] = "PCS_STABLE",
            [(int)la_mac_port::state_e::LINK_UP] = "LINK_UP",
    };

    if ((size_t)state < array_size(strs)) {
        return strs[(size_t)state];
    }

    return "Unknown state";
}

std::string
to_string(la_layer_e layer)
{
    static const char* strs[] = {
            [(int)la_layer_e::L2] = "L2", [(int)la_layer_e::L3] = "L3",
    };

    if ((size_t)layer < array_size(strs)) {
        return std::string(strs[(size_t)layer]);
    }

    return std::string("Unknown layer");
}

std::string
to_string(la_event_e event)
{
    size_t index = (size_t)event;

    if (index >= array_size(la_event_names)) {
        return std::to_string(event);
    }

    return la_event_names[index];
}

std::string
to_string(la_l3_port::urpf_mode_e urpf_mode)
{

    static const char* strs[] = {
            [(int)la_l3_port::urpf_mode_e::NONE] = "NONE",
            [(int)la_l3_port::urpf_mode_e::STRICT] = "STRICT",
            [(int)la_l3_port::urpf_mode_e::LOOSE] = "LOOSE",

    };

    if ((size_t)urpf_mode < array_size(strs)) {
        return std::string(strs[(size_t)urpf_mode]);
    }

    return std::string("Unknown urpf mode");
}

std::string
to_string(limit_type_e limit_type)
{

    static const char* strs[] = {
            [(int)limit_type_e::DEVICE__NUM_CGM_HBM_POOLS] = "DEVICE__NUM_CGM_HBM_POOLS",
            [(int)limit_type_e::DEVICE__MAX_SMS_BYTES_QUANTIZATION_THRESHOLD] = "DEVICE__MAX_SMS_BYTES_QUANTIZATION_THRESHOLD",
            [(int)limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS] = "DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS",
            [(int)limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "DEVICE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::DEVICE__MAX_SMS_PACKETS_QUANTIZATION_THRESHOLD] = "DEVICE__MAX_SMS_PACKETS_QUANTIZATION_THRESHOLD",
            [(int)limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS] = "DEVICE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS",
            [(int)limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "DEVICE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::DEVICE__MAX_SMS_NUM_EVICTED_BUFF_QUANTIZATION_THRESHOLD]
            = "DEVICE__MAX_SMS_NUM_EVICTED_BUFF_QUANTIZATION_THRESHOLD",
            [(int)limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS]
            = "DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS",
            [(int)limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "DEVICE__MAX_SMS_NUM_EVICTED_BUFF_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::DEVICE__MAX_HBM_NUM_OF_VOQS_QUANTIZATION_THRESHOLD]
            = "DEVICE__MAX_HBM_NUM_OF_VOQS_QUANTIZATION_THRESHOLD",
            [(int)limit_type_e::DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_REGIONS] = "DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_REGIONS",
            [(int)limit_type_e::DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::DEVICE__MAX_HBM_POOL_BYTES_QUANTIZATION_THRESHOLD]
            = "DEVICE__MAX_HBM_POOL_BYTES_QUANTIZATION_THRESHOLD",
            [(int)limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS]
            = "DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS",
            [(int)limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::DEVICE__MAX_HBM_BLOCKS_BY_VOQ_QUANTIZATION_THRESHOLD]
            = "DEVICE__MAX_HBM_BLOCKS_BY_VOQ_QUANTIZATION_THRESHOLD",
            [(int)limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS]
            = "DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS",
            [(int)limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::DEVICE__MAX_HBM_VOQ_AGE_QUANTIZATION_THRESHOLD] = "DEVICE__MAX_HBM_VOQ_AGE_QUANTIZATION_THRESHOLD",
            [(int)limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_REGIONS] = "DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_REGIONS",
            [(int)limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::DEVICE__NUM_LOCAL_VOQS] = "DEVICE__NUM_LOCAL_VOQS",
            [(int)limit_type_e::DEVICE__NUM_SYSTEM_VOQS] = "DEVICE__NUM_SYSTEM_VOQS",
            [(int)limit_type_e::DEVICE__NUM_TC_PROFILES] = "DEVICE__NUM_TC_PROFILES",
            [(int)limit_type_e::DEVICE__FIRST_ALLOCATABLE_VOQ] = "DEVICE__FIRST_ALLOCATABLE_VOQ",
            [(int)limit_type_e::DEVICE__MIN_ALLOCATABLE_VSC] = "DEVICE__MIN_ALLOCATABLE_VSC",
            [(int)limit_type_e::DEVICE__MAX_ALLOCATABLE_VSC] = "DEVICE__MAX_ALLOCATABLE_VSC",
            [(int)limit_type_e::DEVICE__MAX_PREFIX_OBJECT_GIDS] = "DEVICE__MAX_PREFIX_OBJECT_GIDS",
            [(int)limit_type_e::DEVICE__MAX_SR_EXTENDED_POLICIES] = "DEVICE__MAX_SR_EXTENDED_POLICIES",
            [(int)limit_type_e::DEVICE__MAX_OIDS] = "DEVICE__MAX_OIDS",
            [(int)limit_type_e::DEVICE__MAX_ERSPAN_SESSION_ID] = "DEVICE__MAX_ERSPAN_SESSION_ID",
            [(int)limit_type_e::DEVICE__MAX_L3_PROTECTION_GROUP_GIDS] = "DEVICE__MAX_L3_PROTECTION_GROUP_GIDS",
            [(int)limit_type_e::DEVICE__MIN_SYSTEM_PORT_GID] = "DEVICE__MIN_SYSTEM_PORT_GID",
            [(int)limit_type_e::DEVICE__MAX_SYSTEM_PORT_GID] = "DEVICE__MAX_SYSTEM_PORT_GID",
            [(int)limit_type_e::DEVICE__MAX_L2_AC_PORT_GID] = "DEVICE__MAX_L2_AC_PORT_GID",
            [(int)limit_type_e::DEVICE__NUM_ACL_TCAM_POOLS] = "DEVICE__NUM_ACL_TCAM_POOLS",
            [(int)limit_type_e::COUNTER_SET__MAX_PQ_COUNTER_OFFSET] = "COUNTER_SET__MAX_PQ_COUNTER_OFFSET",
            [(int)limit_type_e::COUNTER_SET__MAX_PIF_COUNTER_OFFSET] = "COUNTER_SET__MAX_PIF_COUNTER_OFFSET",

            [(int)limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS]
            = "VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS]
            = "VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS]
            = "VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS]
            = "VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS] = "VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_DROP_PROBABILITY_LEVELS]
            = "VOQ_CGM_PROFILE__SMS_NUM_BYTES_DROP_PROBABILITY_LEVELS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_MARK_PROBABILITY_LEVELS]
            = "VOQ_CGM_PROFILE__SMS_NUM_BYTES_MARK_PROBABILITY_LEVELS",

            [(int)limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS]
            = "VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS",

            [(int)limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_BYTES] = "VOQ_CGM_PROFILE__MAX_VOQ_SMS_BYTES",
            [(int)limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_PACKETS] = "VOQ_CGM_PROFILE__MAX_VOQ_SMS_PACKETS",
            [(int)limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_AGE] = "VOQ_CGM_PROFILE__MAX_VOQ_SMS_AGE",
            [(int)limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_HBM_SIZE] = "VOQ_CGM_PROFILE__MAX_VOQ_HBM_SIZE",
            [(int)limit_type_e::ROUTE__MAX_CLASS_IDENTIFIER] = "ROUTE__MAX_CLASS_IDENTIFIER",
            [(int)limit_type_e::HOST__MAX_CLASS_IDENTIFIER] = "HOST__MAX_CLASS_IDENTIFIER",
            [(int)limit_type_e::METER_PROFILE__MAX_BURST_SIZE] = "METER_PROFILE__MAX_BURST_SIZE",
            [(int)limit_type_e::METER_PROFILE__MAX_PPS_BURST_SIZE] = "METER_PROFILE__MAX_PPS_BURST_SIZE",
    };
    if ((size_t)limit_type < array_size(strs)) {
        return std::string(strs[(size_t)limit_type]);
    }

    return std::string("Unknown limit type");
}
std::string
to_string(la_precision_type_e precision_type)
{

    static const char* strs[] = {
            [(int)la_precision_type_e::VOQ_CGM_PROBABILITY_PRECISION] = "VOQ_CGM_PROBABILITY_PRECISION",
    };
    if ((size_t)precision_type < array_size(strs)) {
        return std::string(strs[(size_t)precision_type]);
    }

    return std::string("Unknown precision type");
}

std::string
to_string(const la_l3_destination_vec_t& vec)
{
    return vec_to_string(vec);
}

std::string
to_string(lpts_type_e type)
{

    static const char* strs[] = {
            [(int)lpts_type_e::LPTS_TYPE_IPV4] = "LPTS_TYPE_IPV4",
            [(int)lpts_type_e::LPTS_TYPE_IPV6] = "LPTS_TYPE_IPV6",
            [(int)lpts_type_e::LAST] = "LAST",
    };

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown lpts type");
}

std::string
to_string(la_control_plane_classifier::type_e type)
{

    static const char* strs[] = {
            [(int)la_control_plane_classifier::type_e::IPV4] = "COPC_TYPE_IPV4",
            [(int)la_control_plane_classifier::type_e::IPV6] = "COPC_TYPE_IPV6",
            [(int)la_control_plane_classifier::type_e::MAC] = "COPC_TYPE_MAC",
            [(int)la_control_plane_classifier::type_e::LAST] = "LAST",
    };

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown copc type");
}

std::string
to_string(const la_device_id_vec_t& vec)
{
    return vec_to_string(vec);
}

std::string
to_string(la_device_property_e device_property)
{
    static const char* strs[] = {
            [(int)la_device_property_e::LC_56_FABRIC_PORT_MODE] = "LC_56_FABRIC_PORT_MODE",
            [(int)la_device_property_e::LC_FORCE_FORWARD_THROUGH_FABRIC_MODE] = "LC_FORCE_FORWARD_THROUGH_FABRIC_MODE",
            [(int)la_device_property_e::LC_ADVERTISE_DEVICE_ON_FABRIC_MODE] = "LC_ADVERTISE_DEVICE_ON_FABRIC_MODE",
            [(int)la_device_property_e::LC_TYPE_2_4_T] = "LC_TYPE_2_4_T",
            [(int)la_device_property_e::USING_LEABA_NIC] = "USING_LEABA_NIC",
            [(int)la_device_property_e::ENABLE_NSIM_ACCURATE_SCALE_MODEL] = "ENABLE_NSIM_ACCURATE_SCALE_MODEL",
            [(int)la_device_property_e::ENABLE_HBM] = "ENABLE_HBM",
            [(int)la_device_property_e::TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST] = "TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST",
            [(int)la_device_property_e::TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES]
            = "TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES",
            [(int)la_device_property_e::PROCESS_INTERRUPTS] = "PROCESS_INTERRUPTS",
            [(int)la_device_property_e::POLL_MSI] = "POLL_MSI",
            [(int)la_device_property_e::RTL_SIMULATION_WORKAROUNDS] = "RTL_SIMULATION_WORKAROUNDS",
            [(int)la_device_property_e::EMULATED_DEVICE] = "EMULATED_DEVICE",
            [(int)la_device_property_e::GB_INITIALIZE_CONFIG_MEMORIES] = "GB_INITIALIZE_CONFIG_MEMORIES",
            [(int)la_device_property_e::GB_INITIALIZE_OTHER] = "GB_INITIALIZE_OTHER",
            [(int)la_device_property_e::GB_A1_DISABLE_FIXES] = "GB_A1_DISABLE_FIXES",
            [(int)la_device_property_e::GB_A2_DISABLE_FIXES] = "GB_A2_DISABLE_FIXES",
            [(int)la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION] = "ENABLE_HBM_ROUTE_EXTENSION",
            [(int)la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE] = "ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE",
            [(int)la_device_property_e::ENABLE_LPM_IP_CACHE] = "ENABLE_LPM_IP_CACHE",
            [(int)la_device_property_e::DISABLE_ELECTRICAL_IDLE_DETECTION] = "DISABLE_ELECTRICAL_IDLE_DETECTION",
            [(int)la_device_property_e::ENABLE_MBIST_REPAIR] = "ENABLE_MBIST_REPAIR",
            [(int)la_device_property_e::IGNORE_MBIST_ERRORS] = "IGNORE_MBIST_ERRORS",
            [(int)la_device_property_e::ENABLE_NARROW_COUNTERS] = "ENABLE_NARROW_COUNTERS",
            [(int)la_device_property_e::ENABLE_MPLS_SR_ACCOUNTING] = "ENABLE_MPLS_SR_ACCOUNTING",
            [(int)la_device_property_e::ENABLE_PBTS] = "ENABLE_PBTS",
            [(int)la_device_property_e::ENABLE_CLASS_ID_ACLS] = "ENABLE_CLASS_ID_ACLS",
            [(int)la_device_property_e::ENABLE_PACIFIC_B0_IFG_CHANGES] = "ENABLE_PACIFIC_B0_IFG_CHANGES",
            [(int)la_device_property_e::ENABLE_PACIFIC_OOB_INTERLEAVING] = "ENABLE_PACIFIC_OOB_INTERLEAVING",
            [(int)la_device_property_e::INSTANTIATE_REMOTE_SYSTEM_PORTS] = "INSTANTIATE_REMOTE_SYSTEM_PORTS",
            [(int)la_device_property_e::HBM_MOVE_TO_READ_ON_EMPTY] = "HBM_MOVE_TO_READ_ON_EMPTY",
            [(int)la_device_property_e::HBM_MOVE_TO_WRITE_ON_EMPTY] = "HBM_MOVE_TO_WRITE_ON_EMPTY",
            [(int)la_device_property_e::ENABLE_SERDES_NRZ_FAST_TUNE] = "ENABLE_SERDES_NRZ_FAST_TUNE",
            [(int)la_device_property_e::ENABLE_NETWORK_SERDES_PAM4_FAST_TUNE] = "ENABLE_NETWORK_SERDES_PAM4_FAST_TUNE",
            [(int)la_device_property_e::ENABLE_FABRIC_SERDES_PAM4_FAST_TUNE] = "ENABLE_FABRIC_SERDES_PAM4_FAST_TUNE",
            [(int)la_device_property_e::ENABLE_FABRIC_FEC_RS_KP4] = "ENABLE_FABRIC_FEC_RS_KP4",
            [(int)la_device_property_e::DISABLE_SERDES_POST_ANLT_TUNE] = "DISABLE_SERDES_POST_ANLT_TUNE",
            [(int)la_device_property_e::ENABLE_SERDES_PRE_ICAL_PRIOR_ANLT] = "ENABLE_SERDES_PRE_ICAL_PRIOR_ANLT",
            [(int)la_device_property_e::SERDES_DFE_EID] = "SERDES_DFE_EID",
            [(int)la_device_property_e::ENABLE_SERDES_TX_SLIP] = "ENABLE_SERDES_TX_SLIP",
            [(int)la_device_property_e::ENABLE_SERDES_TX_REFRESH] = "ENABLE_SERDES_TX_REFRESH",
            [(int)la_device_property_e::MAC_PORT_IGNORE_LONG_TUNE] = "MAC_PORT_IGNORE_LONG_TUNE",
            [(int)la_device_property_e::MAC_PORT_ENABLE_25G_DFETAP_CHECK] = "MAC_PORT_ENABLE_25G_DFETAP_CHECK",
            [(int)la_device_property_e::MAC_PORT_ENABLE_SER_CHECK] = "MAC_PORT_ENABLE_SER_CHECK",
            [(int)la_device_property_e::ENABLE_MAC_PORT_DEGRADED_SER_NOTIFICATIONS] = "ENABLE_MAC_PORT_DEGRADED_SER_NOTIFICATIONS",
            [(int)la_device_property_e::ENABLE_SERDES_LOW_POWER] = "ENABLE_SERDES_LOW_POWER",
            [(int)la_device_property_e::RECONNECT_IGNORE_IN_FLIGHT] = "RECONNECT_IGNORE_IN_FLIGHT",
            [(int)la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS] = "ENABLE_FE_PER_DEVICE_MIN_LINKS",
            [(int)la_device_property_e::IGNORE_SBUS_MASTER_MBIST_FAILURE] = "IGNORE_SBUS_MASTER_MBIST_FAILURE",
            [(int)la_device_property_e::ENABLE_SENSOR_POLL] = "ENABLE_SENSOR_POLL",
            [(int)la_device_property_e::ENABLE_PACIFIC_SW_BASED_PFC] = "ENABLE_PACIFIC_SW_BASED_PFC",
            [(int)la_device_property_e::ENABLE_PFC_DEVICE_TUNING] = "ENABLE_PFC_DEVICE_TUNING",
            [(int)la_device_property_e::PACIFIC_PFC_HBM_ENABLED] = "PACIFIC_PFC_HBM_ENABLED",
            [(int)la_device_property_e::SLEEP_IN_SET_MAX_BURST] = "SLEEP_IN_SET_MAX_BURST",
            [(int)la_device_property_e::STATISTICAL_METER_COUNTING] = "SLEEP_IN_SET_MAX_BURST",
            [(int)la_device_property_e::ENABLE_ECN_QUEUING] = "ENABLE_ECN_QUEUING",
            [(int)la_device_property_e::ENABLE_SERDES_LDO_VOLTAGE_REGULATOR] = "ENABLE_SERDES_LDO_VOLTAGE_REGULATOR",
            [(int)la_device_property_e::ENABLE_SRM_OVERRIDE_PLL_KP_KF] = "ENABLE_SRM_OVERRIDE_PLL_KP_KF",
            [(int)la_device_property_e::IGNORE_COMPONENT_INIT_FAILURES] = "IGNORE_COMPONENT_INIT_FAILURES",
            [(int)la_device_property_e::ENABLE_SVL_MODE] = "ENABLE_SVL_MODE",
            [(int)la_device_property_e::DESTINATION_SYSTEM_PORT_IN_IBM_METADATA] = "DESTINATION_SYSTEM_PORT_IN_IBM_METADATA",
            [(int)la_device_property_e::ENABLE_POWER_SAVING_MODE] = "ENABLE_POWER_SAVING_MODE",
            [(int)la_device_property_e::ENABLE_INFO_PHY] = "ENABLE_INFO_PHY",
            [(int)la_device_property_e::FORCE_DISABLE_HBM] = "FORCE_DISABLE_HBM",
            [(int)la_device_property_e::HBM_SKIP_TRAINING] = "HBM_SKIP_TRAINING",
            [(int)la_device_property_e::ENABLE_DUMMY_SERDES_HANDLER] = "ENABLE_DUMMY_SERDES_HANDLER",
            [(int)la_device_property_e::ENABLE_BOOT_OPTIMIZATION] = "ENABLE_BOOT_OPTIMIZATION",
            [(int)la_device_property_e::HBM_FREQUENCY] = "HBM_FREQUENCY",
            [(int)la_device_property_e::STATISTICAL_METER_MULTIPLIER] = "STATISTICAL_METER_MULTIPLIER",
            [(int)la_device_property_e::POLL_INTERVAL_MILLISECONDS] = "POLL_INTERVAL_MILLISECONDS",
            [(int)la_device_property_e::POLL_FAST_INTERVAL_MILLISECONDS] = "POLL_FAST_INTERVAL_MILLISECONDS",
            [(int)la_device_property_e::RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS]
            = "RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS",
            [(int)la_device_property_e::POLL_NON_WIRED_INTERRUPTS_INTERVAL_MILLISECONDS]
            = "POLL_NON_WIRED_INTERRUPTS_INTERVAL_MILLISECONDS",
            [(int)la_device_property_e::MSI_DAMPENING_INTERVAL_MILLISECONDS] = "MSI_DAMPENING_INTERVAL_MILLISECONDS",
            [(int)la_device_property_e::MSI_DAMPENING_THRESHOLD] = "MSI_DAMPENING_THRESHOLD",
            [(int)la_device_property_e::SENSOR_POLL_INTERVAL_MILLISECONDS] = "SENSOR_POLL_INTERVAL_MILLISECONDS",
            [(int)la_device_property_e::TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS]
            = "TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS",
            [(int)la_device_property_e::MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY] = "MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY",
            [(int)la_device_property_e::SERDES_FW_REVISION] = "SERDES_FW_REVISION",
            [(int)la_device_property_e::SERDES_FW_BUILD] = "SERDES_FW_BUILD",
            [(int)la_device_property_e::SBUS_MASTER_FW_REVISION] = "SBUS_MASTER_FW_REVISION",
            [(int)la_device_property_e::SBUS_MASTER_FW_BUILD] = "SBUS_MASTER_FW_BUILD",
            [(int)la_device_property_e::MAC_PORT_TUNE_TIMEOUT] = "MAC_PORT_TUNE_TIMEOUT",
            [(int)la_device_property_e::MAC_PORT_PAM4_MAX_TUNE_RETRY] = "MAC_PORT_PAM4_MAX_TUNE_RETRY",
            [(int)la_device_property_e::MAC_PORT_PAM4_MIN_EYE_HEIGHT] = "MAC_PORT_PAM4_MIN_EYE_HEIGHT",
            [(int)la_device_property_e::MAC_PORT_NRZ_MIN_EYE_HEIGHT] = "MAC_PORT_NRZ_MIN_EYE_HEIGHT",
            [(int)la_device_property_e::MAC_PORT_10G_NRZ_MIN_EYE_HEIGHT] = "MAC_PORT_10G_NRZ_MIN_EYE_HEIGHT",
            [(int)la_device_property_e::MAC_PORT_CDR_LOCK_AFTER_TUNE_TIMEOUT] = "MAC_PORT_CDR_LOCK_AFTER_TUNE_TIMEOUT",
            [(int)la_device_property_e::MAC_PORT_PCS_LOCK_TIME] = "MAC_PORT_PCS_LOCK_TIME",
            [(int)la_device_property_e::MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS] = "MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS",
            [(int)la_device_property_e::MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES]
            = "MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES",
            [(int)la_device_property_e::NETWORK_MAC_PORT_TUNE_AND_PCS_LOCK_ITER] = "NETWORK_MAC_PORT_TUNE_AND_PCS_LOCK_ITER",
            [(int)la_device_property_e::FABRIC_MAC_PORT_TUNE_AND_PCS_LOCK_ITER] = "FABRIC_MAC_PORT_TUNE_AND_PCS_LOCK_ITER",
            [(int)la_device_property_e::MAC_PORT_AUTO_NEGOTIATION_TIMEOUT] = "MAC_PORT_AUTO_NEGOTIATION_TIMEOUT",
            [(int)la_device_property_e::MAC_PORT_LINK_TRAINING_TIMEOUT] = "MAC_PORT_LINK_TRAINING_TIMEOUT",
            [(int)la_device_property_e::MAC_PORT_NRZ_LINK_TRAINING_TIMEOUT] = "MAC_PORT_NRZ_LINK_TRAINING_TIMEOUT",
            [(int)la_device_property_e::MAC_PORT_PAM4_LINK_TRAINING_TIMEOUT] = "MAC_PORT_PAM4_LINK_TRAINING_TIMEOUT",
            [(int)la_device_property_e::SERDES_RXA_POWER_SEQUENCE_MODE] = "SERDES_RXA_POWER_SEQUENCE_MODE",
            [(int)la_device_property_e::SERDES_CL136_PRESET_TYPE] = "SERDES_CL136_PRESET_TYPE",
            [(int)la_device_property_e::LPM_REBALANCE_INTERVAL] = "LPM_REBALANCE_INTERVAL",
            [(int)la_device_property_e::LPM_REBALANCE_START_FAIRNESS_THRESHOLD_PERCENT]
            = "LPM_REBALANCE_START_FAIRNESS_THRESHOLD_PERCENT",
            [(int)la_device_property_e::LPM_REBALANCE_END_FAIRNESS_THRESHOLD_PERCENT]
            = "LPM_REBALANCE_END_FAIRNESS_THRESHOLD_PERCENT",
            [(int)la_device_property_e::LPM_TCAM_SINGLE_WIDTH_KEY_WEIGHT] = "LPM_TCAM_SINGLE_WIDTH_KEY_WEIGHT",
            [(int)la_device_property_e::LPM_TCAM_DOUBLE_WIDTH_KEY_WEIGHT] = "LPM_TCAM_DOUBLE_WIDTH_KEY_WEIGHT",
            [(int)la_device_property_e::LPM_TCAM_QUAD_WIDTH_KEY_WEIGHT] = "LPM_TCAM_QUAD_WIDTH_KEY_WEIGHT",
            [(int)la_device_property_e::LPM_L2_MAX_SRAM_BUCKETS] = "LPM_L2_MAX_SRAM_BUCKETS",
            [(int)la_device_property_e::LPM_TCAM_NUM_BANKSETS] = "LPM_TCAM_NUM_BANKSETS",
            [(int)la_device_property_e::LPM_TCAM_BANK_SIZE] = "LPM_TCAM_BANK_SIZE",
            [(int)la_device_property_e::DEVICE_FREQUENCY] = "DEVICE_FREQUENCY",
            [(int)la_device_property_e::TCK_FREQUENCY] = "TCK_FREQUENCY",
            [(int)la_device_property_e::RESET_INTERRUPT_COUNTERS_INTERVAL_SECONDS] = "INTERRUPT_THRESHOLD_PERIOD_SECONDS",
            [(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_1B] = "INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_1B",
            [(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_2B] = "INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_2B",
            [(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_PARITY] = "INTERRUPT_THRESHOLD_MEM_CONFIG_PARITY",
            [(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_1B] = "INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_1B",
            [(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_2B] = "INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_2B",
            [(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_PARITY] = "INTERRUPT_THRESHOLD_MEM_VOLATILE_PARITY",
            [(int)la_device_property_e::INTERRUPT_THRESHOLD_LPM_SRAM_ECC_1B] = "INTERRUPT_THRESHOLD_LPM_SRAM_ECC_1B",
            [(int)la_device_property_e::INTERRUPT_THRESHOLD_LPM_SRAM_ECC_2B] = "INTERRUPT_THRESHOLD_LPM_SRAM_ECC_2B",
            [(int)la_device_property_e::MAX_COUNTER_THRESHOLD] = "MAX_COUNTER_THRESHOLD",
            [(int)la_device_property_e::AAPL_IFG_DELAY_BEFORE_EXEC] = "AAPL_IFG_DELAY_BEFORE_EXEC",
            [(int)la_device_property_e::AAPL_HBM_DELAY_BEFORE_EXEC] = "AAPL_HBM_DELAY_BEFORE_EXEC",
            [(int)la_device_property_e::AAPL_IFG_DELAY_BEFORE_POLL] = "AAPL_IFG_DELAY_BEFORE_POLL",
            [(int)la_device_property_e::AAPL_HBM_DELAY_BEFORE_POLL] = "AAPL_HBM_DELAY_BEFORE_POLL",
            [(int)la_device_property_e::AAPL_IFG_DELAY_IN_POLL] = "AAPL_IFG_DELAY_IN_POLL",
            [(int)la_device_property_e::AAPL_IFG_POLL_TIMEOUT] = "AAPL_IFG_POLL_TIMEOUT",
            [(int)la_device_property_e::HBM_READ_CYCLES] = "HBM_READ_CYCLES",
            [(int)la_device_property_e::HBM_WRITE_CYCLES] = "HBM_WRITE_CYCLES",
            [(int)la_device_property_e::HBM_MIN_MOVE_TO_READ] = "HBM_MIN_MOVE_TO_READ",
            [(int)la_device_property_e::HBM_LPM_FAVOR_MODE] = "HBM_LPM_FAVOR_MODE",
            [(int)la_device_property_e::MAX_NUMBER_OF_PERIODIC_SAVE_STATE_FILES] = "MAX_NUMBER_OF_PERIODIC_SAVE_STATE_FILES",
            [(int)la_device_property_e::HBM_PHY_T_RDLAT_OFFSET] = "HBM_PHY_T_RDLAT_OFFSET",
            [(int)la_device_property_e::MULTICAST_MCID_SCALE_THRESHOLD] = "MULTICAST_MCID_SCALE_THRESHOLD",
            [(int)la_device_property_e::LPTS_MAX_ENTRY_COUNTERS] = "LPTS_MAX_ENTRY_COUNTERS",
            [(int)la_device_property_e::MAX_NUM_PCL_GIDS] = "MAX_NUM_PCL_GIDS",
            [(int)la_device_property_e::SGACL_MAX_CELL_COUNTERS] = "SGACL_MAX_CELL_COUNTERS",
            [(int)la_device_property_e::LINKUP_TIME_BEFORE_SERDES_REFRESH] = "LINKUP_TIME_BEFORE_SERDES_REFRESH",
            [(int)la_device_property_e::MATILDA_MODEL_TYPE] = "MATILDA_MODEL_TYPE",
            [(int)la_device_property_e::EFUSE_REFCLK_SETTINGS] = "EFUSE_REFCLK_SETTINGS",
            [(int)la_device_property_e::DEV_REFCLK_SEL] = "DEV_REFCLK_SEL",
            [(int)la_device_property_e::OOB_INJ_CREDITS] = "OOB_INJ_CREDITS",
            [(int)la_device_property_e::PACIFIC_PFC_PILOT_PROBABILITY] = "PACIFIC_PFC_PILOT_PROBABILITY",
            [(int)la_device_property_e::PACIFIC_PFC_MEASUREMENT_PROBABILITY] = "PACIFIC_PFC_MEASUREMENT_PROBABILITY",
            [(int)la_device_property_e::CREDIT_SIZE_IN_BYTES] = "CREDIT_SIZE_IN_BYTES",
            [(int)la_device_property_e::NUM_MULTIPORT_PHY] = "NUM_MULTIPORT_PHY",
            [(int)la_device_property_e::COUNTERS_SHADOW_AGE_OUT] = "COUNTERS_SHADOW_AGE_OUT",
            [(int)la_device_property_e::METER_BUCKET_REFILL_POLLING_DELAY] = "METER_BUCKET_REFILL_POLLING_DELAY",
            [(int)la_device_property_e::SERDES_FW_FILE_NAME] = "SERDES_FW_FILE_NAME",
            [(int)la_device_property_e::SBUS_MASTER_FW_FILE_NAME] = "SBUS_MASTER_FW_FILE_NAME",
    };

    if ((size_t)device_property < array_size(strs)) {
        return std::string(strs[(size_t)device_property]);
    }

    return std::string("Unknown device property");
}

std::string
to_string(la_fabric_port_scheduler::fabric_ouput_queue_e fabric_ouput_queue)
{
    static const char* strs[] = {
            [(int)la_fabric_port_scheduler::fabric_ouput_queue_e::PLB_UC_HIGH] = "PLB_UC_HIGH",
            [(int)la_fabric_port_scheduler::fabric_ouput_queue_e::PLB_UC_LOW] = "PLB_UC_LOW",
            [(int)la_fabric_port_scheduler::fabric_ouput_queue_e::PLB_MC] = "PLB_MC",
    };

    if ((size_t)fabric_ouput_queue < array_size(strs)) {
        return std::string(strs[(size_t)fabric_ouput_queue]);
    }

    return std::string("Unknown fabric output queue");
}

std::string
to_string(la_notification_action_e n)
{
    static const char* strs[] = {
            [(int)la_notification_action_e::NONE] = "NONE",
            [(int)la_notification_action_e::HARD_RESET] = "HARD_RESET",
            [(int)la_notification_action_e::SOFT_RESET] = "SOFT_RESET",
            [(int)la_notification_action_e::REPLACE_DEVICE] = "REPLACE_DEVICE",
    };

    static_assert(array_size(strs) == (size_t)la_notification_action_e::LAST + 1, "");

    if ((size_t)n < array_size(strs)) {
        return strs[(size_t)n];
    }

    return "Unknown action";
}

std::string
to_string(const link_down_interrupt_info& info)
{
    std::stringstream interrupt_info;

    if (info.rx_link_status_down) {
        interrupt_info << "MAC link";
        if (info.rx_remote_link_status_down) {
            interrupt_info << "Remote fault";
        } else {
            interrupt_info << "Local fault";
        }
    }
    if (info.rx_pcs_link_status_down) {
        interrupt_info << "PCS link";
    }
    if (info.rx_pcs_align_status_down) {
        interrupt_info << "Alignment marker";
    }
    if (info.rx_pcs_hi_ber_up) {
        interrupt_info << "PCS high BER";
    }
    if (info.rsf_rx_high_ser_interrupt_register) {
        interrupt_info << "FEC high SER";
    }

    bool sig_ok_loss = false;
    std::stringstream sig_ok_info;
    for (int i = 0; i < la_mac_port_max_lanes_e::SERDES; i++) {
        if (info.rx_pma_sig_ok_loss_interrupt_register[i]) {
            sig_ok_loss = true;
            sig_ok_info << " " << i;
        }
    }
    if (sig_ok_loss) {
        interrupt_info << LOG_STRUCT_SEPARATOR << "Signal OK loss on SerDes" << sig_ok_info.str();
    }

    return interrupt_info.str();
}

std::string
to_string(const link_error_interrupt_info& info)
{
    std::stringstream interrupt_info;

    bool add_comma = false;
    struct {
        const bool* info_val;
        std::string desc;
    } reg_vals[] = {
        {&info.rx_code_error, "Rx code"},
        {&info.rx_crc_error, "Rx CRC"},
        {&info.rx_invert_crc_error, "Rx inverted CRC"},
        {&info.rx_oob_invert_crc_error, "Rx OOBI inverted CRC"},
        {&info.rx_oversize_error, "Rx oversize"},
        {&info.rx_undersize_error, "Rx undersize"},

        {&info.tx_crc_error, "Tx CRC"},
        {&info.tx_underrun_error, "Tx underrun"},
        {&info.tx_missing_eop_error, "Tx missing EOP"},

        {&info.rsf_rx_degraded_ser, "RS-FEC degraded SER"},
        {&info.rsf_rx_remote_degraded_ser, "RS-FEC remote degraded SER"},

        {&info.device_time_override, "Device time failed to read"},
        {&info.ptp_time_stamp_error, "PTP time stamp operation failed"},
    };

    for (auto reg_val : reg_vals) {
        if (*reg_val.info_val) {
            if (add_comma) {
                interrupt_info << ",";
            } else {
                add_comma = true;
            }
            interrupt_info << reg_val.desc;
        }
    }

    return interrupt_info.str();
}

std::string
to_string(la_notification_type_e type)
{
    static const char* strs[] = {
            [(int)la_notification_type_e::NONE] = "NONE",
            [(int)la_notification_type_e::BFD] = "BFD",
            [(int)la_notification_type_e::ECC] = "ECC",
            [(int)la_notification_type_e::ECC_REMOTE] = "ECC_REMOTE",
            [(int)la_notification_type_e::INFORMATIVE] = "INFORMATIVE",
            [(int)la_notification_type_e::LACK_OF_RESOURCES] = "LACK_OF_RESOURCES",
            [(int)la_notification_type_e::LINK] = "LINK",
            [(int)la_notification_type_e::LPM_SRAM_MEM_PROTECT] = "LPM_SRAM_MEM_PROTECT",
            [(int)la_notification_type_e::MEM_PROTECT] = "MEM_PROTECT",
            [(int)la_notification_type_e::MISCONFIGURATION] = "MISCONFIGURATION",
            [(int)la_notification_type_e::OTHER] = "OTHER",
            [(int)la_notification_type_e::PCI] = "PCI",
            [(int)la_notification_type_e::RESOURCE_MONITOR] = "RESOURCE_MONITOR",
            [(int)la_notification_type_e::THRESHOLD_CROSSED] = "THRESHOLD_CROSSED",
            [(int)la_notification_type_e::PFC_WATCHDOG] = "PFC_WATCHDOG",
            [(int)la_notification_type_e::CREDIT_GRANT_DEV_UNREACHABLE] = "CREDIT_GRANT_DEV_UNREACHABLE",
            [(int)la_notification_type_e::QUEUE_AGED_OUT] = "QUEUE_AGED_OUT",
            [(int)la_notification_type_e::DRAM_CORRUPTED_BUFFER] = "DRAM_CORRUPTED_BUFFER",
    };

    static_assert(array_size(strs) == (size_t)la_notification_type_e::LAST, "");

    if ((size_t)type < array_size(strs)) {
        return strs[(size_t)type];
    }

    return "Unknown notification type";
}

std::string
to_string(la_link_notification_type_e type)
{
    static const char* strs[] = {
            [(int)la_link_notification_type_e::UP] = "UP",
            [(int)la_link_notification_type_e::DOWN] = "DOWN",
            [(int)la_link_notification_type_e::ERROR] = "ERROR",
    };

    if ((size_t)type < array_size(strs)) {
        return strs[(size_t)type];
    }

    return "Unknown link notification type";
}

std::string
to_string(la_meter_set::type_e type)
{
    static const char* strs[] = {
            [(int)la_meter_set::type_e::EXACT] = "EXACT",
            [(int)la_meter_set::type_e::STATISTICAL] = "STATISTICAL",
            [(int)la_meter_set::type_e::PER_IFG_EXACT] = "PER_IFG_EXACT",
    };

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }
    return std::string("Unknown type");
}

std::string
to_string(la_meter_set::coupling_mode_e coupling_mode)
{
    static const char* strs[] = {
            [(int)la_meter_set::coupling_mode_e::NOT_COUPLED] = "NOT_COUPLED",
            [(int)la_meter_set::coupling_mode_e::TO_EXCESS_BUCKET] = "TO_EXCESS_BUCKET",
    };

    if ((size_t)coupling_mode < array_size(strs)) {
        return std::string(strs[(size_t)coupling_mode]);
    }
    return std::string("Unknown coupling mode");
}

std::string
to_string(la_fabric_port::link_protocol_e link_protocol)
{
    static const char* strs[] = {
            [(int)la_fabric_port::link_protocol_e::PEER_DISCOVERY] = "PEER_DISCOVERY",
            [(int)la_fabric_port::link_protocol_e::LINK_KEEPALIVE] = "LINK_KEEPALIVE",
    };

    if ((size_t)link_protocol < array_size(strs)) {
        return std::string(strs[(size_t)link_protocol]);
    }

    return std::string("Unknown link protocol");
}

std::string
to_string(la_fabric_port::port_status status)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "peer_detected=" << status.peer_detected << LOG_STRUCT_SEPARATOR
                << "fabric_link_up=" << status.fabric_link_up << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_clos_direction_e clos_direction)
{
    static const char* strs[] = {
            [(int)la_clos_direction_e::DOWN] = "DOWN", [(int)la_clos_direction_e::UP] = "UP",
    };

    if ((size_t)clos_direction < array_size(strs)) {
        return std::string(strs[(size_t)clos_direction]);
    }

    return std::string("Unknown CLOS direction");
}

std::string
to_string(const la_lpts_result& result)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "punt_code=" << (size_t)result.punt_code << LOG_STRUCT_SEPARATOR
                << "flow_type=" << (size_t)result.flow_type << LOG_STRUCT_SEPARATOR << "tc=" << (size_t)result.tc
                << LOG_STRUCT_SEPARATOR << "counter_or_meter=";

    if (result.counter_or_meter == nullptr) {
        log_message << "nullptr";
    } else {
        log_message << get_value_string(result.counter_or_meter);
    }

    log_message << LOG_STRUCT_SEPARATOR << "meter=";
    if (result.meter == nullptr) {
        log_message << "nullptr";
    } else {
        log_message << get_value_string(result.meter);
    }

    log_message << LOG_STRUCT_SEPARATOR << "dest=";
    if (result.dest == nullptr) {
        log_message << "nullptr";
    } else {
        log_message << get_value_string(result.dest);
    }
    log_message << LOG_STRUCT_END;

    return log_message.str();
}

template <class _T>
std::string
pack(const _T& o)
{
    uint64_t* p = (uint64_t*)(const uint64_t*)&o;
    return bit_vector(p, sizeof(_T) * CHAR_BIT).to_string();
}

std::string
to_string(const la_lpts_key_l4_ports& ports)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "sport=" << std::hex << std::showbase << ports.sport << LOG_STRUCT_SEPARATOR
                << "dport=" << std::hex << std::showbase << ports.dport << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_lpts_key_ipv4& ipv4)
{
    std::stringstream log_message;

    if (ipv4.app_id) {
        log_message << LOG_STRUCT_START << "app_id=" << (size_t)ipv4.app_id;
        log_message << LOG_STRUCT_SEPARATOR << "sip=" << get_value_string(ipv4.sip);
    } else {
        log_message << LOG_STRUCT_START << "sip=" << get_value_string(ipv4.sip);
    }
    log_message << LOG_STRUCT_SEPARATOR << "src_og_compression_code=" << std::hex << std::showbase << ipv4.src_og_compression_code;
    log_message << LOG_STRUCT_SEPARATOR << "dst_og_compression_code=" << std::hex << std::showbase << ipv4.dst_og_compression_code;
    if ((size_t)ipv4.protocol) {
        log_message << LOG_STRUCT_SEPARATOR << "protocol=" << get_value_string(ipv4.protocol);
    }
    if (ipv4.ports.sport || ipv4.ports.dport) {
        log_message << LOG_STRUCT_SEPARATOR << "ports=" << get_value_string(ipv4.ports);
    }
    if (ipv4.relay_id) {
        log_message << LOG_STRUCT_SEPARATOR << "relay_id=" << std::hex << std::showbase << ipv4.relay_id;
    }
    log_message << LOG_STRUCT_SEPARATOR << "fragment=" << (size_t)ipv4.fragment;
    log_message << LOG_STRUCT_SEPARATOR << "fragment_info=" << get_value_string(ipv4.fragment_info);
    log_message << LOG_STRUCT_SEPARATOR << "ip_length=" << std::hex << std::showbase << ipv4.ip_length;
    log_message << LOG_STRUCT_SEPARATOR << "established=" << get_value_string(ipv4.established);
    log_message << LOG_STRUCT_SEPARATOR << "ttl_255=" << get_value_string(ipv4.ttl_255);
    log_message << LOG_STRUCT_SEPARATOR << "is_mc=" << get_value_string(ipv4.is_mc);
    log_message << LOG_STRUCT_END;
    return log_message.str();
}

std::string
to_string(const la_lpts_key_ipv6& ipv6)
{
    std::stringstream log_message;

    if (ipv6.app_id) {
        log_message << LOG_STRUCT_START << "app_id=" << get_value_string(ipv6.app_id);
        log_message << LOG_STRUCT_SEPARATOR << "sip=" << get_value_string(ipv6.sip);
    } else {
        log_message << LOG_STRUCT_START << "sip=" << get_value_string(ipv6.sip);
    }
    log_message << LOG_STRUCT_SEPARATOR << "src_og_compression_code=" << std::hex << std::showbase << ipv6.src_og_compression_code;
    log_message << LOG_STRUCT_SEPARATOR << "dst_og_compression_code=" << std::hex << std::showbase << ipv6.dst_og_compression_code;
    if ((size_t)ipv6.protocol) {
        log_message << LOG_STRUCT_SEPARATOR << "protocol=" << get_value_string(ipv6.protocol);
    }
    if (ipv6.ports.sport || ipv6.ports.dport) {
        log_message << LOG_STRUCT_SEPARATOR << "ports=" << get_value_string(ipv6.ports);
    }
    if (ipv6.relay_id) {
        log_message << LOG_STRUCT_SEPARATOR << "relay_id=" << std::hex << std::showbase << ipv6.relay_id;
    }
    log_message << LOG_STRUCT_SEPARATOR << "ip_length=" << std::hex << std::showbase << ipv6.ip_length;
    log_message << LOG_STRUCT_SEPARATOR << "established=" << ipv6.established;
    log_message << LOG_STRUCT_SEPARATOR << "ttl_255=" << ipv6.ttl_255;
    log_message << LOG_STRUCT_SEPARATOR << "is_mc=" << ipv6.is_mc;
    log_message << LOG_STRUCT_END;
    return log_message.str();
}

std::string
to_string(const la_lpts_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "type=" << get_value_string(key.type);
    if (key.type == lpts_type_e::LPTS_TYPE_IPV4) {
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv4=" << get_value_string(key.val.ipv4) << LOG_STRUCT_SEPARATOR
                    << "mask.ipv4=" << get_value_string(key.mask.ipv4);
    } else {
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv6=" << get_value_string(key.val.ipv6) << LOG_STRUCT_SEPARATOR
                    << "mask.ipv6=" << get_value_string(key.mask.ipv6);
    }
    log_message << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_system_port_base::port_type_e port_type)
{
    const char* strings[] = {
        "INVALID", "MAC", "PCI", "NPU_HOST", "RECYCLE", "REMOTE",
    };

    if ((size_t)port_type >= (size_t)la_system_port_base::port_type_e::REMOTE) {
        port_type = la_system_port_base::port_type_e::INVALID;
    }

    return strings[(size_t)port_type];
}

std::string
to_string(la_voq_set::voq_counter_type_e voq_counter_type)
{

    static const char* strs[] = {
            [(int)la_voq_set::voq_counter_type_e::ENQUEUED] = "ENQUEUED",
            [(int)la_voq_set::voq_counter_type_e::DROPPED] = "DROPPED",
            [(int)la_voq_set::voq_counter_type_e::BOTH] = "BOTH",
    };

    if ((size_t)voq_counter_type < array_size(strs)) {
        return std::string(strs[(size_t)voq_counter_type]);
    }

    return std::string("Unknown VOQ counter set type");
}

std::string
to_string(const la_bfd_discriminator& discriminator)
{
    std::stringstream log_message;
    log_message << std::hex << std::showbase << to_utype(discriminator);
    return log_message.str();
}

std::string
to_string(la_bfd_diagnostic_code_e& code)
{
    static const char* strs[] = {
            [(int)la_bfd_diagnostic_code_e::NO_DIAGNOSTIC] = "NO_DIAGNOSTIC",
            [(int)la_bfd_diagnostic_code_e::CONTROL_TIME_EXPIRED] = "CONTROL_TIME_EXPIRED",
            [(int)la_bfd_diagnostic_code_e::ECHO_FUNCTION_FAILED] = "ECHO_FUNCTION_FAILED",
            [(int)la_bfd_diagnostic_code_e::NEIGHBOR_SIGNALED_SESSION_DOWN] = "NEIGHBOR_SIGNALED_SESSION_DOWN",
            [(int)la_bfd_diagnostic_code_e::FORWARDING_PLANE_RESET] = "FORWARDING_PLANE_RESET",
            [(int)la_bfd_diagnostic_code_e::PATH_DOWN] = "PATH_DOWN",
            [(int)la_bfd_diagnostic_code_e::CONCATENATED_PATH_DOWN] = "CONCATENATED_PATH_DOWN",
            [(int)la_bfd_diagnostic_code_e::ADMINISTRATIVELY_DOWN] = "ADMINISTRATIVELY_DOWN",
            [(int)la_bfd_diagnostic_code_e::REVERSE_CONCATENTATED_PATH_DOWN] = "REVERSE_CONCATENTATED_PATH_DOWN",
    };

    if ((size_t)code < array_size(strs)) {
        return std::string(strs[(size_t)code]);
    }

    return std::string{"Unknown BFD diagnostic code"};
}

std::string
to_string(la_bfd_session::type_e bfd_type)
{
    static const char* strs[] = {
            [(int)la_bfd_session::type_e::ECHO] = "ECHO",
            [(int)la_bfd_session::type_e::MICRO] = "MICRO",
            [(int)la_bfd_session::type_e::MULTI_HOP] = "MULTI_HOP",
            [(int)la_bfd_session::type_e::SINGLE_HOP] = "SINGLE_HOP",
    };

    if ((size_t)bfd_type < array_size(strs)) {
        return std::string(strs[(size_t)bfd_type]);
    }

    return std::string{"Unknown BFD session type"};
}

std::string
to_string(la_bfd_state_e state)
{
    static const char* state_strs[] = {
            [(int)la_bfd_state_e::ADMIN_DOWN] = "ADMIN_DOWN",
            [(int)la_bfd_state_e::DOWN] = "DOWN",
            [(int)la_bfd_state_e::INIT] = "INIT",
            [(int)la_bfd_state_e::UP] = "UP",
    };

    if ((size_t)state < array_size(state_strs)) {
        return std::string(state_strs[(size_t)state]);
    }

    return std::string{"Unknown BFD session type"};
}

std::string
to_string(la_bfd_flags flags)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "flat=" << (size_t)flags.flat << LOG_STRUCT_END;

    log_message << LOG_INFO_SEPARATOR << "state=" << get_value_string(flags.fields.state) << " flags=";
    if (flags.fields.multipoint) {
        log_message << "M ";
    }
    if (flags.fields.demand) {
        log_message << "D ";
    }
    if (flags.fields.authentication_present) {
        log_message << "A ";
    }
    if (flags.fields.control_plane_independent) {
        log_message << "C ";
    }
    if (flags.fields.final) {
        log_message << "F ";
    }
    if (flags.fields.poll) {
        log_message << "P ";
    }
    log_message << LOG_INFO_SEPARATOR;

    return log_message.str();
}

std::string
to_string(device_mode_e device_mode)
{
    static const char* strs[] = {
            [(int)device_mode_e::INVALID] = "INVALID",
            [(int)device_mode_e::STANDALONE] = "STANDALONE",
            [(int)device_mode_e::LINECARD] = "LINECARD",
            [(int)device_mode_e::FABRIC_ELEMENT] = "FABRIC_ELEMENT",
    };

    if ((size_t)device_mode < array_size(strs)) {
        return strs[(size_t)device_mode];
    }

    return "Unknown device mode";
}

std::string
to_string(std::chrono::milliseconds interval)
{
    std::stringstream log_message;
    log_message << interval.count() << LOG_INFO_SEPARATOR << " ms" << LOG_INFO_SEPARATOR;
    return log_message.str();
}

std::string
to_string(std::chrono::microseconds interval)
{
    std::stringstream log_message;
    log_message << interval.count() << LOG_INFO_SEPARATOR << " us" << LOG_INFO_SEPARATOR;
    return log_message.str();
}

std::string
to_string(std::chrono::seconds interval)
{
    std::stringstream log_message;
    log_message << interval.count() << LOG_INFO_SEPARATOR << " s" << LOG_INFO_SEPARATOR;
    return log_message.str();
}

std::string
to_string(counter_direction_e direction)
{

    static const char* strs[] = {
            [(int)counter_direction_e::COUNTER_DIRECTION_INGRESS] = "INGRESS",
            [(int)counter_direction_e::COUNTER_DIRECTION_EGRESS] = "EGRESS",
    };

    if ((size_t)direction < array_size(strs)) {
        return std::string(strs[(size_t)direction]);
    }

    return std::string("Invalid");
}

std::string
to_string(counter_user_type_e user_type)
{

    static const char* strs[] = {
            [(int)counter_user_type_e::COUNTER_USER_TYPE_QOS] = "QOS",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_DROP] = "DROP",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_SEC_ACE] = "SEC ACE",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_TRAP] = "TRAP",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_L2_AC_PORT] = "L2 AC PORT",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_L3_AC_PORT] = "L3 AC PORT",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_TUNNEL] = "TUNNEL",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_SVI_OR_ADJACENCY] = "SVI OR ADJACENCY",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_VOQ] = "VOQ",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_METER] = "METER",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_MPLS_NH] = "MPLS_NH",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_BFD] = "BFD",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_ERSPAN] = "ERSPAN",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_L2_MIRROR] = "L2 MIRROR",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_MPLS_DECAP] = "MPLS DECAP",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_MPLS_GLOBAL] = "MPLS GLOBAL",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_VNI] = "VNI",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_MCG] = "MCG",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_SR_DM] = "SR DM",
            [(int)counter_user_type_e::COUNTER_USER_TYPE_SECURITY_GROUP_CELL] = "SECURITY GROUP CELL",
    };

    if ((size_t)user_type < array_size(strs)) {
        return std::string(strs[(size_t)user_type]);
    }

    return std::string("Invalid");
}

std::string
to_string(std::chrono::nanoseconds interval)
{
    std::stringstream log_message;
    log_message << interval.count() << LOG_INFO_SEPARATOR << " ns" << LOG_INFO_SEPARATOR;
    return log_message.str();
}

std::string
to_string(la_ecmp_group::level_e level)
{
    static_assert(((size_t)la_ecmp_group::level_e::LEVEL_1 == 1) && ((size_t)la_ecmp_group::level_e::LEVEL_2 == 2),
                  "unexpected values for la_ecmp_group::level_e");
    static const char* strs[] = {
        "LEVEL_1", "LEVEL_2",
    };

    if (((size_t)level != 0) && ((size_t)level <= array_size(strs))) {
        return strs[(size_t)level - 1];
    }

    return "Unknown ECMP level";
}

std::string
to_string(la_acl_field_type_e type)
{
    static const char* strs[] = {
            [(int)la_acl_field_type_e::DA] = "DA",
            [(int)la_acl_field_type_e::SA] = "SA",
            [(int)la_acl_field_type_e::VLAN_OUTER] = "VLAN_OUTER",
            [(int)la_acl_field_type_e::VLAN_INNER] = "VLAN_INNER",
            [(int)la_acl_field_type_e::ETHER_TYPE] = "ETHER_TYPE",
            [(int)la_acl_field_type_e::TOS] = "TOS",
            [(int)la_acl_field_type_e::IPV4_LENGTH] = "IPV4_LENGTH",
            [(int)la_acl_field_type_e::IPV6_LENGTH] = "IPV6_LENGTH",
            [(int)la_acl_field_type_e::IPV4_FLAGS] = "IPV4_FLAGS",
            [(int)la_acl_field_type_e::IPV4_FRAG_OFFSET] = "IPV4_FRAG_OFFSET",
            [(int)la_acl_field_type_e::IPV6_FRAGMENT] = "IPV6_FRAGMENT",
            [(int)la_acl_field_type_e::TTL] = "TTL",
            [(int)la_acl_field_type_e::HOP_LIMIT] = "HOP_LIMIT",
            [(int)la_acl_field_type_e::PROTOCOL] = "PROTOCOL",
            [(int)la_acl_field_type_e::LAST_NEXT_HEADER] = "LAST_NEXT_HEADER",
            [(int)la_acl_field_type_e::IPV4_SIP] = "IPV4_SIP",
            [(int)la_acl_field_type_e::IPV4_DIP] = "IPV4_DIP",
            [(int)la_acl_field_type_e::IPV6_SIP] = "IPV6_SIP",
            [(int)la_acl_field_type_e::IPV6_DIP] = "IPV6_DIP",
            [(int)la_acl_field_type_e::SRC_PCL_BINCODE] = "SRC_PCL_BINCODE",
            [(int)la_acl_field_type_e::DST_PCL_BINCODE] = "DST_PCL_BINCODE",
            [(int)la_acl_field_type_e::CLASS_ID] = "CLASS_ID",
            [(int)la_acl_field_type_e::SPORT] = "SPORT",
            [(int)la_acl_field_type_e::DPORT] = "DPORT",
            [(int)la_acl_field_type_e::MSG_CODE] = "MSG_CODE",
            [(int)la_acl_field_type_e::MSG_TYPE] = "MSG_TYPE",
            [(int)la_acl_field_type_e::TCP_FLAGS] = "TCP_FLAGS",
            [(int)la_acl_field_type_e::VRF_GID] = "VRF_GID",
    };

    if ((size_t)type < array_size(strs)) {
        return strs[(size_t)type];
    } else if (type == la_acl_field_type_e::UDF) {
        return "UDF";
    }

    return "Unknown ACL field type";
}

std::string
to_string(const la_acl_field& field)
{
    std::stringstream log_message;
    log_message << LOG_STRUCT_START << "type=" << get_value_string(field.type);

    switch (field.type) {
    case la_acl_field_type_e::DA:
        log_message << LOG_STRUCT_SEPARATOR << "val.da=" << get_value_string(field.val.da);
        log_message << LOG_STRUCT_SEPARATOR << "mask.da=" << get_value_string(field.mask.da);
        break;
    case la_acl_field_type_e::SA:
        log_message << LOG_STRUCT_SEPARATOR << "val.sa=" << get_value_string(field.val.sa);
        log_message << LOG_STRUCT_SEPARATOR << "mask.sa=" << get_value_string(field.mask.sa);
        break;
    case la_acl_field_type_e::VLAN_OUTER:
        log_message << LOG_STRUCT_SEPARATOR << "val.vlan1=" << get_value_string(field.val.vlan1);
        log_message << LOG_STRUCT_SEPARATOR << "mask.vlan1=" << get_value_string(field.mask.vlan1);
        break;
    case la_acl_field_type_e::VLAN_INNER:
        log_message << LOG_STRUCT_SEPARATOR << "val.vlan2=" << get_value_string(field.val.vlan2);
        log_message << LOG_STRUCT_SEPARATOR << "mask.vlan2=" << get_value_string(field.mask.vlan2);
        break;
    case la_acl_field_type_e::ETHER_TYPE:
        log_message << LOG_STRUCT_SEPARATOR << "val.ethtype=" << std::hex << std::showbase << field.val.ethtype;
        log_message << LOG_STRUCT_SEPARATOR << "mask.ethtype=" << std::hex << std::showbase << field.mask.ethtype;
        break;
    case la_acl_field_type_e::TOS:
        log_message << LOG_STRUCT_SEPARATOR << "val.tos=" << get_value_string(field.val.tos);
        log_message << LOG_STRUCT_SEPARATOR << "mask.tos=" << get_value_string(field.mask.tos);
        break;
    case la_acl_field_type_e::IPV4_LENGTH:
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv4_length=" << get_value_string(field.val.ipv4_length);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ipv4_length=" << get_value_string(field.mask.ipv4_length);
        break;
    case la_acl_field_type_e::IPV6_LENGTH:
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv6_length=" << get_value_string(field.val.ipv6_length);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ipv6_length=" << get_value_string(field.mask.ipv6_length);
        break;
    case la_acl_field_type_e::IPV4_FLAGS:
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv4_flags=" << get_value_string(field.val.ipv4_flags);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ipv4_flags=" << get_value_string(field.mask.ipv4_flags);
        break;
    case la_acl_field_type_e::IPV4_FRAG_OFFSET:
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv4_fragment=" << get_value_string(field.val.ipv4_fragment);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ipv4_fragment=" << get_value_string(field.mask.ipv4_fragment);
        break;
    case la_acl_field_type_e::IPV6_FRAGMENT:
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv6_fragment=" << get_value_string(field.val.ipv6_fragment);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ipv6_fragment=" << get_value_string(field.mask.ipv6_fragment);
        break;
    case la_acl_field_type_e::TTL:
        log_message << LOG_STRUCT_SEPARATOR << "val.ttl=" << (size_t)field.val.ttl;
        log_message << LOG_STRUCT_SEPARATOR << "mask.ttl=" << (size_t)field.mask.ttl;
        break;
    case la_acl_field_type_e::HOP_LIMIT:
        log_message << "???";
        log_message << "???";
        break;
    case la_acl_field_type_e::PROTOCOL:
        log_message << LOG_STRUCT_SEPARATOR << "val.protocol=" << std::hex << std::showbase << (size_t)field.val.protocol;
        log_message << LOG_STRUCT_SEPARATOR << "mask.protocol=" << std::hex << std::showbase << (size_t)field.mask.protocol;
        break;
    case la_acl_field_type_e::LAST_NEXT_HEADER:
        log_message << LOG_STRUCT_SEPARATOR << "val.last_next_header=" << std::hex << std::showbase
                    << (size_t)field.val.last_next_header;
        log_message << LOG_STRUCT_SEPARATOR << "mask.last_next_header=" << std::hex << std::showbase
                    << (size_t)field.mask.last_next_header;
        break;
    case la_acl_field_type_e::IPV4_SIP:
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv4_sip=" << get_value_string(field.val.ipv4_sip);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ipv4_sip=" << get_value_string(field.mask.ipv4_sip);
        break;
    case la_acl_field_type_e::IPV4_DIP:
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv4_dip=" << get_value_string(field.val.ipv4_dip);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ipv4_dip=" << get_value_string(field.mask.ipv4_dip);
        break;
    case la_acl_field_type_e::IPV6_SIP:
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv6_sip=" << get_value_string(field.val.ipv6_sip);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ipv6_sip=" << get_value_string(field.mask.ipv6_sip);
        break;
    case la_acl_field_type_e::IPV6_DIP:
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv6_dip=" << get_value_string(field.val.ipv6_dip);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ipv6_dip=" << get_value_string(field.mask.ipv6_dip);
        break;
    case la_acl_field_type_e::SRC_PCL_BINCODE:
        log_message << LOG_STRUCT_SEPARATOR << "val.src_pcl_bincode=" << field.val.src_pcl_bincode;
        log_message << LOG_STRUCT_SEPARATOR << "mask.src_pcl_bincode=" << pack(field.mask.src_pcl_bincode);
        break;
    case la_acl_field_type_e::DST_PCL_BINCODE:
        log_message << LOG_STRUCT_SEPARATOR << "val.dst_pcl_bincode=" << field.val.dst_pcl_bincode;
        log_message << LOG_STRUCT_SEPARATOR << "mask.dst_pcl_bincode=" << pack(field.mask.dst_pcl_bincode);
        break;
    case la_acl_field_type_e::CLASS_ID:
        log_message << LOG_STRUCT_SEPARATOR << "val.class_id=" << field.val.class_id;
        log_message << LOG_STRUCT_SEPARATOR << "mask.class_id=" << pack(field.mask.class_id);
        break;
    case la_acl_field_type_e::SPORT:
        log_message << LOG_STRUCT_SEPARATOR << "val.sport=" << std::hex << std::showbase << (size_t)field.val.sport;
        log_message << LOG_STRUCT_SEPARATOR << "mask.sport=" << std::hex << std::showbase << (size_t)field.mask.sport;
        break;
    case la_acl_field_type_e::DPORT:
        log_message << LOG_STRUCT_SEPARATOR << "val.dport=" << std::hex << std::showbase << (size_t)field.val.dport;
        log_message << LOG_STRUCT_SEPARATOR << "mask.dport=" << std::hex << std::showbase << (size_t)field.mask.dport;
        break;
    case la_acl_field_type_e::MSG_CODE:
        log_message << LOG_STRUCT_SEPARATOR << "val.mcode=" << std::hex << std::showbase << (size_t)field.val.mcode;
        log_message << LOG_STRUCT_SEPARATOR << "mask.mcode=" << std::hex << std::showbase << (size_t)field.mask.mcode;
        break;
    case la_acl_field_type_e::MSG_TYPE:
        log_message << LOG_STRUCT_SEPARATOR << "val.mtype=" << std::hex << std::showbase << (size_t)field.val.mtype;
        log_message << LOG_STRUCT_SEPARATOR << "mask.mtype=" << std::hex << std::showbase << (size_t)field.mask.mtype;
        break;
    case la_acl_field_type_e::TCP_FLAGS:
        log_message << LOG_STRUCT_SEPARATOR << "val.tcp_flags.flat=" << std::hex << std::showbase
                    << (size_t)field.val.tcp_flags.flat;
        log_message << LOG_STRUCT_SEPARATOR << "mask.tcp_flags.flat=" << std::hex << std::showbase
                    << (size_t)field.mask.tcp_flags.flat;
        break;
    case la_acl_field_type_e::VRF_GID:
        log_message << LOG_STRUCT_SEPARATOR << "val.vrf_gid=" << get_value_string(field.val.vrf_gid);
        log_message << LOG_STRUCT_SEPARATOR << "mask.vrf_gid=" << get_value_string(field.mask.vrf_gid);
        break;
    case la_acl_field_type_e::QOS_GROUP:
        log_message << LOG_STRUCT_SEPARATOR << "val.qos_group=" << get_value_string(field.val.qos_group);
        log_message << LOG_STRUCT_SEPARATOR << "mask.qos_group=" << get_value_string(field.mask.qos_group);
        break;
    case la_acl_field_type_e::UDF:
        log_message << LOG_STRUCT_SEPARATOR << "udf_index=" << std::hex << std::showbase << (size_t)field.udf_index;
        break;
    case la_acl_field_type_e::SGACL_BINCODE:
        log_message << LOG_STRUCT_SEPARATOR << "val.sgacl_bincode=" << (size_t)(field.val.sgacl_bincode);
        log_message << LOG_STRUCT_SEPARATOR << "mask.sgacl_bincode=" << (size_t)(field.mask.sgacl_bincode);
        break;
    case la_acl_field_type_e::IP_VERSION:
        log_message << LOG_STRUCT_SEPARATOR << "val.ip_version=" << (size_t)(field.val.ip_version);
        log_message << LOG_STRUCT_SEPARATOR << "mask.ip_version=" << (size_t)(field.mask.ip_version);
        break;
    }
    log_message << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_acl_key_ipv6_fragment_extension& frag)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "fragment=" << (size_t)frag.fragment << LOG_STRUCT_SEPARATOR << "mf=" << (size_t)frag.mf
                << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_acl_key_ipv4_flags& flags)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "fragment=" << (size_t)flags.fragment << LOG_STRUCT_SEPARATOR << "df=" << (size_t)flags.df
                << LOG_STRUCT_SEPARATOR << "mf=" << (size_t)flags.mf << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_acl_key_ipv4_fragment& fragment)
{
    std::stringstream log_message;
    log_message << LOG_STRUCT_START << "fields.frag_offset=" << (size_t)fragment.fields.frag_offset << LOG_STRUCT_SEPARATOR
                << "fields.df=" << (size_t)fragment.fields.df << LOG_STRUCT_SEPARATOR << "fields.mf=" << (size_t)fragment.fields.mf
                << LOG_STRUCT_SEPARATOR << "fields.evil=" << (size_t)fragment.fields.evil << LOG_STRUCT_END;
    return log_message.str();
}

std::string
to_string(const la_acl_key& key)
{
    return vec_to_string(key);
}

std::string
to_string(const la_acl_command_actions& cmd)
{
    return vec_to_string(cmd);
}

std::string
to_string(la_acl_scale_field_type_e type)
{
    static const char* strs[] = {
            [(int)la_acl_scale_field_type_e::UNDEF] = "UNDEF",
            [(int)la_acl_scale_field_type_e::IPV4] = "IPV4",
            [(int)la_acl_scale_field_type_e::IPV6] = "IPV6",
    };

    if ((size_t)type < array_size(strs)) {
        return strs[(size_t)type];
    }

    return "Unknown scaled field type";
}

std::string
to_string(const la_acl_scale_field_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "type=" << get_value_string(key.type);
    if (key.type == la_acl_scale_field_type_e::IPV4) {
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv4=" << get_value_string(key.val.ipv4) << LOG_STRUCT_SEPARATOR
                    << "mask.ipv4=" << get_value_string(key.mask.ipv4);
    } else {
        log_message << LOG_STRUCT_SEPARATOR << "val.ipv6=" << get_value_string(key.val.ipv6) << LOG_STRUCT_SEPARATOR
                    << "mask.ipv6=" << get_value_string(key.mask.ipv6);
    }
    log_message << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_acl_key_def_vec_t& key_def_vec)
{
    return vec_to_string(key_def_vec);
}

std::string
to_string(const la_acl_command_def_vec_t& command_def_vec)
{
    return vec_to_string(command_def_vec);
}

std::string
to_string(const la_acl_vec_t& acl)
{
    return vec_to_string(acl);
}

std::string
to_string(const la_acl_udf_desc& udf_desc)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "index=" << (size_t)udf_desc.index << LOG_STRUCT_SEPARATOR
                << "protocol_layer=" << (size_t)udf_desc.protocol_layer << LOG_STRUCT_SEPARATOR
                << "header=" << (size_t)udf_desc.header << LOG_STRUCT_SEPARATOR << "offset=" << (size_t)udf_desc.offset
                << LOG_STRUCT_SEPARATOR << "width=" << (size_t)udf_desc.width << LOG_STRUCT_SEPARATOR
                << "is_relative=" << get_value_string(udf_desc.is_relative) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_acl_action_def& action)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "type=" << get_value_string(action.type) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_acl_field_def& field)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "type=" << get_value_string(field.type) << LOG_STRUCT_SEPARATOR
                << "udf_desc=" << get_value_string(field.udf_desc) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_pcl_v4& prefix)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "prefix=" << get_value_string(prefix.prefix) << LOG_STRUCT_SEPARATOR
                << "bincode=" << prefix.bincode << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_pcl_v4_vec_t& prefixes)
{
    return vec_to_string(prefixes);
}

std::string
to_string(const la_pcl_v6& prefix)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "prefix=" << get_value_string(prefix.prefix) << LOG_STRUCT_SEPARATOR
                << "bincode=" << prefix.bincode << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_pcl_v6_vec_t& prefixes)
{
    return vec_to_string(prefixes);
}

std::string
to_string(la_mac_port::pfc_config_queue_state_e state)
{
    static const char* strs[] = {
            [(int)la_mac_port::pfc_config_queue_state_e::ACTIVE] = "ACTIVE",
            [(int)la_mac_port::pfc_config_queue_state_e::DROPPING] = "DROPPING",
    };

    if ((size_t)state < array_size(strs)) {
        return std::string(strs[(size_t)state]);
    }

    return std::string("Unknown la_mac_port::pfc_config_queue_state_e");
}

std::string
to_string(la_mac_port::pfc_queue_state_e state)
{

    static const char* strs[] = {
            [(int)la_mac_port::pfc_queue_state_e::EMPTY] = "EMPTY",
            [(int)la_mac_port::pfc_queue_state_e::TRANSMITTING] = "TRANSMITTING",
            [(int)la_mac_port::pfc_queue_state_e::NOT_TRANSMITTING] = "NOT_TRANSMITTING",
            [(int)la_mac_port::pfc_queue_state_e::NOT_TRANSMITTING_DUE_TO_PFC] = "NOT_TRANSMITTING_DUE_TO_PFC",
    };

    if ((size_t)state < array_size(strs)) {
        return std::string(strs[(size_t)state]);
    }

    return std::string("Unknown la_mac_port::pfc_config_queue_state_e");
}

std::string
to_string(la_rx_cgm_headroom_mode_e mode)
{

    static const char* strs[] = {
            [(int)la_rx_cgm_headroom_mode_e::TIMER] = "TIMER", [(int)la_rx_cgm_headroom_mode_e::THRESHOLD] = "THRESHOLD",
    };

    if ((size_t)mode < array_size(strs)) {
        return std::string(strs[(size_t)mode]);
    }

    return std::string("Unknown la_rx_cgm_headroom_mode_e");
}

std::string
to_string(la_ip_tunnel_port::la_ttl_inheritance_mode_e& ttl_i_m)
{

    static const char* strs[] = {
            [(int)la_ip_tunnel_port::la_ttl_inheritance_mode_e::PIPE] = "PIPE",
            [(int)la_ip_tunnel_port::la_ttl_inheritance_mode_e::UNIFORM] = "UNIFORM",
    };

    if ((size_t)ttl_i_m < array_size(strs)) {
        return strs[(size_t)ttl_i_m];
    }

    return "Unknown la ttl inheritance_mode_e error";
}

std::string
to_string(la_ttl_inheritance_mode_e ttl_mode)
{

    static const char* strs[] = {
            [(int)la_ttl_inheritance_mode_e::PIPE] = "PIPE", [(int)la_ttl_inheritance_mode_e::UNIFORM] = "UNIFORM",
    };

    if ((size_t)ttl_mode < array_size(strs)) {
        return strs[(size_t)ttl_mode];
    }

    return "Unknown ttl inheritance_mode_e error";
}

std::string
to_string(silicon_one::la_ethernet_port::svi_egress_tag_mode_e& svi_egress_tag_mode)
{

    static const char* strs[] = {
            [(int)la_ethernet_port::svi_egress_tag_mode_e::KEEP] = "KEEP",
            [(int)la_ethernet_port::svi_egress_tag_mode_e::STRIP] = "STRIP",
    };

    if ((size_t)svi_egress_tag_mode < array_size(strs)) {
        return strs[(size_t)svi_egress_tag_mode];
    }

    return "Unknown svi egress tag mode error";
}

std::string
to_string(la_device::test_feature_e& feature)
{
    static const char* strs[] = {
            [(int)la_device::test_feature_e::MEM_BIST] = "MEM_BIST", [(int)la_device::test_feature_e::HBM] = "HBM",
    };

    if ((size_t)feature < array_size(strs)) {
        return strs[(size_t)feature];
    }

    return "Unknown test feature error";
}

std::string
to_string(la_device::learn_mode_e& learn_mode)
{
    static const char* strs[] = {
            [(int)la_device::learn_mode_e::LOCAL] = "LOCAL", [(int)la_device::learn_mode_e::SYSTEM] = "SYSTEM",
    };

    if ((size_t)learn_mode < array_size(strs)) {
        return strs[(size_t)learn_mode];
    }

    return "Unknown learn mode error";
}

std::string
to_string(la_device::fabric_mac_ports_mode_e& fabric_mac_ports_mode_e)
{
    static const char* strs[] = {
            [(int)la_device::fabric_mac_ports_mode_e::E_2x50] = "E_2x50",
            [(int)la_device::fabric_mac_ports_mode_e::E_4x50] = "E_4x50",
    };

    if ((size_t)fabric_mac_ports_mode_e < array_size(strs)) {
        return strs[(size_t)fabric_mac_ports_mode_e];
    }

    return "Unknown fabric mac ports mode error";
}

std::string
to_string(const la_voq_cgm_profile::sms_bytes_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_cgm_profile::sms_packets_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_cgm_profile::sms_age_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_cgm_profile::wred_regions_probabilties& probabilities)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "probabilities=" << to_string(probabilities.probabilities) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_cgm_profile::wred_blocks_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_cgm_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << get_value_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_cgm_probability_regions& probabilities)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "probabilities=" << get_value_string(probabilities.probabilities) << LOG_STRUCT_END;

    return log_message.str();
    // return vec_to_string(probabilities.probabilities);
}
std::string
to_string(const la_cgm_sms_bytes_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_sms_packets_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
    return to_string(thresholds.thresholds);
}

std::string
to_string(const la_mac_port::ostc_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_hbm_number_of_voqs_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_hbm_pool_free_blocks_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_hbm_blocks_by_voq_quantization_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "thresholds=" << to_string(thresholds.thresholds) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_evicted_buffers_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "evicted_buffers_region=" << get_value_string(key.evicted_buffers_region)
                << LOG_STRUCT_SEPARATOR << "sms_voqs_total_bytes_region=" << get_value_string(key.sms_voqs_total_bytes_region)
                << LOG_STRUCT_SEPARATOR << "sms_bytes_region=" << get_value_string(key.sms_bytes_region) << LOG_STRUCT_SEPARATOR
                << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_evicted_buffers_drop_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "drop_color_level=" << get_value_string(val.drop_color_level) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_evict_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "evicted_buffers_region=" << get_value_string(key.evicted_buffers_region)
                << LOG_STRUCT_SEPARATOR << "free_dram_cntxt_region=" << get_value_string(key.free_dram_cntxt_region)
                << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_evict_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "permit_eviction=" << get_value_string(val.permit_eviction) << LOG_STRUCT_SEPARATOR
                << "drop_on_eviction=" << get_value_string(val.drop_on_eviction) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_wred_drop_probability_selector_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "packet_size_region=" << get_value_string(key.packet_size_region) << LOG_STRUCT_SEPARATOR
                << "drop_probability_level=" << get_value_string(key.drop_probability_level) << LOG_STRUCT_SEPARATOR
                << "color=" << get_value_string(key.color) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_wred_drop_probability_selector_drop_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "drop_probability=" << get_value_string(val.drop_probability) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_wred_mark_probability_selector_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "packet_size_region=" << get_value_string(key.packet_size_region) << LOG_STRUCT_SEPARATOR
                << "mark_ecn_probability_level=" << get_value_string(key.mark_ecn_probability_level) << LOG_STRUCT_SEPARATOR
                << "color=" << get_value_string(key.color) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_wred_mark_probability_selector_mark_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "mark_ecn_probability=" << get_value_string(val.mark_ecn_probability) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_size_in_bytes_color_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "sms_voqs_total_bytes_region=" << get_value_string(key.sms_voqs_total_bytes_region)
                << LOG_STRUCT_SEPARATOR << "sms_bytes_region=" << get_value_string(key.sms_bytes_region) << LOG_STRUCT_SEPARATOR
                << "sms_age_region=" << get_value_string(key.sms_age_region) << LOG_STRUCT_SEPARATOR
                << "color=" << get_value_string(key.color) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_size_in_bytes_drop_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "drop_probability_level=" << get_value_string(val.drop_probability_level) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_size_in_bytes_mark_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "mark_ecn_probability_level=" << get_value_string(val.mark_ecn_probability_level)
                << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_size_in_bytes_evict_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "sms_voqs_total_bytes_region=" << get_value_string(key.sms_voqs_total_bytes_region)
                << LOG_STRUCT_SEPARATOR << "sms_bytes_region=" << get_value_string(key.sms_bytes_region) << LOG_STRUCT_SEPARATOR
                << "sms_age_region=" << get_value_string(key.sms_age_region) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_size_in_bytes_evict_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "evict_to_hbm=" << get_value_string(val.evict_to_hbm) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_dequeue_size_in_bytes_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "sms_voqs_total_bytes_region=" << get_value_string(key.sms_voqs_total_bytes_region)
                << LOG_STRUCT_SEPARATOR << "sms_bytes_region=" << get_value_string(key.sms_bytes_region) << LOG_STRUCT_SEPARATOR
                << "sms_age_region=" << get_value_string(key.sms_age_region) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_dequeue_size_in_bytes_congestion_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "congestion_level=" << get_value_string(val.congestion_level) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_size_in_packets_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "sms_voqs_total_packets_region=" << get_value_string(key.sms_voqs_total_packets_region)
                << LOG_STRUCT_SEPARATOR << "sms_packets_region=" << get_value_string(key.sms_packets_region) << LOG_STRUCT_SEPARATOR
                << "sms_age_region=" << get_value_string(key.sms_age_region) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_size_in_packets_drop_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "drop_color_level=" << get_value_string(val.drop_color_level) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_size_in_packets_mark_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "mark_ecn_color_level=" << get_value_string(val.mark_ecn_color_level) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_size_in_packets_evict_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "evict_to_hbm=" << get_value_string(val.evict_to_hbm) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_dequeue_size_in_packets_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "sms_voqs_total_packets_region=" << get_value_string(key.sms_voqs_total_packets_region)
                << LOG_STRUCT_SEPARATOR << "sms_packetss_region=" << get_value_string(key.sms_packets_region)
                << LOG_STRUCT_SEPARATOR << "sms_age_region=" << get_value_string(key.sms_age_region) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_voq_sms_dequeue_size_in_packets_congestion_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "congestion_level=" << get_value_string(val.congestion_level) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_hbm_size_in_blocks_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "hbm_blocks_by_voq_region=" << get_value_string(key.hbm_blocks_by_voq_region)
                << LOG_STRUCT_SEPARATOR << "hbm_queue_delay_region=" << get_value_string(key.hbm_queue_delay_region)
                << LOG_STRUCT_SEPARATOR << "hbm_pool_free_blocks_region=" << get_value_string(key.hbm_pool_free_blocks_region)
                << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_hbm_size_in_blocks_drop_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "drop_color_level=" << get_value_string(val.drop_color_level) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_hbm_size_in_blocks_mark_ecn_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "mark_ecn_color_level=" << get_value_string(val.mark_ecn_color_level) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_hbm_dequeue_size_in_blocks_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "hbm_blocks_by_voq_region=" << get_value_string(key.hbm_blocks_by_voq_region)
                << LOG_STRUCT_SEPARATOR << "hbm_pool_free_blocks_region=" << get_value_string(key.hbm_pool_free_blocks_region)
                << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_hbm_dequeue_size_in_blocks_congestion_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "congestion_level=" << get_value_string(val.congestion_level) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_wred_key& key)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "hbm_blocks_by_voq_region=" << get_value_string(key.hbm_blocks_by_voq_region)
                << LOG_STRUCT_SEPARATOR << "hbm_packet_size_region=" << get_value_string(key.hbm_packet_size_region)
                << LOG_STRUCT_SEPARATOR << "color=" << get_value_string(key.color) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_wred_drop_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "drop_probability=" << get_value_string(val.drop_probability) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_cgm_wred_mark_ecn_val& val)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "mark_ecn_probability=" << get_value_string(val.mark_ecn_probability) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(std::vector<double>& vec)
{
    return vec_to_string(vec);
}

std::string
to_string(std::vector<unsigned int>& vec)
{
    return vec_to_string(vec);
}

std::string
to_string(const la_rx_pdr_sms_bytes_drop_thresholds& thresholds)
{
    return to_string(thresholds.thresholds);
}

std::string
to_string(const la_rx_cgm_sms_bytes_quantization_thresholds& thresholds)
{
    return to_string(thresholds.thresholds);
}

std::string
to_string(const la_rx_cgm_sqg_thresholds& thresholds)
{
    return to_string(thresholds.thresholds);
}

std::string
to_string(const la_rx_cgm_sq_profile_thresholds& thresholds)
{
    return to_string(thresholds.thresholds);
}

std::string
to_string(const la_fabric_valid_links_thresholds& thresholds)
{
    return to_string(thresholds.thresholds);
}

std::string
to_string(const la_fabric_congested_links_thresholds& thresholds)
{
    return to_string(thresholds.thresholds);
}

std::string
to_string(const la_rx_cgm_policy_status& status)
{
    std::stringstream log_message;

    log_message << "(counter_a_region=" << to_string(status.counter_a_region)
                << ", sq_group_region=" << to_string(status.sq_group_region)
                << ", sq_profile_region=" << to_string(status.sq_profile_region) << ")";

    return log_message.str();
}

std::string
to_string(const la_tx_cgm_oq_profile_thresholds& thresholds)
{
    std::stringstream log_message;

    log_message << "(fc_bytes_threshold=" << to_string(thresholds.fc_bytes_threshold)
                << "fc_buffers_threshold=" << to_string(thresholds.fc_buffers_threshold)
                << "fc_pds_threshold=" << to_string(thresholds.fc_pds_threshold)
                << "drop_bytes_threshold=" << to_string(thresholds.drop_bytes_threshold)
                << "drop_buffers_threshold=" << to_string(thresholds.drop_buffers_threshold)
                << "drop_pds_threshold=" << to_string(thresholds.drop_pds_threshold) << ")";

    return log_message.str();
}

std::string
to_string(la_device::synce_clock_sel_e synce_clock)
{

    static const char* strs[] = {
            [(int)la_device::synce_clock_sel_e::PRIMARY] = "PRIMARY", [(int)la_device::synce_clock_sel_e::SECONDARY] = "SECONDARY",
    };

    if ((size_t)synce_clock < array_size(strs)) {
        return std::string(strs[(size_t)synce_clock]);
    }

    return std::string("Invalid");
}

std::string
to_string(const la_device::save_state_options& options)
{
    std::stringstream log_message;

    log_message << "(inlcude_all=" << to_string(options.include_all) << ", include_config=" << to_string(options.include_config)
                << ", include_volatile=" << to_string(options.include_volatile)
                << ", include_counters=" << to_string(options.include_counters)
                << ", include_status=" << to_string(options.include_status)
                << ", include_mac_port_serdes=" << to_string(options.include_mac_port_serdes)
                << ", include_interrupt_counters=" << to_string(options.include_interrupt_counters)
                << ", reset_on_read=" << to_string(options.reset_on_read)
                << ", verbose_subfields=" << to_string(options.verbose_subfields)
                << ", internal_states=" << to_string(options.internal_states) << ")";

    return log_message.str();
}

std::string
to_string(const std::vector<std::string>& vect)
{
    std::string log_message = "";

    if (vect.empty() == true) {
        return "()";
    }

    auto it = vect.begin();

    log_message += "(" + *it;
    for (; it < vect.end(); ++it) {
        log_message += ", ";
        log_message += *it;
    }

    log_message += ")";

    return log_message;
}

std::string
to_string(const la_hbm_handler::dram_buffer_cell& cell)
{
    std::stringstream ss;

    ss << "{bank=" << cell.bank << ", channel=" << cell.channel << ", row=" << cell.row << ", column=" << cell.column << "}";

    return ss.str();
}

std::string
to_string(const silicon_one::la_platform_cbs& cbs)
{
    std::stringstream log_message;
    log_message.flags(std::ios::hex | std::ios::showbase);

    log_message << LOG_STRUCT_START << "user_data=" << cbs.user_data << LOG_STRUCT_SEPARATOR;
    if (cbs.i2c_register_access == nullptr) {
        log_message << "i2c_register_access="
                    << "nullptr" << LOG_STRUCT_SEPARATOR;
    } else {
        log_message << "i2c_register_access=" << cbs.i2c_register_access << LOG_STRUCT_SEPARATOR;
    }
    if (cbs.dma_alloc == nullptr) {
        log_message << "dma_alloc="
                    << "nullptr" << LOG_STRUCT_SEPARATOR;
    } else {
        log_message << "dma_alloc=" << cbs.dma_alloc << LOG_STRUCT_SEPARATOR;
    }
    if (cbs.dma_free == nullptr) {
        log_message << "dma_free="
                    << "nullptr" << LOG_STRUCT_SEPARATOR;
    } else {
        log_message << "dma_free=" << cbs.dma_free << LOG_STRUCT_SEPARATOR;
    }
    if (cbs.open_device == nullptr) {
        log_message << "open_device="
                    << "nullptr" << LOG_STRUCT_SEPARATOR;
    } else {
        log_message << "open_device=" << cbs.open_device << LOG_STRUCT_SEPARATOR;
    }
    if (cbs.close_device == nullptr) {
        log_message << "close_device="
                    << "nullptr";
    } else {
        log_message << "close_device=" << cbs.close_device;
    }
    log_message << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_gre_port::tunnel_termination_type_e term_type)
{

    static const char* strs[] = {[(int)la_gre_port::tunnel_termination_type_e::P2P] = "P2P",
                                 [(int)la_gre_port::tunnel_termination_type_e::P2MP] = "P2MP"};

    if ((size_t)term_type < array_size(strs)) {
        return std::string(strs[(size_t)term_type]);
    }

    return std::string("Unknown type");
}

std::string
to_string(la_switch::vxlan_termination_mode_e vni_profile)
{

    static const char* strs[] = {[(int)la_switch::vxlan_termination_mode_e::CHECK_DMAC] = "CHECK_DMAC",
                                 [(int)la_switch::vxlan_termination_mode_e::IGNORE_DMAC] = "IGNORE_DMAC"};

    if ((size_t)vni_profile < array_size(strs)) {
        return std::string(strs[(size_t)vni_profile]);
    }

    return std::string("Unknown type");
}

std::string
to_string(const la_lpts_app_properties_key_fields& fields)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "ip_version=" << get_value_string(fields.ip_version) << LOG_STRUCT_SEPARATOR
                << "protocol=" << get_value_string(fields.protocol) << LOG_STRUCT_SEPARATOR
                << "ports=" << get_value_string(fields.ports) << LOG_STRUCT_SEPARATOR
                << "fragment=" << get_value_string(fields.fragment) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_lpts_app_properties& properties)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "val=" << get_value_string(properties.val) << LOG_STRUCT_SEPARATOR
                << "mask=" << get_value_string(properties.mask) << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_l2_service_port::egress_feature_mode_e mode)
{

    static const char* strs[] = {
            [(int)la_l2_service_port::egress_feature_mode_e::L3] = "L3",
            [(int)la_l2_service_port::egress_feature_mode_e::L2] = "L2",
    };

    if ((size_t)mode < array_size(strs)) {
        return std::string(strs[(size_t)mode]);
    }

    return std::string("Unknown mode");
}

std::string
to_string(la_ethernet_port::traffic_matrix_type_e type)
{

    static const char* strs[] = {[(int)la_ethernet_port::traffic_matrix_type_e::INTERNAL] = "INTERNAL",
                                 [(int)la_ethernet_port::traffic_matrix_type_e::EXTERNAL] = "EXTERNAL"};

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown type");
}

std::string
to_string(const la_fwd_class_id& fcid)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "value=" << (size_t)fcid.value << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(const la_pbts_destination_offset& offset)
{
    std::stringstream log_message;

    log_message << LOG_STRUCT_START << "value=" << (size_t)offset.value << LOG_STRUCT_END;

    return log_message.str();
}

std::string
to_string(la_pbts_map_profile::level_e level)
{
    static const char* strs[] = {
        "LEVEL_0", "LEVEL_1", "LEVEL_2", "LEVEL_3",
    };

    if ((size_t)level <= array_size(strs)) {
        return strs[(size_t)level];
    }

    return "Unknown PBTS MAP Profile level";
}

std::string
to_string(pcl_feature_type_e type)
{
    static const char* strs[] = {[(int)pcl_feature_type_e::ACL] = "ACL", [(int)pcl_feature_type_e::LPTS] = "LPTS"};

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown type");
}

} // namespace silicon_one
