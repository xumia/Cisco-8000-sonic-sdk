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

/// SWIG interface file for Leaba SDK driver/CLI.

%feature("flatnested");
%module sdk

%include std_string.i
%include std_vector.i
%include <pybuffer.i>

%{

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"
#include "api/types/la_status_info_types.h"
#include "api/types/la_object.h"
#include "api/types/la_counter_or_meter_set.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_lb_types.h"
#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l2_port.h"
#include "api/npu/la_l3_destination.h"
#include "api/npu/la_ac_profile.h"
#include "api/npu/la_acl_key_profile.h"
#include "api/npu/la_acl_command_profile.h"
#include "api/npu/la_acl_group.h"
#include "api/npu/la_pcl.h"
#include "api/npu/la_security_group_cell.h"
#include "api/npu/la_og_lpts_application.h"
#include "api/npu/la_acl.h"
#include "api/npu/la_acl_scaled.h"
#include "api/npu/la_bfd_session.h"
#include "api/npu/la_lpts.h"
#include "api/npu/la_copc.h"
#include "api/npu/la_counter_set.h"
#include "api/npu/la_destination_pe.h"
#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_filter_group.h"
#include "api/npu/la_ip_over_ip_tunnel_port.h"
#include "api/npu/la_gre_port.h"
#include "api/npu/la_gue_port.h"
#include "api/npu/la_ip_tunnel_destination.h"
#include "api/npu/la_ip_tunnel_port.h"
#include "api/npu/la_l2_protection_group.h"
#include "api/npu/la_l3_protection_group.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_fec.h"
#include "api/npu/la_l2_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_mpls_label_destination.h"
#include "api/npu/la_mpls_nhlfe.h"
#include "api/npu/la_mpls_vpn_decap.h"
#include "api/npu/la_mpls_vpn_encap.h"
#include "api/npu/la_mldp_vpn_decap.h"
#include "api/npu/la_multicast_protection_group.h"
#include "api/npu/la_multicast_protection_monitor.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_lsr.h"
#include "api/npu/la_prefix_object.h"
#include "api/npu/la_asbr_lsp.h"
#include "api/npu/la_protection_monitor.h"
#include "api/npu/la_stack_port.h"
#include "api/npu/la_svi_port.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_te_tunnel.h"
#include "api/npu/la_l2_multicast_group.h"
#include "api/npu/la_ip_multicast_group.h"
#include "api/npu/la_mpls_multicast_group.h"
#include "api/npu/la_fabric_multicast_group.h"
#include "api/npu/la_vrf.h"
#include "api/npu/la_ecmp_group.h"
#include "api/npu/la_forus_destination.h"
#include "api/npu/la_rate_limiter_set.h"
#include "api/npu/la_vxlan_next_hop.h"
#include "api/npu/la_pbts_group.h"
#include "api/npu/la_vrf_redirect_destination.h"

#include "api/packetapi/la_packet_headers.h"
#include "api/packetapi/la_packet_types.h"

#include "api/system/la_pbts_map_profile.h"
#include "api/system/la_device.h"
#include "api/system/la_erspan_mirror_command.h"
#include "api/system/la_fabric_port.h"
#include "api/system/la_flow_cache_handler.h"
#include "api/system/la_hbm_handler.h"
#include "api/system/la_ptp_handler.h"
#include "api/system/la_log.h"
#include "api/system/la_mac_port.h"
#include "api/system/la_npu_host_destination.h"
#include "api/system/la_npu_host_port.h"
#include "api/system/la_recycle_port.h"
#include "api/system/la_remote_port.h"
#include "api/system/la_remote_device.h"
#include "api/system/la_spa_port.h"
#include "api/system/la_system_port.h"
#include "api/system/la_pci_port.h"
#include "api/system/la_punt_inject_port.h"
#include "api/system/la_punt_destination.h"
#include "api/system/la_l2_punt_destination.h"
#include "api/system/la_mirror_command.h"
#include "api/system/la_l2_mirror_command.h"
#include "api/system/la_assert.h"
#include "api/system/la_css_memory_layout.h"

#include "api/tm/la_fabric_port_scheduler.h"
#include "api/tm/la_ifg_scheduler.h"
#include "api/tm/la_interface_scheduler.h"
#include "api/tm/la_logical_port_scheduler.h"
#include "api/tm/la_output_queue_scheduler.h"
#include "api/tm/la_system_port_scheduler.h"
#include "api/tm/la_unicast_tc_profile.h"
#include "api/tm/la_voq_set.h"

#include "api/qos/la_ingress_qos_profile.h"
#include "api/qos/la_egress_qos_profile.h"
#include "api/qos/la_meter_set.h"
#include "api/qos/la_meter_profile.h"
#include "api/qos/la_meter_action_profile.h"
#include "api/qos/la_meter_markdown_profile.h"

#include "api/cgm/la_voq_cgm_evicted_profile.h"
#include "api/cgm/la_rx_cgm_sq_profile.h"
#include "api/cgm/la_voq_cgm_profile.h"

#include "api/types/la_event_types.h"
#include "api/types/la_bfd_types.h"
#include "api/types/la_cgm_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_limit_types.h"
#include "api/types/la_notification_types.h"
#include "api/types/la_security_group_types.h"

#include "apb/apb_types.h"
#include "cpu2jtag/cpu2jtag.h"
#include "api/system/la_info_phy_handler.h"
#include "api/system/la_info_phy_brick_handler.h"

#include "common/la_ip_addr.h"
#include "common/la_profile_database.h"

namespace silicon_one {
        class la_ac_profile_impl;
        class la_acl_key_profile_base;
        class la_acl_command_profile_base;
        class la_acl_group_base;
        class la_pcl_impl;
        class la_acl_impl;
        class la_acl_scaled_impl;
        class la_bfd_session_impl;
        class la_counter_set_impl;
        class la_device_impl;
        class la_destination_pe_impl;
        class la_ecmp_group_impl;
        class la_egress_qos_profile_impl;
        class la_erspan_mirror_command_base;
        class la_ethernet_port_impl;
        class la_fabric_port_impl;
        class la_fabric_port_scheduler_impl;
        class la_l3_fec_impl;
        class la_filter_group_impl;
        class la_flow_cache_handler_impl;
        class la_forus_destination_impl;
        class la_hbm_handler_impl;
        class la_ifg_scheduler_impl;
        class la_asbr_lsp_impl;
        class la_ingress_qos_profile_impl;
        class la_interface_scheduler_impl;
        class la_ip_multicast_group_base;
        class la_ip_over_ip_tunnel_port_impl;
        class la_mpls_multicast_group_impl;
        class la_l2_multicast_group_base;
        class la_security_group_cell_base;
        class la_fabric_multicast_group_impl;
        class la_gre_port_impl;
        class la_gue_port_impl;
        class la_ip_tunnel_destination_impl;
        class la_logical_port_scheduler_impl;
        class la_lpts_impl;
        class la_og_lpts_application_impl;
        class la_l2_mirror_command_base;
        class la_l2_protection_group_base;
        class la_l3_protection_group_impl;
        class la_l2_punt_destination_impl;
        class la_l2_service_port_base;
        class la_l3_ac_port_impl;
        class la_lsr_impl;
        class la_mac_port_base;
        class la_meter_action_profile_impl;
        class la_meter_markdown_profile_impl;
        class la_meter_profile_impl;
        class la_meter_set_impl;
        class la_mpls_label_destination_impl;
        class la_mpls_nhlfe_impl;
        class la_mpls_vpn_decap_impl;
        class la_mpls_vpn_encap_impl;
        class la_mldp_vpn_decap_impl;
        class la_multicast_protection_group_base;
        class la_multicast_protection_monitor_base;
        class la_next_hop_base;
        class la_npu_host_destination_impl;
        class la_npu_host_port_base;
        class la_output_queue_scheduler_impl;
        class la_pci_port_base;
        class la_prefix_object_base;
        class la_copc_base;
        class la_protection_monitor_impl;
        class la_punt_inject_port_base;
        class la_rate_limiter_set_base;
        class la_recycle_port_base;
        class la_remote_port_impl;
        class la_remote_device_base;
        class la_spa_port_base;
        class la_stack_port_base;
        class la_svi_port_base;
        class la_switch_impl;
        class la_system_port_base;
        class la_system_port_scheduler_impl;
        class la_te_tunnel_impl;
        class la_tc_profile_impl;
        class la_rx_cgm_sq_profile_impl;
        class la_voq_cgm_profile_impl;
        class la_voq_cgm_evicted_profile_impl;
        class la_voq_set_impl;
        class la_vrf_impl;
        class la_vxlan_next_hop_impl;
        class la_vxlan_next_hop_base;
        class la_vrf_redirect_destination_impl;
        class apb;
        class la_pbts_map_profile_impl;
        class la_pbts_group_impl;
};

using namespace silicon_one;

#define LA_OBJECT_DOWNCAST_MACRO(LA_TYPE, OBJ_TYPE) \
    case la_object::object_type_e::LA_TYPE:         \
    { \
        silicon_one::OBJ_TYPE* casted_obj = static_cast<OBJ_TYPE*>(object); \
        PyObject* elem_object = SWIG_NewPointerObj(casted_obj, SWIGTYPE_p_silicon_one__##OBJ_TYPE, 0); \
        return elem_object; \
    }

PyObject*
la_object_downcast(silicon_one::la_object* object) {
    if (object == nullptr) {
        PyErr_SetString(PyExc_ValueError, "Expecting an object");
        return nullptr;
    }

    switch(object->type()) {
        LA_OBJECT_DOWNCAST_MACRO(AC_PROFILE, la_ac_profile)
        LA_OBJECT_DOWNCAST_MACRO(ACL_KEY_PROFILE, la_acl_key_profile)
        LA_OBJECT_DOWNCAST_MACRO(ACL_COMMAND_PROFILE, la_acl_command_profile)
        LA_OBJECT_DOWNCAST_MACRO(ACL_GROUP, la_acl_group)
        LA_OBJECT_DOWNCAST_MACRO(PCL, la_pcl)
        LA_OBJECT_DOWNCAST_MACRO(ACL, la_acl)
        LA_OBJECT_DOWNCAST_MACRO(ACL_SCALED, la_acl_scaled)
        LA_OBJECT_DOWNCAST_MACRO(BFD_SESSION, la_bfd_session)
        LA_OBJECT_DOWNCAST_MACRO(COUNTER_SET, la_counter_set)
        LA_OBJECT_DOWNCAST_MACRO(DEVICE, la_device)
        LA_OBJECT_DOWNCAST_MACRO(DESTINATION_PE, la_destination_pe)
        LA_OBJECT_DOWNCAST_MACRO(ECMP_GROUP, la_ecmp_group)
        LA_OBJECT_DOWNCAST_MACRO(EGRESS_QOS_PROFILE, la_egress_qos_profile)
        LA_OBJECT_DOWNCAST_MACRO(ERSPAN_MIRROR_COMMAND, la_erspan_mirror_command)
        LA_OBJECT_DOWNCAST_MACRO(ETHERNET_PORT, la_ethernet_port)
        LA_OBJECT_DOWNCAST_MACRO(FABRIC_PORT, la_fabric_port)
        LA_OBJECT_DOWNCAST_MACRO(FABRIC_PORT_SCHEDULER, la_fabric_port_scheduler)
        LA_OBJECT_DOWNCAST_MACRO(FEC, la_l3_fec)
        LA_OBJECT_DOWNCAST_MACRO(FILTER_GROUP, la_filter_group)
        LA_OBJECT_DOWNCAST_MACRO(FLOW_CACHE_HANDLER, la_flow_cache_handler)
        LA_OBJECT_DOWNCAST_MACRO(FORUS_DESTINATION, la_forus_destination)
        LA_OBJECT_DOWNCAST_MACRO(GRE_PORT, la_gre_port)
        LA_OBJECT_DOWNCAST_MACRO(GUE_PORT, la_gue_port)
        LA_OBJECT_DOWNCAST_MACRO(HBM_HANDLER, la_hbm_handler)
        LA_OBJECT_DOWNCAST_MACRO(PTP_HANDLER, la_ptp_handler)
        LA_OBJECT_DOWNCAST_MACRO(IFG_SCHEDULER, la_ifg_scheduler)
        LA_OBJECT_DOWNCAST_MACRO(INGRESS_QOS_PROFILE, la_ingress_qos_profile)
        LA_OBJECT_DOWNCAST_MACRO(ASBR_LSP, la_asbr_lsp)
        LA_OBJECT_DOWNCAST_MACRO(INTERFACE_SCHEDULER, la_interface_scheduler)
        LA_OBJECT_DOWNCAST_MACRO(IP_MULTICAST_GROUP, la_ip_multicast_group)
        LA_OBJECT_DOWNCAST_MACRO(IP_OVER_IP_TUNNEL_PORT, la_ip_over_ip_tunnel_port)
        LA_OBJECT_DOWNCAST_MACRO(IP_TUNNEL_DESTINATION, la_ip_tunnel_destination)
        LA_OBJECT_DOWNCAST_MACRO(MPLS_MULTICAST_GROUP, la_mpls_multicast_group)
        LA_OBJECT_DOWNCAST_MACRO(L2_MULTICAST_GROUP, la_l2_multicast_group)
        LA_OBJECT_DOWNCAST_MACRO(SECURITY_GROUP_CELL, la_security_group_cell)
        LA_OBJECT_DOWNCAST_MACRO(FABRIC_MULTICAST_GROUP, la_fabric_multicast_group)
        LA_OBJECT_DOWNCAST_MACRO(LOGICAL_PORT_SCHEDULER, la_logical_port_scheduler)
        LA_OBJECT_DOWNCAST_MACRO(LPTS, la_lpts)
        LA_OBJECT_DOWNCAST_MACRO(OG_LPTS_APPLICATION,la_og_lpts_application)
        LA_OBJECT_DOWNCAST_MACRO(L2_MIRROR_COMMAND, la_l2_mirror_command)
        LA_OBJECT_DOWNCAST_MACRO(L2_PROTECTION_GROUP, la_l2_protection_group)
        LA_OBJECT_DOWNCAST_MACRO(L3_PROTECTION_GROUP, la_l3_protection_group)
        LA_OBJECT_DOWNCAST_MACRO(L2_PUNT_DESTINATION, la_l2_punt_destination)
        LA_OBJECT_DOWNCAST_MACRO(L2_SERVICE_PORT, la_l2_service_port)
        LA_OBJECT_DOWNCAST_MACRO(L3_AC_PORT, la_l3_ac_port)
        LA_OBJECT_DOWNCAST_MACRO(LSR, la_lsr)
        LA_OBJECT_DOWNCAST_MACRO(MAC_PORT, la_mac_port)
        LA_OBJECT_DOWNCAST_MACRO(METER_ACTION_PROFILE, la_meter_action_profile)
        LA_OBJECT_DOWNCAST_MACRO(METER_MARKDOWN_PROFILE, la_meter_markdown_profile)
        LA_OBJECT_DOWNCAST_MACRO(METER_PROFILE, la_meter_profile)
        LA_OBJECT_DOWNCAST_MACRO(METER_SET, la_meter_set)
        LA_OBJECT_DOWNCAST_MACRO(MPLS_LABEL_DESTINATION, la_mpls_label_destination)
        LA_OBJECT_DOWNCAST_MACRO(MPLS_NHLFE, la_mpls_nhlfe)
        LA_OBJECT_DOWNCAST_MACRO(MPLS_VPN_DECAP, la_mpls_vpn_decap)
        LA_OBJECT_DOWNCAST_MACRO(MPLS_VPN_ENCAP, la_mpls_vpn_encap)
        LA_OBJECT_DOWNCAST_MACRO(MLDP_VPN_DECAP, la_mldp_vpn_decap)
        LA_OBJECT_DOWNCAST_MACRO(MULTICAST_PROTECTION_GROUP, la_multicast_protection_group)
        LA_OBJECT_DOWNCAST_MACRO(MULTICAST_PROTECTION_MONITOR, la_multicast_protection_monitor)
        LA_OBJECT_DOWNCAST_MACRO(NEXT_HOP, la_next_hop)
        LA_OBJECT_DOWNCAST_MACRO(NPU_HOST_DESTINATION, la_npu_host_destination)
        LA_OBJECT_DOWNCAST_MACRO(NPU_HOST_PORT, la_npu_host_port)
        LA_OBJECT_DOWNCAST_MACRO(OUTPUT_QUEUE_SCHEDULER, la_output_queue_scheduler)
        LA_OBJECT_DOWNCAST_MACRO(PCI_PORT, la_pci_port)
        LA_OBJECT_DOWNCAST_MACRO(PREFIX_OBJECT, la_prefix_object)
        LA_OBJECT_DOWNCAST_MACRO(COPC, la_control_plane_classifier)
        LA_OBJECT_DOWNCAST_MACRO(PROTECTION_MONITOR, la_protection_monitor)
        LA_OBJECT_DOWNCAST_MACRO(PUNT_INJECT_PORT, la_punt_inject_port)
        LA_OBJECT_DOWNCAST_MACRO(RATE_LIMITER_SET, la_rate_limiter_set)
        LA_OBJECT_DOWNCAST_MACRO(RECYCLE_PORT, la_recycle_port)
        LA_OBJECT_DOWNCAST_MACRO(REMOTE_PORT, la_remote_port)
        LA_OBJECT_DOWNCAST_MACRO(REMOTE_DEVICE, la_remote_device)
        LA_OBJECT_DOWNCAST_MACRO(SPA_PORT, la_spa_port)
        LA_OBJECT_DOWNCAST_MACRO(STACK_PORT, la_stack_port)
        LA_OBJECT_DOWNCAST_MACRO(SVI_PORT, la_svi_port)
        LA_OBJECT_DOWNCAST_MACRO(SWITCH, la_switch)
        LA_OBJECT_DOWNCAST_MACRO(SYSTEM_PORT, la_system_port)
        LA_OBJECT_DOWNCAST_MACRO(SYSTEM_PORT_SCHEDULER, la_system_port_scheduler)
        LA_OBJECT_DOWNCAST_MACRO(TE_TUNNEL, la_te_tunnel)
        LA_OBJECT_DOWNCAST_MACRO(TC_PROFILE, la_tc_profile)
        LA_OBJECT_DOWNCAST_MACRO(RX_CGM_SQ_PROFILE, la_rx_cgm_sq_profile)
        LA_OBJECT_DOWNCAST_MACRO(VOQ_CGM_PROFILE, la_voq_cgm_profile)
        LA_OBJECT_DOWNCAST_MACRO(VOQ_SET, la_voq_set)
        LA_OBJECT_DOWNCAST_MACRO(VRF, la_vrf)
        LA_OBJECT_DOWNCAST_MACRO(VXLAN_NEXT_HOP, la_vxlan_next_hop)
        LA_OBJECT_DOWNCAST_MACRO(VOQ_CGM_EVICTED_PROFILE, la_voq_cgm_evicted_profile)
        LA_OBJECT_DOWNCAST_MACRO(PBTS_MAP_PROFILE, la_pbts_map_profile)
        LA_OBJECT_DOWNCAST_MACRO(PBTS_GROUP, la_pbts_group)
        LA_OBJECT_DOWNCAST_MACRO(VRF_REDIRECT_DESTINATION, la_vrf_redirect_destination)
    default:
        return nullptr;
    }
}

%}

%include "include/common/common_swig_typemaps.i"
%include "lld/swig_typemaps.i"

%rename (get_sms_bytes_quantization_gb) get_sms_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
%rename (get_sms_packets_quantization_gb) get_sms_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
%rename (get_sms_age_quantization_gb) get_sms_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
%rename (get_averaging_configuration_gb) get_averaging_configuration(double& out_ema_coefficient, la_voq_cgm_quantization_thresholds& out_thresholds) const;
%rename (get_fcn_configuration_gb) get_fcn_configuration(bool out_enabled, std::vector<double>& out_action_probabilities) const;
%rename (get_cgm_sms_voqs_bytes_quantization_gb) get_cgm_sms_voqs_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
%rename (get_cgm_sms_voqs_packets_quantization_gb) get_cgm_sms_voqs_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
%rename (get_cgm_hbm_number_of_voqs_quantization_gb) get_cgm_hbm_number_of_voqs_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
%rename (get_cgm_hbm_pool_free_blocks_quantization_gb) get_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id, la_voq_cgm_quantization_thresholds& out_thresholds) const;
%rename (get_cgm_hbm_blocks_by_voq_quantization_gb) get_cgm_hbm_blocks_by_voq_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
%typemap(out) silicon_one::la_object*
{
    $result = la_object_downcast($1);
}

%typemap(out) std::vector< silicon_one::la_object *,std::allocator< silicon_one::la_object * > >
{
    $result = PyList_New($1.size());
    for(size_t i = 0; i < $1.size(); ++i)
    {
       PyObject* elem_object = la_object_downcast($1.at(i));
       PyList_SetItem($result, i, elem_object);
    }
}

%typemap(out) std::vector< silicon_one::la_object const*,std::allocator< silicon_one::la_object const* > >
{
    $result = PyList_New($1.size());
    for(size_t i = 0; i < $1.size(); ++i)
    {
       silicon_one::la_object* casted_obj = const_cast<la_object*>(static_cast<const silicon_one::la_object*>($1.at(i))); \
       PyObject* elem_object = la_object_downcast(casted_obj);
       PyList_SetItem($result, i, elem_object);
    }
}


// BSWAP
%typemap(in,numinputs=1,noblock=1) (const unsigned char* c_header, size_t bytes_nr, unsigned char* out_npl_header) {

    if (!PyList_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        return NULL;
    }

    $2 = PyList_Size($input);
    $1 = (unsigned char*)calloc($2, sizeof(unsigned char));
    $3 = (unsigned char*)calloc($2, sizeof(unsigned char));
    for (size_t j = 0; j < $2; j++) {
      PyObject *py = PyList_GetItem($input, j);
      $1[j] = PyLong_AsLongLong(py);
    }
}

%typemap(argout,noblock=1) (const unsigned char* c_header, size_t bytes_nr, unsigned char* out_npl_header) {
    $result = PyList_New($2);
    for (size_t i = 0; i < $2; i++) {
        PyList_SetItem($result, i, PyLong_FromLongLong($3[i]));
    }
}

%typemap(freearg,noblock=1) (const unsigned char* c_header, size_t bytes_nr, unsigned char* out_npl_header) {
    free($1);
    free($3);
}

// Typemap converting string out-arg to Python
%define OUTARG_STRING_TYPEMAPS(TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) TYPE& ARG (size_t _global_processed_args_count) {
    _global_processed_args_count = 0;
    std::string temp_$1;
    $1 = &temp_$1;
}

%typemap(argout) TYPE& ARG {
    PyObject* out_object = PyString_FromString((temp_$1).c_str());

    $result = add_argout_value($result, out_object, _global_processed_args_count);
}

%typemap(out) la_uint128_t {
    $result = PyInt_FromLong(static_cast<__int128>($1));
}

%enddef

%typemap(in) (const la_rate_t rate_limit) {
    $1 = PyLong_AsLongLong($input);
}



ARRAY_HANDLER(char, PyLong_AsLongLong, PyLong_FromLongLong)
ARRAY_HANDLER(unsigned char, PyLong_AsLongLong, PyLong_FromLongLong)
ARRAY_HANDLER(int, PyLong_AsLongLong, PyLong_FromLongLong)
ARRAY_HANDLER(unsigned short, PyLong_AsLongLong, PyLong_FromLongLong);
ARRAY_HANDLER(unsigned int, PyLong_AsLongLong, PyLong_FromLongLong)
ARRAY_HANDLER(unsigned long, PyLong_AsLongLong, PyLong_FromLongLong)
ARRAY_HANDLER(unsigned long long, PyLong_AsLongLong, PyLong_FromLongLong)
ARRAY_HANDLER(float, PyFloat_AsDouble, PyFloat_FromDouble)
ARRAY_HANDLER(double, PyFloat_AsDouble, PyFloat_FromDouble)
ARRAY_HANDLER(bool, PyLong_AsLongLong, PyBool_FromLong)
ARRAY_HANDLER(size_t, PyLong_AsLongLong, PyLong_FromLongLong)

OUTARG_BOOL_TYPEMAPS(out_active)
OUTARG_BOOL_TYPEMAPS(out_activated)
OUTARG_BOOL_TYPEMAPS(out_allow_drop)
OUTARG_BOOL_TYPEMAPS(out_completed)
OUTARG_BOOL_TYPEMAPS(out_drop_enable)
OUTARG_BOOL_TYPEMAPS(out_debug_status)
OUTARG_BOOL_TYPEMAPS(out_empty)
OUTARG_BOOL_TYPEMAPS(out_enabled)
OUTARG_BOOL_TYPEMAPS(out_enforcement)
OUTARG_BOOL_TYPEMAPS(out_evict_to_hbm)
OUTARG_BOOL_TYPEMAPS(out_global)
OUTARG_BOOL_TYPEMAPS(out_invert)
OUTARG_BOOL_TYPEMAPS(out_is_eir)
OUTARG_BOOL_TYPEMAPS(out_mark_ecn)
OUTARG_BOOL_TYPEMAPS(out_mode)
OUTARG_BOOL_TYPEMAPS(out_property_value)
OUTARG_BOOL_TYPEMAPS(out_signal_ok)
OUTARG_BOOL_TYPEMAPS(out_sync_status)
OUTARG_BOOL_TYPEMAPS(out_is_acl_conditioned)
OUTARG_BOOL_TYPEMAPS(out_is_high_priority)
OUTARG_BOOL_TYPEMAPS(out_skip_inject_up_packets)
OUTARG_BOOL_TYPEMAPS(out_skip_p2p_packets)
OUTARG_BOOL_TYPEMAPS(out_overwrite_phb)
OUTARG_BOOL_TYPEMAPS(out_counter_allocated)
OUTARG_BOOL_TYPEMAPS(out_punt_enabled)
OUTARG_BOOL_TYPEMAPS(out_punt_snoop_enabled)
OUTARG_BOOL_TYPEMAPS(out_owner)
OUTARG_BOOL_TYPEMAPS(out_drop_unknown_uc_enabled)
OUTARG_BOOL_TYPEMAPS(out_drop_unknown_mc_enabled)
OUTARG_BOOL_TYPEMAPS(out_drop_unknown_bc_enabled)
OUTARG_BOOL_TYPEMAPS(out_label_present)
OUTARG_BOOL_TYPEMAPS(out_flow_control)
OUTARG_BOOL_TYPEMAPS(out_drop_yellow)
OUTARG_BOOL_TYPEMAPS(out_drop_green)
OUTARG_BOOL_TYPEMAPS(out_fc_trig)
OUTARG_BOOL_TYPEMAPS(out_primary_active)
OUTARG_BOOL_TYPEMAPS(out_backup_active)
OUTARG_BOOL_TYPEMAPS(out_fcn_enabled)

OUTARG_FLOAT_TYPEMAPS(silicon_one::la_temperature_t, out_temperature)
OUTARG_FLOAT_TYPEMAPS(silicon_one::la_voltage_t, out_voltage)
OUTARG_FLOAT_TYPEMAPS(float, out_threshold)
OUTARG_FLOAT_TYPEMAPS(la_float_t, out_max_pps_percent)
OUTARG_FLOAT_TYPEMAPS(la_float_t, out_max_rate_percent)
OUTARG_FLOAT_TYPEMAPS(double, out_ema_coefficient)
OUTARG_FLOAT_TYPEMAPS(double, out_probability)
OUTARG_FLOAT_TYPEMAPS(float, out_probability)
OUTARG_FLOAT_TYPEMAPS(double, out_precision)

OUTARG_ENUM_TYPEMAPS(int, out_fd_critical)
OUTARG_ENUM_TYPEMAPS(int, out_fd_normal)
OUTARG_ENUM_TYPEMAPS(int, out_overhead)
OUTARG_ENUM_TYPEMAPS(int, out_property_value)
OUTARG_ENUM_TYPEMAPS(int32_t, out_value)
OUTARG_ENUM_TYPEMAPS(uint32_t, out_serdes_addr)
OUTARG_ENUM_TYPEMAPS(size_t, out_burst)
OUTARG_ENUM_TYPEMAPS(size_t, out_count)
OUTARG_ENUM_TYPEMAPS(size_t, out_available_space)
OUTARG_ENUM_TYPEMAPS(size_t, out_counter)
OUTARG_ENUM_TYPEMAPS(size_t, out_dropped_packets)
OUTARG_ENUM_TYPEMAPS(size_t, out_id)
OUTARG_ENUM_TYPEMAPS(size_t, out_packets)
OUTARG_ENUM_TYPEMAPS(size_t, out_num_of_serdes)
OUTARG_ENUM_TYPEMAPS(size_t, out_member_id)
OUTARG_ENUM_TYPEMAPS(size_t, out_bytes)
OUTARG_ENUM_TYPEMAPS(size_t, out_size)
OUTARG_ENUM_TYPEMAPS(size_t, out_group_size)
OUTARG_ENUM_TYPEMAPS(size_t, out_state)
OUTARG_ENUM_TYPEMAPS(size_t, out_key_size)
OUTARG_ENUM_TYPEMAPS(size_t, out_num_links)
OUTARG_ENUM_TYPEMAPS(size_t, out_offset)
OUTARG_ENUM_TYPEMAPS(size_t, out_load_balancing_node_id)
OUTARG_ENUM_TYPEMAPS(la_user_data_t, out_token)
OUTARG_STRING_TYPEMAPS(std::string, out_property_value)

OUTARG_ENUM_TYPEMAPS(la_rate_t, out_cir)
OUTARG_ENUM_TYPEMAPS(la_rate_t, out_eir)
OUTARG_ENUM_TYPEMAPS(la_rate_t, out_rate)
OUTARG_ENUM_TYPEMAPS(la_rate_t, out_rate_limit)
OUTARG_ENUM_TYPEMAPS(la_sgt_t, out_sgt)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_fw_id)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_build_id)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_min_size)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_max_size)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_serdes)
OUTARG_ENUM_TYPEMAPS(la_uint16_t, out_gap_len)
OUTARG_ENUM_TYPEMAPS(la_uint16_t, out_gap_tx_bytes)
OUTARG_ENUM_TYPEMAPS(la_uint64_t, out_cbs)
OUTARG_ENUM_TYPEMAPS(la_uint64_t, out_ebs_or_pbs)
OUTARG_ENUM_TYPEMAPS(la_uint64_t, out_max_addresses)
OUTARG_ENUM_TYPEMAPS(la_uint8_t, out_offset)
OUTARG_ENUM_TYPEMAPS(la_uint8_t, out_detection_time_multiplier)
OUTARG_ENUM_TYPEMAPS(la_uint8_t, out_ttl)
OUTARG_ENUM_TYPEMAPS(la_uint8_t, out_prof_val)
OUTARG_ENUM_TYPEMAPS(la_uint8_t, out_bd_attributes)
OUTARG_ENUM_TYPEMAPS(la_uint64_t, out_limit)
OUTARG_ENUM_TYPEMAPS(la_uint16_t, out_lb_id)
OUTARG_ENUM_TYPEMAPS(la_vni_t, out_vni)
OUTARG_ENUM_TYPEMAPS(la_uint32_t, out_count)
OUTARG_ENUM_TYPEMAPS(la_uint64_t, out_free_buffer_count)
OUTARG_ENUM_TYPEMAPS(la_uint64_t, out_offset)
OUTARG_ENUM_TYPEMAPS(la_uint64_t, out_inject_count)
OUTARG_ENUM_TYPEMAPS(la_uint64_t, out_punt_count)
OUTARG_ENUM_TYPEMAPS(la_uint8_t, out_mep_lvl)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_control_plane_classifier::ethernet_profile_id_t, out_ethernet_profile_id)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_control_plane_classifier::switch_profile_id_t, out_switch_profile_id)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_control_plane_classifier::l2_service_port_profile_id_t, out_l2_service_port_profile_id)

OUTARG_ENUM_TYPEMAPS(silicon_one::la_ac_profile::key_selector_e, out_key_selector)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_device::learn_mode_e, out_learn_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_filter_group::filtering_mode_e, out_filtering_mode)
OUTARG_ENUM_TYPEMAPS(la_wfq_weight_t, out_weight)
OUTARG_ENUM_TYPEMAPS(la_wfq_weight_t, out_mcw)
OUTARG_ENUM_TYPEMAPS(la_wfq_weight_t, out_ucw)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_redirect_code_t, out_redirect_code)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_system_port_scheduler::priority_group_e, out_pg)
OUTARG_ENUM_TYPEMAPS(la_trap_priority_t, out_priority)
OUTARG_ENUM_TYPEMAPS(la_snoop_priority_t, out_priority)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_traffic_class_t, out_tc)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_protection_monitor::monitor_state_e, out_state)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_acl::stage_e, out_stage);
OUTARG_ENUM_TYPEMAPS(silicon_one::la_acl::type_e, out_type);
OUTARG_ENUM_TYPEMAPS(silicon_one::la_pcl::type_e, out_type);
OUTARG_ENUM_TYPEMAPS(silicon_one::pcl_feature_type_e, out_feature)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_og_lpts_application::type_e, out_type);
OUTARG_ENUM_TYPEMAPS(silicon_one::la_acl_key_type_e, out_key_type);
OUTARG_ENUM_TYPEMAPS(silicon_one::la_acl_tcam_pool_id_t, out_tcam_pool_id);
OUTARG_ENUM_TYPEMAPS(silicon_one::la_acl_key_profile::key_size_e, out_key_size);
OUTARG_ENUM_TYPEMAPS(silicon_one::la_ethernet_port::svi_egress_tag_mode_e, out_mode);
OUTARG_ENUM_TYPEMAPS(silicon_one::la_egress_qos_marking_source_e, out_marking_source)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_gre_port::tunnel_termination_type_e, out_term_type)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_ip_tunnel_mode_e, out_tunnel_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_l3_port::urpf_mode_e, out_urpf_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_l3_port::lb_profile_e, out_lb_profile)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::port_speed_e, out_speed)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::fc_mode_e, out_fc_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::fec_mode_e, out_fec_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::loopback_mode_e, out_loopback_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::pcs_test_mode_e, out_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::pma_test_mode_e, out_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::serdes_test_mode_e, out_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::serdes_param_mode_e, out_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::serdes_tuning_mode_e, out_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::fec_bypass_e, out_fec_bp)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::state_e, out_state)
OUTARG_ENUM_TYPEMAPS(la_layer_e, out_layer)
OUTARG_ENUM_TYPEMAPS(la_lp_mac_learning_mode_e, out_learning_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_cgm_hbm_pool_id_t, out_hbm_pool_id)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_cgm_sms_voqs_age_time_units_t, out_sms_voqs_age_time_units)
OUTARG_ENUM_TYPEMAPS(la_lb_mode_e, out_lb_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_traffic_class_t, out_tc)
OUTARG_ENUM_TYPEMAPS(la_replication_paradigm_e, out_replication_paradigm)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_meter_profile::meter_measure_mode_e, out_meter_measure_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_meter_profile::meter_rate_mode_e, out_meter_rate_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_meter_profile::color_awareness_mode_e, out_color_awareness_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_meter_set::coupling_mode_e, out_coupling_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_meter_set::cascade_mode_e, out_cascade_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_qos_color_e, out_color)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_qos_color_e, out_drop_color_level)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_qos_color_e, out_packet_color)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_qos_color_e, out_rx_cgm_color)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_qos_group_t, out_qos_group)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_slice_mode_e, out_slice_mode)
OUTARG_ENUM_TYPEMAPS(la_vlan_id_t, out_vid1)
OUTARG_ENUM_TYPEMAPS(la_vlan_id_t, out_vid2)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_output_queue_scheduler::scheduling_mode_e, out_mode)
OUTARG_ENUM_TYPEMAPS(la_vsc_gid_t, out_base_vsc)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_over_subscription_tc_t, out_default_ostc)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_over_subscription_tc_t, out_ostc)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_initial_tc_t, out_default_itc)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_initial_tc_t, out_itc)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_voq_cgm_profile::wred_action_e, out_action)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_next_hop::nh_type_e, out_nh_type)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_te_tunnel::tunnel_type_e, out_type)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_prefix_object::prefix_type_e, out_type)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_pbts_map_profile::level_e, out_level)
OUTARG_ENUM_TYPEMAPS(la_uint64_t, out_profile_id)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_prefix_object::lsp_counter_mode_e, out_counter_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_voq_set::state_e, out_state)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_voq_set::voq_counter_type_e, out_voq_counter_type)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_resource_granularity, out_granularity)
OUTARG_ENUM_TYPEMAPS(la_mac_aging_time_t, out_mac_aging_time)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::pfc_config_queue_state_e, out_state)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_mac_port::pfc_queue_state_e, out_state)
OUTARG_ENUM_TYPEMAPS(la_port_stp_state_e, out_state)
OUTARG_ENUM_TYPEMAPS(la_lp_mac_learning_mode_e, out_learning_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_bfd_session::la_bfd_diagnostic_code_e, out_diag_code)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_bfd_session::type_e, out_type)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_rx_cgm_hr_management_mode_e, out_mode)
OUTARG_ENUM_TYPEMAPS(uint32_t, out_synce_pin)
OUTARG_ENUM_TYPEMAPS(uint32_t, out_divider)
OUTARG_ENUM_TYPEMAPS(size_t, out_count_success)
OUTARG_ENUM_TYPEMAPS(la_class_id_t, out_class_id)
OUTARG_ENUM_TYPEMAPS(la_slice_id_t, out_slice_id)
OUTARG_ENUM_TYPEMAPS(la_ifg_id_t, out_ifg_id)
OUTARG_ENUM_TYPEMAPS(la_uint8_t, out_tc_bitmap)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_serdes_id)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_ac_profile::qos_mode_e, out_qos_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_l2_service_port::egress_feature_mode_e, out_mode)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_device::fabric_mac_ports_mode_e, out_fabric_mac_ports_mode)
OUTARG_ENUM_TYPEMAPS(size_t, out_age)
OUTARG_ENUM_TYPEMAPS(la_device_id_t, out_device_id)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_packets)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_group_index)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_drop_counter_index)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_value)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_balance)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_rate)
OUTARG_ENUM_TYPEMAPS(la_uint_t, out_rate_map_index)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_control_plane_classifier::type_e, out_type)
OUTARG_ENUM_TYPEMAPS(size_t, out_count)
OUTARG_ENUM_TYPEMAPS(silicon_one::la_l2_service_port::feature_control_type_e, out_control_type)

OUTARG_STRUCT_TYPEMAPS(silicon_one::la_pbts_destination_offset, out_pbts_offset)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_pbts_destination_offset, out_max_offset)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_voq_set::voq_size, out_size);
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_cgm_hbm_blocks_by_voq_quantization_thresholds, out_thresholds);
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_cgm_hbm_number_of_voqs_quantization_thresholds, out_thresholds);
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_cgm_hbm_pool_free_blocks_quantization_thresholds, out_thresholds);
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_cgm_sms_packets_quantization_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_voq_cgm_profile::sms_bytes_quantization_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_voq_cgm_quantization_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_voq_cgm_profile::sms_packets_quantization_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_voq_cgm_profile::wred_blocks_quantization_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_voq_cgm_profile::wred_regions_probabilties, out_action_probabilities)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_voq_cgm_evicted_profile::la_voq_sms_evicted_buffers_drop_val, out_val)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_device_info_t, out_dev_info)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_fabric_port::port_status, out_port_status)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_fabric_port::adjacent_peer_info, out_adjacent_peer_info)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_flow_cache_handler::flow_cache_counters, out_flow_cache_counters)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_hbm_handler::error_counters, out_err_counters)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ptp_handler::ptp_time, out_load_time)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ptp_handler::ptp_pads_config, out_config)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ptp_handler::ptp_time_unit, out_time_unit)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ip_route_info, out_ip_route_info)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ip_mc_route_info, out_ip_mc_route_info)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_l2_mc_route_info, out_l2_mc_route_info)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mpls_route_info, out_mpls_route_info)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mpls_label, out_label)
OUTARG_STRUCT_TYPEMAPS(silicon_one::acl_entry_desc, out_acl_entry_desc)
OUTARG_STRUCT_TYPEMAPS(silicon_one::acl_new_entry_desc, out_acl_new_entry_desc)
OUTARG_STRUCT_TYPEMAPS(silicon_one::lpts_entry_desc, out_lpts_entry_desc)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_lpts_key_og, out_la_lpts_key_og)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_lpts_app_properties, out_la_lpts_app_properties)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_lpts_app_properties_key_fields, out_la_lpts_app_properties_key_fields)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::serdes_status, out_serdes_status)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::mac_status, out_mac_status)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::mac_pcs_lane_mapping, out_mac_pcs_lane_mapping)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::mac_pma_ber, out_mac_pma_ber)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::serdes_prbs_ber, out_serdes_prbs_ber)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::mib_counters, out_mib_counters)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::rs_fec_debug_counters, out_debug_counters)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::rs_fec_sym_err_counters, out_sym_err_counters)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_egress_qos_profile::encapsulating_headers_qos_values, out_encap_qos_values)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_vlan_pcpdei, out_remark_pcpdei)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_vlan_pcpdei, out_mapped_pcpdei_tag)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_vlan_pcpdei, out_pcpdei)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ip_dscp, out_remark_dscp)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ip_dscp, out_mapped_dscp_tag)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ip_dscp, out_dscp)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mpls_tc, out_remark_mpls_tc)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mpls_tc, out_mpls_tc)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mpls_tc, out_mapped_mpls_tc_tag)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mpls_tc, out_encap_mpls_tc)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ip_dscp, out_markdown_dscp)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_vlan_pcpdei, out_markdown_pcp)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mpls_tc, out_markdown_mpls_tc)
OUTARG_STRUCT_TYPEMAPS(la_vlan_tag_t, out_tag1)
OUTARG_STRUCT_TYPEMAPS(la_vlan_tag_t, out_tag2)
OUTARG_STRUCT_TYPEMAPS(la_vlan_tag_tci_t, out_vlan_tag)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_cgm_sms_bytes_quantization_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_resource_usage_descriptor, out_descriptor)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_resource_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ipv4_route_entry_parameters, out_la_ipv4_route_entry_parameters)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ipv6_route_entry_parameters, out_la_ipv6_route_entry_parameters)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::ostc_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(la_mac_addr_t, out_mac_addr)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ipv4_addr_t, out_addr)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ipv4_prefix_t, out_prefix)
OUTARG_STRUCT_TYPEMAPS(la_vlan_edit_command, out_edit_command)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ipv4_addr_t, out_ipv4_addr)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::link_down_interrupt_histogram, out_link_down_histogram)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::serdes_debug_info_e, out_serdes_debug_info)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::serdes_ctrl_e, out_serdes_ctrl_e)
OUTARG_STRUCT_TYPEMAPS(silicon_one::cem::cem_age_info, out_age_info)
OUTARG_STRUCT_TYPEMAPS(la_mac_age_info_t, out_mac_entry_info)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_device::la_heartbeat_t, out_heartbeat)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_device::la_sms_packet_counts, out_packet_count)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_device::la_sms_error_counts, out_error_count)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_device::la_cgm_watermarks, out_watermarks)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_rx_cgm_sms_bytes_quantization_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_rx_cgm_sqg_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_rx_cgm_sq_profile_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_rx_pdr_sms_bytes_drop_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_tx_cgm_oq_profile_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(la_fabric_valid_links_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(la_fabric_congested_links_thresholds, out_thresholds)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_system_port::egress_max_congestion_watermark, out_cong_wm)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_system_port::egress_max_delay_watermark, out_delay_wm)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mac_port::output_queue_counters, out_counters)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_control_plane_classifier::entry_desc, out_copc_entry_desc)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ip_multicast_group::member_info, out_member)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_info_phy_brick_handler::info_link_counters, out_info_link_counters)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_mpls_multicast_group::la_mpls_multicast_group_member_info, out_member)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_ip_tos, out_tos)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_bfd_discriminator, out_local_discriminator)
OUTARG_STRUCT_TYPEMAPS(silicon_one::la_bfd_discriminator, out_remote_discriminator)
OUTARG_PTR_TYPEMAPS(silicon_one::la_ac_profile*, out_ac_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_acl_key_profile* ,out_acl_key_profile);
OUTARG_PTR_TYPEMAPS(silicon_one::la_acl_command_profile* ,out_acl_command_profile);
OUTARG_PTR_TYPEMAPS(silicon_one::la_acl_group* ,out_acl_group);
OUTARG_PTR_TYPEMAPS(silicon_one::la_pcl*, out_pcl)
OUTARG_PTR_TYPEMAPS(silicon_one::la_acl*, out_acl)
OUTARG_PTR_TYPEMAPS(silicon_one::la_acl*, out_sgacl)
OUTARG_PTR_TYPEMAPS(silicon_one::la_acl_scaled*, out_acl)
OUTARG_PTR_TYPEMAPS(silicon_one::la_bfd_session*, out_bfd_session)
OUTARG_PTR_TYPEMAPS(silicon_one::la_lpts*, out_lpts)
OUTARG_PTR_TYPEMAPS(silicon_one::la_og_lpts_application*, out_lpts_app)
OUTARG_PTR_TYPEMAPS(silicon_one::la_forus_destination*, out_destination)
OUTARG_PTR_TYPEMAPS(silicon_one::la_ip_addr*, la_ip_addr)
OUTARG_PTR_TYPEMAPS(silicon_one::la_device*, out_device)
OUTARG_PTR_TYPEMAPS(silicon_one::la_ecmp_group*,  out_ecmp_group);
OUTARG_PTR_TYPEMAPS(silicon_one::la_ethernet_port*, out_ethernet_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_filter_group*, out_filter_group)
OUTARG_PTR_TYPEMAPS(silicon_one::la_flow_cache_handler*, out_flow_cache_handler)
OUTARG_PTR_TYPEMAPS(silicon_one::la_fabric_port*, out_fabric_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_gre_port*, out_gre_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_gue_port*, out_gue_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_hbm_handler*, out_hbm)
OUTARG_PTR_TYPEMAPS(silicon_one::la_ptp_handler*, out_ptp)
OUTARG_PTR_TYPEMAPS(silicon_one::apb*, out_apb)
OUTARG_PTR_TYPEMAPS(silicon_one::cpu2jtag*, out_cpu2jtag)
OUTARG_PTR_TYPEMAPS(silicon_one::la_info_phy_handler*, out_info_phy)
OUTARG_PTR_TYPEMAPS(silicon_one::la_ifg_scheduler*, out_sch)
OUTARG_PTR_TYPEMAPS(silicon_one::la_ip_tunnel_destination*, out_ip_tunnel_destination)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l2_destination*, out_l2_destination)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l2_protection_group*, out_l2_protection_group)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l2_mirror_command*, out_mirror_cmd)
OUTARG_PTR_TYPEMAPS(silicon_one::la_erspan_mirror_command*, out_mirror_cmd)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l2_punt_destination*, out_punt_dest)
OUTARG_PTR_TYPEMAPS(silicon_one::la_counter_set*, out_counter)
OUTARG_PTR_TYPEMAPS(silicon_one::la_mirror_command*, out_mirror_cmd)
OUTARG_PTR_TYPEMAPS(silicon_one::la_counter_or_meter_set*, out_counter_or_meter)
OUTARG_PTR_TYPEMAPS(silicon_one::la_meter_set*, out_meter)
OUTARG_PTR_TYPEMAPS(silicon_one::la_meter_profile*, out_meter_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_meter_action_profile*, out_meter_action_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_meter_markdown_profile*, out_meter_markdown_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l2_service_port*, out_l2_service_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l3_ac_port*, out_l3_ac_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l3_destination*, out_l3_destination)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l3_protection_group*, out_l3_protection_group)
OUTARG_PTR_TYPEMAPS(silicon_one::la_forus_destination*, out_forus_destination)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l3_fec*, out_fec)
OUTARG_PTR_TYPEMAPS(silicon_one::la_logical_port_scheduler*, out_lp_sch)
OUTARG_PTR_TYPEMAPS(silicon_one::la_lsr*, out_lsr)
OUTARG_PTR_TYPEMAPS(silicon_one::la_mac_port*, out_mac_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_voq_cgm_evicted_profile*, out_evicted_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_rx_cgm_sq_profile*, out_default_rx_cgm_sq_profile);
OUTARG_PTR_TYPEMAPS(silicon_one::la_rx_cgm_sq_profile*, out_profile);
OUTARG_PTR_TYPEMAPS(silicon_one::la_rx_cgm_sq_profile*, out_rx_cgm_sq_profile);
OUTARG_PTR_TYPEMAPS(silicon_one::la_voq_cgm_profile*, out_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_mpls_label_destination*, out_mpls_label_destination)
OUTARG_PTR_TYPEMAPS(silicon_one::la_mpls_nhlfe*, out_nhlfe)
OUTARG_PTR_TYPEMAPS(silicon_one::la_mpls_vpn_decap*, out_mpls_vpn_decap)
OUTARG_PTR_TYPEMAPS(silicon_one::la_mpls_vpn_encap*, out_mpls_vpn_encap)
OUTARG_PTR_TYPEMAPS(silicon_one::la_mldp_vpn_decap*, out_mldp_vpn_decap)
OUTARG_PTR_TYPEMAPS(silicon_one::la_multicast_protection_group*, out_multicast_protection_group)
OUTARG_PTR_TYPEMAPS(silicon_one::la_multicast_protection_monitor*, out_protection_monitor)
OUTARG_PTR_TYPEMAPS(silicon_one::la_next_hop*, out_next_hop)
OUTARG_PTR_TYPEMAPS(silicon_one::la_npu_host_destination*, out_npu_host_destination)
OUTARG_PTR_TYPEMAPS(silicon_one::la_npu_host_port*, out_npu_host_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_output_queue_scheduler*, out_oq_sch)
OUTARG_PTR_TYPEMAPS(silicon_one::la_pci_port*, out_pci_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_prefix_object*, out_prefix)
OUTARG_PTR_TYPEMAPS(silicon_one::la_control_plane_classifier*, out_copc)
OUTARG_PTR_TYPEMAPS(silicon_one::la_prefix_object*, out_prefix_object)
OUTARG_PTR_TYPEMAPS(silicon_one::la_destination_pe*, out_destination_pe)
OUTARG_PTR_TYPEMAPS(silicon_one::la_asbr_lsp*, out_asbr_lsp)
OUTARG_PTR_TYPEMAPS(silicon_one::la_te_tunnel*, out_te_tunnel)
OUTARG_PTR_TYPEMAPS(silicon_one::la_protection_monitor*, out_protection_monitor);
OUTARG_PTR_TYPEMAPS(silicon_one::la_punt_destination*, out_destination);
OUTARG_PTR_TYPEMAPS(silicon_one::la_punt_inject_port*, out_punt_inject_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_recycle_port*, out_recycle_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_remote_port*, out_remote_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_remote_device*, out_remote_device)
OUTARG_PTR_TYPEMAPS(silicon_one::la_spa_port*, out_spa_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_ip_over_ip_tunnel_port*, out_ip_over_ip_tunnel_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_pbts_map_profile*, out_pbts_map_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_pbts_group*, out_pbts_group)
OUTARG_PTR_TYPEMAPS(silicon_one::la_stack_port*, out_stack_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_svi_port*, out_svi_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_switch*, out_switch)
OUTARG_PTR_TYPEMAPS(silicon_one::la_system_port*, out_system_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_system_port*, out_dsp)
OUTARG_PTR_TYPEMAPS(silicon_one::la_vrf*, out_vrf)
OUTARG_PTR_TYPEMAPS(silicon_one::la_vxlan_next_hop*, out_vxlan_next_hop)
OUTARG_PTR_TYPEMAPS(silicon_one::la_ingress_qos_profile*, out_ingress_qos_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_egress_qos_profile*, out_egress_qos_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_voq_cgm_profile*, out_cgm_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_voq_set*, out_voq_set)
OUTARG_PTR_TYPEMAPS(silicon_one::la_tc_profile*, out_tc_profile)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l2_multicast_group*, out_l2_multicast_group)
OUTARG_PTR_TYPEMAPS(silicon_one::la_ip_multicast_group*, out_ip_multicast_group)
OUTARG_PTR_TYPEMAPS(silicon_one::la_mpls_multicast_group*, out_mpls_multicast_group)
OUTARG_PTR_TYPEMAPS(silicon_one::la_fabric_multicast_group*, out_fabric_multicast_group)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l2_destination*, out_destination)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l3_destination*, out_member)
OUTARG_PTR_TYPEMAPS(Aapl_t*, out_aapl)
OUTARG_PTR_TYPEMAPS(silicon_one::la_object*, out_object)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l3_port*, out_l3_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l3_port*, out_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l2_port*, out_l2_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_l2_port*, out_vxlan_port)
OUTARG_PTR_TYPEMAPS(silicon_one::la_rate_limiter_set*, out_rate_limiter_set)
OUTARG_PTR_TYPEMAPS(json_t*, out_root)
OUTARG_PTR_TYPEMAPS(silicon_one::la_acl* , out_ipv4_pbr_acl)
OUTARG_PTR_TYPEMAPS(silicon_one::la_acl* , out_ipv6_pbr_acl)
OUTARG_PTR_TYPEMAPS(silicon_one::la_security_group_cell*, out_security_group_cell)
OUTARG_PTR_TYPEMAPS(const silicon_one::la_object*, out_resolved_object)
OUTARG_PTR_TYPEMAPS(silicon_one::la_counter_set*, out_rx_counter)
OUTARG_PTR_TYPEMAPS(silicon_one::la_vrf_redirect_destination*, out_vrf_redirect_dest)


OUTARG_ENUM_VECTOR_TYPEMAPS(uint32_t, out_device_int_capabilities)
OUTARG_ENUM_VECTOR_TYPEMAPS(uint32_t, out_fuse_userbits)
OUTARG_ENUM_VECTOR_TYPEMAPS(size_t, out_state_histogram)
OUTARG_ENUM_VECTOR_TYPEMAPS(la_uint_t, out_serdes_mapping_vec)
OUTARG_ENUM_VECTOR_TYPEMAPS(la_uint_t, out_serdes_anlt_order_vec)
OUTARG_ENUM_VECTOR_TYPEMAPS(la_device_id_t, out_device_id_vec)
OUTARG_ENUM_VECTOR_TYPEMAPS(la_tpid_t, out_tpids)
OUTARG_ENUM_VECTOR_TYPEMAPS(la_ethertype_t, out_protocols)
OUTARG_ENUM_VECTOR_TYPEMAPS(la_vlan_id_t, out_mapped_vids)


OUTARG_VECTOR_TYPEMAPS(bool, out_device_bool_capabilities)
OUTARG_VECTOR_TYPEMAPS(std::string, out_device_string_capabilities)
OUTARG_VECTOR_TYPEMAPS(la_oq_pg, out_oq_vector)
OUTARG_VECTOR_TYPEMAPS(la_vsc_oq, out_vsc_vector)
OUTARG_VECTOR_TYPEMAPS(la_vsc_gid_t, out_vsc_vec)
OUTARG_VECTOR_TYPEMAPS(la_mac_addr_t, out_mac_addresses)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_mpls_label, out_labels)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_mpls_vpn_properties_t, out_nh_vpn_properties)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_ipv4_prefix_t, out_subnets)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_ipv6_prefix_t, out_subnets)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_resource_usage_descriptor, out_descriptors)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_resource_thresholds, out_thresholds_vec)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_ipv4_route_entry_parameters, out_la_ipv4_route_entry_parameters_vec)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_ipv6_route_entry_parameters, out_la_ipv6_route_entry_parameters_vec)
//OUTARG_VECTOR_TYPEMAPS(silicon_one::la_l2cp_definition, out_l2cp_definition_vec)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_mac_port::serdes_parameter, out_param_array)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_l2_destination*, out_destinations)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_system_port*, out_system_ports)
OUTARG_VECTOR_TYPEMAPS(const silicon_one::la_l2_destination*, out_l2_mcg_members)
OUTARG_VECTOR_TYPEMAPS(const silicon_one::la_l3_destination*, out_members)
OUTARG_VECTOR_TYPEMAPS(const silicon_one::la_object*, out_resolution_chain)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_acl_field_def, out_key_def_vec)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_acl_action_def, out_command_def_vec)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_acl_key_def_vec_t, out_key_def_vec)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_acl*, out_acls)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_pcl_v4_vec_t, out_pcl_v4_vec)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_pcl_v6_vec_t, out_pcl_v6_vec)
OUTARG_VECTOR_TYPEMAPS(la_mac_entry_t, out_mac_entries)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_copc_protocol_table_data, out_entries)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_ipv4_route_entry, out_route_entries)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_ipv6_route_entry, out_route_entries)
OUTARG_VECTOR_TYPEMAPS(la_component_health_t, out_component_health)
OUTARG_VECTOR_TYPEMAPS(silicon_one::la_ip_snooping_entry_t, out_ip_snooping_prefixes)

OUTARG_CHRONO_TYPEMAPS(std::chrono::milliseconds, out_interval)
OUTARG_CHRONO_TYPEMAPS(std::chrono::microseconds, out_interval)
OUTARG_CHRONO_TYPEMAPS(std::chrono::milliseconds, out_duration)
OUTARG_CHRONO_TYPEMAPS(std::chrono::microseconds, out_detection_time)
OUTARG_CHRONO_TYPEMAPS(std::chrono::microseconds, out_desired_min_tx_interval)
OUTARG_CHRONO_TYPEMAPS(std::chrono::microseconds, out_required_min_rx_interval)
OUTARG_CHRONO_TYPEMAPS(std::chrono::microseconds, out_latency)
OUTARG_CHRONO_TYPEMAPS(std::chrono::nanoseconds, out_xoff_time)
OUTARG_CHRONO_TYPEMAPS(std::chrono::nanoseconds, out_period)


%include "stdint.i"

%template(UIntVector) std::vector<unsigned int>;
%template(SizeVector) std::vector<size_t>;
%template(l3_dest_vector) std::vector<const silicon_one::la_l3_destination*>;
%template(mpls_label_vector) std::vector<silicon_one::la_mpls_label>;
%template(UShortVector) std::vector<unsigned short>;
%template(la_lb_entry_vector) std::vector<la_lb_vector_t>;
//%template(l2cp_entry_vector) std::vector<silicon_one::la_l2cp_definition>;
%template(acl_key_def_vector) std::vector<silicon_one::la_acl_field_def>;
%template(acl_command_def_vector) std::vector<silicon_one::la_acl_action_def>;
%template(acl_command_actions_vector) std::vector<silicon_one::la_acl_command_action>;
%template(pcl_v4_vector) std::vector<silicon_one::la_pcl_v4>;
%template(pcl_v6_vector) std::vector<silicon_one::la_pcl_v6>;
%template(acl_key_val_vector) std::vector<silicon_one::la_acl_field>;
%template(StringVector) std::vector<std::string>;
%template(DoubleVector) std::vector<double>;
%template(resource_thresholds_vector) std::vector<silicon_one::la_resource_thresholds>;
%template(la_ipv4_route_entry_parameters_vec) std::vector<silicon_one::la_ipv4_route_entry_parameters>;
%template(la_ipv6_route_entry_parameters_vec) std::vector<silicon_one::la_ipv6_route_entry_parameters>;
%template(acl_vector) std::vector<silicon_one::la_acl *>;
%template(copc_key_val_vector) std::vector<silicon_one::la_control_plane_classifier::field>;

// The order of the following %includes is important and should match the usage dependencies of classes.

%include "common/la_status.h"
%include "common/la_ip_addr.h"
%nodefaultctor dassert;
%nodefaultdtor dassert;
%include "common/dassert.h"
%clearnodefaultctor dassert;
%clearnodefaultdtor dassert;

%include "api/types/la_common_types.h"
%include "api/types/la_security_group_types.h"
%include "api/types/la_system_types.h"
%include "api/types/la_status_info_types.h"
%include "api/types/la_qos_types.h"
%include "api/types/la_acl_types.h"
%include "api/types/la_bfd_types.h"
%include "api/types/la_ip_types.h"
%include "api/types/la_ethernet_types.h"
%include "api/types/la_fe_types.h"
%include "api/types/la_lpts_types.h"
%include "api/types/la_mpls_types.h"
%include "api/types/la_tm_types.h"
%include "api/types/la_tunnel_types.h"
%include "api/types/la_object.h"
%include "api/types/la_cgm_types.h"
%include "api/types/la_counter_or_meter_set.h"
%include "api/types/la_limit_types.h"
%include "api/types/la_lb_types.h"

%include "api/npu/la_acl_group.h"
%include "api/npu/la_acl_key_profile.h"
%include "api/npu/la_acl_command_profile.h"
%include "api/npu/la_pcl.h"
%include "api/npu/la_acl.h"
%include "api/npu/la_acl_scaled.h"
%include "api/npu/la_bfd_session.h"
%include "api/npu/la_lpts.h"
%include "api/npu/la_copc.h"
%include "api/npu/la_og_lpts_application.h"
%include "api/npu/la_counter_set.h"

%include "api/npu/la_l2_destination.h"
%include "api/npu/la_l2_port.h"
%include "api/npu/la_l3_destination.h"
%include "api/npu/la_destination_pe.h"

%include "api/npu/la_protection_monitor.h"
%include "api/npu/la_l2_protection_group.h"
%include "api/npu/la_l3_protection_group.h"
%include "api/npu/la_multicast_protection_group.h"
%include "api/npu/la_multicast_protection_monitor.h"
%include "api/npu/la_asbr_lsp.h"
%include "api/npu/la_forus_destination.h"
%include "api/npu/la_rate_limiter_set.h"
%include "api/npu/la_stack_port.h"
%include "api/npu/la_vrf_redirect_destination.h"

%include "api/packetapi/la_packet_headers.h"
%include "api/packetapi/la_packet_types.h"

%include "apb/apb_types.h"
%include "cpu2jtag/cpu2jtag.h"
%include "api/system/la_info_phy_handler.h"
%include "api/system/la_info_phy_brick_handler.h"

%include "api/cgm/la_rx_cgm_sq_profile.h"

%include "api/system/la_pbts_map_profile.h"
%include "api/system/la_device.h"
%include "api/system/la_fabric_port.h"
%include "api/system/la_flow_cache_handler.h"
%include "api/system/la_log.h"
%include "api/system/la_hbm_handler.h"
%include "api/system/la_ptp_handler.h"
%include "api/system/la_mac_port.h"
%include "api/system/la_npu_host_port.h"
%include "api/system/la_system_port.h"
%include "api/system/la_recycle_port.h"
%include "api/system/la_remote_port.h"
%include "api/system/la_remote_device.h"
%include "api/system/la_spa_port.h"
%include "api/system/la_pci_port.h"
%include "api/system/la_punt_inject_port.h"
%include "api/system/la_punt_destination.h"
%include "api/system/la_l2_punt_destination.h"
%include "api/system/la_mirror_command.h"
%include "api/system/la_l2_mirror_command.h"
%include "api/system/la_erspan_mirror_command.h"
%include "api/system/la_npu_host_destination.h"
%include "api/system/la_assert.h"
%include "api/system/la_css_memory_layout.h"

%include "api/npu/la_ac_profile.h"
%include "api/npu/la_ecmp_group.h"
%include "api/npu/la_ethernet_port.h"
%include "api/npu/la_filter_group.h"
%include "api/npu/la_l2_service_port.h"
%include "api/npu/la_l3_fec.h"
%include "api/npu/la_l2_port.h"
%include "api/npu/la_l3_port.h"
%include "api/npu/la_ip_tunnel_port.h"
%include "api/npu/la_mpls_label_destination.h"
%include "api/npu/la_mpls_nhlfe.h"
%include "api/npu/la_mpls_vpn_decap.h"
%include "api/npu/la_mpls_vpn_encap.h"
%include "api/npu/la_mldp_vpn_decap.h"
%include "api/npu/la_next_hop.h"
%include "api/npu/la_l3_ac_port.h"
%include "api/npu/la_lsr.h"
%include "api/npu/la_prefix_object.h"
%include "api/npu/la_copc.h"
%include "api/npu/la_te_tunnel.h"
%include "api/npu/la_ip_over_ip_tunnel_port.h"
%include "api/npu/la_svi_port.h"
%include "api/npu/la_gre_port.h"
%include "api/npu/la_gue_port.h"
%include "api/npu/la_ip_tunnel_destination.h"
%include "api/npu/la_switch.h"
%include "api/npu/la_l2_multicast_group.h"
%include "api/npu/la_security_group_cell.h"
%include "api/npu/la_ip_multicast_group.h"
%include "api/npu/la_mpls_multicast_group.h"
%include "api/npu/la_fabric_multicast_group.h"
%include "api/npu/la_vrf.h"
%include "api/npu/la_vxlan_next_hop.h"
%include "api/npu/la_pbts_group.h"

%include "api/tm/la_fabric_port_scheduler.h"
%include "api/tm/la_ifg_scheduler.h"
%include "api/tm/la_interface_scheduler.h"
%include "api/tm/la_logical_port_scheduler.h"
%include "api/tm/la_output_queue_scheduler.h"
%include "api/tm/la_system_port_scheduler.h"
%include "api/tm/la_unicast_tc_profile.h"
%include "api/tm/la_voq_set.h"

%include "api/qos/la_ingress_qos_profile.h"
%include "api/qos/la_egress_qos_profile.h"
%include "api/qos/la_meter_set.h"
%include "api/qos/la_meter_profile.h"
%include "api/qos/la_meter_action_profile.h"
%include "api/qos/la_meter_markdown_profile.h"

%include "api/cgm/la_voq_cgm_evicted_profile.h"
%include "api/cgm/la_voq_cgm_profile.h"

%include "api/types/la_event.h"
%include "api/types/la_event_types.h"
%include "api/types/la_common_types.h"
%include "api/types/la_notification_types.h"

%include "common/la_profile_database.h"

%extend silicon_one::la_notification_desc {
    // map a buffer of a Python object to 'pointer' and 'size'
    %pybuffer_mutable_binary(char *objbuf, size_t objbuf_sz);
    la_notification_desc(char* objbuf, size_t objbuf_sz) {
        la_notification_desc *desc = new la_notification_desc;
        if (objbuf_sz >= sizeof(la_notification_desc)) {
            // Size is valid, copy from input buffer
            memcpy(desc, objbuf, sizeof(*desc));
        } else {
            // Size is invalid, set to all-ones
            memset(desc, 0xff, sizeof(*desc));
        }

        return desc;
    }

    static size_t
    __sizeof__()
    {
        return sizeof(la_notification_desc);
    }
};

%inline %{

    void
        set_ipv4_addr(silicon_one::la_ipv4_addr_t * addr, la_uint8_t b_addr_0, la_uint8_t b_addr_1, la_uint8_t b_addr_2, la_uint8_t b_addr_3)
        {
            addr->b_addr[0] = b_addr_0;
            addr->b_addr[1] = b_addr_1;
            addr->b_addr[2] = b_addr_2;
            addr->b_addr[3] = b_addr_3;
        }

    void
        set_ipv6_w_addr(silicon_one::la_ipv6_addr_t * addr, la_uint16_t w_addr_0, la_uint16_t w_addr_1, la_uint16_t w_addr_2, la_uint16_t w_addr_3, la_uint16_t w_addr_4, la_uint16_t w_addr_5, la_uint16_t w_addr_6, la_uint16_t w_addr_7)
        {
            addr->w_addr[0] = w_addr_0;
            addr->w_addr[1] = w_addr_1;
            addr->w_addr[2] = w_addr_2;
            addr->w_addr[3] = w_addr_3;
            addr->w_addr[4] = w_addr_4;
            addr->w_addr[5] = w_addr_5;
            addr->w_addr[6] = w_addr_6;
            addr->w_addr[7] = w_addr_7;
        }

    void
        set_ipv6_addr(silicon_one::la_ipv6_addr_t * addr, uint64_t q_addr_0, uint64_t q_addr_1)
    {
        addr->q_addr[0] = q_addr_0;
        addr->q_addr[1] = q_addr_1;
    }

    uint64_t
        get_ipv6_addr_q0(silicon_one::la_ipv6_addr_t * addr)
    {
        return addr->q_addr[0];
    }

    uint64_t
        get_ipv6_addr_q1(silicon_one::la_ipv6_addr_t * addr)
    {
        return addr->q_addr[1];
    }
%}

%inline %{

    void
        set_udf_data(silicon_one::la_acl_udf_data * data, uint64_t q_data_0, uint64_t q_data_1)
    {
        data->q_data[0] = q_data_0;
        data->q_data[1] = q_data_1;
    }

    uint64_t
        get_udf_data_q0(silicon_one::la_acl_udf_data * data)
    {
        return data->q_data[0];
    }

    uint64_t
        get_udf_data_q1(silicon_one::la_acl_udf_data * data)
    {
        return data->q_data[1];
    }
%}

%extend silicon_one::la_object {
	PyObject* downcast() {
		return la_object_downcast(self);
	}
}

%define EXTEND_IMPL_MACRO(OBJ_TYPE)
%extend silicon_one::##OBJ_TYPE {
    silicon_one::##OBJ_TYPE##_impl* imp() {
        return reinterpret_cast<##OBJ_TYPE##_impl*>(self);
    }
}
%enddef

%define EXTEND_BASE_MACRO(OBJ_TYPE)
%extend silicon_one::##OBJ_TYPE {
    silicon_one::##OBJ_TYPE##_base* imp() {
        return reinterpret_cast<##OBJ_TYPE##_base*>(self);
    }
}
%enddef

EXTEND_IMPL_MACRO(la_ac_profile)
EXTEND_BASE_MACRO(la_acl_group)
EXTEND_BASE_MACRO(la_acl_key_profile)
EXTEND_BASE_MACRO(la_acl_command_profile)
EXTEND_IMPL_MACRO(la_pcl)
EXTEND_IMPL_MACRO(la_acl)
EXTEND_IMPL_MACRO(la_acl_scaled)
EXTEND_IMPL_MACRO(la_bfd_session)
EXTEND_IMPL_MACRO(la_counter_set)
EXTEND_IMPL_MACRO(la_device)
EXTEND_IMPL_MACRO(la_destination_pe)
EXTEND_IMPL_MACRO(la_ecmp_group)
EXTEND_IMPL_MACRO(la_egress_qos_profile)
EXTEND_BASE_MACRO(la_erspan_mirror_command)
EXTEND_IMPL_MACRO(la_ethernet_port)
EXTEND_IMPL_MACRO(la_fabric_port)
EXTEND_IMPL_MACRO(la_fabric_port_scheduler)
EXTEND_IMPL_MACRO(la_l3_fec)
EXTEND_BASE_MACRO(la_security_group_cell)
EXTEND_IMPL_MACRO(la_filter_group)
EXTEND_IMPL_MACRO(la_flow_cache_handler)
EXTEND_IMPL_MACRO(la_forus_destination)
EXTEND_IMPL_MACRO(la_gre_port)
EXTEND_IMPL_MACRO(la_gue_port)
EXTEND_IMPL_MACRO(la_hbm_handler)
EXTEND_IMPL_MACRO(la_ifg_scheduler)
EXTEND_IMPL_MACRO(la_ingress_qos_profile)
EXTEND_IMPL_MACRO(la_asbr_lsp)
EXTEND_IMPL_MACRO(la_interface_scheduler)
EXTEND_BASE_MACRO(la_ip_multicast_group)
EXTEND_IMPL_MACRO(la_ip_over_ip_tunnel_port)
EXTEND_IMPL_MACRO(la_ip_tunnel_destination)
EXTEND_IMPL_MACRO(la_mpls_multicast_group)
EXTEND_BASE_MACRO(la_l2_multicast_group)
EXTEND_IMPL_MACRO(la_fabric_multicast_group)
EXTEND_IMPL_MACRO(la_logical_port_scheduler)
EXTEND_IMPL_MACRO(la_lpts)
EXTEND_IMPL_MACRO(la_og_lpts_application)
EXTEND_BASE_MACRO(la_l2_mirror_command)
EXTEND_BASE_MACRO(la_l2_protection_group)
EXTEND_IMPL_MACRO(la_l3_protection_group)
EXTEND_IMPL_MACRO(la_l2_punt_destination)
EXTEND_BASE_MACRO(la_l2_service_port)
EXTEND_IMPL_MACRO(la_l3_ac_port)
EXTEND_IMPL_MACRO(la_lsr)
EXTEND_BASE_MACRO(la_mac_port)
EXTEND_IMPL_MACRO(la_meter_action_profile)
EXTEND_IMPL_MACRO(la_meter_markdown_profile)
EXTEND_IMPL_MACRO(la_meter_profile)
EXTEND_IMPL_MACRO(la_meter_set)
EXTEND_IMPL_MACRO(la_mpls_label_destination)
EXTEND_IMPL_MACRO(la_mpls_nhlfe)
EXTEND_IMPL_MACRO(la_mpls_vpn_decap)
EXTEND_IMPL_MACRO(la_mpls_vpn_encap)
EXTEND_IMPL_MACRO(la_mldp_vpn_decap)
EXTEND_BASE_MACRO(la_multicast_protection_group)
EXTEND_BASE_MACRO(la_multicast_protection_monitor)
EXTEND_BASE_MACRO(la_next_hop)
EXTEND_IMPL_MACRO(la_npu_host_destination)
EXTEND_BASE_MACRO(la_npu_host_port)
EXTEND_IMPL_MACRO(la_output_queue_scheduler)
EXTEND_BASE_MACRO(la_pci_port)
EXTEND_BASE_MACRO(la_prefix_object)
EXTEND_BASE_MACRO(la_copc)
EXTEND_IMPL_MACRO(la_protection_monitor)
EXTEND_BASE_MACRO(la_punt_inject_port)
EXTEND_BASE_MACRO(la_rate_limiter_set)
EXTEND_BASE_MACRO(la_recycle_port)
EXTEND_IMPL_MACRO(la_remote_port)
EXTEND_BASE_MACRO(la_remote_device)
EXTEND_BASE_MACRO(la_spa_port)
EXTEND_BASE_MACRO(la_stack_port)
EXTEND_BASE_MACRO(la_svi_port)
EXTEND_IMPL_MACRO(la_switch)
EXTEND_BASE_MACRO(la_system_port)
EXTEND_IMPL_MACRO(la_system_port_scheduler)
EXTEND_IMPL_MACRO(la_te_tunnel)
EXTEND_IMPL_MACRO(la_tc_profile)
EXTEND_IMPL_MACRO(la_rx_cgm_sq_profile)
EXTEND_IMPL_MACRO(la_voq_cgm_profile)
EXTEND_IMPL_MACRO(la_voq_cgm_evicted_profile)
EXTEND_IMPL_MACRO(la_voq_set)
EXTEND_IMPL_MACRO(la_vrf)
EXTEND_IMPL_MACRO(la_vxlan_next_hop)
EXTEND_BASE_MACRO(la_vxlan_next_hop)
EXTEND_IMPL_MACRO(la_pbts_map_profile)
EXTEND_IMPL_MACRO(la_pbts_group)
EXTEND_IMPL_MACRO(la_vrf_redirect_destination)
